//! Logging in through an OpenID Connect provider — UwUAuth or any other — the way Bitwarden's
//! clients do it with Vaultwarden 1.34 and later (docs/uwu-api.md §19).
//!
//! SSO says who somebody is; the vault is still opened with the master password, which the
//! server never sees. The official clients' "Log in with SSO" goes:
//!
//! 1. `/identity/sso/prevalidate` hands out a short token, whatever SSO identifier was typed.
//! 2. `/identity/connect/authorize` checks the client's redirect address, keeps the client's
//!    state and PKCE challenge, and sends the browser on to the provider with a state, a nonce
//!    and a PKCE challenge of its own — and a cookie that ties the login to that browser.
//! 3. The provider sends the browser back to `/identity/connect/oidc-signin`. The server trades
//!    the provider's code for an ID token, checks it (signature, issuer, audience, time, nonce),
//!    finds the account (or makes one without keys, if the settings let this person sign up),
//!    and sends the browser back to the client with a code of its own.
//! 4. The client trades that code (with its PKCE verifier) at `/identity/connect/token`. The
//!    server's own two-step login still applies. A new account then sets its master password
//!    with `/api/accounts/set-password`.
//!
//! The admin portal logs in the same way; who is an admin can follow a group (or UwUAuth's
//! `admin` role), within the admin networks. Pairing with UwUAuth fills in all of this with a
//! one-time code instead of by hand.

use crate::auth::{self, Admin, ClientIp, Session};
use crate::errors::{ApiError, ApiResult};
use crate::identity::{self, KdfData, Login, TokenForm};
use crate::oidc::{self, Expected, Refused};
use crate::{AppState, notices};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::net::IpAddr;
use uwulock_store::{Event, Kdf, NewUser, SsoCode, SsoState, StoreError, User, clock, normalize_email};

/// A login may take this long at the provider.
const STATE_SECONDS: i64 = 10 * 60;
/// The client has this long to trade the code.
const CODE_SECONDS: i64 = 5 * 60;
/// Where the provider sends the browser back to.
pub const CALLBACK: &str = "/identity/connect/oidc-signin";
/// What UwULock's clients may call their own login when they are not a Bitwarden client.
const SUITE_CLIENTS: [&str; 5] = ["cli", "uwussh", "uwurdp", "uwumail", "uwusuite"];

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/organizations/domain/sso/verified", post(verified_domains))
        .route("/identity/sso/prevalidate", get(prevalidate))
        .route("/identity/connect/authorize", get(authorize))
        .route(CALLBACK, get(signin))
        .route("/api/accounts/set-password", post(set_password))
        .route("/api/organizations/{id}/auto-enroll-status", get(auto_enroll_status))
        .route("/api/organizations/{id}/policies/master-password", get(master_password_policy))
        .route("/uwu/v1/admin/sso", get(get_settings).put(put_settings))
        .route("/uwu/v1/admin/sso/test", post(test))
        .route("/uwu/v1/admin/sso/pair", post(pair))
        .route("/uwu/v1/admin/sso/pairing", delete(unpair))
        .route("/uwu/v1/admin/scim/token", post(scim_token))
}

// ── Settings ──────────────────────────────────────────────

/// Who may make an account by logging in through SSO.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Signups {
    /// Only accounts there are already.
    Off,
    /// And addresses with an invitation, or pushed over SCIM.
    #[default]
    Invitation,
    /// And everybody in the user group (or with UwUAuth's `user` role).
    Group,
}

/// The pairing with UwUAuth, when there is one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Paired {
    pub url: String,
    pub app_id: String,
    pub manage_url: Option<String>,
    pub date: String,
}

/// §19.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SsoSettings {
    pub enabled: bool,
    pub issuer: String,
    pub client_id: String,
    /// Sealed with the server's secret ([`crate::secret`]); the portal only learns whether there
    /// is one.
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub pkce: bool,
    /// What `/api/organizations/domain/sso/verified` hands out; the clients may type anything.
    pub identifier: String,
    /// What the login pages write on the button.
    pub label: String,
    /// Password logins only for admins (while `adminsOnlyWithSso` is off) and the CLI's API key.
    pub only: bool,
    pub signups: Signups,
    pub user_group: Option<String>,
    pub admin_group: Option<String>,
    pub admins_only_with_sso: bool,
    pub trust_unverified_email: bool,
    pub groups_claim: String,
    /// After pairing with UwUAuth: its roles `admin` and `user` in place of the two groups.
    pub roles_claim: Option<String>,
    pub paired: Option<Paired>,
}

impl Default for SsoSettings {
    fn default() -> Self {
        SsoSettings {
            enabled: false,
            issuer: String::new(),
            client_id: String::new(),
            client_secret: None,
            scopes: DEFAULT_SCOPES.iter().map(|scope| scope.to_string()).collect(),
            pkce: true,
            identifier: "uwulock".into(),
            label: "SSO".into(),
            only: false,
            signups: Signups::Invitation,
            user_group: None,
            admin_group: None,
            admins_only_with_sso: false,
            trust_unverified_email: false,
            groups_claim: "groups".into(),
            roles_claim: None,
            paired: None,
        }
    }
}

const DEFAULT_SCOPES: [&str; 4] = ["openid", "email", "profile", "groups"];
/// What the secret is sealed for.
const SECRET_PURPOSE: &str = "sso.clientSecret";

impl SsoSettings {
    /// Switched on, and with enough to work.
    pub fn active(&self) -> bool {
        self.enabled && !self.issuer.trim().is_empty() && !self.client_id.trim().is_empty()
    }

    pub fn check(&self) -> Result<(), String> {
        if !self.issuer.trim().is_empty() {
            oidc::checked_endpoint(&self.issuer, "The issuer")?;
        }
        if self.enabled && (self.issuer.trim().is_empty() || self.client_id.trim().is_empty()) {
            return Err("SSO needs the provider's issuer address and the client id.".into());
        }
        if self.client_id.len() > 255 {
            return Err("The client id is too long.".into());
        }
        if self.enabled && !self.scopes.iter().any(|scope| scope == "openid") {
            return Err("The scopes have to include openid.".into());
        }
        if self.scopes.len() > 20
            || self
                .scopes
                .iter()
                .any(|scope| scope.is_empty() || scope.len() > 100 || scope.contains(char::is_whitespace))
        {
            return Err("Scopes are single words, at most 20 of them.".into());
        }
        if !(1..=50).contains(&self.identifier.trim().chars().count()) {
            return Err("The SSO identifier has 1 to 50 characters.".into());
        }
        if !(1..=40).contains(&self.label.trim().chars().count()) {
            return Err("The button's label has 1 to 40 characters.".into());
        }
        let claim_ok = |claim: &str| !claim.trim().is_empty() && claim.len() <= 100;
        if !claim_ok(&self.groups_claim) || self.roles_claim.as_deref().is_some_and(|claim| !claim_ok(claim)) {
            return Err("A claim's name has 1 to 100 characters.".into());
        }
        for group in [&self.user_group, &self.admin_group].into_iter().flatten() {
            if group.trim().is_empty() || group.len() > 200 {
                return Err("A group's name has 1 to 200 characters.".into());
            }
        }
        Ok(())
    }
}

/// The settings as the portal shows them (§19.1), with what it needs for setting a provider up
/// by hand.
fn settings_json(state: &AppState) -> Value {
    let settings = state.settings();
    let sso = &settings.sso;
    let mut value = serde_json::to_value(sso).expect("settings serialize");
    if let Some(object) = value.as_object_mut() {
        object.remove("clientSecret");
        object.insert("clientSecretSet".into(), sso.client_secret.is_some().into());
        object.insert("redirectUri".into(), format!("{}{CALLBACK}", state.config.public).into());
        object.insert("scimUrl".into(), format!("{}/scim/v2", state.config.public).into());
        object.insert("scimTokenSet".into(), settings.scim.token_hash.is_some().into());
        object.insert("scimOnDelete".into(), serde_json::to_value(settings.scim.on_delete).unwrap_or(Value::Null));
    }
    value
}

/// A password (or passkey) login, while SSO is the only way in: only admins that may.
pub(crate) fn password_allowed(state: &AppState, user: &User) -> ApiResult<()> {
    let settings = state.settings.read();
    let sso = &settings.sso;
    if !sso.active() || !sso.only || (user.admin && !sso.admins_only_with_sso) {
        return Ok(());
    }
    Err(ApiError::bad("Log in with SSO.").code("sso_required"))
}

// ── What the clients ask before they go ───────────────────

#[derive(Deserialize, Default)]
struct EmailData {
    #[serde(default, alias = "Email")]
    email: String,
}

/// Which "organization" an address logs in with: the SSO identifier, for any address.
async fn verified_domains(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    body: Option<Json<EmailData>>,
) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let settings = state.settings();
    let email = body.map(|Json(body)| body.email).unwrap_or_default();
    let domain = email.rsplit_once('@').map(|(_, domain)| normalize_email(domain)).unwrap_or_default();
    let data = if settings.sso.active() {
        vec![json!({
            "object": "verifiedOrganizationDomainSsoDetails",
            "organizationIdentifier": settings.sso.identifier,
            "organizationName": "UwULock",
            "domainName": domain,
        })]
    } else {
        Vec::new()
    };
    Ok(Json(json!({ "object": "list", "data": data, "continuationToken": null })))
}

async fn prevalidate(State(state): State<AppState>, ClientIp(ip): ClientIp) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    if !state.settings().sso.active() {
        return Err(ApiError::bad("SSO is not enabled on this server."));
    }
    Ok(Json(json!({ "token": state.tokens.sso_token() })))
}

/// The UUID the clients get for the SSO identifier, where they want an organization's id.
fn identifier_id(identifier: &str) -> String {
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, format!("uwulock:sso:{}", identifier.to_lowercase()).as_bytes())
        .to_string()
}

async fn auto_enroll_status(
    State(state): State<AppState>,
    _session: Session,
    Path(identifier): Path<String>,
) -> ApiResult<Json<Value>> {
    let settings = state.settings();
    if !identifier.trim().eq_ignore_ascii_case(settings.sso.identifier.trim()) {
        return Err(ApiError::not_found("Organization not found."));
    }
    Ok(Json(json!({
        "object": "organizationAutoEnrollStatus",
        "id": identifier_id(&settings.sso.identifier),
        "resetPasswordEnabled": false,
    })))
}

/// The server's master password rules, where the clients' "set initial password" asks the
/// organization of the SSO identifier for them.
async fn master_password_policy(
    State(state): State<AppState>,
    _session: Session,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let settings = state.settings();
    let own = identifier_id(&settings.sso.identifier);
    if !id.eq_ignore_ascii_case(&own) {
        return Err(ApiError::not_found("Organization not found."));
    }
    let rules = &settings.policies.master_password;
    Ok(Json(json!({
        "object": "policy",
        "id": own,
        "organizationId": own,
        "type": 1,
        "enabled": rules.min_length > 0 || rules.min_complexity > 0,
        "data": {
            "minComplexity": rules.min_complexity,
            "minLength": rules.min_length,
            "requireUpper": false,
            "requireLower": false,
            "requireNumbers": false,
            "requireSpecial": false,
            "enforceOnLogin": rules.enforce_on_login,
        },
    })))
}

// ── To the provider ───────────────────────────────────────

/// `http://localhost:<port>/…` or `http://127.0.0.1:<port>/…`: where a native app listens.
fn loopback_redirect(uri: &str) -> bool {
    reqwest::Url::parse(uri).is_ok_and(|url| {
        url.scheme() == "http"
            && url.port().is_some()
            && url.host_str().is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "[::1]"))
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

/// The redirect address of a browser extension's `identity` API: Chromium's or Firefox's.
fn extension_redirect(uri: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(uri) else { return false };
    let Some(host) = url.host_str() else { return false };
    let plain = url.scheme() == "https"
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none();
    let chromium = host
        .strip_suffix(".chromiumapp.org")
        .is_some_and(|id| id.len() == 32 && id.bytes().all(|byte| (b'a'..=b'p').contains(&byte)));
    let firefox = host
        .strip_suffix(".extensions.allizom.org")
        .is_some_and(|id| id.len() == 40 && id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    plain && (chromium || firefox)
}

/// Whether `client_id` may be sent back to `uri` (§19.2 step 3).
fn redirect_allowed(public: &str, client_id: &str, uri: &str) -> bool {
    match client_id {
        "web" | "browser" => uri == format!("{public}/sso-connector.html"),
        "mobile" => uri == "bitwarden://sso-callback",
        "desktop" => uri == "bitwarden://sso-callback" || loopback_redirect(uri),
        "uwulock-extension" => extension_redirect(uri),
        other if SUITE_CLIENTS.contains(&other) => loopback_redirect(uri),
        _ => false,
    }
}

/// The name of the cookie that ties a login to the browser: `__Host-` where the server is
/// reached by https, as it should be.
fn cookie_name(state: &AppState) -> &'static str {
    if state.config.public.starts_with("https://") { "__Host-uwu-sso" } else { "uwu-sso" }
}

fn cookie(state: &AppState, value: &str, seconds: i64) -> HeaderValue {
    let secure = if state.config.public.starts_with("https://") { "Secure; " } else { "" };
    let text = format!("{}={value}; {secure}HttpOnly; SameSite=Lax; Path=/; Max-Age={seconds}", cookie_name(state));
    HeaderValue::from_str(&text).expect("a cookie of plain characters")
}

fn cookie_value(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let name = cookie_name(state);
    headers.get_all(header::COOKIE).iter().filter_map(|value| value.to_str().ok()).find_map(|line| {
        line.split(';').find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name).then(|| value.trim().to_string())
        })
    })
}

fn pkce_challenge(verifier: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(auth::sha256(verifier.as_bytes()))
}

fn redirect(to: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(value) = HeaderValue::from_str(to) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

/// `uri` with `pairs` added to its query.
fn with_query(uri: &str, pairs: &[(&str, &str)]) -> String {
    match reqwest::Url::parse(uri) {
        Ok(mut url) => {
            {
                let mut query = url.query_pairs_mut();
                for (key, value) in pairs {
                    query.append_pair(key, value);
                }
            }
            url.to_string()
        }
        Err(_) => uri.to_string(),
    }
}

async fn authorize(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult<Response> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let settings = state.settings();
    let sso = &settings.sso;
    if !sso.active() {
        return Err(ApiError::bad("SSO is not enabled on this server."));
    }
    let get = |name: &str| query.get(name).map(|value| value.trim()).filter(|value| !value.is_empty());
    let client_id = get("client_id").ok_or_else(|| ApiError::bad("client_id is missing."))?;
    let redirect_uri = get("redirect_uri").ok_or_else(|| ApiError::bad("redirect_uri is missing."))?;
    if !redirect_allowed(&state.config.public, client_id, redirect_uri) {
        return Err(ApiError::bad("This redirect_uri is not allowed for this client."));
    }
    if get("response_type") != Some("code") {
        return Err(ApiError::bad("Only response_type=code is supported."));
    }
    let client_state =
        get("state").filter(|value| value.len() <= 2048).ok_or_else(|| ApiError::bad("state is missing."))?;
    let challenge = get("code_challenge")
        .filter(|value| {
            (43..=128).contains(&value.len())
                && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte))
        })
        .ok_or_else(|| ApiError::bad("code_challenge is missing."))?;
    if get("code_challenge_method") != Some("S256") {
        return Err(ApiError::bad("Only code_challenge_method=S256 is supported."));
    }
    let sso_token = get("ssoToken").or_else(|| get("sso_token")).unwrap_or_default();
    if !state.tokens.check_sso_token(sso_token) {
        return Err(ApiError::bad("The SSO token is missing or ran out. Start the login again."));
    }
    let discovery = oidc::discover(&state.oidc, &sso.issuer).await.map_err(|error| {
        tracing::warn!(%error, "the SSO provider could not be reached");
        ApiError::upstream("The login provider does not answer. Try again later, or ask an admin.")
    })?;
    let own_state = auth::random_token(32);
    let nonce = auth::random_token(32);
    let verifier = sso.pkce.then(|| auth::random_token(48));
    let binding = auth::random_token(32);
    state
        .store
        .put_sso_state(
            auth::sha256(own_state.as_bytes()),
            SsoState {
                client_id: client_id.to_string(),
                redirect_uri: redirect_uri.to_string(),
                client_state: client_state.to_string(),
                code_challenge: challenge.to_string(),
                nonce: nonce.clone(),
                verifier: verifier.clone(),
                binding_hash: auth::sha256(binding.as_bytes()),
                expires: clock::in_seconds(STATE_SECONDS),
            },
        )
        .await?;
    let mut url = reqwest::Url::parse(&discovery.authorization_endpoint).map_err(ApiError::internal)?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs
            .append_pair("response_type", "code")
            .append_pair("client_id", sso.client_id.trim())
            .append_pair("redirect_uri", &format!("{}{CALLBACK}", state.config.public))
            .append_pair("scope", &sso.scopes.join(" "))
            .append_pair("state", &own_state)
            .append_pair("nonce", &nonce);
        if let Some(verifier) = &verifier {
            pairs.append_pair("code_challenge", &pkce_challenge(verifier)).append_pair("code_challenge_method", "S256");
        }
    }
    let mut response = redirect(url.as_str());
    response.headers_mut().insert(header::SET_COOKIE, cookie(&state, &binding, STATE_SECONDS));
    Ok(response)
}

// ── Back from the provider ────────────────────────────────

#[derive(Deserialize)]
struct SigninQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    iss: Option<String>,
}

/// A page for a browser that came back with nothing to go on: no client to send it to.
fn stranded(state: &AppState, message: &str) -> Response {
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
         <title>UwULock</title><body style=\"font-family:sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem\">\
         <h1>UwULock</h1><p>{message}</p><p><a href=\"{}/\">UwULock</a></p>",
        state.config.public
    );
    let mut response = (StatusCode::BAD_REQUEST, Html(body)).into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie(state, "", 0));
    response
}

async fn signin(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Query(query): Query<SigninQuery>,
) -> Response {
    if !state.limits.anonymous.check(ip) {
        return ApiError::too_many("Too many requests. Wait a minute and try again.").into_response();
    }
    let Some(own_state) = query.state.as_deref().filter(|value| !value.is_empty() && value.len() <= 256) else {
        return stranded(&state, "This login has no state. Start it again in the app.");
    };
    let Ok(Some(login)) = state.store.take_sso_state(auth::sha256(own_state.as_bytes())).await else {
        return stranded(&state, "This login ran out or was used already. Start it again in the app.");
    };
    // The browser that comes back has to be the one that set out: otherwise somebody could have a
    // victim's browser finish a login they started, into their own account.
    let bound = cookie_value(&state, &headers)
        .is_some_and(|value| auth::constant_time_eq(&auth::sha256(value.as_bytes()), &login.binding_hash));
    if !bound {
        return stranded(&state, "This login was started in another browser. Start it again in the app.");
    }
    let back = |error: Option<&str>, code: Option<&str>| {
        let target = match (error, code) {
            (_, Some(code)) => with_query(&login.redirect_uri, &[("code", code), ("state", &login.client_state)]),
            (message, None) => with_query(
                &login.redirect_uri,
                &[
                    ("error", "access_denied"),
                    ("error_description", message.unwrap_or("The login was refused.")),
                    ("state", &login.client_state),
                ],
            ),
        };
        let mut response = redirect(&target);
        response.headers_mut().insert(header::SET_COOKIE, cookie(&state, "", 0));
        response
    };
    if let Some(error) = &query.error {
        tracing::info!(%error, description = ?query.error_description, "the SSO provider refused a login");
        let message = match error.as_str() {
            "access_denied" => "The login provider refused the login.",
            _ => "The login provider could not log you in.",
        };
        return back(Some(message), None);
    }
    let Some(code) = query.code.as_deref().filter(|code| !code.is_empty() && code.len() <= 4096) else {
        return back(Some("The login provider sent no code."), None);
    };
    let settings = state.settings();
    if !settings.sso.active() {
        return back(Some("SSO is not enabled on this server."), None);
    }
    if let Some(iss) = &query.iss
        && iss.trim_end_matches('/') != settings.sso.issuer.trim().trim_end_matches('/')
    {
        tracing::warn!(%iss, "an SSO answer came back from another issuer");
        return back(Some("The answer came from another login provider."), None);
    }
    let claims = match provider_claims(&state, &settings.sso, code, &login.nonce, login.verifier.as_deref()).await {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(%error, "an SSO login failed at the provider");
            return back(Some("The login provider's answer could not be used. Ask an admin to look at the log."), None);
        }
    };
    let user = match account_for(&state, &settings, &claims, ip).await {
        Ok(user) => user,
        Err(refusal) => {
            let email = claims.get("email").and_then(Value::as_str).unwrap_or_default();
            let event = Event {
                kind: "login-failed".into(),
                email: Some(normalize_email(email).chars().take(identity::MAX_EMAIL).collect()),
                ip: Some(ip.to_string()),
                detail: Some(format!("SSO: {refusal}")),
                ..Event::default()
            };
            let _ = state.store.log_event(event).await;
            return back(Some(&refusal), None);
        }
    };
    let one_time = auth::random_token(32);
    let stored = state
        .store
        .put_sso_code(
            auth::sha256(one_time.as_bytes()),
            SsoCode {
                user_id: user.id.clone(),
                client_id: login.client_id.clone(),
                redirect_uri: login.redirect_uri.clone(),
                code_challenge: login.code_challenge.clone(),
                expires: clock::in_seconds(CODE_SECONDS),
            },
        )
        .await;
    if let Err(error) = stored {
        tracing::error!(%error, "an SSO code could not be kept");
        return back(Some("Something went wrong on the server. Try again."), None);
    }
    back(None, Some(&one_time))
}

/// The provider's code traded, the ID token checked, and what it (or userinfo) says.
async fn provider_claims(
    state: &AppState,
    sso: &SsoSettings,
    code: &str,
    nonce: &str,
    verifier: Option<&str>,
) -> Result<Map<String, Value>, String> {
    let discovery = oidc::discover(&state.oidc, &sso.issuer).await?;
    let secret = match &sso.client_secret {
        Some(sealed) => Some(state.secret.open(sealed, SECRET_PURPOSE)?),
        None => None,
    };
    let client = oidc::ClientAuth { client_id: sso.client_id.trim(), client_secret: secret.as_deref() };
    let callback = format!("{}{CALLBACK}", state.config.public);
    let answer = oidc::exchange(&discovery, &client, code, &callback, verifier).await?;
    let id_token = answer.id_token.ok_or("the token endpoint sent no ID token (is the scope openid there?)")?;
    let expected = Expected { issuer: &discovery.issuer, client_id: sso.client_id.trim(), nonce };
    let now = auth::now_seconds();
    let keys = oidc::keys(&state.oidc, &discovery, false).await?;
    let mut claims = match oidc::check_id_token(&id_token, &keys, &expected, now) {
        Err(Refused::UnknownKey) => {
            let keys = oidc::keys(&state.oidc, &discovery, true).await?;
            oidc::check_id_token(&id_token, &keys, &expected, now)
        }
        other => other,
    }
    .map_err(|refused| match refused {
        Refused::UnknownKey => "the ID token is signed with a key the provider does not list".to_string(),
        Refused::Invalid(reason) => format!("the ID token was refused: {reason}"),
    })?;
    // What the ID token leaves out may be in userinfo: the address, and the groups or roles.
    let wanted = ["email"]
        .into_iter()
        .chain((sso.user_group.is_some() || sso.admin_group.is_some()).then_some(sso.groups_claim.as_str()))
        .chain(sso.roles_claim.as_deref());
    if wanted.clone().any(|name| claim(&claims, name).is_none())
        && let Some(access_token) = &answer.access_token
    {
        let info = oidc::userinfo(&discovery, access_token).await?;
        if info.get("sub") == claims.get("sub") {
            for (key, value) in info {
                claims.entry(key).or_insert(value);
            }
        }
    }
    Ok(claims)
}

/// A claim, also a nested one like `realm_access.roles`.
fn claim<'a>(claims: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    let mut parts = name.split('.');
    let mut found = claims.get(parts.next()?)?;
    for part in parts {
        found = found.get(part)?;
    }
    Some(found)
}

/// A claim as a list of names: an array of strings, or one string. Keycloak writes groups as
/// paths (`/vault-users`); the leading slash does not count.
fn claim_list(claims: &Map<String, Value>, name: &str) -> Vec<String> {
    let names = match claim(claims, name) {
        Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        Some(Value::String(one)) => vec![one.clone()],
        _ => Vec::new(),
    };
    names.into_iter().map(|name| name.trim().trim_start_matches('/').to_string()).collect()
}

fn in_group(groups: &[String], group: &str) -> bool {
    let group = group.trim().trim_start_matches('/');
    groups.iter().any(|name| name == group)
}

/// What the provider says about somebody's rights here: admin (or not, or it does not say),
/// and whether they may make an account.
struct Rights {
    admin: Option<bool>,
    user: bool,
}

fn rights(sso: &SsoSettings, claims: &Map<String, Value>) -> Rights {
    if let Some(roles_claim) = &sso.roles_claim {
        let roles = claim_list(claims, roles_claim);
        let admin = in_group(&roles, "admin");
        return Rights { admin: Some(admin), user: admin || in_group(&roles, "user") };
    }
    let groups = claim_list(claims, &sso.groups_claim);
    let admin = sso.admin_group.as_deref().map(|group| in_group(&groups, group));
    let user = match &sso.user_group {
        Some(group) => in_group(&groups, group),
        None => true,
    };
    Rights { admin, user: user || admin == Some(true) }
}

/// §19.3: the account this login is for, linked or made now; the reason in words otherwise.
async fn account_for(
    state: &AppState,
    settings: &crate::Settings,
    claims: &Map<String, Value>,
    ip: IpAddr,
) -> Result<User, String> {
    let sso = &settings.sso;
    let issuer = sso.issuer.trim().trim_end_matches('/').to_string();
    let internal = |error: StoreError| {
        tracing::error!(%error, "an SSO login could not be looked up");
        "Something went wrong on the server. Try again.".to_string()
    };
    let subject = claims.get("sub").and_then(Value::as_str).unwrap_or_default().to_string();
    let email = claims.get("email").and_then(Value::as_str).map(normalize_email).filter(|email| email.contains('@'));
    let verified = sso.trust_unverified_email
        || matches!(claims.get("email_verified"), Some(Value::Bool(true)))
        || claims.get("email_verified").and_then(Value::as_str) == Some("true");
    let rights = rights(sso, claims);
    let context = notices::Context { ip: Some(ip), ..notices::Context::default() };

    let user = if let Some(identity) = state.store.sso_identity(&issuer, &subject).await.map_err(internal)? {
        state.store.user(&identity.user_id).await.map_err(internal)?.ok_or("This account is gone.")?
    } else {
        let email = email
            .filter(|_| verified)
            .ok_or("The login provider did not give a verified email address, which the account is found by.")?;
        match state.store.user_by_email(&email).await.map_err(internal)? {
            Some(user) => {
                if state.store.sso_identity_of(&user.id, &issuer).await.map_err(internal)?.is_some() {
                    return Err("This account is linked to another login at this provider.".into());
                }
                if user.disabled {
                    return Err("This account has been disabled.".into());
                }
                state.store.link_sso(&user.id, &issuer, &subject).await.map_err(|error| match error {
                    StoreError::Exists => "This account is linked to another login at this provider.".to_string(),
                    other => internal(other),
                })?;
                notices::record(state, &user, "ssoLinked", &context, json!({ "issuer": issuer })).await;
                tracing::info!(email = %user.email, "an account was linked to an SSO login");
                user
            }
            None => sign_up(state, settings, claims, &email, &issuer, &subject, &rights, ip).await?,
        }
    };
    if user.disabled {
        return Err("This account has been disabled.".into());
    }
    let _ = state.store.sso_logged_in(&issuer, &subject).await;
    follow_admin_right(state, settings, user, rights.admin, ip).await.map_err(internal)
}

/// A new account without keys, if this person may have one (§19.3 step 3).
#[allow(clippy::too_many_arguments)]
async fn sign_up(
    state: &AppState,
    settings: &crate::Settings,
    claims: &Map<String, Value>,
    email: &str,
    issuer: &str,
    subject: &str,
    rights: &Rights,
    ip: IpAddr,
) -> Result<User, String> {
    let sso = &settings.sso;
    let internal = |error: StoreError| {
        tracing::error!(%error, "an SSO account could not be made");
        "Something went wrong on the server. Try again.".to_string()
    };
    let invitation =
        state.store.invitation(email).await.map_err(internal)?.filter(|invitation| invitation.expires > clock::now());
    let provisioned = state.store.scim_provisioned(email).await.map_err(internal)?.filter(|entry| entry.active);
    let allowed = match sso.signups {
        Signups::Off => false,
        Signups::Invitation => invitation.is_some() || provisioned.is_some(),
        Signups::Group => invitation.is_some() || provisioned.is_some() || rights.user,
    };
    if !allowed {
        return Err("There is no account for this address. Ask for an invitation.".into());
    }
    let admin_here = crate::networks::allowed(&settings.admin_networks, ip);
    let name = claims
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| provisioned.as_ref().and_then(|entry| entry.display_name.as_deref()))
        .map(|name| name.trim().chars().take(50).collect::<String>())
        .filter(|name| !name.is_empty());
    let new = NewUser {
        email: email.to_string(),
        name,
        // No master password yet: its owner sets one with the first login (§19.2 step 6).
        password_hash: String::new(),
        password_hint: None,
        user_key: String::new(),
        private_key: None,
        public_key: None,
        kdf: Kdf { kind: 0, iterations: 600_000, memory: None, parallelism: None },
        language: invitation
            .as_ref()
            .map_or_else(|| settings.default_language.code().to_string(), |i| i.language.clone()),
        admin: invitation.as_ref().is_some_and(|invitation| invitation.admin)
            || (rights.admin == Some(true) && admin_here),
    };
    let user = state.store.create_user(new).await.map_err(|error| match error {
        StoreError::Exists => "There is an account for this address already. Log in again.".to_string(),
        other => internal(other),
    })?;
    if let Err(error) = state.store.link_sso(&user.id, issuer, subject).await {
        let _ = state.store.delete_user(&user.id).await;
        return Err(match error {
            StoreError::Exists => "This login belongs to another account.".to_string(),
            other => internal(other),
        });
    }
    let _ = state.store.claim_scim_user(email, &user.id).await;
    let event = Event {
        kind: "register".into(),
        user_id: Some(user.id.clone()),
        email: Some(user.email.clone()),
        ip: Some(ip.to_string()),
        detail: Some("through SSO".into()),
        ..Event::default()
    };
    let _ = state.store.log_event(event).await;
    tracing::info!(email = %user.email, admin = user.admin, "account made through SSO");
    Ok(user)
}

/// Being an admin follows the provider's group (or role) at every SSO login, where it says so:
/// given only within the admin networks, taken wherever — but never from the last admin, who
/// would lock everybody out of the portal.
async fn follow_admin_right(
    state: &AppState,
    settings: &crate::Settings,
    user: User,
    admin: Option<bool>,
    ip: IpAddr,
) -> Result<User, StoreError> {
    let change = match admin {
        Some(true) if !user.admin && crate::networks::allowed(&settings.admin_networks, ip) => true,
        Some(false) if user.admin => {
            if state.store.admin_count().await? <= 1 {
                tracing::warn!(email = %user.email, "SSO says this is no admin, but it is the last one: it stays");
                false
            } else {
                true
            }
        }
        _ => false,
    };
    if !change {
        return Ok(user);
    }
    let now_admin = !user.admin;
    let updated = state.store.update_user(&user.id, move |user| user.admin = now_admin).await?.unwrap_or(user);
    let event = Event {
        kind: "admin".into(),
        user_id: Some(updated.id.clone()),
        email: Some(updated.email.clone()),
        ip: Some(ip.to_string()),
        detail: Some(format!("SSO {} the admin right", if now_admin { "gave" } else { "took" })),
        ..Event::default()
    };
    let _ = state.store.log_event(event).await;
    tracing::info!(email = %updated.email, admin = now_admin, "the admin right follows SSO");
    Ok(updated)
}

// ── The client trades its code ────────────────────────────

/// `grant_type=authorization_code` at `/identity/connect/token`.
pub(crate) async fn grant(state: &AppState, ip: IpAddr, headers: &HeaderMap, form: &TokenForm) -> ApiResult<Response> {
    let required =
        |name: &str, label: &str| form.get(name).ok_or_else(|| ApiError::bad(format!("{label} cannot be blank")));
    let code = required("code", "code")?;
    let verifier = required("codeverifier", "code_verifier")?;
    let redirect_uri = required("redirecturi", "redirect_uri")?;
    let client_id = required("clientid", "client_id")?;
    let device_id = required("deviceidentifier", "device_identifier")?;
    let device_name = required("devicename", "device_name")?;
    let device_type: i64 = required("devicetype", "device_type")?.trim().parse().unwrap_or(14);
    identity::check_scope(state, client_id, form.get("scope"))?;
    if device_name.len() > 256 || device_id.len() > 256 {
        return Err(ApiError::bad("The device is not what it should be."));
    }
    if !state.limits.login.check(ip) {
        return Err(ApiError::too_many("Too many login requests. Wait a minute and try again."));
    }
    let refused = || {
        ApiError::json(json!({
            "error": "invalid_grant",
            "error_description": "invalid_code",
            "ErrorModel": { "Message": "This SSO login ran out or was used already. Start it again.", "Object": "error" },
        }))
    };
    let code_hash = auth::sha256(code.as_bytes());
    let stored = state.store.sso_code(code_hash.clone()).await?.ok_or_else(refused)?;
    let right_client = stored.client_id == client_id && stored.redirect_uri == redirect_uri;
    let right_verifier = auth::constant_time_eq(pkce_challenge(verifier).as_bytes(), stored.code_challenge.as_bytes());
    if !right_client || !right_verifier {
        return Err(refused());
    }
    let user = state.store.user(&stored.user_id).await?.ok_or_else(refused)?;
    if user.disabled {
        identity::log(state, "login-failed", Some(&user), &user.email, ip, device_type, "account disabled").await;
        return Err(ApiError::bad("This account has been disabled."));
    }
    let known_device = state.store.device(&user.id, device_id).await?;
    let remember = match crate::two_factor::check_login(state, &user, form, known_device.as_ref(), ip, headers).await {
        Ok(remember) => remember,
        Err(error) => {
            if error.status == StatusCode::BAD_REQUEST && form.get("twofactortoken").is_some() {
                identity::log(state, "two-factor-failed", Some(&user), &user.email, ip, device_type, "wrong code")
                    .await;
                let context = notices::Context { device_type: Some(device_type), ..notices::Context::ip(ip) };
                let provider = form.get("twofactorprovider").and_then(|value| value.trim().parse::<i64>().ok());
                notices::failed(state, &user, "failedTwoFactor", "two-factor-failed", &context, provider).await;
            }
            return Err(error);
        }
    };
    // Through: the code is used up now, and only once.
    if !state.store.take_sso_code(code_hash).await? {
        return Err(refused());
    }
    let login = Login {
        device_id,
        device_name,
        device_type,
        known: known_device.is_some(),
        remember,
        by_request: false,
        sso: true,
    };
    let mut body = identity::finish_login(state, &user, ip, form, login).await?;
    if user.user_key.is_empty()
        && let Some(object) = body.as_object_mut()
    {
        // No master password yet: the clients go to "set initial password".
        for key in ["Key", "PrivateKey", "AccountKeys"] {
            object.remove(key);
        }
        object.insert(
            "UserDecryptionOptions".into(),
            json!({ "HasMasterPassword": false, "Object": "userDecryptionOptions" }),
        );
    }
    Ok(Json(body).into_response())
}

// ── Setting the first master password ─────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyPair {
    #[serde(alias = "wrappedPrivateKey")]
    encrypted_private_key: Option<String>,
    public_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountKeysData {
    #[serde(default)]
    user_key_encrypted_account_private_key: Option<String>,
    #[serde(default)]
    account_public_key: Option<String>,
    #[serde(default)]
    public_key_encryption_key_pair: Option<KeyPair>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetPasswordData {
    #[serde(default)]
    master_password_hash: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    master_password_hint: Option<String>,
    #[serde(default)]
    keys: Option<identity::Keys>,
    #[serde(default)]
    kdf: Option<i64>,
    #[serde(default)]
    kdf_iterations: Option<i64>,
    #[serde(default)]
    kdf_memory: Option<i64>,
    #[serde(default)]
    kdf_parallelism: Option<i64>,
    #[serde(default)]
    master_password_authentication: Option<identity::MasterPasswordAuthentication>,
    #[serde(default)]
    master_password_unlock: Option<identity::MasterPasswordUnlock>,
    #[serde(default)]
    account_keys: Option<AccountKeysData>,
}

/// `POST /api/accounts/set-password`: an account made through SSO gets its master password,
/// keys and KDF — once. The session goes on (as with Vaultwarden): nobody else could have had
/// one, there was no password to steal.
async fn set_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(data): Json<SetPasswordData>,
) -> ApiResult<StatusCode> {
    let user = &session.user;
    if !user.user_key.is_empty() {
        return Err(ApiError::bad("This account has a master password already."));
    }
    let (hash, key, kdf) = match (data.master_password_authentication, data.master_password_unlock) {
        (Some(authentication), Some(unlock)) => {
            if authentication.kdf != unlock.kdf
                || normalize_email(&authentication.salt) != user.email
                || normalize_email(&unlock.salt) != user.email
            {
                return Err(ApiError::bad("The salt or the KDF do not fit this account."));
            }
            (authentication.hash, unlock.key, unlock.kdf)
        }
        _ => {
            let missing = || ApiError::bad("The master password is missing.");
            let kdf = KdfData {
                kdf: data.kdf.ok_or_else(missing)?,
                kdf_iterations: data.kdf_iterations.ok_or_else(missing)?,
                kdf_memory: data.kdf_memory,
                kdf_parallelism: data.kdf_parallelism,
            };
            (data.master_password_hash.ok_or_else(missing)?, data.key.ok_or_else(missing)?, kdf)
        }
    };
    if hash.is_empty() || !key.starts_with("2.") {
        return Err(ApiError::bad("The master password is missing."));
    }
    let kdf = kdf.check()?;
    state.settings().policies.check_kdf(&kdf)?;
    let hint = identity::clean_hint(&state, data.master_password_hint)?;
    let (private_key, public_key) = match (data.keys, data.account_keys) {
        (Some(keys), _) => (Some(keys.encrypted_private_key), Some(keys.public_key)),
        (None, Some(keys)) => match keys.public_key_encryption_key_pair {
            Some(pair) => (pair.encrypted_private_key, pair.public_key),
            None => (keys.user_key_encrypted_account_private_key, keys.account_public_key),
        },
        (None, None) => (None, None),
    };
    if private_key.is_some() != public_key.is_some() {
        return Err(ApiError::bad("The key pair is missing half."));
    }
    let password_hash = auth::hash_password(state.config.hash_cost, &hash).await?;
    let updated = state
        .store
        .update_user(&user.id, move |user| {
            // Checked again in the same step: two of these at once set one password.
            if !user.user_key.is_empty() {
                return;
            }
            user.password_hash = password_hash;
            user.user_key = key;
            user.kdf = kdf;
            user.password_hint = hint;
            // Keys the client put there before (`/api/accounts/keys`) stay, unless new ones come.
            if private_key.is_some() {
                user.private_key = private_key;
                user.public_key = public_key;
            }
            user.revision = clock::now();
        })
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    if updated.user_key.is_empty() || updated.password_hash.is_empty() {
        return Err(ApiError::bad("This account has a master password already."));
    }
    let event = Event {
        kind: "password-set".into(),
        user_id: Some(updated.id.clone()),
        email: Some(updated.email.clone()),
        ip: Some(ip.to_string()),
        detail: Some("the first master password, after an SSO login".into()),
        ..Event::default()
    };
    let _ = state.store.log_event(event).await;
    crate::notify::user(&state, &updated.id, Some(&session), uwulock_notify::Kind::Settings);
    Ok(StatusCode::OK)
}

// ── Admin ─────────────────────────────────────────────────

async fn get_settings(State(state): State<AppState>, _admin: Admin) -> Json<Value> {
    Json(settings_json(&state))
}

async fn put_settings(
    State(state): State<AppState>,
    admin: Admin,
    // `clientSecret` comes as typed, when it changes.
    Json(mut new): Json<SsoSettings>,
) -> ApiResult<Json<Value>> {
    let mut all = state.settings();
    let current = all.sso.clone();
    new.issuer = new.issuer.trim().trim_end_matches('/').to_string();
    new.client_id = new.client_id.trim().to_string();
    new.identifier = new.identifier.trim().to_string();
    new.label = new.label.trim().to_string();
    new.scopes = new.scopes.iter().map(|scope| scope.trim().to_string()).filter(|scope| !scope.is_empty()).collect();
    let clean = |group: Option<String>| group.map(|group| group.trim().to_string()).filter(|group| !group.is_empty());
    new.user_group = clean(new.user_group);
    new.admin_group = clean(new.admin_group);
    new.roles_claim = clean(new.roles_claim);
    new.groups_claim = new.groups_claim.trim().to_string();
    new.paired = current.paired.clone();
    // The secret left out: kept for the same provider and client only, so that an admin session
    // cannot send it to a provider of its own.
    new.client_secret = match new.client_secret.as_deref().map(str::trim).filter(|secret| !secret.is_empty()) {
        Some(secret) => Some(state.secret.seal(secret, SECRET_PURPOSE).map_err(ApiError::internal)?),
        None if new.issuer == current.issuer && new.client_id == current.client_id => current.client_secret.clone(),
        None => None,
    };
    new.check().map_err(ApiError::bad)?;
    if new.enabled && new.admins_only_with_sso && !admin.0.sso {
        return Err(ApiError::bad(
            "Log in to the admin portal with SSO first: with “admins only with SSO”, a password login would not get you back in.",
        )
        .code("would_lock_out"));
    }
    if new.enabled && (new.issuer != current.issuer || !current.enabled) {
        state.oidc.forget();
        oidc::discover(&state.oidc, &new.issuer)
            .await
            .map_err(|error| ApiError::bad(format!("The provider's discovery document: {error}")))?;
    }
    all.sso = new;
    all.check().map_err(ApiError::bad)?;
    all.save(&state.store).await?;
    state.apply_settings(all);
    state.oidc.forget();
    crate::admin::record(&state, &admin, "changed the SSO settings".into()).await;
    Ok(Json(settings_json(&state)))
}

#[derive(Deserialize, Default)]
struct TestData {
    #[serde(default)]
    issuer: Option<String>,
}

/// Whether the provider's discovery document and keys can be read: with the issuer given, or
/// the saved one.
async fn test(State(state): State<AppState>, _admin: Admin, body: Option<Json<TestData>>) -> Json<Value> {
    let issuer = body
        .and_then(|Json(body)| body.issuer)
        .map(|issuer| issuer.trim().to_string())
        .filter(|issuer| !issuer.is_empty())
        .unwrap_or_else(|| state.settings().sso.issuer);
    state.oidc.forget();
    let result = async {
        let discovery = oidc::discover(&state.oidc, &issuer).await?;
        let keys = oidc::keys(&state.oidc, &discovery, false).await?;
        if keys.is_empty() {
            return Err("The provider lists no signing keys.".to_string());
        }
        Ok(())
    }
    .await;
    match result {
        Ok(()) => Json(json!({ "ok": true, "error": null })),
        Err(error) => Json(json!({ "ok": false, "error": error })),
    }
}

async fn scim_token(State(state): State<AppState>, admin: Admin) -> ApiResult<Json<Value>> {
    let token = auth::random_token(32);
    let mut all = state.settings();
    all.scim.token_hash = Some(crate::metrics::hex(&auth::sha256(token.as_bytes())));
    all.save(&state.store).await?;
    state.apply_settings(all);
    crate::admin::record(&state, &admin, "made a new SCIM token".into()).await;
    Ok(Json(json!({ "token": token })))
}

// ── Pairing with UwUAuth ──────────────────────────────────

/// The app's icon for UwUAuth's tiles: a PNG well under its 64 KiB.
const ICON: &[u8] = include_bytes!("uwulock-icon.png");

#[derive(Deserialize)]
struct PairData {
    #[serde(default)]
    url: Option<String>,
    code: String,
}

/// `<UwUAuth>/#pair=<code>` from the QR code, or the address and the code as typed.
fn pairing_input(url: Option<&str>, code: &str) -> Result<(String, String), String> {
    let code = code.trim();
    let (url, code) = match code.split_once("#pair=") {
        Some((from_qr, code)) => (url.map(str::trim).filter(|url| !url.is_empty()).unwrap_or(from_qr), code),
        None => (url.map(str::trim).unwrap_or_default(), code),
    };
    let url = url.trim().trim_end_matches('/').to_string();
    if url.is_empty() {
        return Err("Enter UwUAuth's address.".into());
    }
    let parsed = oidc::checked_endpoint(&url, "UwUAuth's address")?;
    if parsed.query().is_some() {
        return Err("UwUAuth's address has no ?query.".into());
    }
    let code = code.trim().to_string();
    if code.is_empty() || code.len() > 64 {
        return Err("Enter the pairing code from UwUAuth.".into());
    }
    Ok((url, code))
}

async fn pair(State(state): State<AppState>, admin: Admin, Json(data): Json<PairData>) -> ApiResult<Json<Value>> {
    let (base, code) = pairing_input(data.url.as_deref(), &data.code).map_err(ApiError::bad)?;
    let public = state.config.public.clone();
    let public_url = reqwest::Url::parse(&public).map_err(ApiError::internal)?;
    if public_url.scheme() != "https" && !public_url.host_str().is_some_and(oidc::is_loopback) {
        return Err(ApiError::bad("UwUAuth pairs only with a server at an https address."));
    }
    let client = crate::outbound::client().map_err(ApiError::internal)?;
    let unreachable = |error: String| ApiError::upstream(format!("UwUAuth did not answer: {error}"));

    // 1. Is it UwUAuth, and does it pair?
    let response = client
        .get(format!("{base}/uwu/v1/server"))
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| unreachable(crate::outbound::error_text(&error)))?;
    let not_uwuauth = || ApiError::bad("This is not a UwUAuth that can pair (0.4 or newer).").code("not_uwuauth");
    let server: Value = oidc::read(response, "UwUAuth")
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(not_uwuauth)?;
    if server["product"] != "UwUAuth" || server["pairing"].as_i64().unwrap_or(0) < 1 {
        return Err(not_uwuauth());
    }
    let issuer = server["issuer"].as_str().unwrap_or_default().trim_end_matches('/').to_string();

    // 2. Pair.
    use base64::Engine as _;
    let body = json!({
        "code": code,
        "app": {
            "product": "UwULock",
            "version": state.version,
            "name": format!("UwULock ({})", state.host()),
            "url": public,
            "icon": format!("data:image/png;base64,{}", base64::engine::general_purpose::STANDARD.encode(ICON)),
            "redirectUris": [format!("{public}{CALLBACK}")],
            "postLogoutRedirectUris": [format!("{public}/")],
            "scopes": ["openid", "email", "profile", "groups", "roles"],
            "roles": [
                { "id": "admin", "name": "Administrator", "description": "Uses the admin portal" },
                { "id": "user", "name": "User", "description": "May create a vault without an invitation" },
            ],
            "scim": { "baseUrl": format!("{public}/scim/v2"), "resources": ["User", "Group"], "userName": "email" },
        },
    });
    let response = client
        .post(format!("{base}/uwu/v1/pair"))
        .header("accept", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|error| unreachable(crate::outbound::error_text(&error)))?;
    let status = response.status();
    let bytes = match status.as_u16() {
        200 => oidc::read(response, "UwUAuth").await.map_err(ApiError::upstream)?,
        400 | 429 => {
            let answer: Value = response.json().await.unwrap_or(Value::Null);
            return Err(match (status.as_u16(), answer["error"].as_str()) {
                (429, _) => ApiError::too_many("UwUAuth says: too many tries. Wait a quarter of an hour."),
                (_, Some("invalid_code")) => {
                    ApiError::bad("UwUAuth does not know this code (any more). Make a new one there.")
                        .code("invalid_code")
                }
                _ => {
                    let message = answer["message"].as_str().unwrap_or("it refused the pairing");
                    let field =
                        answer["detail"]["field"].as_str().map(|field| format!(" ({field})")).unwrap_or_default();
                    ApiError::bad(format!("UwUAuth: {message}{field}"))
                }
            });
        }
        _ => return Err(ApiError::upstream(format!("UwUAuth answered {status}."))),
    };
    let answer: Value =
        serde_json::from_slice(&bytes).map_err(|_| ApiError::upstream("UwUAuth's answer is not JSON."))?;
    let text = |name: &str| answer[name].as_str().map(str::to_string).filter(|value| !value.is_empty());
    let (Some(paired_issuer), Some(client_id)) = (text("issuer"), text("clientId")) else {
        return Err(ApiError::upstream("UwUAuth's answer lacks the issuer or the client id."));
    };
    if paired_issuer.trim_end_matches('/') != issuer {
        return Err(ApiError::upstream("UwUAuth's answer names another issuer than it said before."));
    }
    state.oidc.forget();
    oidc::discover(&state.oidc, &issuer)
        .await
        .map_err(|error| ApiError::upstream(format!("UwUAuth's discovery document: {error}")))?;

    // 3. Keep it.
    let mut all = state.settings();
    let previous = all.sso.clone();
    let scopes: Vec<String> = answer["scopes"]
        .as_array()
        .map(|list| list.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .filter(|list: &Vec<String>| list.iter().any(|scope| scope == "openid"))
        .unwrap_or_else(|| ["openid", "email", "profile", "groups", "roles"].map(str::to_string).to_vec());
    let client_secret = match text("clientSecret") {
        Some(secret) => Some(state.secret.seal(&secret, SECRET_PURPOSE).map_err(ApiError::internal)?),
        None => None,
    };
    all.sso = SsoSettings {
        enabled: true,
        issuer,
        client_id,
        client_secret,
        scopes,
        pkce: true,
        identifier: previous.identifier,
        label: "UwUAuth".into(),
        only: false,
        signups: Signups::Group,
        user_group: None,
        admin_group: None,
        admins_only_with_sso: false,
        trust_unverified_email: false,
        groups_claim: text("groupsClaim").unwrap_or_else(|| "groups".into()),
        roles_claim: Some(text("rolesClaim").unwrap_or_else(|| "roles".into())),
        paired: Some(Paired {
            url: base.clone(),
            app_id: text("appId").unwrap_or_default(),
            manage_url: text("manageUrl"),
            date: clock::now(),
        }),
    };
    if let Some(token) = text("scimToken") {
        all.scim.token_hash = Some(crate::metrics::hex(&auth::sha256(token.as_bytes())));
    }
    all.check().map_err(ApiError::bad)?;
    all.save(&state.store).await?;
    state.apply_settings(all);
    crate::admin::record(&state, &admin, format!("paired with UwUAuth at {base}")).await;
    Ok(Json(settings_json(&state)))
}

async fn unpair(State(state): State<AppState>, admin: Admin) -> ApiResult<Json<Value>> {
    let mut all = state.settings();
    let Some(paired) = all.sso.paired.take() else {
        return Err(ApiError::not_found("This server is not paired with UwUAuth."));
    };
    all.sso = SsoSettings { identifier: all.sso.identifier.clone(), ..SsoSettings::default() };
    all.scim.token_hash = None;
    all.save(&state.store).await?;
    state.apply_settings(all);
    state.oidc.forget();
    crate::admin::record(&state, &admin, format!("ended the pairing with UwUAuth at {}", paired.url)).await;
    Ok(Json(settings_json(&state)))
}

#[cfg(test)]
mod tests;
