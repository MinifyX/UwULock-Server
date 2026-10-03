//! `/identity`: logging in, staying logged in, and registering.
//!
//! - `POST /identity/connect/token` with the master password hash logs a device in — after the
//!   second step, if the account has two-step login — and with the refresh token keeps it
//!   logged in.
//! - The prelogin tells a client how to derive the master key for an address. For an address
//!   without an account it answers the same as for one, so it tells nobody which exist.
//! - Registering takes an invitation. Its link carries a token; the official clients' "create
//!   account" sends the invitation mail again.

use crate::auth::{self, ClientIp, refresh_days};
use crate::errors::{ApiError, ApiResult};
use crate::{AppState, notices, policies, two_factor};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Form, Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use uwulock_mail::{Language, Mail};
use uwulock_store::{DeviceLogin, Event, Kdf, NewUser, StoreError, User, clock, normalize_email};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/identity/connect/token", post(token))
        .route("/identity/accounts/prelogin", post(prelogin))
        .route("/identity/accounts/prelogin/password", post(prelogin))
        .route("/api/accounts/prelogin", post(prelogin))
        .route("/identity/accounts/register/send-verification-email", post(send_verification_email))
        .route("/identity/accounts/register/finish", post(register_finish))
        .route("/identity/accounts/register", post(register_without_invitation))
        .route("/api/accounts/register", post(register_without_invitation))
}

/// The form of a token request, with its names written one way: `device_identifier`,
/// `deviceIdentifier` and `DeviceIdentifier` all become `deviceidentifier`.
pub(crate) struct TokenForm(HashMap<String, String>);

impl TokenForm {
    fn new(raw: HashMap<String, String>) -> Self {
        TokenForm(raw.into_iter().map(|(key, value)| (key.to_ascii_lowercase().replace('_', ""), value)).collect())
    }

    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str).filter(|value| !value.is_empty())
    }

    fn require(&self, name: &str, label: &str) -> ApiResult<&str> {
        self.get(name).ok_or_else(|| ApiError::bad(format!("{label} cannot be blank")))
    }
}

async fn token(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    send_host: Option<axum::Extension<crate::send_hosts::SendHost>>,
    headers: HeaderMap,
    Form(raw): Form<HashMap<String, String>>,
) -> ApiResult<Response> {
    let form = TokenForm::new(raw);
    // A send domain opens Sends, nothing else: no logins there.
    if send_host.is_some() && form.get("granttype") != Some("send_access") {
        return Err(ApiError::bad("Only Sends can be opened on this address."));
    }
    let client = LoginClient::new(&headers, &form);
    let (grant, result) = CLIENT.scope(client, grant(&state, ip, &headers, &form)).await?;
    let outcome = match &result {
        Ok(_) => "success",
        Err(error) if error.message().contains("\"TwoFactorProviders\"") => "two_factor",
        Err(_) => "failure",
    };
    state.metrics.login(grant, outcome);
    result
}

/// The grant a token request asks for, and what came of it.
async fn grant(
    state: &AppState,
    ip: std::net::IpAddr,
    headers: &HeaderMap,
    form: &TokenForm,
) -> ApiResult<(&'static str, ApiResult<Response>)> {
    Ok(match form.get("granttype") {
        Some("password") => ("password", password_login(state, ip, headers, form).await),
        Some("refresh_token") => ("refresh_token", refresh(state, ip, form).await),
        Some("client_credentials") => ("client_credentials", api_key_login(state, ip, form).await),
        Some("webauthn") => ("webauthn", crate::passkeys::grant(state, ip, form).await),
        Some("authorization_code") => ("authorization_code", crate::sso::grant(state, ip, headers, form).await),
        Some("send_access") => {
            let proof = crate::sends::GrantProof {
                password: form.get("passwordhashb64"),
                email: form.get("email"),
                otp: form.get("otp"),
            };
            ("send_access", crate::sends::grant(state, ip, headers, form.get("sendid"), proof).await)
        }
        _ => return Err(ApiError::bad("Invalid type")),
    })
}

tokio::task_local! {
    /// The client of the token request being answered, for the events [`log`] writes: set once
    /// in [`token`], so every grant (password, API key, passkey, SSO) has it without passing it
    /// along.
    static CLIENT: LoginClient;
}

/// What a client says about itself at a login, cut to lengths worth keeping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LoginClient {
    pub user_agent: Option<String>,
    /// Bitwarden's `Bitwarden-Client-Name` (`web`, `browser`, `desktop`, `mobile`, `cli`), else
    /// the token request's `client_id`.
    pub name: Option<String>,
    pub version: Option<String>,
    pub device_name: Option<String>,
}

impl LoginClient {
    pub(crate) fn new(headers: &HeaderMap, form: &TokenForm) -> Self {
        let header = |name: &str, most: usize| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(|text| clip(text, most))
                .filter(|text| !text.is_empty())
        };
        LoginClient {
            user_agent: header("user-agent", 300),
            name: header("bitwarden-client-name", 40).or_else(|| form.get("clientid").map(|id| clip(id, 40))),
            version: header("bitwarden-client-version", 40),
            device_name: form.get("devicename").map(|name| clip(name, 128)),
        }
    }
}

/// `text` without control characters, at most `most` characters long.
fn clip(text: &str, most: usize) -> String {
    text.chars().filter(|char| !char.is_control()).take(most).collect::<String>().trim().to_string()
}

async fn password_login(
    state: &AppState,
    ip: std::net::IpAddr,
    headers: &HeaderMap,
    form: &TokenForm,
) -> ApiResult<Response> {
    form.require("clientid", "client_id")?;
    let password = form.require("password", "password")?;
    let scope = form.require("scope", "scope")?;
    let username = form.require("username", "username")?;
    let device_id = form.require("deviceidentifier", "device_identifier")?;
    let device_name = form.require("devicename", "device_name")?;
    let device_type: i64 = form.require("devicetype", "device_type")?.trim().parse().unwrap_or(14);
    check_scope(state, form.get("clientid").unwrap_or_default(), Some(scope))?;
    // An address is never this long; what is, is not kept in the event log either.
    if username.len() > MAX_EMAIL || device_name.len() > 256 || device_id.len() > 256 {
        return Err(ApiError::bad("Username or password is incorrect. Try again"));
    }
    if !state.limits.login.check(ip) || !state.limits.login_wide.check_wide(ip) {
        return Err(ApiError::too_many("Too many login requests. Wait a minute and try again."));
    }

    let user = state.store.user_by_email(username).await?;
    // With the code of an approved "log in with a device" request instead of the password.
    let by_request = form.get("authrequest");
    // Wrong passwords per address tried, from everywhere at once (R1-2): when they ran out, only
    // a device the account knows gets its password checked. Keyed by the address as typed, so
    // the answer is the same whether it has an account.
    let account_key = username.trim().to_lowercase();
    if by_request.is_none() && !state.limits.login_account.allows(&account_key) {
        let known = match &user {
            Some(user) => state.store.device(&user.id, device_id).await?.is_some(),
            None => false,
        };
        if !known {
            log(state, "login-failed", user.as_ref(), username, ip, device_type, "too many wrong passwords").await;
            return Err(ApiError::too_many(
                "Too many wrong passwords for this account lately. Log in on a device you used before, or try again in a few minutes.",
            )
            .code("account_limited"));
        }
    }
    // Rather "busy" at once than a queue that ends in the request's timeout (R1-2).
    if by_request.is_none() && auth::hashing_busy() {
        let mut response = ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "The server is busy. Try again in a moment.")
            .code("busy")
            .into_response();
        response.headers_mut().insert(axum::http::header::RETRY_AFTER, axum::http::HeaderValue::from(2));
        return Ok(response);
    }
    let passed = match (by_request, &user) {
        (Some(request), Some(found)) => state
            .store
            .use_auth_request(request, device_id, auth::sha256(password.as_bytes()))
            .await?
            .is_some_and(|request| request.user_id == found.id),
        (Some(_), None) => false,
        (None, _) => {
            // An account made through SSO has no master password until its owner sets one.
            let known = user.as_ref().map(|user| user.password_hash.as_str()).filter(|hash| !hash.is_empty());
            let legacy_rounds = state.legacy_rounds.load(std::sync::atomic::Ordering::Relaxed);
            auth::verify_login(state.config.hash_cost, known, password, legacy_rounds).await
        }
    };
    if !passed {
        if by_request.is_none() {
            state.limits.login_account.take(account_key);
        }
        log(state, "login-failed", user.as_ref(), username, ip, device_type, "wrong email or password").await;
        // Beside the answer, not before it: the time a refused login takes must not tell whether
        // the address has an account.
        if let Some(user) = user {
            let (state, context) =
                (state.clone(), notices::Context { device_type: Some(device_type), ..notices::Context::ip(ip) });
            tokio::spawn(async move {
                notices::failed(&state, &user, "failedLogins", "login-failed", &context, None).await;
            });
        }
        return Err(ApiError::bad("Username or password is incorrect. Try again"));
    }
    let user = user.expect("a password matched, so there is a user");
    if user.disabled {
        log(state, "login-failed", Some(&user), username, ip, device_type, "account disabled").await;
        return Err(ApiError::bad("This account has been disabled."));
    }
    crate::sso::password_allowed(state, &user)?;
    // A hash that came over from Vaultwarden becomes one of this server's now that the password
    // is here to make it from.
    if by_request.is_none() && auth::is_legacy(&user.password_hash) {
        let rehashed = auth::hash_password(state.config.hash_cost, password).await?;
        state.store.update_user(&user.id, move |user| user.password_hash = rehashed).await?;
        tracing::info!(user = %user.id, "a password hash from Vaultwarden was replaced");
        state.count_legacy_hashes().await;
    }

    let known_device = state.store.device(&user.id, device_id).await?;
    // A device that another one let in has passed its second step with that.
    let remember = if by_request.is_some() {
        None
    } else {
        match two_factor::check_login(state, &user, form, known_device.as_ref(), ip, headers).await {
            Ok(remember) => remember,
            Err(error) => {
                if error.status == StatusCode::BAD_REQUEST && form.get("twofactortoken").is_some() {
                    log(state, "two-factor-failed", Some(&user), username, ip, device_type, "wrong code").await;
                    let context = notices::Context { device_type: Some(device_type), ..notices::Context::ip(ip) };
                    let provider = form.get("twofactorprovider").and_then(|value| value.trim().parse::<i64>().ok());
                    notices::failed(state, &user, "failedTwoFactor", "two-factor-failed", &context, provider).await;
                }
                return Err(error);
            }
        }
    };
    let login = Login {
        device_id,
        device_name,
        device_type,
        known: known_device.is_some(),
        remember,
        by_request: by_request.is_some(),
        sso: false,
    };
    let body = finish_login(state, &user, ip, form, login).await?;
    Ok(Json(body).into_response())
}

/// Whether a login may ask for `scope` as `client_id`: Bitwarden's `api offline_access` for
/// every client but the suite apps, which ask for `uwu.suite offline_access` (docs/uwu-api.md
/// §6.5) and get nothing else. No scope at all (an SSO code) is the client's usual one.
pub(crate) fn check_scope(state: &AppState, client_id: &str, scope: Option<&str>) -> ApiResult<()> {
    let asked: std::collections::BTreeSet<&str> = scope.unwrap_or_default().split_whitespace().collect();
    let suite = crate::suite::space_of_client(client_id).is_some();
    let invalid_client = || ApiError::json(json!({ "error": "invalid_client", "error_description": "invalid_client" }));
    if asked.contains(crate::suite::SCOPE) != suite && scope.is_some() {
        return Err(if suite {
            ApiError::json(json!({ "error": "invalid_scope", "error_description": "invalid_scope" }))
        } else {
            invalid_client()
        });
    }
    if suite {
        if !state.feature(crate::Feature::Suite) {
            return Err(invalid_client());
        }
        if scope.is_some() && asked != [crate::suite::SCOPE, "offline_access"].into() {
            return Err(ApiError::bad("Scope not supported"));
        }
    } else if scope.is_some() && asked != ["api", "offline_access"].into() {
        return Err(ApiError::bad("Scope not supported"));
    }
    Ok(())
}

/// The device a login is for, and what the second step said.
pub(crate) struct Login<'a> {
    pub device_id: &'a str,
    pub device_name: &'a str,
    pub device_type: i64,
    /// The device was logged in to this account before.
    pub known: bool,
    /// A new token that skips the second step on this device.
    pub remember: Option<String>,
    /// Let in by another device: the mail goes out whatever the device and the setting, since
    /// an approval is all it took — the approving device's session may be a stolen one.
    pub by_request: bool,
    /// Through SSO: the tokens say so, also after a refresh.
    pub sso: bool,
}

/// Everything after the credentials were checked: the device logged in, the event written, a
/// mail for a new device, and the answer with the tokens and keys.
pub(crate) async fn finish_login(
    state: &AppState,
    user: &User,
    ip: std::net::IpAddr,
    form: &TokenForm,
    login: Login<'_>,
) -> ApiResult<Value> {
    let Login { device_id, device_name, device_type, known, remember, by_request, sso } = login;
    let client_id = form.get("clientid").unwrap_or("undefined");
    let setup_only = two_factor_policy(state, user, client_id).await?;
    let refresh_token = auth::random_token(64);
    let first_device = !known && state.store.devices(&user.id).await?.is_empty();
    let new = state
        .store
        .log_in_device(DeviceLogin {
            user_id: user.id.clone(),
            id: device_id.to_string(),
            name: device_name.to_string(),
            kind: device_type,
            ip: Some(ip.to_string()),
            refresh_hash: auth::sha256(refresh_token.as_bytes()),
            refresh_expires: clock::in_seconds(refresh_days(device_type) * 86_400),
            remember: remember
                .as_ref()
                .map(|token| (auth::sha256(token.as_bytes()), clock::in_seconds(auth::REMEMBER_DAYS * 86_400))),
            sso,
            client_id: Some(client_id.chars().take(64).collect()),
        })
        .await?;
    log(state, "login", Some(user), &user.email, ip, device_type, device_name).await;
    let suite = crate::suite::space_of_client(client_id);
    let context = notices::Context {
        ip: Some(ip),
        device_type: Some(device_type),
        device_name: Some(device_name.to_string()),
        app: Some(client_id.to_string()),
    };
    let mut new_device_mailed = false;
    if (new && !first_device) || by_request {
        let settings = state.settings();
        let mail_off = settings.security_notices.mail_off.iter().any(|kind| kind == "newDevice");
        let wanted = by_request || (settings.new_device_mail && !mail_off);
        let mailed = wanted && state.mailer.enabled();
        if mailed {
            let mail = Mail::NewDevice {
                device: format!("{device_name} ({})", auth::device_type_name(device_type)),
                ip: ip.to_string(),
                time: format_time(&clock::now()),
            };
            send_later(state, &user.email, mail, Language::from_code(&user.language));
        }
        if new && !first_device && suite.is_none() {
            notices::record_mailed(state, user, "newDevice", &context, json!({ "app": client_id }), mailed).await;
        }
        new_device_mailed = mailed;
    }
    // A suite app that logs in can read its space: always a notice, a new one or not.
    if let Some(space) = suite {
        let detail = json!({ "app": client_id, "space": space, "new": new });
        if new_device_mailed {
            notices::record_mailed(state, user, "suiteLogin", &context, detail, true).await;
        } else {
            notices::record(state, user, "suiteLogin", &context, detail).await;
        }
    }
    notices::kdf_below_minimum(state, user, &context).await;

    let (access_token, expires_in) =
        state.tokens.access_token_for(user, device_id, device_type, client_id, sso, setup_only);
    let mut body = login_response(user, access_token, expires_in);
    if suite.is_some() {
        body["scope"] = format!("{} offline_access", crate::suite::SCOPE).into();
    }
    body["MasterPasswordPolicy"] = state.settings().policies.master_password_policy();
    body["refresh_token"] = refresh_token.into();
    if let Some(remember) = remember {
        body["TwoFactorToken"] = remember.into();
    }
    Ok(body)
}

/// While two-step login is required, an account without it gets a token only for the web
/// vault, and one that opens nothing but the setup until there is a second step (docs/uwu-api.md
/// §20): `true` then.
async fn two_factor_policy(state: &AppState, user: &User, client_id: &str) -> ApiResult<bool> {
    if !must_set_up_two_factor(state, user).await? {
        return Ok(false);
    }
    if client_id == policies::WEB_VAULT { Ok(true) } else { Err(policies::two_factor_required(&state.config.public)) }
}

/// Whether two-step login is required by now and the account has none enabled.
pub(crate) async fn must_set_up_two_factor(state: &AppState, user: &User) -> ApiResult<bool> {
    if !state.settings().policies.two_factor_enforced() {
        return Ok(false);
    }
    Ok(!state.store.two_factors(&user.id).await?.iter().any(|factor| factor.enabled))
}

/// The CLI's login with the API key: `client_id` is `user.<id>`, `client_secret` the key. Like
/// Bitwarden, it needs no second step: the key is a secret of its own.
async fn api_key_login(state: &AppState, ip: std::net::IpAddr, form: &TokenForm) -> ApiResult<Response> {
    let client_id = form.require("clientid", "client_id")?;
    let secret = form.require("clientsecret", "client_secret")?;
    let scope = form.require("scope", "scope")?;
    let device_id = form.require("deviceidentifier", "device_identifier")?;
    let device_name = form.require("devicename", "device_name")?;
    let device_type: i64 = form.require("devicetype", "device_type")?.trim().parse().unwrap_or(14);
    if scope != "api" {
        return Err(ApiError::bad("Scope not supported"));
    }
    if device_name.len() > 256 || device_id.len() > 256 {
        return Err(ApiError::bad("Client credentials invalid"));
    }
    if !state.limits.login.check(ip) {
        return Err(ApiError::too_many("Too many login requests. Wait a minute and try again."));
    }
    let wrong = || ApiError::json(json!({ "error": "invalid_client" }));
    let user_id = client_id.strip_prefix("user.").ok_or_else(wrong)?;
    let user = state.store.user(user_id).await?;
    let stored = match &user {
        Some(user) => state.store.api_key_of(&user.id).await?,
        None => None,
    };
    let right = stored.as_deref().is_some_and(|stored| auth::constant_time_eq(stored.as_bytes(), secret.as_bytes()));
    let Some(user) = user.filter(|_| right) else {
        log(state, "login-failed", None, client_id, ip, device_type, "wrong API key").await;
        return Err(wrong());
    };
    if user.disabled {
        log(state, "login-failed", Some(&user), &user.email, ip, device_type, "account disabled").await;
        return Err(ApiError::bad("This account has been disabled."));
    }
    let known = state.store.device(&user.id, device_id).await?.is_some();
    let login = Login { device_id, device_name, device_type, known, remember: None, by_request: false, sso: false };
    let mut body = finish_login(state, &user, ip, form, login).await?;
    // Like Bitwarden: the CLI logs in with its key again rather than refreshing.
    if let Some(body) = body.as_object_mut() {
        body.remove("refresh_token");
        body.insert("scope".into(), "api".into());
    }
    Ok(Json(body).into_response())
}

/// What a successful password login answers, Bitwarden's mix of casings and all.
pub(crate) fn login_response(user: &User, access_token: String, expires_in: i64) -> Value {
    let kdf = json!({
        "KdfType": user.kdf.kind,
        "Iterations": user.kdf.iterations,
        "Memory": user.kdf.memory,
        "Parallelism": user.kdf.parallelism,
    });
    json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "scope": "api offline_access",
        "Key": user.user_key,
        "PrivateKey": user.private_key,
        "Kdf": user.kdf.kind,
        "KdfIterations": user.kdf.iterations,
        "KdfMemory": user.kdf.memory,
        "KdfParallelism": user.kdf.parallelism,
        "ResetMasterPassword": false,
        "ForcePasswordReset": false,
        "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
        "AccountKeys": match &user.private_key {
            Some(private) => json!({
                "publicKeyEncryptionKeyPair": {
                    "wrappedPrivateKey": private,
                    "publicKey": user.public_key,
                    "Object": "publicKeyEncryptionKeyPair",
                },
                "Object": "privateKeys",
            }),
            None => Value::Null,
        },
        "UserDecryptionOptions": {
            "HasMasterPassword": true,
            "MasterPasswordUnlock": {
                "Kdf": kdf,
                "MasterKeyEncryptedUserKey": user.user_key,
                "MasterKeyWrappedUserKey": user.user_key,
                "Salt": user.email,
            },
            "Object": "userDecryptionOptions",
        },
    })
}

/// A refused refresh has to be exactly this, or the clients do not log out cleanly.
fn invalid_grant() -> ApiError {
    ApiError::json(json!({ "error": "invalid_grant" }))
}

async fn refresh(state: &AppState, ip: std::net::IpAddr, form: &TokenForm) -> ApiResult<Response> {
    let Some(token) = form.get("refreshtoken") else { return Err(invalid_grant()) };
    let token = token.trim();
    // A device that moved over from Vaultwarden holds its refresh token: a JWT around the token
    // Vaultwarden kept for the device.
    let signed = crate::vaultwarden::device_token(state, token).await;
    let presented = signed.as_deref().unwrap_or(token);
    let find = |hash: Vec<u8>| {
        state.store.refresh_device(hash, |kind| clock::in_seconds(refresh_days(kind) * 86_400), Some(ip.to_string()))
    };
    // This server's own first; then one that came over from Vaultwarden, which is replaced now.
    // (Imports of 0.4.0-beta.1 hashed a signed one like this server's own.)
    let (device, moved) = match find(auth::sha256(presented.as_bytes())).await? {
        Some(device) => (device, signed.is_some()),
        None => (find(crate::vaultwarden::moved_token_hash(presented)).await?.ok_or_else(invalid_grant)?, true),
    };
    let token = if moved {
        let fresh = auth::random_token(64);
        state.store.replace_refresh(&device.user_id, &device.id, auth::sha256(fresh.as_bytes())).await?;
        fresh
    } else {
        token.to_string()
    };
    let session = state.store.session_user(&device.user_id).await?.ok_or_else(invalid_grant)?;
    if session.user.disabled {
        return Err(invalid_grant());
    }
    let asked = form.get("clientid").unwrap_or("undefined");
    // A suite app's device stays one: its refresh token gives a suite token, and only to it.
    let stored_suite = device.client_id.as_deref().filter(|client| crate::suite::space_of_client(client).is_some());
    let client_id = match stored_suite {
        Some(stored) if stored == asked => stored,
        Some(_) => return Err(invalid_grant()),
        None if crate::suite::space_of_client(asked).is_some() => return Err(invalid_grant()),
        // Every device keeps the client it logged in with: another client's refresh token
        // cannot pass as the web vault's (which the two-step login rule lets through).
        None => device.client_id.as_deref().unwrap_or(asked),
    };
    if stored_suite.is_some() && !state.feature(crate::Feature::Suite) {
        return Err(invalid_grant());
    }
    let setup_only = two_factor_policy(state, &session.user, client_id).await?;
    let (access_token, expires_in) =
        state.tokens.access_token_for(&session.user, &device.id, device.kind, client_id, device.sso, setup_only);
    let scope = if stored_suite.is_some() { "uwu.suite offline_access" } else { "api offline_access" };
    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "refresh_token": token,
        "scope": scope,
    }))
    .into_response())
}

pub(crate) async fn log(
    state: &AppState,
    kind: &str,
    user: Option<&User>,
    email: &str,
    ip: std::net::IpAddr,
    device_type: i64,
    detail: &str,
) {
    let client = CLIENT.try_with(Clone::clone).unwrap_or_default();
    let reason = match (kind, detail) {
        ("two-factor-failed", _) => Some("two-factor"),
        ("login-failed", "account disabled") => Some("disabled"),
        ("login-failed", "wrong API key") => Some("api-key"),
        ("login-failed", _) if user.is_none() => Some("unknown-account"),
        ("login-failed", _) => Some("password"),
        _ => None,
    };
    let event = Event {
        kind: kind.into(),
        user_id: user.map(|user| user.id.clone()),
        email: Some(normalize_email(email).chars().take(MAX_EMAIL).collect()),
        ip: Some(ip.to_string()),
        device_type: Some(device_type),
        detail: Some(detail.chars().take(200).collect()),
        user_agent: client.user_agent,
        client_name: client.name,
        client_version: client.version,
        device_name: client.device_name,
        reason: reason.map(Into::into),
        ..Event::default()
    };
    if let Err(error) = state.store.log_event(event).await {
        tracing::warn!(%error, "could not write an event");
    }
    if kind != "login" {
        tracing::info!(%ip, email = ?normalize_email(email), kind, detail, "login refused");
    }
}

/// The longest address anything here takes: RFC 5321 allows 254 characters.
pub(crate) const MAX_EMAIL: usize = 254;

/// Refused when `to` has had enough mails from this server lately that somebody else asked for
/// — or `user`, if a logged-in account asks, has sent enough of them.
pub(crate) fn mail_allowed(state: &AppState, to: &str, user: Option<&str>) -> ApiResult<()> {
    if to.len() > MAX_EMAIL {
        return Err(ApiError::bad("That is not an email address."));
    }
    let to_ok = state.limits.mail.take(format!("to:{}", normalize_email(to)));
    let user_ok = user.is_none_or(|user| state.limits.mail.take(format!("from:{user}")));
    if to_ok && user_ok {
        Ok(())
    } else {
        Err(ApiError::too_many("Too many mails to this address. Wait a few minutes and try again."))
    }
}

/// A mail that did not go out, for a request that asked for it: what went wrong goes to the log,
/// where an admin sees it, and not to whoever asked.
pub(crate) fn mail_failed(error: impl std::fmt::Display) -> ApiError {
    tracing::warn!(%error, "a mail did not go out");
    ApiError::bad("The mail did not go out. Try again later, or ask an admin.")
}

/// Send a mail without making the request wait for the mail server.
pub(crate) fn send_later(state: &AppState, to: &str, mail: Mail, language: Language) {
    let mailer = state.mailer.clone();
    let to = to.to_string();
    tokio::spawn(async move {
        if let Err(error) = mailer.send(&to, &mail, language).await {
            tracing::warn!(%error, "a mail did not go out");
        }
    });
}

/// `2026-09-25 14:03 UTC`, for a mail.
pub(crate) fn format_time(text: &str) -> String {
    clock::parse(text).map_or_else(
        || text.to_string(),
        |when| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02} UTC",
                when.year(),
                u8::from(when.month()),
                when.day(),
                when.hour(),
                when.minute()
            )
        },
    )
}

// ── Prelogin ──────────────────────────────────────────────

#[derive(Deserialize)]
struct PreloginRequest {
    #[serde(alias = "Email")]
    email: String,
}

async fn prelogin(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(request): Json<PreloginRequest>,
) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let kdf = match state.store.user_by_email(&request.email).await? {
        Some(user) => user.kdf,
        None => stand_in_kdf(&state, &request.email),
    };
    Ok(Json(json!({
        "kdf": kdf.kind,
        "kdfIterations": kdf.iterations,
        "kdfMemory": kdf.memory,
        "kdfParallelism": kdf.parallelism,
        "kdfSettings": {
            "kdfType": kdf.kind,
            "iterations": kdf.iterations,
            "memory": kdf.memory,
            "parallelism": kdf.parallelism,
        },
        "salt": null,
    })))
}

/// The KDF the prelogin answers for an address without an account: one of the defaults accounts
/// use — the web vault's Argon2id (3 iterations, 64 MiB, 4 threads) three times in four, the
/// apps' PBKDF2 with 600 000 iterations otherwise — chosen by a MAC of the address under the
/// server's secret, so asking again gives the same answer and nobody else can tell it from a
/// real one (R1-6).
fn stand_in_kdf(state: &AppState, email: &str) -> Kdf {
    let pbkdf2 = Kdf { kind: 0, iterations: 600_000, memory: None, parallelism: None };
    let normalized = email.trim().to_lowercase();
    match state.secret.mac("prelogin-kdf", normalized.as_bytes()) {
        Ok(mac) if mac[0] < 192 => Kdf { kind: 1, iterations: 3, memory: Some(64), parallelism: Some(4) },
        Ok(_) => pbkdf2,
        Err(error) => {
            tracing::warn!(%error, "the server secret could not be read for the prelogin");
            pbkdf2
        }
    }
}

// ── Registering ───────────────────────────────────────────

/// A KDF as the clients send it, in either of Bitwarden's spellings.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KdfData {
    #[serde(alias = "kdfType")]
    pub kdf: i64,
    #[serde(alias = "iterations")]
    pub kdf_iterations: i64,
    #[serde(default, alias = "memory")]
    pub kdf_memory: Option<i64>,
    #[serde(default, alias = "parallelism")]
    pub kdf_parallelism: Option<i64>,
}

impl KdfData {
    /// Checked against what Bitwarden allows, with a ceiling a login can still finish under.
    pub(crate) fn check(self) -> ApiResult<Kdf> {
        match self.kdf {
            0 => {
                if self.kdf_iterations < 100_000 {
                    return Err(ApiError::bad("PBKDF2 KDF iterations must be at least 100000."));
                }
                if self.kdf_iterations > 2_000_000 {
                    return Err(ApiError::bad("PBKDF2 KDF iterations must be at most 2000000."));
                }
                Ok(Kdf { kind: 0, iterations: self.kdf_iterations, memory: None, parallelism: None })
            }
            1 => {
                if !(2..=10).contains(&self.kdf_iterations) {
                    return Err(ApiError::bad("Argon2 KDF iterations must be between 2 and 10."));
                }
                let memory = self.kdf_memory.ok_or_else(|| ApiError::bad("Argon2 memory parameter is required."))?;
                if !(15..=1024).contains(&memory) {
                    return Err(ApiError::bad("Argon2 memory must be between 15 MB and 1024 MB."));
                }
                let parallelism =
                    self.kdf_parallelism.ok_or_else(|| ApiError::bad("Argon2 parallelism parameter is required."))?;
                if !(1..=16).contains(&parallelism) {
                    return Err(ApiError::bad("Argon2 parallelism must be between 1 and 16."));
                }
                Ok(Kdf {
                    kind: 1,
                    iterations: self.kdf_iterations,
                    memory: Some(memory),
                    parallelism: Some(parallelism),
                })
            }
            _ => Err(ApiError::bad("This key derivation is not supported.")),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Keys {
    pub encrypted_private_key: String,
    pub public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MasterPasswordAuthentication {
    pub kdf: KdfData,
    pub salt: String,
    #[serde(alias = "masterPasswordAuthenticationHash")]
    pub hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MasterPasswordUnlock {
    pub kdf: KdfData,
    pub salt: String,
    #[serde(alias = "masterKeyWrappedUserKey")]
    pub key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterData {
    email: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    master_password_hint: Option<String>,
    #[serde(default, alias = "userAsymmetricKeys")]
    keys: Option<Keys>,
    #[serde(default)]
    email_verification_token: Option<String>,
    #[serde(default)]
    master_password_hash: Option<String>,
    #[serde(default, alias = "userSymmetricKey")]
    key: Option<String>,
    #[serde(default, alias = "kdfType")]
    kdf: Option<i64>,
    #[serde(default, alias = "iterations")]
    kdf_iterations: Option<i64>,
    #[serde(default, alias = "memory")]
    kdf_memory: Option<i64>,
    #[serde(default, alias = "parallelism")]
    kdf_parallelism: Option<i64>,
    #[serde(default)]
    master_password_authentication: Option<MasterPasswordAuthentication>,
    #[serde(default)]
    master_password_unlock: Option<MasterPasswordUnlock>,
    /// Registering from an organisation's invitation (docs/uwu-api.md §16.2): its token and the
    /// membership it is for.
    #[serde(default)]
    org_invite_token: Option<String>,
    #[serde(default)]
    organization_user_id: Option<String>,
}

const BY_INVITATION: &str = "Registration is by invitation only. Open the link from your invitation.";

/// A trimmed hint, or none. Refused when hints are off.
pub(crate) fn clean_hint(state: &AppState, hint: Option<String>) -> ApiResult<Option<String>> {
    let hint = hint.map(|hint| hint.trim().to_string()).filter(|hint| !hint.is_empty());
    if hint.is_some() && !state.settings().password_hints {
        return Err(ApiError::bad("Password hints are turned off on this server. Remove the hint and try again."));
    }
    if hint.as_ref().is_some_and(|hint| hint.chars().count() > 50) {
        return Err(ApiError::bad("The password hint can be at most 50 characters long."));
    }
    Ok(hint)
}

async fn register_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(data): Json<RegisterData>,
) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let email = normalize_email(&data.email);
    let not_valid = || ApiError::bad("This invitation is not valid (any more). Ask for a new one.");
    // An organisation's invitation also registers, when the server invitation that came with it
    // (from an inviter who may invite people) is still there.
    let joining = match (data.org_invite_token.as_deref(), data.organization_user_id.as_deref()) {
        (Some(token), Some(member)) => Some(
            crate::org_members::invitation_for(&state, token.trim(), member, &email).await?.ok_or_else(not_valid)?,
        ),
        _ => None,
    };
    let invitation = match (data.email_verification_token.as_deref(), &joining) {
        (Some(token), _) => state.store.invitation_by_token(auth::sha256(token.trim().as_bytes())).await?,
        (None, Some(_)) => state.store.invitation(&email).await?.filter(|invitation| invitation.expires > clock::now()),
        (None, None) => return Err(ApiError::bad(BY_INVITATION)),
    }
    .filter(|invitation| invitation.email == email)
    .ok_or_else(|| if joining.is_some() { ApiError::bad(BY_INVITATION) } else { not_valid() })?;

    let (password, key, kdf) = match (data.master_password_authentication, data.master_password_unlock) {
        (Some(authentication), Some(unlock)) => {
            if authentication.kdf != unlock.kdf
                || normalize_email(&authentication.salt) != email
                || normalize_email(&unlock.salt) != email
            {
                return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "Unexpected RegisterData format"));
            }
            (authentication.hash, unlock.key, unlock.kdf)
        }
        _ => {
            let missing = || ApiError::bad("Registration is missing required parameters");
            let kdf = KdfData {
                kdf: data.kdf.ok_or_else(missing)?,
                kdf_iterations: data.kdf_iterations.ok_or_else(missing)?,
                kdf_memory: data.kdf_memory,
                kdf_parallelism: data.kdf_parallelism,
            };
            (data.master_password_hash.ok_or_else(missing)?, data.key.ok_or_else(missing)?, kdf)
        }
    };
    let kdf = kdf.check()?;
    state.settings().policies.check_kdf(&kdf)?;
    let name = data.name.map(|name| name.trim().to_string()).filter(|name| !name.is_empty());
    if name.as_ref().is_some_and(|name| name.len() > 50) {
        return Err(ApiError::bad("The field Name must be a string with a maximum length of 50."));
    }
    let hint = clean_hint(&state, data.master_password_hint)?;
    let (private_key, public_key) = match data.keys {
        Some(keys) => (Some(keys.encrypted_private_key), Some(keys.public_key)),
        None => (None, None),
    };
    let new = NewUser {
        email: email.clone(),
        name,
        password_hash: auth::hash_password(state.config.hash_cost, &password).await?,
        password_hint: hint,
        user_key: key,
        private_key,
        public_key,
        kdf,
        language: invitation.language.clone(),
        admin: invitation.admin,
    };
    let user = match state.store.create_user(new).await {
        Ok(user) => user,
        Err(StoreError::Exists) => return Err(ApiError::bad("There is an account for this address already.")),
        Err(error) => return Err(error.into()),
    };
    tracing::info!(email = %user.email, admin = user.admin, "account registered");
    if let Some((org, member)) = joining
        && let Err(error) = crate::org_members::accept_as(&state, &org, &member.id, &user).await
    {
        tracing::warn!(error = %error.message(), "the organisation's invitation was not taken with the registration");
    }
    let event = Event {
        kind: "register".into(),
        user_id: Some(user.id.clone()),
        email: Some(user.email.clone()),
        ip: Some(ip.to_string()),
        ..Event::default()
    };
    let _ = state.store.log_event(event).await;
    Ok(Json(json!({ "object": "register", "captchaBypassToken": "" })))
}

#[derive(Deserialize)]
struct VerificationRequest {
    email: String,
}

/// The official clients' "create account": for an invited address, the invitation mail goes out
/// again, with a new link. Everybody else is told registering needs an invitation.
async fn send_verification_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(request): Json<VerificationRequest>,
) -> ApiResult<Response> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let email = normalize_email(&request.email);
    let invitation = state.store.invitation(&email).await?.filter(|invitation| invitation.expires > clock::now());
    let Some(invitation) = invitation else { return Err(ApiError::bad(BY_INVITATION)) };
    if !state.mailer.enabled() {
        return Err(ApiError::bad(BY_INVITATION));
    }
    // Every new mail makes the link before it useless: nobody may do that over and over.
    mail_allowed(&state, &email, None)?;
    crate::admin::invite(&state, &email, invitation.admin, invitation.invited_by.clone()).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn register_without_invitation() -> ApiError {
    ApiError::bad(BY_INVITATION)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::http::StatusCode;
    use serde_json::json;

    #[tokio::test]
    async fn an_invitation_registers_one_account_that_logs_in() {
        let server = TestServer::new().await;
        let token = server.invite("nyu@example.com", false).await;
        let response = server
            .call("POST", "/identity/accounts/register/finish", None, register_body("Nyu@Example.com", &token))
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        assert_eq!(json(response).await["object"], "register");
        let again = server
            .call("POST", "/identity/accounts/register/finish", None, register_body("nyu@example.com", &token))
            .await;
        assert_eq!(again.status(), StatusCode::BAD_REQUEST, "the invitation is used up");

        let response = server.form("/identity/connect/token", &login_form("nyu@example.com", "d1")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["Key"], "2.userkey|userkey|userkey");
        assert_eq!(body["PrivateKey"], "2.private|private|private");
        assert_eq!(body["Kdf"], 0);
        assert_eq!(body["KdfIterations"], 600000);
        assert_eq!(body["UserDecryptionOptions"]["MasterPasswordUnlock"]["Salt"], "nyu@example.com");
        assert_eq!(body["MasterPasswordPolicy"]["Object"], "masterPasswordPolicy");
        assert!(body["refresh_token"].as_str().unwrap().len() > 60);
    }

    #[tokio::test]
    async fn nobody_registers_without_an_invitation() {
        let server = TestServer::new().await;
        let token = server.invite("nyu@example.com", false).await;
        for (email, token) in [("other@example.com", token.as_str()), ("nyu@example.com", "made-up")] {
            let response =
                server.call("POST", "/identity/accounts/register/finish", None, register_body(email, token)).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{email}");
        }
        let mut body = register_body("nyu@example.com", &token);
        body.as_object_mut().unwrap().remove("emailVerificationToken");
        for path in ["/identity/accounts/register/finish", "/identity/accounts/register", "/api/accounts/register"] {
            let response = server.call("POST", path, None, body.clone()).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        }
    }

    #[tokio::test]
    async fn the_new_form_of_registering_works_too() {
        let server = TestServer::new().await;
        let token = server.invite("nyu@example.com", false).await;
        let kdf = json!({"kdfType": 1, "iterations": 3, "memory": 64, "parallelism": 4});
        let body = json!({
            "email": "nyu@example.com",
            "masterPasswordAuthentication": {"kdf": kdf, "salt": "nyu@example.com", "masterPasswordAuthenticationHash": password_hash("nyu@example.com")},
            "masterPasswordUnlock": {"kdf": kdf, "salt": "nyu@example.com", "masterKeyWrappedUserKey": "2.k|k|k"},
            "userAsymmetricKeys": {"encryptedPrivateKey": "2.p|p|p", "publicKey": "pub"},
            "emailVerificationToken": token,
        });
        let response = server.call("POST", "/identity/accounts/register/finish", None, body).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        let prelogin =
            json(server.call("POST", "/identity/accounts/prelogin", None, json!({"email": "NYU@example.com"})).await)
                .await;
        assert_eq!((prelogin["kdf"].clone(), prelogin["kdfMemory"].clone()), (json!(1), json!(64)));
        assert_eq!(prelogin["kdfSettings"]["parallelism"], 4);
    }

    #[tokio::test]
    async fn a_cheap_or_unknown_kdf_is_refused() {
        let server = TestServer::new().await;
        for (kdf, iterations, memory) in
            [(0, 5000, None), (0, 5_000_000, None), (1, 3, Some(4)), (1, 3, None), (7, 3, None)]
        {
            let token = server.invite("nyu@example.com", false).await;
            let mut body = register_body("nyu@example.com", &token);
            body["kdf"] = json!(kdf);
            body["kdfIterations"] = json!(iterations);
            body["kdfMemory"] = json!(memory);
            body["kdfParallelism"] = json!(4);
            let response = server.call("POST", "/identity/accounts/register/finish", None, body).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{kdf} {iterations} {memory:?}");
        }
    }

    #[tokio::test]
    async fn a_prelogin_tells_nobody_who_has_an_account() {
        let server = TestServer::new().await;
        let ask = |email: String| {
            let server = &server;
            async move { json(server.call("POST", "/api/accounts/prelogin", None, json!({ "email": email })).await).await }
        };
        // The same address, the same answer; the defaults accounts use, both of them (R1-6).
        let unknown = ask("nobody@example.com".into()).await;
        assert_eq!(ask(" NOBODY@example.com".into()).await, unknown);
        let mut kinds = std::collections::BTreeSet::new();
        for n in 0..40 {
            let answer = ask(format!("nobody{n}@example.com")).await;
            match answer["kdf"].as_i64().unwrap() {
                0 => assert_eq!(answer["kdfIterations"], 600000),
                1 => assert_eq!(
                    (answer["kdfIterations"].clone(), answer["kdfMemory"].clone(), answer["kdfParallelism"].clone()),
                    (json!(3), json!(64), json!(4))
                ),
                other => panic!("kdf {other}"),
            }
            kinds.insert(answer["kdf"].as_i64().unwrap());
        }
        assert_eq!(kinds.len(), 2);
    }

    #[tokio::test]
    async fn a_wrong_password_is_refused_and_written_down() {
        let server = TestServer::new().await;
        server.account("nyu@example.com").await;
        let mut form = login_form("nyu@example.com", "d2");
        form[2].1 = "wrong";
        let response = server.form("/identity/connect/token", &form).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(response).await["message"], "Username or password is incorrect. Try again");
        let unknown = server.form("/identity/connect/token", &login_form("nobody@example.com", "d2")).await;
        assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
        let events = server.state.store.events(Some("login-failed".into()), None, 10).await.unwrap();
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn too_many_wrong_passwords_leave_only_known_devices_in() {
        let server = TestServer::new().await;
        server.account("nyu@example.com").await; // device-1
        let mut limits = crate::Limits::generous();
        limits.login_account = crate::limits::Limiter::new(2, std::time::Duration::from_secs(3600));
        let server = server.with_limits(limits);
        for _ in 0..2 {
            let mut form = login_form("NYU@example.com", "elsewhere");
            form[2].1 = "wrong";
            assert_eq!(server.form("/identity/connect/token", &form).await.status(), StatusCode::BAD_REQUEST);
        }
        // The right password from a new device now waits…
        let refused = server.form("/identity/connect/token", &login_form("nyu@example.com", "elsewhere")).await;
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(json(refused).await["code"], "account_limited");
        // …the owner's own device is not locked out.
        server.login("nyu@example.com", "device-1").await;
        // An address without an account answers the same way once its tries ran out.
        for _ in 0..2 {
            server.form("/identity/connect/token", &login_form("nobody@example.com", "x")).await;
        }
        let unknown = server.form("/identity/connect/token", &login_form("nobody@example.com", "x")).await;
        assert_eq!(unknown.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn a_refresh_token_keeps_a_device_logged_in_until_it_logs_out() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let response = server
            .form(
                "/identity/connect/token",
                &[("grant_type", "refresh_token"), ("client_id", "browser"), ("refresh_token", &account.refresh)],
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["refresh_token"], account.refresh.as_str());
        let fresh = body["access_token"].as_str().unwrap().to_string();
        assert_eq!(server.get_as(&fresh, "/api/accounts/revision-date").await.status(), StatusCode::OK);

        server.state.store.log_out_device(&account.id, &account.device).await.unwrap();
        let response = server
            .form("/identity/connect/token", &[("grant_type", "refresh_token"), ("refresh_token", &account.refresh)])
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(response).await, json!({"error": "invalid_grant"}));
        assert_eq!(
            server.get_as(&fresh, "/api/accounts/revision-date").await.status(),
            StatusCode::UNAUTHORIZED,
            "its access token ends too"
        );
    }

    #[tokio::test]
    async fn a_new_device_gets_a_mail_but_the_first_does_not() {
        let server = TestServer::new().await;
        server.account("nyu@example.com").await;
        tokio::task::yield_now().await;
        assert!(server.mails().iter().all(|mail| !mail.subject.contains("Anmeldung")), "the first device");
        server.login("nyu@example.com", "device-2").await;
        server.wait_for_mail(|mail| mail.to == "nyu@example.com" && mail.subject.contains("Neue Anmeldung")).await;
    }

    #[tokio::test]
    async fn a_disabled_account_does_not_log_in() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        server.state.store.update_user(&account.id, |user| user.disabled = true).await.unwrap();
        let response = server.form("/identity/connect/token", &login_form("nyu@example.com", "d3")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(server.get_as(&account.token, "/api/sync").await.status(), StatusCode::UNAUTHORIZED);
    }
}
