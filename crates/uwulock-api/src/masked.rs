//! Masked addresses from UwUMail (docs/uwu-api.md §13).
//!
//! A person connects their account to a UwUMail server an admin allowed, once, through OAuth in
//! the web vault: the server registers itself there as a public client, sends the browser to
//! UwUMail with PKCE, a `state` and a cookie that ties the answer to that browser, and keeps the
//! grant's refresh token sealed with the server secret (`secret.key` in the data directory). From
//! then on the server makes masked addresses for the account through UwUMail's JMAP
//! `MaskedEmail` — for the web vault and UwULock's clients under `/uwu/v1/masked`, and for the
//! official Bitwarden clients through an addy.io- and a SimpleLogin-compatible endpoint with keys
//! of their own ([`compat`]).
//!
//! UwUMail rotates the refresh token on every use and ends the whole grant when an old one comes
//! back. So refreshing happens one at a time per account, and the new refresh token is in the
//! database before the new access token is used.

mod compat;
pub(crate) mod uwumail;

use crate::auth::{Admin, ClientIp, Session};
use crate::errors::{ApiError, ApiResult};
use crate::notices::{self, Context};
use crate::{AppState, auth};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use parking_lot::Mutex;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uwulock_store::masked::{MaskedClient, MaskedConnection, MaskedLink};
use uwumail::{Call, Upstream};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/masked/connect", post(connect))
        .route("/uwu/v1/masked/callback", get(callback))
        .route("/uwu/v1/masked/connection", get(connection).delete(disconnect))
        .route("/uwu/v1/masked/addresses", get(addresses).post(create))
        .route("/uwu/v1/masked/addresses/{id}", patch(change).delete(remove))
        .route("/uwu/v1/masked/links", get(links))
        .route("/uwu/v1/admin/masked/check", post(admin_check))
        .merge(compat::routes())
}

/// How long the browser has from "connect" to coming back from UwUMail.
const PENDING: Duration = Duration::from_secs(10 * 60);
/// At most this many connects wait for their answer at once, across all accounts.
const MOST_PENDING: usize = 1000;
/// An access token this close to running out is refreshed first.
const MARGIN_SECONDS: i64 = 60;
/// UwUMail forgets a client without a grant after seven days unused; one this old is registered
/// again before it is used for a new connection.
const CLIENT_DAYS: i64 = 6;
/// UwUMail's limits of a masked address's texts.
const TEXT_CHARS: usize = 200;

/// What waits for UwUMail's answer, by the SHA-256 of the `state`.
struct Pending {
    user_id: String,
    server: String,
    issuer: String,
    client_id: String,
    redirect_uri: String,
    verifier: String,
    binding: Vec<u8>,
    token_endpoint: String,
    revocation_endpoint: Option<String>,
    until: Instant,
}

/// What the running server keeps for masked addresses: connects that wait for their answer, and
/// one lock per account for refreshing its tokens.
#[derive(Default)]
pub struct Masked {
    pending: Mutex<HashMap<Vec<u8>, Pending>>,
    refreshing: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl Masked {
    fn lock_for(&self, user_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.refreshing.lock();
        // Locks nobody holds or waits for are dropped now and then, so the map stays small.
        if locks.len() > 1000 {
            locks.retain(|_, lock| Arc::strong_count(lock) > 1);
        }
        locks.entry(user_id.to_string()).or_default().clone()
    }
}

// ── Errors ────────────────────────────────────────────────

/// Why an address could not be made or changed.
#[derive(Debug)]
pub(crate) enum Refusal {
    NotConnected,
    Revoked,
    /// The account's UwUMail server is not on the admin's list (any more).
    NotAllowed,
    Upstream(String),
    RateLimited,
    /// UwUMail's `invalidProperties`, with its description.
    Invalid(String),
    Forbidden(String),
    Quota(String),
    NotFound,
    Store(uwulock_store::StoreError),
}

impl From<uwulock_store::StoreError> for Refusal {
    fn from(error: uwulock_store::StoreError) -> Self {
        Refusal::Store(error)
    }
}

impl From<Refusal> for ApiError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::NotConnected => ApiError::new(
                StatusCode::CONFLICT,
                "This account is not connected to UwUMail. Connect it in the web vault under Settings → Masked addresses.",
            )
            .code("not_connected"),
            Refusal::Revoked => ApiError::new(
                StatusCode::CONFLICT,
                "UwUMail ended the connection. Connect again in the web vault under Settings → Masked addresses.",
            )
            .code("revoked"),
            Refusal::NotAllowed => {
                ApiError::forbidden("This UwUMail server is not allowed on this server (any more).").code("server_not_allowed")
            }
            Refusal::Upstream(text) => ApiError::upstream(format!("UwUMail: {text}")),
            Refusal::RateLimited => {
                ApiError::too_many("Too many masked addresses at once. Wait a minute and try again.")
            }
            Refusal::Invalid(text) => ApiError::bad(format!("UwUMail: {text}")),
            Refusal::Forbidden(text) => ApiError::forbidden(format!("UwUMail refused it: {text}")),
            Refusal::Quota(text) => {
                ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, format!("UwUMail: {text}")).code("quota")
            }
            Refusal::NotFound => ApiError::not_found("No such masked address."),
            Refusal::Store(error) => error.into(),
        }
    }
}

fn feature_off() -> ApiError {
    ApiError::not_found("Masked addresses are not switched on on this server.").code("feature_off")
}

/// The feature is on when the admin listed at least one UwUMail server.
fn check_on(state: &AppState) -> ApiResult<()> {
    if state.settings().masked.servers.is_empty() { Err(feature_off()) } else { Ok(()) }
}

// ── Tokens ────────────────────────────────────────────────

fn purpose(kind: &str, user_id: &str, server: &str) -> String {
    format!("masked.{kind}:{user_id}:{server}")
}

fn seal(state: &AppState, kind: &str, user_id: &str, server: &str, plain: &str) -> Result<String, Refusal> {
    state.secret.seal(plain, &purpose(kind, user_id, server)).map_err(|error| Refusal::Store(internal(error)))
}

fn open(state: &AppState, kind: &str, connection: &MaskedConnection, sealed: &str) -> Result<String, Refusal> {
    state
        .secret
        .open(sealed, &purpose(kind, &connection.user_id, &connection.server))
        .map_err(|error| Refusal::Store(internal(error)))
}

fn internal(error: String) -> uwulock_store::StoreError {
    uwulock_store::StoreError::Io(std::io::Error::other(error))
}

/// The account's connection, if its server is still allowed.
async fn usable_connection(state: &AppState, user_id: &str) -> Result<MaskedConnection, Refusal> {
    let connection = state.store.masked_connection(user_id).await?.ok_or(Refusal::NotConnected)?;
    if state.settings().masked.server(&connection.server).is_none() {
        return Err(Refusal::NotAllowed);
    }
    if connection.status == "revoked" {
        return Err(Refusal::Revoked);
    }
    Ok(connection)
}

/// A working access token for the account, refreshed when it ran out or when `stale` — one
/// UwUMail just refused — is still the one kept. One refresh at a time per account.
async fn access(state: &AppState, user_id: &str, stale: Option<&str>) -> Result<(MaskedConnection, String), Refusal> {
    let lock = state.masked.lock_for(user_id);
    let _held = lock.lock().await;
    // Read again under the lock: another request may have refreshed meanwhile.
    let connection = usable_connection(state, user_id).await?;
    let now = auth::now_seconds();
    if let Some(sealed) = &connection.access_token
        && connection.access_expires > now + MARGIN_SECONDS
    {
        let token = open(state, "access", &connection, sealed)?;
        if stale != Some(token.as_str()) {
            return Ok((connection, token));
        }
    }
    let refresh = open(state, "refresh", &connection, &connection.refresh_token)?;
    match uwumail::refresh(&connection.token_endpoint, &connection.client_id, &refresh).await {
        Ok(tokens) => {
            let access = seal(state, "access", user_id, &connection.server, &tokens.access_token)?;
            let refresh = seal(state, "refresh", user_id, &connection.server, &tokens.refresh_token)?;
            // Kept before it is used: UwUMail ends the grant when the old one comes again.
            let expires = now + tokens.expires_in.clamp(60, 86_400);
            let kept = state
                .store
                .masked_tokens_refreshed(user_id, &connection.refresh_token, access.clone(), expires, refresh.clone())
                .await?;
            if !kept {
                // Disconnected while UwUMail answered: the new tokens go with it.
                return Err(Refusal::NotConnected);
            }
            let _ = state.store.masked_client_used(&connection.server, &connection.client_id, now).await;
            let connection = MaskedConnection {
                access_token: Some(access),
                access_expires: expires,
                refresh_token: refresh,
                ..connection
            };
            Ok((connection, tokens.access_token))
        }
        Err(error) if error.is("invalid_grant") || error.is("invalid_client") || error.is("invalid_scope") => {
            tracing::info!(user = user_id, server = %connection.server, error = %error.text(), "UwUMail ended a masked-address grant");
            state.store.masked_status(user_id, "revoked", None).await?;
            if error.is("invalid_client") {
                state.store.forget_masked_client(&connection.server, &connection.client_id).await?;
            }
            Err(Refusal::Revoked)
        }
        Err(Upstream::RateLimited) => Err(Refusal::RateLimited),
        Err(error) => {
            state.store.masked_status(user_id, "unreachable", None).await?;
            Err(Refusal::Upstream(error.text()))
        }
    }
}

/// One JMAP method for the account, with a fresh token once when UwUMail refuses the one it had.
async fn jmap(
    state: &AppState,
    user_id: &str,
    method: &str,
    arguments: Value,
) -> Result<(MaskedConnection, Value), Refusal> {
    let (mut connection, mut token) = access(state, user_id, None).await?;
    let with_account = |connection: &MaskedConnection| {
        let mut arguments = arguments.clone();
        arguments["accountId"] = json!(connection.account_id);
        arguments
    };
    let mut result = uwumail::call(&connection.api_url, &token, method, with_account(&connection)).await;
    if matches!(&result, Err(Call::Http(Upstream::Refused { status: 401, .. }))) {
        (connection, token) = access(state, user_id, Some(&token)).await?;
        result = uwumail::call(&connection.api_url, &token, method, with_account(&connection)).await;
    }
    match result {
        Ok(value) => {
            state.store.masked_status(user_id, "ok", None).await?;
            Ok((connection, value))
        }
        Err(Call::Http(Upstream::RateLimited)) => Err(Refusal::RateLimited),
        Err(Call::Http(Upstream::Refused { status: 401 | 403, .. })) => {
            state.store.masked_status(user_id, "revoked", None).await?;
            Err(Refusal::Revoked)
        }
        Err(Call::Http(error)) => {
            state.store.masked_status(user_id, "unreachable", None).await?;
            Err(Refusal::Upstream(error.text()))
        }
        Err(Call::Method(kind, description)) => Err(method_refusal(&kind, &description)),
    }
}

/// A JMAP error (`type` and description) as a refusal.
fn method_refusal(kind: &str, description: &str) -> Refusal {
    let text = if description.is_empty() { kind.to_string() } else { description.to_string() };
    match kind {
        "invalidProperties" | "invalidArguments" => Refusal::Invalid(text),
        "notFound" => Refusal::NotFound,
        // UwUMail says `forbidden` for its 5000-address limit too.
        "forbidden" if description.contains("5000") || description.to_ascii_lowercase().contains("limit") => {
            Refusal::Quota(text)
        }
        "forbidden" => Refusal::Forbidden(text),
        _ => Refusal::Upstream(text),
    }
}

// ── Connecting ────────────────────────────────────────────

fn redirect_uri(state: &AppState) -> String {
    format!("{}/uwu/v1/masked/callback", state.config.public.trim_end_matches('/'))
}

fn client_name(state: &AppState) -> String {
    format!("UwULock ({})", state.host())
}

/// This server's client at `server`: the one registered, or a new registration when there is
/// none, it is for another address of this server, or UwUMail may have forgotten it.
async fn client_at(state: &AppState, server: &str, discovery: &uwumail::Discovery) -> Result<MaskedClient, Refusal> {
    let redirect = redirect_uri(state);
    let now = auth::now_seconds();
    if let Some(client) = state.store.masked_client(server).await?
        && client.redirect_uri == redirect
    {
        if now - client.used < CLIENT_DAYS * 86_400 {
            return Ok(client);
        }
        // Older: UwUMail keeps it only while a grant holds it. When one of ours might, ask the
        // token endpoint with a refresh token that is none — it names an unknown client first.
        if state.store.masked_client_in_use(&client.client_id).await? {
            let probe = uwumail::refresh(&discovery.token_endpoint, &client.client_id, "uwulock-probe").await;
            if !probe.as_ref().is_err_and(|error| error.is("invalid_client")) {
                let _ = state.store.masked_client_used(server, &client.client_id, now).await;
                return Ok(MaskedClient { used: now, ..client });
            }
        }
    }
    let client_id =
        uwumail::register(discovery, &client_name(state), &redirect).await.map_err(|error| match error {
            Upstream::RateLimited => Refusal::RateLimited,
            error => Refusal::Upstream(error.text()),
        })?;
    let client = MaskedClient { server: server.to_string(), client_id, redirect_uri: redirect, used: now };
    state.store.set_masked_client(client.clone()).await?;
    Ok(client)
}

/// The name of the cookie that ties the answer to the browser that asked: `__Host-` where the
/// server is reached by https.
fn cookie_name(state: &AppState) -> &'static str {
    if state.config.public.starts_with("https://") { "__Host-uwu-masked" } else { "uwu-masked" }
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

#[derive(Deserialize)]
struct ConnectBody {
    #[serde(default)]
    server: String,
}

async fn connect(
    State(state): State<AppState>,
    session: Session,
    Json(body): Json<ConnectBody>,
) -> ApiResult<Response> {
    check_on(&state)?;
    let settings = state.settings();
    let server = settings.masked.server(&body.server).map(|server| server.url.clone()).ok_or_else(|| {
        ApiError::forbidden("This UwUMail server is not one this server may talk to.").code("server_not_allowed")
    })?;
    if !state.limits.masked_connect.take(session.user.id.clone()) {
        return Err(ApiError::too_many("Too many tries to connect. Wait a few minutes and try again."));
    }
    let discovery = uwumail::discover(&server).await.map_err(|error| match error {
        Upstream::RateLimited => ApiError::from(Refusal::RateLimited),
        error => ApiError::upstream(format!("UwUMail: {}", error.text())),
    })?;
    let client = client_at(&state, &server, &discovery).await?;
    let verifier = auth::random_token(32);
    let state_token = auth::random_token(32);
    let binding = auth::random_token(32);
    {
        let mut pending = state.masked.pending.lock();
        let now = Instant::now();
        pending.retain(|_, waiting| waiting.until > now);
        if pending.len() >= MOST_PENDING {
            return Err(ApiError::too_many("Too many connects at once. Try again in a few minutes."));
        }
        pending.insert(
            auth::sha256(state_token.as_bytes()),
            Pending {
                user_id: session.user.id.clone(),
                server: server.clone(),
                issuer: discovery.issuer.clone(),
                client_id: client.client_id.clone(),
                redirect_uri: client.redirect_uri.clone(),
                verifier: verifier.clone(),
                binding: auth::sha256(binding.as_bytes()),
                token_endpoint: discovery.token_endpoint.clone(),
                revocation_endpoint: discovery.revocation_endpoint.clone(),
                until: now + PENDING,
            },
        );
    }
    let mut url = reqwest::Url::parse(&discovery.authorization_endpoint).map_err(ApiError::internal)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client.client_id)
        .append_pair("redirect_uri", &client.redirect_uri)
        .append_pair("scope", uwumail::SCOPE)
        .append_pair("state", &state_token)
        .append_pair("code_challenge", &URL_SAFE_NO_PAD.encode(auth::sha256(verifier.as_bytes())))
        .append_pair("code_challenge_method", "S256")
        .append_pair("prompt", "consent");
    let mut response = Json(json!({ "object": "maskedConnect", "authorizeUrl": url.to_string() })).into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie(&state, &binding, PENDING.as_secs() as i64));
    Ok(response)
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    iss: Option<String>,
    error: Option<String>,
}

/// Back from UwUMail: the web vault's page for masked addresses, with how it went.
fn back(state: &AppState, result: &str) -> Response {
    let to = format!("{}/#/settings/masked?result={result}", state.config.public.trim_end_matches('/'));
    let mut response = StatusCode::SEE_OTHER.into_response();
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&to) {
        headers.insert(header::LOCATION, value);
    }
    headers.insert(header::SET_COOKIE, cookie(state, "", 0));
    response
}

async fn callback(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let error = |reason: &str| back(&state, &format!("error&reason={reason}"));
    if !state.limits.anonymous.check(ip) {
        return ApiError::too_many("Too many requests. Wait a minute and try again.").into_response();
    }
    let Some(state_token) = query.state.as_deref().filter(|token| !token.is_empty()) else {
        return error("invalid_state");
    };
    // Single use: taken out whatever comes next.
    let Some(pending) = state.masked.pending.lock().remove(&auth::sha256(state_token.as_bytes())) else {
        return error("invalid_state");
    };
    let binding = cookie_value(&state, &headers).unwrap_or_default();
    if !auth::constant_time_eq(&auth::sha256(binding.as_bytes()), &pending.binding) {
        return error("invalid_state");
    }
    if pending.until <= Instant::now() {
        return error("expired");
    }
    if let Some(refused) = &query.error {
        return error(if refused == "access_denied" { "denied" } else { "upstream" });
    }
    // RFC 9207: the answer names who sent it, so another server cannot pass for this one.
    if query.iss.as_deref() != Some(pending.issuer.as_str()) {
        return error("invalid_state");
    }
    let Some(code) = query.code.as_deref().filter(|code| !code.is_empty()) else {
        return error("invalid_state");
    };
    match finish(&state, &pending, code).await {
        Ok(()) => {
            if let Ok(Some(user)) = state.store.user(&pending.user_id).await {
                notices::record(
                    &state,
                    &user,
                    "maskedConnected",
                    &Context::ip(ip),
                    json!({ "server": pending.server }),
                )
                .await;
            }
            back(&state, "connected")
        }
        Err(problem) => {
            tracing::warn!(server = %pending.server, %problem, "connecting to UwUMail for masked addresses did not work");
            error("upstream")
        }
    }
}

/// The code for tokens, the session for the account and its domains, and all of it kept.
async fn finish(state: &AppState, pending: &Pending, code: &str) -> Result<(), String> {
    let tokens = match uwumail::exchange(
        &pending.token_endpoint,
        &pending.client_id,
        code,
        &pending.redirect_uri,
        &pending.verifier,
    )
    .await
    {
        Ok(tokens) => tokens,
        Err(error) => {
            if error.is("invalid_client") {
                // UwUMail forgot this server: it registers again on the next try.
                let _ = state.store.forget_masked_client(&pending.server, &pending.client_id).await;
            }
            return Err(error.text());
        }
    };
    let session = uwumail::session(&pending.server, &tokens.access_token).await.map_err(|error| error.text())?;
    let now = auth::now_seconds();
    let user_id = &pending.user_id;
    let sealed = |kind: &str, plain: &str| state.secret.seal(plain, &purpose(kind, user_id, &pending.server));
    let previous = state.store.masked_connection(user_id).await.map_err(|error| error.to_string())?;
    let connection = MaskedConnection {
        user_id: user_id.clone(),
        server: pending.server.clone(),
        issuer: pending.issuer.clone(),
        client_id: pending.client_id.clone(),
        token_endpoint: pending.token_endpoint.clone(),
        revocation_endpoint: pending.revocation_endpoint.clone(),
        api_url: session.api_url,
        account_id: session.account_id,
        username: session.username,
        domains: session.domains,
        default_domain: session.default_domain,
        access_token: Some(sealed("access", &tokens.access_token)?),
        access_expires: now + tokens.expires_in.clamp(60, 86_400),
        refresh_token: sealed("refresh", &tokens.refresh_token)?,
        status: "ok".into(),
        connected: uwulock_store::clock::now(),
        last_used: None,
    };
    if let Some(previous) = &previous
        && (previous.server != connection.server || previous.account_id != connection.account_id)
    {
        // Another mailbox: the links named its addresses, which this one does not have.
        state.store.delete_masked_connection(user_id).await.map_err(|error| error.to_string())?;
        end_grant(state, previous).await;
    }
    state.store.set_masked_connection(connection).await.map_err(|error| error.to_string())?;
    let _ = state.store.masked_client_used(&pending.server, &pending.client_id, now).await;
    Ok(())
}

/// Tell UwUMail a grant is over, when its server is still allowed. Best effort.
async fn end_grant(state: &AppState, connection: &MaskedConnection) {
    let (Some(endpoint), Some(_)) =
        (&connection.revocation_endpoint, state.settings().masked.server(&connection.server))
    else {
        return;
    };
    let Ok(refresh) = open(state, "refresh", connection, &connection.refresh_token) else { return };
    if let Err(error) = uwumail::revoke(endpoint, &connection.client_id, &refresh).await {
        tracing::info!(server = %connection.server, error = %error.text(), "UwUMail did not take the end of a grant");
    }
}

/// Before an account goes: its grant at UwUMail ends too (best effort; the connection goes with
/// the account's row).
pub(crate) async fn account_going(state: &AppState, user_id: &str) {
    let Ok(Some(connection)) = state.store.masked_connection(user_id).await else { return };
    let lock = state.masked.lock_for(user_id);
    let _held = lock.lock().await;
    let connection = state.store.masked_connection(user_id).await.ok().flatten().unwrap_or(connection);
    end_grant(state, &connection).await;
}

async fn connection(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let settings = state.settings();
    let allowed: Vec<Value> =
        settings.masked.servers.iter().map(|server| json!({ "url": server.url, "name": server.name })).collect();
    // A connection from before the admin took the last server off the list is still shown, so
    // it can be ended; without one, the feature is off.
    let Some(mut connection) = state.store.masked_connection(&session.user.id).await? else {
        check_on(&state)?;
        return Ok(Json(json!({
            "object": "maskedConnection",
            "connected": false,
            "server": null,
            "username": null,
            "domains": null,
            "defaultDomain": null,
            "status": null,
            "connectedDate": null,
            "lastUsedDate": null,
            "allowedServers": allowed,
        })));
    };
    // The domains follow UwUMail's policy, which its admin may have changed: read them again.
    if connection.status != "revoked" && settings.masked.server(&connection.server).is_some() {
        match session_now(&state, &session.user.id).await {
            Ok(fresh) => connection = fresh,
            Err(error) => tracing::debug!(?error, "the UwUMail session could not be read again"),
        }
    }
    Ok(Json(json!({
        "object": "maskedConnection",
        "connected": true,
        "server": connection.server,
        "username": connection.username,
        "domains": connection.domains,
        "defaultDomain": connection.default_domain,
        "status": connection.status,
        "connectedDate": connection.connected,
        "lastUsedDate": connection.last_used,
        "allowedServers": allowed,
    })))
}

/// The session read again for its domains; the connection as it is afterwards.
async fn session_now(state: &AppState, user_id: &str) -> Result<MaskedConnection, Refusal> {
    let (connection, token) = access(state, user_id, None).await?;
    let fresh = match uwumail::session(&connection.server, &token).await {
        Err(Upstream::Refused { status: 401, .. }) => {
            let (connection, token) = access(state, user_id, Some(&token)).await?;
            uwumail::session(&connection.server, &token).await
        }
        other => other,
    };
    match fresh {
        Ok(fresh) => {
            state.store.masked_status(user_id, "ok", Some((fresh.domains, fresh.default_domain))).await?;
        }
        Err(error) => {
            state.store.masked_status(user_id, "unreachable", None).await?;
            return Err(Refusal::Upstream(error.text()));
        }
    }
    state.store.masked_connection(user_id).await?.ok_or(Refusal::NotConnected)
}

async fn disconnect(State(state): State<AppState>, session: Session, ClientIp(ip): ClientIp) -> ApiResult<StatusCode> {
    let connection = state.store.masked_connection(&session.user.id).await?.ok_or(Refusal::NotConnected)?;
    // Under the lock, so no refresh runs while the grant ends.
    let lock = state.masked.lock_for(&session.user.id);
    let _held = lock.lock().await;
    let connection = state.store.masked_connection(&session.user.id).await?.unwrap_or(connection);
    end_grant(&state, &connection).await;
    state.store.delete_masked_connection(&session.user.id).await?;
    let context = Context::of(&state, &session, ip).await;
    notices::record(&state, &session.user, "maskedDisconnected", &context, json!({ "server": connection.server }))
        .await;
    Ok(StatusCode::OK)
}

// ── Addresses ─────────────────────────────────────────────

/// The link to an item in the web vault, which UwUMail keeps as the address's `url`.
fn item_url(state: &AppState, cipher_id: &str) -> String {
    format!("{}/#/vault?itemId={cipher_id}", state.config.public.trim_end_matches('/'))
}

fn render(address: &Value, links: &HashMap<String, String>) -> Value {
    let id = address["id"].as_str().unwrap_or_default();
    json!({
        "object": "maskedAddress",
        "id": id,
        "email": address["email"],
        "state": address["state"],
        "forDomain": address["forDomain"].as_str().unwrap_or_default(),
        "description": address["description"].as_str().unwrap_or_default(),
        "url": address["url"],
        "createdAt": address["createdAt"],
        "lastMessageAt": address["lastMessageAt"],
        "createdBy": address["createdBy"],
        "cipherId": links.get(id),
    })
}

/// Masked id → cipher id, for the account.
async fn link_map(state: &AppState, user_id: &str) -> Result<HashMap<String, String>, Refusal> {
    Ok(state.store.masked_links(user_id).await?.into_iter().map(|link| (link.masked_id, link.cipher_id)).collect())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListQuery {
    cipher_id: Option<String>,
}

async fn addresses(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    check_on(&state)?;
    let user_id = &session.user.id;
    let (_, answer) = jmap(&state, user_id, "MaskedEmail/get", json!({ "ids": null })).await?;
    let list = answer["list"].as_array().cloned().unwrap_or_default();
    let links = link_map(&state, user_id).await?;
    // The states of linked addresses, for clients that show them without asking UwUMail.
    let states: BTreeMap<String, String> = list
        .iter()
        .filter_map(|address| Some((address["id"].as_str()?.to_string(), address["state"].as_str()?.to_string())))
        .filter(|(id, _)| links.contains_key(id))
        .collect();
    state.store.masked_link_states(user_id, states).await?;
    let data: Vec<Value> = list
        .iter()
        .map(|address| render(address, &links))
        .filter(|address| query.cipher_id.as_ref().is_none_or(|cipher| address["cipherId"].as_str() == Some(cipher)))
        .collect();
    Ok(Json(json!({ "object": "list", "data": data, "continuationToken": null })))
}

/// A text for UwUMail: without control characters, at most 200 characters.
fn clean_text(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(TEXT_CHARS).collect::<String>().trim().to_string()
}

/// `https://host` of what was given as the site, or `""`.
pub(crate) fn clean_for_domain(text: &str) -> String {
    compat::host_in(text).map(|host| format!("https://{host}")).unwrap_or_default()
}

/// That the account sees the item.
async fn check_cipher(state: &AppState, user_id: &str, cipher_id: &str) -> ApiResult<()> {
    let own = state.store.cipher(user_id, cipher_id).await?.is_some();
    if own || state.store.org_cipher(user_id, cipher_id).await?.is_some() {
        Ok(())
    } else {
        Err(ApiError::not_found("No such item."))
    }
}

/// The per-account (or per-key) limits of new addresses.
pub(crate) fn take_creation(state: &AppState, key: String) -> bool {
    state.limits.masked_minute.take(key.clone()) && state.limits.masked_day.take(key)
}

/// What a new address is made with.
pub(crate) struct NewAddress {
    pub for_domain: String,
    pub description: String,
    pub domain: Option<String>,
    pub prefix: Option<String>,
    pub url: Option<String>,
}

/// Make an address at UwUMail; the address as UwUMail's `MaskedEmail` (id, email, …).
pub(crate) async fn make(state: &AppState, user_id: &str, new: NewAddress) -> Result<Value, Refusal> {
    let connection = usable_connection(state, user_id).await?;
    let mut create = json!({
        "state": "enabled",
        "forDomain": new.for_domain,
        "description": new.description,
    });
    if let Some(domain) = new.domain {
        let domain = domain.trim().to_ascii_lowercase();
        if !connection.domains.contains(&domain) {
            return Err(Refusal::Invalid(format!("{domain} is not one of the domains this account may use.")));
        }
        create["domain"] = json!(domain);
    }
    if let Some(prefix) = new.prefix.filter(|prefix| !prefix.is_empty()) {
        create["emailPrefix"] = json!(prefix);
    }
    if let Some(url) = &new.url {
        create["url"] = json!(url);
    }
    let (_, answer) = jmap(state, user_id, "MaskedEmail/set", json!({ "create": { "k1": create } })).await?;
    if let Some(error) = answer["notCreated"].get("k1") {
        return Err(method_refusal(
            error["type"].as_str().unwrap_or("serverFail"),
            error["description"].as_str().unwrap_or_default(),
        ));
    }
    let created = answer["created"]["k1"].clone();
    if created["email"].as_str().is_none() {
        return Err(Refusal::Upstream("UwUMail made no address".into()));
    }
    let mut address = create;
    for (key, value) in created.as_object().cloned().unwrap_or_default() {
        address[key] = value;
    }
    address.as_object_mut().map(|object| object.remove("domain"));
    Ok(address)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateBody {
    #[serde(default)]
    for_domain: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    email_prefix: Option<String>,
    #[serde(default)]
    cipher_id: Option<String>,
}

async fn create(
    State(state): State<AppState>,
    session: Session,
    Json(body): Json<CreateBody>,
) -> ApiResult<Json<Value>> {
    check_on(&state)?;
    let user_id = &session.user.id;
    let cipher_id = body.cipher_id.filter(|id| !id.is_empty());
    if let Some(cipher_id) = &cipher_id {
        check_cipher(&state, user_id, cipher_id).await?;
        if state.store.masked_links(user_id).await?.iter().any(|link| &link.cipher_id == cipher_id) {
            return Err(ApiError::new(StatusCode::CONFLICT, "This item has a masked address already.").code("exists"));
        }
    }
    if !take_creation(&state, format!("user:{user_id}")) {
        return Err(Refusal::RateLimited.into());
    }
    let new = NewAddress {
        for_domain: clean_for_domain(body.for_domain.as_deref().unwrap_or_default()),
        description: clean_text(body.description.as_deref().unwrap_or_default()),
        domain: body.domain.filter(|domain| !domain.trim().is_empty()),
        prefix: body.email_prefix,
        url: cipher_id.as_ref().map(|id| item_url(&state, id)),
    };
    let address = make(&state, user_id, new).await?;
    let mut links = HashMap::new();
    if let Some(cipher_id) = cipher_id {
        let link = MaskedLink {
            masked_id: address["id"].as_str().unwrap_or_default().to_string(),
            cipher_id: cipher_id.clone(),
            email: address["email"].as_str().unwrap_or_default().to_string(),
            state: address["state"].as_str().map(str::to_string),
        };
        links.insert(link.masked_id.clone(), cipher_id);
        if state.store.link_masked(user_id, link).await?.is_err() {
            // Another address got linked in between; this one stays without a link.
            links.clear();
        }
    }
    Ok(Json(render(&address, &links)))
}

/// `Some(None)` for a key given as `null`, `None` for one left out.
fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeBody {
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    for_domain: Option<String>,
    #[serde(default, deserialize_with = "present")]
    cipher_id: Option<Option<String>>,
}

/// One address as UwUMail has it now.
async fn fetch(state: &AppState, user_id: &str, id: &str) -> Result<Value, Refusal> {
    let (_, answer) = jmap(state, user_id, "MaskedEmail/get", json!({ "ids": [id] })).await?;
    answer["list"].get(0).cloned().ok_or(Refusal::NotFound)
}

async fn update(state: &AppState, user_id: &str, id: &str, patch: Value) -> Result<(), Refusal> {
    let (_, answer) = jmap(state, user_id, "MaskedEmail/set", json!({ "update": { id: patch } })).await?;
    if let Some(error) = answer["notUpdated"].get(id) {
        return Err(method_refusal(
            error["type"].as_str().unwrap_or("serverFail"),
            error["description"].as_str().unwrap_or_default(),
        ));
    }
    Ok(())
}

async fn change(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(body): Json<ChangeBody>,
) -> ApiResult<Json<Value>> {
    check_on(&state)?;
    let user_id = &session.user.id;
    let mut patch = serde_json::Map::new();
    if let Some(new_state) = &body.state {
        if !matches!(new_state.as_str(), "enabled" | "disabled" | "deleted") {
            return Err(ApiError::bad("The state is enabled, disabled or deleted."));
        }
        patch.insert("state".into(), json!(new_state));
    }
    if let Some(description) = &body.description {
        patch.insert("description".into(), json!(clean_text(description)));
    }
    if let Some(for_domain) = &body.for_domain {
        patch.insert("forDomain".into(), json!(clean_for_domain(for_domain)));
    }
    let cipher = body.cipher_id.map(|cipher| cipher.filter(|id| !id.is_empty()));
    if let Some(cipher) = &cipher {
        if let Some(cipher_id) = cipher {
            check_cipher(&state, user_id, cipher_id).await?;
            let taken = state.store.masked_links(user_id).await?;
            if taken.iter().any(|link| &link.cipher_id == cipher_id && link.masked_id != id) {
                return Err(
                    ApiError::new(StatusCode::CONFLICT, "This item has a masked address already.").code("exists")
                );
            }
        }
        patch.insert("url".into(), json!(cipher.as_ref().map(|cipher_id| item_url(&state, cipher_id))));
    }
    if !patch.is_empty() {
        update(&state, user_id, &id, Value::Object(patch)).await?;
    }
    let address = fetch(&state, user_id, &id).await?;
    match cipher {
        Some(Some(cipher_id)) => {
            let link = MaskedLink {
                masked_id: id.clone(),
                cipher_id,
                email: address["email"].as_str().unwrap_or_default().to_string(),
                state: address["state"].as_str().map(str::to_string),
            };
            if state.store.link_masked(user_id, link).await?.is_err() {
                return Err(
                    ApiError::new(StatusCode::CONFLICT, "This item has a masked address already.").code("exists")
                );
            }
        }
        Some(None) => state.store.unlink_masked(user_id, &id).await?,
        None => {
            if let Some(new_state) = address["state"].as_str() {
                let states = BTreeMap::from([(id.clone(), new_state.to_string())]);
                state.store.masked_link_states(user_id, states).await?;
            }
        }
    }
    Ok(Json(render(&address, &link_map(&state, user_id).await?)))
}

async fn remove(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    check_on(&state)?;
    let user_id = &session.user.id;
    update(&state, user_id, &id, json!({ "state": "deleted" })).await?;
    let address = fetch(&state, user_id, &id).await?;
    state.store.masked_link_states(user_id, BTreeMap::from([(id.clone(), "deleted".to_string())])).await?;
    Ok(Json(render(&address, &link_map(&state, user_id).await?)))
}

/// The links of the account's addresses to its items, from this server alone: `{ cipherId: { id,
/// email, state } }`. The web vault shows them at the items without asking UwUMail.
async fn links(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let links = state.store.masked_links(&session.user.id).await?;
    let map: serde_json::Map<String, Value> = links
        .into_iter()
        .map(|link| (link.cipher_id, json!({ "id": link.masked_id, "email": link.email, "state": link.state })))
        .collect();
    Ok(Json(Value::Object(map)))
}

// ── Admin ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct CheckBody {
    #[serde(default)]
    url: String,
}

/// Whether a UwUMail server would do: its discovery, the `maskedemail` scope, registration.
async fn admin_check(_admin: Admin, Json(body): Json<CheckBody>) -> ApiResult<Json<Value>> {
    let server = crate::outbound::checked_url(&body.url, "UwUMail server").map_err(ApiError::bad)?;
    Ok(Json(uwumail::inspect(&server).await))
}

#[cfg(test)]
pub(crate) mod fake;
#[cfg(test)]
mod tests;
