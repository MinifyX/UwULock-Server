//! Masked addresses for the official Bitwarden clients (docs/uwu-api.md §13.4–§13.6): their
//! generator's "forwarded email alias" speaks addy.io's and SimpleLogin's APIs, pointed at a
//! self-hosted address — this server — with a key made in the web vault. The keys work here and
//! nowhere else, never as a login.
//!
//! Errors are `{ "error", "message" }` (the web clients show `error: message`), never a redirect.

use super::{NewAddress, Refusal, make, take_creation};
use crate::AppState;
use crate::accounts::check_password;
use crate::auth::{self, ClientIp, Session};
use crate::errors::{ApiError, ApiResult};
use crate::notices::{self, Context};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_store::masked::MaskedApiKey;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/masked/api-keys", get(keys).post(new_key))
        .route("/uwu/v1/masked/api-keys/{id}", delete(delete_key))
        // The clients put `/api/…` behind whatever base was typed, so a trailing slash there
        // makes a double one: both are taken.
        .route("/uwu/v1/masked/addy/{*rest}", post(addy))
        .route("/uwu/v1/masked/simplelogin/{*rest}", post(simplelogin))
}

/// Keys one account may have.
const MOST_KEYS: i64 = 10;
const KEY_PREFIX: &str = "uwulock_ma_";

// ── Keys ──────────────────────────────────────────────────

fn render_key(key: &MaskedApiKey) -> Value {
    json!({
        "object": "maskedApiKey",
        "id": key.id,
        "name": key.name,
        "hint": format!("…{}", key.hint),
        "creationDate": key.created,
        "lastUsedDate": key.last_used,
    })
}

async fn keys(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let keys = state.store.masked_api_keys(&session.user.id).await?;
    Ok(Json(
        json!({ "object": "list", "data": keys.iter().map(render_key).collect::<Vec<_>>(), "continuationToken": null }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewKey {
    #[serde(default)]
    name: String,
    #[serde(default)]
    master_password_hash: Option<String>,
}

async fn new_key(
    State(state): State<AppState>,
    session: Session,
    ClientIp(ip): ClientIp,
    Json(body): Json<NewKey>,
) -> ApiResult<Json<Value>> {
    check_password(&state, &session.user, body.master_password_hash.as_deref()).await?;
    let name: String = body.name.trim().chars().filter(|c| !c.is_control()).take(60).collect();
    if name.is_empty() {
        return Err(ApiError::bad("Give the key a name, like the browser it is for."));
    }
    let id = uuid::Uuid::new_v4();
    let secret = auth::random_token(32);
    let key = format!("{KEY_PREFIX}{}_{secret}", URL_SAFE_NO_PAD.encode(id.as_bytes()));
    let stored = MaskedApiKey {
        id: id.to_string(),
        user_id: session.user.id.clone(),
        name: name.clone(),
        hash: auth::sha256(secret.as_bytes()),
        hint: key[key.len() - 4..].to_string(),
        created: uwulock_store::clock::now(),
        last_used: None,
    };
    if !state.store.add_masked_api_key(stored.clone(), MOST_KEYS).await? {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("An account can have {MOST_KEYS} keys for masked addresses; delete one first."),
        )
        .code("quota"));
    }
    let context = Context::of(&state, &session, ip).await;
    notices::record(&state, &session.user, "maskedApiKeyCreated", &context, json!({ "name": name })).await;
    let mut body = render_key(&stored);
    body["key"] = json!(key);
    Ok(Json(body))
}

async fn delete_key(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<StatusCode> {
    if !state.store.delete_masked_api_key(&session.user.id, &id).await? {
        return Err(ApiError::not_found("No such key."));
    }
    Ok(StatusCode::OK)
}

// ── The endpoints the official clients call ───────────────

/// An answer the way both services' clients read it.
fn refuse(status: StatusCode, error: &'static str, message: &str) -> Refused {
    Refused { status, error, message: message.to_string() }
}

/// A refusal of these endpoints: `{ "error", "message" }` with its status.
struct Refused {
    status: StatusCode,
    error: &'static str,
    message: String,
}

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.error, "message": self.message }))).into_response()
    }
}

fn refusal(refusal: Refusal) -> Refused {
    const CONNECT: &str = "Connect UwUMail in the web vault under Settings → Masked addresses.";
    match refusal {
        Refusal::NotConnected => refuse(StatusCode::FORBIDDEN, "not_connected", CONNECT),
        Refusal::Revoked => refuse(
            StatusCode::FORBIDDEN,
            "revoked",
            "UwUMail ended the connection. Connect again in the web vault under Settings → Masked addresses.",
        ),
        Refusal::NotAllowed => refuse(
            StatusCode::FORBIDDEN,
            "server_not_allowed",
            "This server may not talk to the UwUMail server of the connection any more. Ask the admin.",
        ),
        Refusal::Forbidden(text) | Refusal::Quota(text) | Refusal::Invalid(text) => {
            refuse(StatusCode::FORBIDDEN, "forbidden", &format!("UwUMail refused it: {text}"))
        }
        Refusal::RateLimited => {
            refuse(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Too many masked addresses at once. Wait a minute.")
        }
        Refusal::Upstream(text) => {
            refuse(StatusCode::BAD_GATEWAY, "upstream", &format!("UwUMail does not answer: {text}"))
        }
        Refusal::NotFound => refuse(StatusCode::BAD_GATEWAY, "upstream", "UwUMail lost the new address."),
        Refusal::Store(error) => {
            tracing::error!(%error, "a masked address for an official client failed");
            refuse(StatusCode::INTERNAL_SERVER_ERROR, "error", "Something went wrong on the server.")
        }
    }
}

/// The key a request carries: addy.io's `Authorization: Bearer`, SimpleLogin's bare
/// `Authentication` — either on both paths.
fn presented(headers: &HeaderMap) -> Option<&str> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer ")));
    bearer
        .or_else(|| headers.get("authentication").and_then(|value| value.to_str().ok()))
        .map(str::trim)
        .filter(|key| !key.is_empty())
}

/// The account of a valid key; the key's id too, for its limits.
async fn key_owner(state: &AppState, ip: std::net::IpAddr, headers: &HeaderMap) -> Result<(String, String), Refused> {
    let unauthorized =
        || refuse(StatusCode::UNAUTHORIZED, "unauthorized", "The API key is not valid. Make one in the web vault.");
    // Wrong keys count like wrong logins, per address.
    let network = crate::limits::network_of(ip);
    if !state.limits.login.allows(&network) {
        return Err(refuse(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Too many wrong keys. Wait a few minutes."));
    }
    let wrong = || {
        state.limits.login.take(network);
        unauthorized()
    };
    let Some(key) = presented(headers) else { return Err(unauthorized()) };
    let Some(rest) = key.strip_prefix(KEY_PREFIX) else { return Err(wrong()) };
    // The id is 22 characters of base64url, which may hold `_` too; then `_` and the secret.
    let (Some(id_part), Some(secret)) = (rest.get(..22), rest.get(22..).and_then(|rest| rest.strip_prefix('_'))) else {
        return Err(wrong());
    };
    let Some(id) = URL_SAFE_NO_PAD
        .decode(id_part)
        .ok()
        .and_then(|bytes| uuid::Uuid::from_slice(&bytes).ok())
        .map(|id| id.to_string())
    else {
        return Err(wrong());
    };
    let stored = match state.store.masked_api_key(&id).await {
        Ok(stored) => stored,
        Err(error) => return Err(refusal(Refusal::Store(error))),
    };
    let Some(stored) = stored.filter(|stored| auth::constant_time_eq(&auth::sha256(secret.as_bytes()), &stored.hash))
    else {
        return Err(wrong());
    };
    let _ = state.store.masked_api_key_used(&stored.id).await;
    Ok((stored.user_id, stored.id))
}

/// Everything but the address itself: the key, the switch, the connection, the limits.
async fn prepare(
    state: &AppState,
    ip: std::net::IpAddr,
    headers: &HeaderMap,
) -> Result<(String, Vec<String>, Option<String>), Refused> {
    if state.settings().masked.servers.is_empty() {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "feature_off",
            "Masked addresses are not switched on on this server.",
        ));
    }
    let (user_id, key_id) = key_owner(state, ip, headers).await?;
    let connection = super::usable_connection(state, &user_id).await.map_err(refusal)?;
    if !take_creation(state, format!("key:{key_id}")) {
        return Err(refusal(Refusal::RateLimited));
    }
    Ok((user_id, connection.domains, connection.default_domain))
}

/// The first host name in `text`: after `Website: ` up to `. ` if that is there, else the first
/// word that is one; the host of a URL. Lower case.
pub(crate) fn host_in(text: &str) -> Option<String> {
    let text = text.trim();
    let candidate = text.split_once("Website: ").map(|(_, rest)| rest.split(". ").next().unwrap_or(rest));
    let from = |candidate: &str| {
        candidate.split_whitespace().find_map(|word| {
            let word = word.trim_matches(|c: char| matches!(c, '.' | ',' | ';' | ':' | '(' | ')' | '"' | '\''));
            let without_scheme = word.split_once("://").map_or(word, |(_, rest)| rest);
            let host = without_scheme.split(['/', '?', '#', ':', '&']).next().unwrap_or_default().to_ascii_lowercase();
            is_host(&host).then_some(host)
        })
    };
    candidate.and_then(from).or_else(|| from(text))
}

/// `[a-z0-9-]+(\.[a-z0-9-]+)+`.
fn is_host(text: &str) -> bool {
    let labels: Vec<&str> = text.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

fn cut(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(super::TEXT_CHARS).collect()
}

fn body_json(body: &Bytes) -> Value {
    serde_json::from_slice(body).unwrap_or(Value::Null)
}

/// The path after the service's base, without the slashes the clients doubled.
fn rest_is(rest: &str, wanted: &str) -> bool {
    rest.trim_start_matches('/') == wanted
}

/// addy.io: `POST <base>/api/v1/aliases` with `{ domain, description }`.
async fn addy(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(rest): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !rest_is(&rest, "api/v1/aliases") {
        return refuse(StatusCode::NOT_FOUND, "not_found", "Only POST /api/v1/aliases is here.").into_response();
    }
    let (user_id, domains, default_domain) = match prepare(&state, ip, &headers).await {
        Ok(prepared) => prepared,
        Err(refused) => return refused.into_response(),
    };
    let body = body_json(&body);
    let description = cut(body["description"].as_str().unwrap_or_default());
    // Any domain the connection has, else UwUMail's default: people type something into the
    // clients' required field.
    let typed = body["domain"].as_str().unwrap_or_default().trim().to_ascii_lowercase();
    let domain = domains.iter().find(|domain| **domain == typed).cloned();
    let new = NewAddress {
        for_domain: host_in(&description).map(|host| format!("https://{host}")).unwrap_or_default(),
        description: description.clone(),
        domain,
        prefix: None,
        url: None,
    };
    let address = match make(&state, &user_id, new).await {
        Ok(address) => address,
        Err(error) => return refusal(error).into_response(),
    };
    let email = address["email"].as_str().unwrap_or_default();
    let (local, domain) = email.rsplit_once('@').unwrap_or((email, default_domain.as_deref().unwrap_or_default()));
    let when = addy_time(address["createdAt"].as_str());
    let data = json!({
        "id": address["id"],
        "user_id": user_id,
        "local_part": local,
        "domain": domain,
        "email": email,
        "active": address["state"] == "enabled",
        "description": description,
        "created_at": when,
        "updated_at": when,
    });
    (StatusCode::CREATED, Json(json!({ "data": data }))).into_response()
}

/// `2026-09-28 12:00:00`, the way addy.io writes times.
fn addy_time(created: Option<&str>) -> String {
    let when = created.and_then(uwulock_store::clock::parse).unwrap_or_else(time::OffsetDateTime::now_utc);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        when.year(),
        u8::from(when.month()),
        when.day(),
        when.hour(),
        when.minute(),
        when.second()
    )
}

/// The `hostname` of SimpleLogin's query, as the clients send it: not URL-encoded, maybe a whole
/// URL (the SDK).
fn hostname_in(uri: &Uri) -> Option<String> {
    let query = uri.query()?;
    let start = query.find("hostname=")? + "hostname=".len();
    let value = &query[start..];
    let decoded = percent_decode(value);
    host_in(&decoded)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let Some(byte) = text.get(index + 1..index + 3).and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            out.push(byte);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// SimpleLogin: `POST <base>/api/alias/random/new?hostname=…` with `{ note }`.
async fn simplelogin(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(rest): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !rest_is(&rest, "api/alias/random/new") {
        return refuse(StatusCode::NOT_FOUND, "not_found", "Only POST /api/alias/random/new is here.").into_response();
    }
    let (user_id, _, _) = match prepare(&state, ip, &headers).await {
        Ok(prepared) => prepared,
        Err(refused) => return refused.into_response(),
    };
    let note = cut(body_json(&body)["note"].as_str().unwrap_or_default());
    let host = hostname_in(&uri).or_else(|| host_in(&note));
    let new = NewAddress {
        for_domain: host.map(|host| format!("https://{host}")).unwrap_or_default(),
        description: note.clone(),
        domain: None,
        prefix: None,
        url: None,
    };
    let address = match make(&state, &user_id, new).await {
        Ok(address) => address,
        Err(error) => return refusal(error).into_response(),
    };
    let created = address["createdAt"]
        .as_str()
        .and_then(uwulock_store::clock::parse)
        .map_or_else(auth::now_seconds, |when| when.unix_timestamp());
    (
        StatusCode::CREATED,
        Json(json!({
            "alias": address["email"],
            "email": address["email"],
            "enabled": address["state"] == "enabled",
            "note": note,
            "creation_timestamp": created,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_site_from_what_the_clients_write() {
        let host = |text: &str| host_in(text);
        assert_eq!(host("Website: shop.example.com. Generated by Bitwarden.").as_deref(), Some("shop.example.com"));
        assert_eq!(
            host("Website: https://shop.example.com/login. Generated by Bitwarden.").as_deref(),
            Some("shop.example.com")
        );
        assert_eq!(host("Webseite: shop.example.org. Erstellt von Bitwarden.").as_deref(), Some("shop.example.org"));
        assert_eq!(host("Generated by Bitwarden."), None);
        assert_eq!(host(""), None);
        let uri: Uri = "/x?hostname=https://Shop.Example.com/login?next=/a&b=c".parse().unwrap();
        assert_eq!(hostname_in(&uri).as_deref(), Some("shop.example.com"));
        let uri: Uri = "/x?hostname=shop.example.net".parse().unwrap();
        assert_eq!(hostname_in(&uri).as_deref(), Some("shop.example.net"));
        assert_eq!(addy_time(Some("2026-09-28T12:00:00.000000Z")), "2026-09-28 12:00:00");
    }
}
