//! The suite vault (docs/uwu-api.md §6): UwUSSH, UwURDP and the other UwU apps keep their
//! records here instead of on a UwUSync server, in UwUSync's record model — records sealed by the
//! apps with hybrid logical clocks, and optimistic concurrency by `baseSeq`. The records are not
//! Bitwarden ciphers and never show in `/api/sync`.
//!
//! A suite app logs in like a Bitwarden client with its own `client_id` and the scope
//! `uwu.suite`; its token opens its one space and nothing else ([`space_of_client`], and
//! [`crate::auth::AnySession`] where it is let in at all).

use crate::AppState;
use crate::auth::{AnySession, Session};
use crate::errors::{ApiError, ApiResult};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_notify::realtime::Live;
use uwulock_store::{PushRefusal, SpaceRefusal, SuiteQuota, SuiteRecord, SuiteSpace};

/// The scope of a suite app's token.
pub(crate) const SCOPE: &str = "uwu.suite";

/// Records in one push or pull, and the most one push may bring.
pub(crate) const MAX_RECORDS: usize = 500;
/// A push's body, and a page of a pull's sealed bytes.
pub(crate) const MAX_PUSH_BYTES: usize = 8 * 1024 * 1024;
/// The body of a push that carries that much: base64 inside JSON, with room to spare (as the
/// apps count a page).
pub(crate) const MAX_PUSH_BODY: usize = MAX_PUSH_BYTES * 2 + (1 << 20);
/// One record's sealed payload.
const MAX_BLOB: usize = 256 * 1024;
/// The record schema of UwUSync's protocol this speaks.
const SCHEMA: i64 = 2;

/// The space a suite app's `client_id` may touch (§6.5); none for any other client.
pub(crate) fn space_of_client(client_id: &str) -> Option<&'static str> {
    match client_id {
        "uwussh" => Some("ssh"),
        "uwurdp" => Some("rdp"),
        "uwumail" => Some("mail"),
        "uwusuite" => Some("generic"),
        _ => None,
    }
}

/// The spaces there are.
pub(crate) const SPACES: [&str; 4] = ["ssh", "rdp", "mail", "generic"];

/// The record kinds of a space (§6.1); none for a space there is not.
fn kinds(space: &str) -> Option<&'static [&'static str]> {
    const APPS: &[&str] = &[
        "host",
        "group",
        "identity",
        "key",
        "snippet",
        "port_forward",
        "known_host",
        "terminal_profile",
        "secret",
        "manifest",
    ];
    match space {
        "ssh" | "rdp" => Some(APPS),
        "mail" => Some(&["account", "secret", "manifest"]),
        "generic" => Some(&["item", "secret", "manifest"]),
        _ => None,
    }
}

/// What a suite app's token gets everywhere it may not go.
pub(crate) fn scope_error() -> ApiError {
    ApiError::forbidden("A suite app's login may only reach its own space.").code("scope")
}

fn feature_off() -> ApiError {
    ApiError::not_found("The suite vault is switched off on this server.").code("feature_off")
}

pub(crate) fn enabled(state: &AppState) -> ApiResult<()> {
    if state.feature(crate::Feature::Suite) { Ok(()) } else { Err(feature_off()) }
}

/// The space of the path, if the session may touch it: any for an account's own token, only
/// its own for a suite app's.
fn allowed(session: &Session, space: &str) -> ApiResult<&'static str> {
    let space = SPACES
        .into_iter()
        .find(|known| *known == space)
        .ok_or_else(|| ApiError::not_found("There is no such space.").code("not_found"))?;
    match session.space {
        Some(own) if own != space => Err(scope_error()),
        _ => Ok(space),
    }
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/suite/spaces", get(spaces))
        .route("/uwu/v1/suite/spaces/{space}", put(create).delete(remove))
        .route("/uwu/v1/suite/spaces/{space}/records", get(pull))
}

/// A push may bring 8 MiB; a new key every record of the space.
pub(crate) fn push_routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/suite/spaces/{space}/records", post(push))
}

pub(crate) fn rekey_routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/suite/spaces/{space}/rekey", post(rekey))
}

pub(crate) fn space_json(space: &SuiteSpace) -> Value {
    json!({
        "object": "suiteSpace",
        "space": space.space,
        "id": space.id,
        "key": space.key,
        "records": space.records,
        "bytes": space.bytes,
        "creationDate": space.created,
        "revisionDate": space.revision,
    })
}

/// An envelope as the apps read it (§6.3).
pub(crate) fn record_json(record: &SuiteRecord) -> Value {
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    json!({
        "id": record.id,
        "kind": record.kind,
        "updatedAt": { "wallMs": record.wall_ms, "counter": record.counter, "device": record.device },
        // What an app would base its next write of it on.
        "baseSeq": record.seq,
        "deleted": record.deleted,
        "nonce": b64(&record.nonce),
        "blob": b64(&record.blob),
        "seq": record.seq,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Clock {
    wall_ms: u64,
    counter: u32,
    device: u32,
}

/// An envelope as the apps send it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    id: String,
    kind: String,
    updated_at: Clock,
    #[serde(default)]
    base_seq: i64,
    #[serde(default)]
    deleted: bool,
    nonce: String,
    blob: String,
}

/// Base64 as the apps write it: standard, and URL-safe or unpadded taken too.
fn decode(text: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let text = text.trim();
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD].iter().find_map(|engine| engine.decode(text).ok())
}

/// A UUID as this server writes them: lower case, with hyphens.
fn uuid(text: &str) -> Option<String> {
    uuid::Uuid::parse_str(text.trim()).ok().map(|id| id.hyphenated().to_string())
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::bad(message).code("invalid")
}

fn read(space: &str, envelope: Envelope) -> ApiResult<SuiteRecord> {
    let id = uuid(&envelope.id).ok_or_else(|| invalid("A record's id is a UUID."))?;
    if !kinds(space).is_some_and(|kinds| kinds.contains(&envelope.kind.as_str())) {
        return Err(invalid(format!("There are no records of the kind “{}” in this space.", envelope.kind)));
    }
    let nonce = decode(&envelope.nonce).filter(|nonce| nonce.len() == 24);
    let nonce = nonce.ok_or_else(|| invalid("A record's nonce is 24 bytes in base64."))?;
    let blob = decode(&envelope.blob).ok_or_else(|| invalid("A record's blob is base64."))?;
    if blob.len() > MAX_BLOB {
        return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "A record is at most 256 KiB.").code("too_large"));
    }
    if envelope.base_seq < 0 {
        return Err(invalid("baseSeq is not negative."));
    }
    Ok(SuiteRecord {
        id,
        space: space.to_string(),
        kind: envelope.kind,
        wall_ms: envelope.updated_at.wall_ms,
        counter: envelope.updated_at.counter,
        device: envelope.updated_at.device,
        deleted: envelope.deleted,
        nonce,
        blob,
        base_seq: envelope.base_seq,
        seq: 0,
    })
}

async fn spaces(State(state): State<AppState>, AnySession(session): AnySession) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let data: Vec<Value> = state
        .store
        .suite_spaces(&session.user.id)
        .await?
        .iter()
        .filter(|space| session.space.is_none_or(|own| own == space.space))
        .map(space_json)
        .collect();
    Ok(Json(json!({ "object": "list", "data": data, "continuationToken": null })))
}

#[derive(Deserialize)]
struct NewSpace {
    id: String,
    key: String,
}

fn check_key(key: &str) -> ApiResult<()> {
    if crate::keys::enc_string(key, 2, 1000) {
        Ok(())
    } else {
        Err(invalid("The space key is an EncString of type 2 under the extras key."))
    }
}

async fn create(
    State(state): State<AppState>,
    AnySession(session): AnySession,
    Path(space): Path<String>,
    Json(body): Json<NewSpace>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let space = allowed(&session, &space)?;
    let id = uuid(&body.id).ok_or_else(|| invalid("A space's id is a UUID."))?;
    check_key(&body.key)?;
    match state.store.create_suite_space(&session.user.id, space, &id, &body.key).await? {
        Ok(made) => {
            crate::notify::live(&state, &session.user.id, Some(&session), Live::suite(space));
            Ok(Json(space_json(&made)))
        }
        Err(SpaceRefusal::Exists) => {
            Err(ApiError::new(StatusCode::CONFLICT, "The account has this space already.").code("exists"))
        }
        Err(_) => Err(ApiError::new(StatusCode::CONFLICT, "That id is taken.").code("exists")),
    }
}

/// Only with the master password, and never by a suite app itself.
async fn remove(
    State(state): State<AppState>,
    session: Session,
    Path(space): Path<String>,
    Json(secret): Json<crate::two_factor::Secret>,
) -> ApiResult<StatusCode> {
    enabled(&state)?;
    let space = allowed(&session, &space)?;
    crate::accounts::check_password(&state, &session.user, secret.master_password_hash.as_deref()).await?;
    if !state.store.delete_suite_space(&session.user.id, space).await? {
        return Err(ApiError::not_found("The account has no such space."));
    }
    crate::notify::live(&state, &session.user.id, Some(&session), Live::suite(space));
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Rekey {
    id: String,
    key: String,
    #[serde(default)]
    records: Vec<Envelope>,
}

async fn rekey(
    State(state): State<AppState>,
    AnySession(session): AnySession,
    Path(space): Path<String>,
    Json(body): Json<Rekey>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let space = allowed(&session, &space)?;
    let id = uuid(&body.id).ok_or_else(|| invalid("A space's id is a UUID."))?;
    check_key(&body.key)?;
    let records = body.records.into_iter().map(|envelope| read(space, envelope)).collect::<ApiResult<Vec<_>>>()?;
    match state.store.rekey_suite_space(&session.user.id, space, &id, &body.key, records).await? {
        Ok(space_now) => {
            crate::notify::live(&state, &session.user.id, Some(&session), Live::suite(space));
            Ok(Json(space_json(&space_now)))
        }
        Err(SpaceRefusal::Missing) => Err(ApiError::not_found("The account has no such space.")),
        Err(SpaceRefusal::IdTaken) => Err(ApiError::new(StatusCode::CONFLICT, "That id is taken.").code("exists")),
        Err(_) => Err(ApiError::new(
            StatusCode::CONFLICT,
            "Every record has to come along, each as it is on the server now. Pull and try again.",
        )
        .code("conflict")),
    }
}

#[derive(Deserialize)]
struct PullQuery {
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    limit: Option<String>,
}

async fn pull(
    State(state): State<AppState>,
    AnySession(session): AnySession,
    Path(space): Path<String>,
    Query(query): Query<PullQuery>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let space = allowed(&session, &space)?;
    let since = match query.since.as_deref().map(str::trim).filter(|since| !since.is_empty()) {
        None => 0,
        Some(text) => {
            text.parse::<i64>().ok().filter(|since| *since >= 0).ok_or_else(|| invalid("since is a number."))?
        }
    };
    let limit = match query.limit.as_deref().map(str::trim).filter(|limit| !limit.is_empty()) {
        None => MAX_RECORDS,
        Some(text) => text.parse::<usize>().map_err(|_| invalid("limit is a number."))?.clamp(1, MAX_RECORDS),
    };
    let Some(page) = state.store.suite_pull(&session.user.id, space, since, limit, MAX_PUSH_BYTES).await? else {
        return Err(ApiError::not_found("The account has no such space."));
    };
    Ok(Json(json!({
        "object": "suitePull",
        "reset": page.reset,
        "records": page.records.iter().map(record_json).collect::<Vec<_>>(),
        "cursor": page.cursor,
        "hasMore": page.has_more,
    })))
}

#[derive(Deserialize)]
struct Push {
    #[serde(default)]
    schema: Option<i64>,
    #[serde(default)]
    records: Vec<Envelope>,
}

async fn push(
    State(state): State<AppState>,
    AnySession(session): AnySession,
    Path(space): Path<String>,
    Json(body): Json<Push>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let space = allowed(&session, &space)?;
    if body.schema != Some(SCHEMA) {
        return Err(ApiError::bad("This server speaks record schema 2.").code("schema"));
    }
    if body.records.len() > MAX_RECORDS {
        return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "At most 500 records at once.").code("too_large"));
    }
    let records = body.records.into_iter().map(|envelope| read(space, envelope)).collect::<ApiResult<Vec<_>>>()?;
    if records.iter().map(|record| record.blob.len()).sum::<usize>() > MAX_PUSH_BYTES {
        return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "At most 8 MiB of records at once.").code("too_large"));
    }
    let settings = state.settings().suite;
    let quota =
        SuiteQuota { records: i64::from(settings.max_records), bytes: i64::from(settings.max_mb) * 1024 * 1024 };
    // The account's storage limit counts the suite too.
    if let Some(limit) = state.settings().storage_limit() {
        let incoming: usize = records.iter().map(|record| record.blob.len() + record.nonce.len()).sum();
        if state.store.storage_used(&session.user.id).await? + incoming as i64 > limit {
            return Err(quota_error());
        }
    }
    let answer = match state.store.suite_push(&session.user.id, space, records, quota).await? {
        Ok(answer) => answer,
        Err(PushRefusal::NoSpace) => return Err(ApiError::not_found("The account has no such space.")),
        Err(PushRefusal::Exists) => {
            return Err(
                ApiError::new(StatusCode::CONFLICT, "A record with that id belongs to another space.").code("exists")
            );
        }
        Err(PushRefusal::Quota) => return Err(quota_error()),
    };
    if !answer.accepted.is_empty() {
        crate::notify::live(&state, &session.user.id, Some(&session), Live::suite(space));
    }
    Ok(Json(json!({
        "object": "suitePush",
        "accepted": answer.accepted.iter().map(|(id, seq)| json!({ "id": id, "seq": seq })).collect::<Vec<_>>(),
        "conflicts": answer.conflicts.iter().map(record_json).collect::<Vec<_>>(),
        "cursor": answer.cursor,
    })))
}

fn quota_error() -> ApiError {
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "The suite vault of this account is full.").code("quota")
}

#[cfg(test)]
mod tests;
