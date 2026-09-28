//! Sends: a text or a file behind a link, for somebody without an account.
//!
//! The owner's client encrypts the Send with a key of its own and puts that key in the link, so
//! the server never can read it. Whoever has the link asks the server for the Send by its
//! access id — the Send's id, as base64url — and, if it has a password, proves it with a hash of
//! it. The newest clients do that through the identity endpoint first (`send_access`), which
//! answers with a short-lived token for the Send; older ones send the hash along each time.

use crate::auth::{ClientIp, Session};
use crate::errors::{ApiError, ApiResult};
use crate::files::{self, LINK_SECONDS};
use crate::{AppState, auth, json as out, notify};
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use uwulock_notify::Kind;
use uwulock_store::clock;
use uwulock_store::sends::{FILE, Send, TEXT};

/// A Send is deleted at the latest this long after it was saved, like at Bitwarden.
const MAX_DAYS: i64 = 31;

const GONE: &str = "Send does not exist or is no longer available";

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/sends", get(list).post(create))
        .route("/api/sends/file/v2", post(create_file))
        .route("/api/sends/file", post(legacy_file))
        .route("/api/sends/{id}", get(one).put(update).delete(delete))
        .route("/api/sends/{id}/remove-password", put(remove_password))
        .route("/api/sends/{id}/file/{file}", get(renew))
        .route("/api/sends/access", post(access))
        .route("/api/sends/access/{access_id}", post(access_legacy))
        .route("/api/sends/access/file/{file}", post(access_file))
        .route("/api/sends/{id}/access/file/{file}", post(access_file_legacy))
        .route("/api/sends/{id}/{file}", get(download))
}

/// The upload of a Send's file: no body limit but the one for files, no time limit but the
/// connection's.
pub(crate) fn upload_routes() -> Router<AppState> {
    Router::new().route("/api/sends/{id}/file/{file}", post(upload))
}

/// The access id in a Send's link: its id's 16 bytes, base64url.
pub(crate) fn access_id(id: &str) -> String {
    uuid::Uuid::parse_str(id).map(|uuid| URL_SAFE_NO_PAD.encode(uuid.as_bytes())).unwrap_or_default()
}

/// The Send an access id names. Bitwarden's server writes the id's bytes the way .NET orders
/// them, Vaultwarden (and this server) the way they are written: both are tried.
fn ids_for(access_id: &str) -> Vec<String> {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(access_id.trim_end_matches('=')) else { return Vec::new() };
    let Ok(bytes) = <[u8; 16]>::try_from(bytes.as_slice()) else { return Vec::new() };
    let plain = uuid::Uuid::from_bytes(bytes);
    let dotnet = uuid::Uuid::from_bytes_le(bytes);
    let mut ids = vec![plain.to_string()];
    if dotnet != plain {
        ids.push(dotnet.to_string());
    }
    ids
}

async fn by_access_id(state: &AppState, access_id: &str) -> ApiResult<Send> {
    for id in ids_for(access_id) {
        if let Some(send) = state.store.send_by_id(&id).await? {
            return Ok(send);
        }
    }
    Err(ApiError::not_found(GONE))
}

/// The Send's text or file object, with the size as a string: the phone apps read it as one.
fn data(send: &Send) -> Value {
    let mut data: Value = serde_json::from_str(&send.data).unwrap_or_else(|_| json!({}));
    if let Some(size) = data.get("size").and_then(Value::as_i64) {
        data["size"] = Value::String(size.to_string());
    }
    data
}

/// A Send, as its owner's clients read it.
pub(crate) fn render(send: &Send) -> Value {
    let data = data(send);
    json!({
        "id": send.id,
        "accessId": access_id(&send.id),
        "type": send.kind,
        "name": send.name,
        "notes": send.notes,
        "text": if send.kind == TEXT { data.clone() } else { Value::Null },
        "file": if send.kind == FILE { data } else { Value::Null },
        "key": send.key,
        "maxAccessCount": send.max_access_count,
        "accessCount": send.access_count,
        // Only whether there is one matters to the clients; the hash stays here.
        "password": send.password_hash.as_ref().map(|_| "set"),
        "authType": if send.password_hash.is_some() { 1 } else { 2 },
        "emails": null,
        "disabled": send.disabled,
        "hideEmail": send.hide_email,
        "revisionDate": send.revision,
        "expirationDate": send.expiration,
        "deletionDate": send.deletion,
        "object": "send",
    })
}

/// A Send, as somebody with the link sees it.
async fn render_access(state: &AppState, send: &Send) -> ApiResult<Value> {
    let data = data(send);
    let creator = if send.hide_email { None } else { state.store.user(&send.user_id).await?.map(|user| user.email) };
    Ok(json!({
        "id": send.id,
        "type": send.kind,
        "name": send.name,
        "text": if send.kind == TEXT { data.clone() } else { Value::Null },
        "file": if send.kind == FILE { data } else { Value::Null },
        "expirationDate": send.expiration,
        "creatorIdentifier": creator,
        "object": "send-access",
    }))
}

fn number_or_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<i64>, D::Error> {
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Number(number)) => number.as_i64(),
        Some(Value::String(text)) => text.trim().parse().ok(),
        _ => None,
    })
}

/// A Send as the clients send it: new, changed, or in a key rotation.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SendData {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "type")]
    kind: i64,
    key: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default, deserialize_with = "number_or_string")]
    max_access_count: Option<i64>,
    #[serde(default)]
    expiration_date: Option<String>,
    deletion_date: String,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    hide_email: Option<bool>,
    #[serde(default)]
    emails: Option<String>,
    name: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    text: Option<Value>,
    #[serde(default)]
    file: Option<Value>,
    #[serde(default, deserialize_with = "number_or_string")]
    file_length: Option<i64>,
}

/// Only these keys of the text or file object are kept.
fn tidy(value: Option<Value>, keys: &[&str]) -> ApiResult<String> {
    let Some(Value::Object(map)) = value else { return Err(ApiError::bad("Send data not provided")) };
    let kept: serde_json::Map<String, Value> = map
        .into_iter()
        .filter_map(|(key, value)| {
            let mut chars = key.chars();
            let lower: String = chars.next()?.to_lowercase().chain(chars).collect();
            keys.contains(&lower.as_str()).then_some((lower, value))
        })
        .collect();
    Ok(Value::Object(kept).to_string())
}

/// `data` over `into`: everything a Send is, except its id, owner, file and counts. The
/// password is hashed here; none given keeps the one there is.
pub(crate) async fn apply(state: &AppState, data: SendData, mut into: Send) -> ApiResult<Send> {
    if data.emails.is_some() {
        return Err(ApiError::bad("Sends that ask for a code by mail are not available on this server."));
    }
    if into.kind != data.kind {
        return Err(ApiError::bad("Sends can't change type"));
    }
    let deletion = clock::parse(&data.deletion_date).ok_or_else(|| ApiError::bad("Invalid deletion date"))?;
    if clock::format(deletion) > clock::in_seconds(MAX_DAYS * 86_400) {
        return Err(ApiError::bad(
            "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.",
        ));
    }
    if [Some(&data.name), data.notes.as_ref(), Some(&data.key)]
        .into_iter()
        .flatten()
        .any(|text| text.len() > out::MAX_NOTE)
    {
        return Err(ApiError::bad("The Send is too large."));
    }
    if data.max_access_count.is_some_and(|count| count < 0) {
        return Err(ApiError::bad("The maximum access count can't be negative."));
    }
    if data.kind == TEXT {
        into.data = tidy(data.text, &["text", "hidden"])?;
        if into.data.len() > out::MAX_NOTE * 2 {
            return Err(ApiError::bad("The Send is too large."));
        }
    }
    into.name = data.name;
    into.notes = data.notes.filter(|notes| !notes.is_empty());
    into.key = data.key;
    into.max_access_count = data.max_access_count;
    into.expiration = data.expiration_date.as_deref().and_then(clock::parse).map(clock::format);
    into.deletion = clock::format(deletion);
    into.disabled = data.disabled;
    into.hide_email = data.hide_email.unwrap_or(false);
    if let Some(password) = data.password.filter(|password| !password.is_empty()) {
        into.password_hash = Some(auth::hash_password(state.config.hash_cost, &password).await?);
    }
    Ok(into)
}

fn new_send(user_id: &str, kind: i64) -> Send {
    let now = clock::now();
    Send {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        kind,
        name: String::new(),
        notes: None,
        data: "{}".into(),
        key: String::new(),
        password_hash: None,
        max_access_count: None,
        access_count: 0,
        created: now.clone(),
        revision: now,
        expiration: None,
        deletion: String::new(),
        disabled: false,
        hide_email: false,
        uploaded: false,
    }
}

async fn save(state: &AppState, send: Send) -> ApiResult<Send> {
    state.store.save_send(send).await?.ok_or_else(|| ApiError::bad("Send not found"))
}

async fn own(state: &AppState, session: &Session, id: &str) -> ApiResult<Send> {
    state.store.send(&session.user.id, id).await?.ok_or_else(|| ApiError::bad("Send not found"))
}

async fn list(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let sends = state.store.sends(&session.user.id).await?;
    Ok(Json(out::list(sends.iter().map(render).collect())))
}

async fn one(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    Ok(Json(render(&own(&state, &session, &id).await?)))
}

async fn create(State(state): State<AppState>, session: Session, Json(data): Json<SendData>) -> ApiResult<Json<Value>> {
    if data.kind != TEXT {
        return Err(ApiError::bad("File Sends go through /sends/file/v2."));
    }
    let send = save(&state, apply(&state, data, new_send(&session.user.id, TEXT)).await?).await?;
    notify::send(&state, &session.user.id, Some(&session), Kind::SendCreate, &send.id, &send.revision);
    Ok(Json(render(&send)))
}

async fn legacy_file() -> ApiError {
    ApiError::bad("This client is too old for file Sends. Update it and try again.")
}

/// A file Send, announced: what it is called and how large it is. Where to upload it comes back.
async fn create_file(
    State(state): State<AppState>,
    session: Session,
    Json(mut data): Json<SendData>,
) -> ApiResult<Json<Value>> {
    if data.kind != FILE {
        return Err(ApiError::bad("Send content is not a file"));
    }
    let size = data.file_length.ok_or_else(|| ApiError::bad("Invalid send length"))?;
    if size < 0 {
        return Err(ApiError::bad("Send size can't be negative"));
    }
    let limit = files::limit(&state);
    if size as u64 > limit {
        return Err(files::too_large(limit));
    }
    let file_name = data
        .file
        .take()
        .and_then(|file| {
            file.get("fileName").or_else(|| file.get("FileName")).and_then(Value::as_str).map(str::to_string)
        })
        .ok_or_else(|| ApiError::bad("Send data not provided"))?;
    if file_name.len() > out::MAX_NOTE {
        return Err(ApiError::bad("The file name is too long."));
    }
    let mut send = apply(&state, data, new_send(&session.user.id, FILE)).await?;
    let file_id = files::new_file_id();
    send.data =
        json!({ "id": file_id, "fileName": file_name, "size": size, "sizeName": files::size_name(size) }).to_string();
    let send = save(&state, send).await?;
    Ok(Json(upload_answer(&send, &file_id)))
}

fn upload_answer(send: &Send, file_id: &str) -> Value {
    json!({
        "fileUploadType": 0,
        // Relative to the API, as Bitwarden's server answers for uploads it takes itself.
        "url": format!("/sends/{}/file/{file_id}", send.id),
        "sendResponse": render(send),
        "object": "send-fileUpload",
    })
}

fn file_of(send: &Send) -> Option<(String, i64)> {
    let data: Value = serde_json::from_str(&send.data).ok()?;
    Some((data.get("id")?.as_str()?.to_string(), data.get("size")?.as_i64()?))
}

/// Where to upload the file, asked again after the first try failed.
async fn renew(
    State(state): State<AppState>,
    session: Session,
    Path((id, file)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let send = own(&state, &session, &id).await?;
    if send.kind != FILE || send.uploaded || file_of(&send).is_none_or(|(expected, _)| expected != file) {
        return Err(ApiError::bad("Send not found"));
    }
    Ok(Json(upload_answer(&send, &file)))
}

async fn upload(
    State(state): State<AppState>,
    session: Session,
    Path((id, file)): Path<(String, String)>,
    form: Multipart,
) -> ApiResult<StatusCode> {
    let send = own(&state, &session, &id).await?;
    let Some((expected, size)) = file_of(&send).filter(|_| send.kind == FILE) else {
        return Err(ApiError::bad("Send is not a file type send."));
    };
    if expected != file {
        return Err(ApiError::bad("Send file does not match send data."));
    }
    if send.uploaded {
        return Err(ApiError::bad("The file of this Send is uploaded already."));
    }
    let path = files::send_path(&state, &id, &file)?;
    let _uploading = state.uploads.start(&session.user.id)?;
    let uploaded = files::receive(form, &path, size.max(0) as u64).await?;
    if uploaded.size != size {
        files::discard(&uploaded).await;
        return Err(ApiError::bad("Send file size does not match."));
    }
    files::keep(&uploaded, &path).await?;
    let send = state
        .store
        .send_file_uploaded(&session.user.id, &id)
        .await?
        .ok_or_else(|| ApiError::bad("The file of this Send is uploaded already."))?;
    notify::send(&state, &session.user.id, Some(&session), Kind::SendCreate, &send.id, &send.revision);
    Ok(StatusCode::OK)
}

async fn update(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(data): Json<SendData>,
) -> ApiResult<Json<Value>> {
    let current = own(&state, &session, &id).await?;
    let send = save(&state, apply(&state, data, current).await?).await?;
    notify::send(&state, &session.user.id, Some(&session), Kind::SendUpdate, &send.id, &send.revision);
    Ok(Json(render(&send)))
}

async fn delete(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<StatusCode> {
    if !state.store.delete_send(&session.user.id, &id).await? {
        return Err(ApiError::bad("Send not found"));
    }
    notify::send(&state, &session.user.id, Some(&session), Kind::SendDelete, &id, &clock::now());
    Ok(StatusCode::OK)
}

async fn remove_password(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let mut send = own(&state, &session, &id).await?;
    send.password_hash = None;
    let send = save(&state, send).await?;
    notify::send(&state, &session.user.id, Some(&session), Kind::SendUpdate, &send.id, &send.revision);
    Ok(Json(render(&send)))
}

// ── For whoever has the link ──────────────────────────────

/// Whether `password` opens `send`. Wrong ones count per Send, so nobody guesses a short
/// password from many addresses.
async fn check_password(state: &AppState, send: &Send, password: Option<&str>) -> Result<(), PasswordRefusal> {
    let Some(hash) = &send.password_hash else { return Ok(()) };
    let Some(password) = password.filter(|password| !password.is_empty()) else { return Err(PasswordRefusal::Missing) };
    let key = format!("send:{}", send.id);
    // Taken before the check and given back when it was right: guesses sent all at once do not
    // get past the limit while the first ones are still being hashed.
    if !state.limits.password.take(key.clone()) {
        return Err(PasswordRefusal::TooMany);
    }
    if auth::verify_password(state.config.hash_cost, Some(hash), password).await {
        state.limits.password.give_back(&key);
        Ok(())
    } else {
        Err(PasswordRefusal::Wrong)
    }
}

pub(crate) enum PasswordRefusal {
    Missing,
    Wrong,
    TooMany,
}

#[derive(Deserialize, Default)]
struct AccessData {
    #[serde(default)]
    password: Option<String>,
}

fn refused(refusal: PasswordRefusal) -> ApiError {
    match refusal {
        PasswordRefusal::Missing => ApiError::new(StatusCode::UNAUTHORIZED, "Password not provided"),
        PasswordRefusal::Wrong => ApiError::bad("Invalid password."),
        PasswordRefusal::TooMany => ApiError::too_many("Too many wrong passwords. Wait a few minutes and try again."),
    }
}

/// Open a Send the old way: its access id, and the password hash if it has a password. A
/// text counts as opened now; a file when it is downloaded.
async fn access_legacy(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(access_id): Path<String>,
    body: Option<Json<AccessData>>,
) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let send = by_access_id(&state, &access_id).await?;
    if !send.accessible() {
        return Err(ApiError::not_found(GONE));
    }
    let password = body.and_then(|Json(data)| data.password);
    check_password(&state, &send, password.as_deref()).await.map_err(refused)?;
    if send.kind == TEXT && !state.store.register_send_access(&send.id).await? {
        return Err(ApiError::not_found(GONE));
    }
    opened(&state, &send);
    Ok(Json(render_access(&state, &send).await?))
}

async fn access_file_legacy(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path((id, file)): Path<(String, String)>,
    body: Option<Json<AccessData>>,
) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let send = state.store.send_by_id(&id).await?.filter(Send::accessible).ok_or_else(|| ApiError::not_found(GONE))?;
    let password = body.and_then(|Json(data)| data.password);
    check_password(&state, &send, password.as_deref()).await.map_err(refused)?;
    file_download(&state, &send, &file).await
}

/// What a download link's token is for: a Send's file, never an attachment of the same ids.
fn file_subject(send_id: &str, file: &str) -> String {
    format!("send:{send_id}/{file}")
}

/// The file's download link, and one more opening counted.
async fn file_download(state: &AppState, send: &Send, file: &str) -> ApiResult<Json<Value>> {
    if send.kind != FILE || file_of(send).is_none_or(|(expected, _)| expected != file) {
        return Err(ApiError::not_found(GONE));
    }
    if !state.store.register_send_access(&send.id).await? {
        return Err(ApiError::not_found(GONE));
    }
    opened(state, send);
    let token = state.tokens.file_token(&file_subject(&send.id, file), LINK_SECONDS);
    Ok(Json(json!({
        "id": file,
        "url": format!("{}/api/sends/{}/{file}?t={token}", state.config.public, send.id),
        "object": "send-fileDownload",
    })))
}

/// The owner's clients hear that their Send was opened: its count changed.
fn opened(state: &AppState, send: &Send) {
    notify::send(state, &send.user_id, None, Kind::SendUpdate, &send.id, &clock::now());
}

/// The Send a send access token in `Authorization` opens.
async fn by_token(state: &AppState, headers: &HeaderMap) -> ApiResult<Send> {
    let header = headers.get("authorization").and_then(|value| value.to_str().ok()).unwrap_or_default();
    let token = header.rsplit_once("Bearer ").map_or(header, |(_, token)| token);
    let id = state.tokens.check_send_token(token).ok_or_else(ApiError::unauthorized)?;
    // Its opening was counted when the token was given, so the count does not shut it here.
    state.store.send_by_id(&id).await?.filter(Send::open).ok_or_else(|| ApiError::not_found(GONE))
}

/// Open a Send the new way, with the token the identity endpoint gave for it. For a text, that
/// counted the opening already; a file counts each download link, as the old way does.
async fn access(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let send = by_token(&state, &headers).await?;
    Ok(Json(render_access(&state, &send).await?))
}

async fn access_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file): Path<String>,
) -> ApiResult<Json<Value>> {
    let send = by_token(&state, &headers).await?;
    file_download(&state, &send, &file).await
}

/// The identity endpoint's `send_access` grant: a token for one Send, after its password.
/// Answers the way Bitwarden's newest clients expect, errors included.
pub(crate) async fn grant(
    state: &AppState,
    ip: std::net::IpAddr,
    access_id: Option<&str>,
    password: Option<&str>,
) -> ApiResult<Response> {
    use axum::response::IntoResponse;
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let invalid = |kind: &str| {
        let mut error = ApiError::json(json!({ "error": "invalid_grant", "send_access_error_type": kind }));
        error.status = StatusCode::NOT_FOUND;
        error
    };
    let send = match access_id {
        Some(access_id) => by_access_id(state, access_id).await.map_err(|_| invalid("send_id_invalid"))?,
        None => {
            return Err(ApiError::json(
                json!({ "error": "invalid_request", "send_access_error_type": "send_id_required" }),
            ));
        }
    };
    if !send.accessible() {
        return Err(invalid("send_id_invalid"));
    }
    match check_password(state, &send, password).await {
        Ok(()) => {}
        Err(PasswordRefusal::Missing) => {
            return Err(ApiError::json(
                json!({ "error": "invalid_request", "send_access_error_type": "password_hash_b64_required" }),
            ));
        }
        Err(PasswordRefusal::Wrong) => return Err(invalid("password_hash_b64_invalid")),
        Err(PasswordRefusal::TooMany) => {
            return Err(ApiError::too_many("Too many wrong passwords. Wait a few minutes and try again."));
        }
    }
    // A text is opened now; a file is counted when its download link is asked for.
    if send.kind == TEXT {
        if !state.store.register_send_access(&send.id).await? {
            return Err(invalid("send_id_invalid"));
        }
        opened(state, &send);
    }
    let (token, expires_in) = state.tokens.send_token(&send.id);
    Ok(Json(json!({
        "access_token": token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "scope": "api.send.access",
    }))
    .into_response())
}

#[derive(Deserialize)]
struct DownloadQuery {
    #[serde(default)]
    t: String,
}

async fn download(
    State(state): State<AppState>,
    Path((id, file)): Path<(String, String)>,
    Query(query): Query<DownloadQuery>,
) -> ApiResult<Response> {
    if !state.tokens.check_file_token(&query.t, &file_subject(&id, &file)) {
        return Err(ApiError::unauthorized());
    }
    // A link from before the Send was disabled or ran out opens nothing any more.
    if !state.store.send_by_id(&id).await?.is_some_and(|send| send.open()) {
        return Err(ApiError::not_found(GONE));
    }
    files::serve(&files::send_path(&state, &id, &file)?).await
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::{Value, json};
    use uwulock_store::clock;

    fn text_send() -> Value {
        json!({
            "type": 0,
            "key": "2.key|key|key",
            "name": "2.name|name|name",
            "text": {"text": "2.text|text|text", "hidden": false, "response": null},
            "deletionDate": clock::in_seconds(86_400),
            "disabled": false,
        })
    }

    #[tokio::test]
    async fn a_text_send_opens_for_whoever_has_the_link() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let mut send = text_send();
        send["maxAccessCount"] = json!("2");
        send["password"] = json!("hash-of-the-password");
        let created = json(server.call("POST", "/api/sends", Some(&account.token), send).await).await;
        assert_eq!(created["object"], "send");
        assert_eq!(created["authType"], 1);
        assert_eq!(created["password"], "set");
        let access_id = created["accessId"].as_str().unwrap().to_string();
        let path = format!("/api/sends/access/{access_id}");

        let response = server.call("POST", &path, None, json!({})).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "a password first");
        let response = server.call("POST", &path, None, json!({"password": "wrong"})).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let opened = json(server.call("POST", &path, None, json!({"password": "hash-of-the-password"})).await).await;
        assert_eq!(opened["object"], "send-access");
        assert_eq!(opened["text"]["text"], "2.text|text|text");
        assert!(opened["text"].get("response").is_none());
        assert_eq!(opened["creatorIdentifier"], "nyu@example.com");

        let vault = json(server.get_as(&account.token, "/api/sync").await).await;
        assert_eq!(vault["sends"][0]["accessCount"], 1);

        let response = server.call("POST", &path, None, json!({"password": "hash-of-the-password"})).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = server.call("POST", &path, None, json!({"password": "hash-of-the-password"})).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "opened as often as it may be");
    }

    #[tokio::test]
    async fn the_newest_clients_get_a_token_for_a_send_first() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let mut send = text_send();
        send["hideEmail"] = json!(true);
        let created = json(server.call("POST", "/api/sends", Some(&account.token), send).await).await;
        let access_id = created["accessId"].as_str().unwrap();
        let response = server
            .form(
                "/identity/connect/token",
                &[("grant_type", "send_access"), ("client_id", "send"), ("send_id", access_id)],
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        let token = json(response).await["access_token"].as_str().unwrap().to_string();
        let request = Request::post("/api/sends/access")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let opened = json(server.send(request).await).await;
        assert_eq!(opened["name"], "2.name|name|name");
        assert!(opened["creatorIdentifier"].is_null(), "the address is hidden");
        assert_eq!(server.get_as(&token, "/api/sync").await.status(), StatusCode::UNAUTHORIZED, "no account token");

        let unknown = server
            .form(
                "/identity/connect/token",
                &[("grant_type", "send_access"), ("client_id", "send"), ("send_id", "AAAA")],
            )
            .await;
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
        assert_eq!(json(unknown).await["send_access_error_type"], "send_id_invalid");
    }

    #[tokio::test]
    async fn a_send_opened_once_opens_once_for_the_newest_clients_too() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let mut send = text_send();
        send["maxAccessCount"] = json!(1);
        let created = json(server.call("POST", "/api/sends", Some(&account.token), send).await).await;
        let access_id = created["accessId"].as_str().unwrap().to_string();
        let form = [("grant_type", "send_access"), ("client_id", "send"), ("send_id", access_id.as_str())];
        let grant = || server.form("/identity/connect/token", &form);
        let response = grant().await;
        assert_eq!(response.status(), StatusCode::OK);
        let token = json(response).await["access_token"].as_str().unwrap().to_string();
        let request = Request::post("/api/sends/access")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(server.send(request).await.status(), StatusCode::OK, "the one opening it may have");
        assert_eq!(grant().await.status(), StatusCode::NOT_FOUND, "and no second");
    }

    #[tokio::test]
    async fn a_file_send_is_announced_uploaded_and_downloaded() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let mut send = text_send();
        send["type"] = json!(1);
        send["text"] = json!(null);
        send["file"] = json!({"fileName": "2.file|file|file"});
        send["fileLength"] = json!(4);
        let answer = json(server.call("POST", "/api/sends/file/v2", Some(&account.token), send).await).await;
        let url = answer["url"].as_str().unwrap().to_string();
        let send = &answer["sendResponse"];
        assert_eq!(send["file"]["size"], "4");
        let access_id = send["accessId"].as_str().unwrap().to_string();
        let id = send["id"].as_str().unwrap().to_string();
        let file = send["file"]["id"].as_str().unwrap().to_string();

        let response = server.call("POST", &format!("/api/sends/access/{access_id}"), None, json!({})).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "no file yet");

        let boundary = "b";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"data\"; filename=\"2.file|file|file\"\r\n\r\nabcd\r\n--{boundary}--\r\n"
        );
        let upload = Request::post(format!("/api{url}"))
            .header("authorization", format!("Bearer {}", account.token))
            .header("content-type", format!("multipart/form-data; boundary={boundary}"))
            .body(Body::from(body.clone()))
            .unwrap();
        let response = server.send(upload).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);

        let opened = json(server.call("POST", &format!("/api/sends/access/{access_id}"), None, json!({})).await).await;
        assert_eq!(opened["file"]["fileName"], "2.file|file|file");
        let link =
            json(server.call("POST", &format!("/api/sends/{id}/access/file/{file}"), None, json!({})).await).await;
        let path = link["url"].as_str().unwrap().strip_prefix("https://vault.example.com").unwrap().to_string();
        let response = server.get(&path).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap().as_ref(), b"abcd");

        // A second upload for the same file finds it there, and the link dies with the Send's
        // being disabled.
        let upload = Request::post(format!("/api{url}"))
            .header("authorization", format!("Bearer {}", account.token))
            .header("content-type", format!("multipart/form-data; boundary={boundary}"))
            .body(Body::from(body.replace("abcd", "efgh")))
            .unwrap();
        assert_eq!(server.send(upload).await.status(), StatusCode::BAD_REQUEST);
        let mut stored = server.state.store.send_by_id(&id).await.unwrap().unwrap();
        stored.disabled = true;
        server.state.store.save_send(stored).await.unwrap();
        assert_eq!(server.get(&path).await.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn sends_are_changed_and_deleted_by_their_owner_only() {
        let server = TestServer::new().await;
        let nyu = server.account("nyu@example.com").await;
        let other = server.account("other@example.com").await;
        let created = json(server.call("POST", "/api/sends", Some(&nyu.token), text_send()).await).await;
        let id = created["id"].as_str().unwrap();
        let mut changed = text_send();
        changed["name"] = json!("2.new|new|new");
        let response = server.call("PUT", &format!("/api/sends/{id}"), Some(&other.token), changed.clone()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = server.call("PUT", &format!("/api/sends/{id}"), Some(&nyu.token), changed).await;
        assert_eq!(json(response).await["name"], "2.new|new|new");

        let mut far = text_send();
        far["deletionDate"] = json!(clock::in_seconds(40 * 86_400));
        let response = server.call("POST", "/api/sends", Some(&nyu.token), far).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "at most 31 days");

        let response = server.call("DELETE", &format!("/api/sends/{id}"), Some(&other.token), json!({})).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = server.call("DELETE", &format!("/api/sends/{id}"), Some(&nyu.token), json!({})).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(json(server.get_as(&nyu.token, "/api/sends").await).await["data"].as_array().unwrap().is_empty());
    }

    #[test]
    fn access_ids_in_either_byte_order() {
        let id = "b1c2d3e4-0000-4000-8000-00000000abcd";
        let access = super::access_id(id);
        assert_eq!(super::ids_for(&access)[0], id);
        let dotnet = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            uuid::Uuid::parse_str(id).unwrap().to_bytes_le(),
        );
        assert!(super::ids_for(&dotnet).contains(&id.to_string()));
    }
}
