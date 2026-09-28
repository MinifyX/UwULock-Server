//! File requests (docs/uwu-api.md §11): Sends in the other direction. The owner makes a link;
//! somebody without an account uploads files and a message to it, encrypted in their browser for
//! the owner's public key. The server keeps ciphertext, counts it to the owner's storage, mails
//! the owner when something arrives, and moves a file into an item when the owner takes it over.
//!
//! The public side answers every request that is unknown, expired, disabled or full with the
//! same 404 `gone`, so a link cannot be probed. It is rate-limited per address, wrong passwords
//! per request, and submissions per address and hour.

use crate::AppState;
use crate::auth::{ClientIp, Session};
use crate::errors::{ApiError, ApiResult};
use crate::keys::enc_string;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;
use uwulock_store::file_requests::{Refusal, RequestFile, Submission};
use uwulock_store::{FileRequest, FileRequestSummary, clock};

/// The longest message, in characters before encryption, and what that makes of it after: a
/// type 2 of it in base64, with room for the IV, the MAC and multi-byte characters.
const TEXT_MOST: usize = 100_000 * 4 * 4 / 3 + 200;
/// The largest label, sender or file name, encrypted.
const SMALL_MOST: usize = 4000;
/// The public details: title, note (a few thousand characters) and the public key.
const INFO_MOST: usize = 20_000;
/// What an EncArrayBuffer adds to the file it holds: the header, and padding.
const FILE_OVERHEAD: i64 = 65;
/// Submissions one request may have at most.
const SUBMISSIONS_MOST: i64 = 100;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/file-requests", get(list).post(create))
        .route("/uwu/v1/file-requests/{id}", get(one).put(update).delete(remove))
        .route("/uwu/v1/file-requests/{id}/submissions", get(submissions))
        .route("/uwu/v1/file-requests/{id}/submissions/{sid}", axum::routing::delete(remove_submission))
        .route("/uwu/v1/file-requests/{id}/submissions/{sid}/seen", post(seen))
        .route("/uwu/v1/file-requests/{id}/submissions/{sid}/files/{fid}", get(download))
        .route("/uwu/v1/file-requests/{id}/submissions/{sid}/files/{fid}/attach", post(attach))
        .route("/uwu/v1/public/file-requests/{access_id}", get(access))
        .route("/uwu/v1/public/file-requests/{access_id}/open", post(open))
        .route("/uwu/v1/public/file-requests/{access_id}/submissions", post(start))
        .route("/uwu/v1/public/file-requests/{access_id}/submissions/{id}/complete", post(complete))
}

/// The uploads themselves: no body limit but the one each file announced.
pub(crate) fn upload_routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/public/file-requests/{access_id}/submissions/{id}/files/{fid}", put(upload))
}

fn feature_off() -> ApiError {
    ApiError::not_found("File requests are switched off on this server.").code("feature_off")
}

fn enabled(state: &AppState) -> ApiResult<()> {
    if state.settings().file_requests.enabled { Ok(()) } else { Err(feature_off()) }
}

fn not_found() -> ApiError {
    ApiError::not_found("There is no such file request.").code("not_found")
}

/// Unknown, expired, disabled or full: all the same to whoever holds a link.
fn gone() -> ApiError {
    ApiError::not_found("This link does not take uploads (any more).").code("gone")
}

/// The access id in a link: the request id's 16 bytes, base64url.
pub(crate) fn access_id(id: &str) -> String {
    uuid::Uuid::parse_str(id).map(|uuid| URL_SAFE_NO_PAD.encode(uuid.as_bytes())).unwrap_or_default()
}

fn request_id(access_id: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(access_id.trim_end_matches('=')).ok()?;
    uuid::Uuid::from_slice(&bytes).ok().map(|uuid| uuid.hyphenated().to_string())
}

/// Where a request's files lie.
fn folder(state: &AppState, request_id: &str) -> ApiResult<PathBuf> {
    if !crate::files::valid_id(request_id) {
        return Err(not_found());
    }
    Ok(state.config.data.join("file-requests").join(request_id))
}

fn file_path(state: &AppState, request_id: &str, file_id: &str) -> ApiResult<PathBuf> {
    if !crate::files::valid_id(file_id) {
        return Err(not_found());
    }
    Ok(folder(state, request_id)?.join(file_id))
}

fn render(summary: &FileRequestSummary) -> Value {
    let request = &summary.request;
    json!({
        "object": "fileRequest",
        "id": request.id,
        "accessId": access_id(&request.id),
        "name": request.name,
        "linkSecret": request.link_secret,
        "publicInfo": request.public_info,
        "passwordSet": request.password_hash.is_some(),
        "expirationDate": request.expiration,
        "deletionDate": request.deletion,
        "maxSubmissions": request.max_submissions,
        "submissionCount": request.submission_count,
        "maxFiles": request.max_files,
        "maxFileBytes": request.max_file_bytes,
        "textAllowed": request.text_allowed,
        "sendDomainId": request.send_domain_id,
        "disabled": request.disabled,
        "unseen": summary.unseen,
        "bytes": summary.bytes,
        "creationDate": request.created,
        "revisionDate": request.revision,
    })
}

// ── The owner's side ──────────────────────────────────────

async fn list(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let requests = state.store.file_requests(&session.user.id).await?;
    let data: Vec<Value> = requests.iter().map(render).collect();
    Ok(Json(json!({ "object": "list", "data": data, "continuationToken": null })))
}

async fn one(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let summary = state.store.file_request(&session.user.id, &id).await?.ok_or_else(not_found)?;
    Ok(Json(render(&summary)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    link_secret: Option<String>,
    public_info: String,
    /// Left out on a change: the password stays. `null` on a new one: none.
    #[serde(default, deserialize_with = "some")]
    password_hash: Option<Option<String>>,
    #[serde(default)]
    remove_password: bool,
    expiration_date: String,
    #[serde(default)]
    max_submissions: Option<i64>,
    max_files: i64,
    max_file_bytes: i64,
    #[serde(default = "yes")]
    text_allowed: bool,
    #[serde(default)]
    send_domain_id: Option<String>,
    #[serde(default)]
    disabled: bool,
}

fn yes() -> bool {
    true
}

/// A key that is there, even as `null`, is `Some`.
fn some<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(Some)
}

/// The request as the owner sent it, checked; `before` for a change.
async fn request_from(
    state: &AppState,
    session: &Session,
    body: RequestBody,
    id: String,
    before: Option<&FileRequest>,
) -> ApiResult<FileRequest> {
    let settings = state.settings();
    let invalid = |message: &str| ApiError::bad(message.to_string()).code("invalid");
    let small = |value: &Option<String>| value.as_deref().is_none_or(|value| enc_string(value, 2, SMALL_MOST));
    if !small(&body.name) || !small(&body.link_secret) || !enc_string(&body.public_info, 2, INFO_MOST) {
        return Err(invalid("The request is not encrypted the way it should be."));
    }
    let expiration =
        clock::parse(&body.expiration_date).ok_or_else(|| invalid("The expiration date is not a date."))?;
    let now = time::OffsetDateTime::now_utc();
    let latest = now + time::Duration::days(i64::from(settings.file_requests.max_days));
    // A little leeway for the clock of the device that made it.
    if expiration < now + time::Duration::minutes(55) || expiration > latest + time::Duration::minutes(5) {
        return Err(invalid(&format!(
            "A file request runs out between an hour and {} days from now.",
            settings.file_requests.max_days
        )));
    }
    if body.max_submissions.is_some_and(|most| !(1..=SUBMISSIONS_MOST).contains(&most)) {
        return Err(invalid("A file request takes 1 to 100 submissions, or any number until it runs out."));
    }
    let max_files = i64::from(settings.file_requests.max_files);
    if !(0..=max_files).contains(&body.max_files) {
        return Err(invalid(&format!("A submission may bring 0 to {max_files} files.")));
    }
    let max_file_bytes = crate::files::limit(state) as i64;
    if body.max_files > 0 && !(1..=max_file_bytes).contains(&body.max_file_bytes) {
        return Err(invalid(&format!("A file may be at most {}.", crate::files::size_name(max_file_bytes))));
    }
    if body.max_files == 0 && !body.text_allowed {
        return Err(invalid("A file request takes files, a message, or both."));
    }
    let password_hash = match (body.password_hash, body.remove_password) {
        (_, true) => None,
        (Some(Some(hash)), _) if !hash.is_empty() => {
            if hash.len() > 200 {
                return Err(invalid("The password is not hashed the way it should be."));
            }
            Some(crate::auth::hash_password(state.config.hash_cost, &hash).await?)
        }
        (Some(_), _) => None,
        (None, _) => before.and_then(|request| request.password_hash.clone()),
    };
    let now_text = clock::now();
    let deletion = clock::format(expiration + time::Duration::days(30));
    Ok(FileRequest {
        id,
        user_id: session.user.id.clone(),
        name: body.name,
        link_secret: body.link_secret,
        public_info: body.public_info,
        password_hash,
        expiration: clock::format(expiration),
        deletion,
        max_submissions: body.max_submissions,
        submission_count: before.map_or(0, |request| request.submission_count),
        max_files: body.max_files,
        max_file_bytes: body.max_file_bytes.max(0),
        text_allowed: body.text_allowed,
        send_domain_id: body.send_domain_id,
        disabled: body.disabled,
        created: before.map_or_else(|| now_text.clone(), |request| request.created.clone()),
        revision: now_text,
    })
}

async fn create(
    State(state): State<AppState>,
    session: Session,
    Json(body): Json<RequestBody>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let id = uuid::Uuid::new_v4().to_string();
    let request = request_from(&state, &session, body, id.clone(), None).await?;
    let most = i64::from(state.settings().file_requests.per_user);
    if !state.store.create_file_request(request, most).await? {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("An account may have {most} file requests; delete old ones first."),
        )
        .code("quota"));
    }
    let summary = state.store.file_request(&session.user.id, &id).await?.ok_or_else(not_found)?;
    Ok(Json(render(&summary)))
}

async fn update(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(body): Json<RequestBody>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let before = state.store.file_request(&session.user.id, &id).await?.ok_or_else(not_found)?;
    let request = request_from(&state, &session, body, id.clone(), Some(&before.request)).await?;
    if !state.store.update_file_request(request).await? {
        return Err(not_found());
    }
    let summary = state.store.file_request(&session.user.id, &id).await?.ok_or_else(not_found)?;
    Ok(Json(render(&summary)))
}

async fn remove(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<StatusCode> {
    enabled(&state)?;
    if !state.store.delete_file_request(&session.user.id, &id).await? {
        return Err(not_found());
    }
    let _ = tokio::fs::remove_dir_all(folder(&state, &id)?).await;
    Ok(StatusCode::OK)
}

fn render_submission(submission: &Submission) -> Value {
    let files: Vec<Value> = submission
        .files
        .iter()
        .map(|file| json!({ "id": file.id, "fileName": file.file_name, "key": file.key, "size": file.size }))
        .collect();
    json!({
        "object": "fileRequestSubmission",
        "id": submission.id,
        "requestId": submission.request_id,
        "creationDate": submission.completed.as_ref().unwrap_or(&submission.created),
        "wrappedKey": submission.wrapped_key,
        "sender": submission.sender,
        "text": submission.text,
        "files": files,
        "seen": submission.seen,
    })
}

async fn submissions(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    let list = state.store.submissions(&session.user.id, &id).await?.ok_or_else(not_found)?;
    let data: Vec<Value> = list.iter().map(render_submission).collect();
    Ok(Json(json!({ "object": "list", "data": data, "continuationToken": null })))
}

async fn seen(
    State(state): State<AppState>,
    session: Session,
    Path((id, sid)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    enabled(&state)?;
    if !state.store.mark_submission(&session.user.id, &id, &sid, false).await? {
        return Err(not_found());
    }
    Ok(StatusCode::OK)
}

async fn remove_submission(
    State(state): State<AppState>,
    session: Session,
    Path((id, sid)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    enabled(&state)?;
    let files = state.store.submissions(&session.user.id, &id).await?.ok_or_else(not_found)?;
    let files: Vec<String> = files
        .into_iter()
        .find(|submission| submission.id == sid)
        .map(|submission| submission.files.into_iter().map(|file| file.id).collect())
        .ok_or_else(not_found)?;
    if !state.store.mark_submission(&session.user.id, &id, &sid, true).await? {
        return Err(not_found());
    }
    for file in files {
        let _ = tokio::fs::remove_file(file_path(&state, &id, &file)?).await;
    }
    Ok(StatusCode::OK)
}

async fn download(
    State(state): State<AppState>,
    session: Session,
    Path((id, sid, fid)): Path<(String, String, String)>,
) -> ApiResult<axum::response::Response> {
    enabled(&state)?;
    let file = state
        .store
        .submission_file(&session.user.id, &id, &sid, &fid)
        .await?
        .filter(|file| file.uploaded)
        .ok_or_else(not_found)?;
    crate::files::serve(&file_path(&state, &id, &file.id)?).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Attach {
    cipher_id: String,
    file_name: String,
    key: String,
}

/// Takes a file into an item: the name and the file's key come under the item's key, the bytes
/// on disk move among its attachments as they are.
async fn attach(
    State(state): State<AppState>,
    session: Session,
    Path((id, sid, fid)): Path<(String, String, String)>,
    Json(body): Json<Attach>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    if !enc_string(&body.file_name, 2, SMALL_MOST) || !enc_string(&body.key, 2, SMALL_MOST) {
        return Err(ApiError::bad("The file's name and key are not encrypted the way they should be.").code("invalid"));
    }
    let file = state
        .store
        .submission_file(&session.user.id, &id, &sid, &fid)
        .await?
        .filter(|file| file.uploaded)
        .ok_or_else(not_found)?;
    let (_, owner, collections) = crate::attachments::changeable(&state, &session, &body.cipher_id)
        .await
        .map_err(|_| ApiError::not_found("There is no such item you may change.").code("not_found"))?;
    let attachment = crate::files::new_file_id();
    let from = file_path(&state, &id, &file.id)?;
    let to = crate::files::attachment_path(&state, &body.cipher_id, &attachment)?;
    tokio::fs::create_dir_all(to.parent().expect("attachments have a folder")).await.map_err(ApiError::internal)?;
    tokio::fs::rename(&from, &to).await.map_err(ApiError::internal)?;
    let taken = state
        .store
        .take_request_file(
            &session.user.id,
            &sid,
            &fid,
            &owner,
            &body.cipher_id,
            &attachment,
            &body.file_name,
            &body.key,
        )
        .await;
    let cipher = match taken {
        Ok(Some(cipher)) => cipher,
        other => {
            let _ = tokio::fs::rename(&to, &from).await;
            other?;
            return Err(not_found());
        }
    };
    let rendered = crate::attachments::changed(&state, &session, &cipher, &collections).await?;
    Ok(Json(serde_json::from_str(&rendered).unwrap_or(Value::Null)))
}

// ── The uploader's side ───────────────────────────────────

fn limited(state: &AppState, ip: std::net::IpAddr) -> ApiResult<()> {
    if state.limits.anonymous.check(ip) {
        Ok(())
    } else {
        Err(ApiError::too_many("Too many requests. Wait a minute and try again."))
    }
}

async fn open_request(state: &AppState, access_id: &str) -> ApiResult<FileRequest> {
    let id = request_id(access_id).ok_or_else(gone)?;
    state.store.open_file_request(&id).await?.ok_or_else(gone)
}

async fn access(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(access_id): Path<String>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    limited(&state, ip)?;
    let request = open_request(&state, &access_id).await?;
    Ok(Json(json!({ "object": "fileRequestAccess", "passwordRequired": request.password_hash.is_some() })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenBody {
    #[serde(default)]
    password_hash: Option<String>,
}

async fn open(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(access_id): Path<String>,
    Json(body): Json<OpenBody>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    limited(&state, ip)?;
    let request = open_request(&state, &access_id).await?;
    if let Some(hash) = &request.password_hash {
        let Some(given) = body.password_hash.filter(|given| !given.is_empty()) else {
            return Err(ApiError::bad("This file request needs its password.").code("password_required"));
        };
        // Wrong passwords count per request, so nobody guesses a short one from many addresses.
        let key = format!("filerequest:{}", request.id);
        if !state.limits.password.take(key.clone()) {
            return Err(ApiError::too_many("Too many wrong passwords. Wait a few minutes and try again."));
        }
        if !crate::auth::verify_password(state.config.hash_cost, Some(hash), &given).await {
            return Err(ApiError::bad("The password is not right.").code("password_invalid"));
        }
        state.limits.password.give_back(&key);
    }
    let (token, seconds) = state.tokens.upload_token(&request.id);
    Ok(Json(json!({
        "object": "fileRequestOpen",
        "publicInfo": request.public_info,
        "token": token,
        "expiresIn": seconds,
        "expirationDate": request.expiration,
        "maxFiles": request.max_files,
        "maxFileBytes": request.max_file_bytes,
        "textAllowed": request.text_allowed,
    })))
}

/// The request an upload token opens, and that it is the one in the address.
fn uploader(state: &AppState, headers: &HeaderMap, access_id: &str) -> ApiResult<String> {
    let header = headers.get("authorization").and_then(|value| value.to_str().ok()).unwrap_or_default();
    let token = header.strip_prefix("Bearer ").unwrap_or(header);
    let id = state.tokens.check_upload_token(token).ok_or_else(|| {
        ApiError::new(StatusCode::UNAUTHORIZED, "The upload page has been open too long. Open the link again.")
            .code("unauthorized")
    })?;
    if request_id(access_id).as_deref() != Some(id.as_str()) {
        return Err(gone());
    }
    Ok(id)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileBody {
    file_name: String,
    key: String,
    size: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartBody {
    wrapped_key: String,
    #[serde(default)]
    sender: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    files: Vec<FileBody>,
}

async fn start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(access_id): Path<String>,
    Json(body): Json<StartBody>,
) -> ApiResult<Json<Value>> {
    enabled(&state)?;
    limited(&state, ip)?;
    let id = uploader(&state, &headers, &access_id)?;
    let request = state.store.open_file_request(&id).await?.ok_or_else(gone)?;
    let invalid = |message: &str| ApiError::bad(message.to_string()).code("invalid");
    if !enc_string(&body.wrapped_key, 4, 2000) {
        return Err(invalid("The submission's key is not wrapped the way it should be."));
    }
    let text = body.text.filter(|text| !text.is_empty());
    if text.is_some() && !request.text_allowed {
        return Err(invalid("This file request takes no message."));
    }
    if text.as_deref().is_some_and(|text| !enc_string(text, 2, TEXT_MOST)) {
        return Err(invalid("The message is too long, or not encrypted the way it should be."));
    }
    let sender = body.sender.filter(|sender| !sender.is_empty());
    if sender.as_deref().is_some_and(|sender| !enc_string(sender, 2, SMALL_MOST)) {
        return Err(invalid("The sender is not encrypted the way it should be."));
    }
    if text.is_none() && body.files.is_empty() {
        return Err(invalid("A submission brings a message or a file."));
    }
    if body.files.len() as i64 > request.max_files {
        return Err(invalid(&format!("This file request takes at most {} files at once.", request.max_files)));
    }
    for file in &body.files {
        if !enc_string(&file.file_name, 2, SMALL_MOST) || !enc_string(&file.key, 2, SMALL_MOST) {
            return Err(invalid("A file's name or key is not encrypted the way it should be."));
        }
        if !(1..=request.max_file_bytes + FILE_OVERHEAD).contains(&file.size) {
            return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "A file is larger than this file request takes.")
                .code("too_large"));
        }
    }
    // Last, so a submission the checks above refuse costs nothing.
    if !state.limits.file_request_uploads.check(ip) {
        return Err(ApiError::too_many("Too many uploads from here. Wait an hour and try again."));
    }
    let submission_id = uuid::Uuid::new_v4().to_string();
    let files: Vec<RequestFile> = body
        .files
        .into_iter()
        .map(|file| RequestFile {
            id: crate::files::new_file_id(),
            file_name: file.file_name,
            key: file.key,
            size: file.size,
            uploaded: false,
        })
        .collect();
    let submission = Submission {
        id: submission_id.clone(),
        request_id: id.clone(),
        wrapped_key: body.wrapped_key,
        sender,
        text,
        files: files.clone(),
        ..Submission::default()
    };
    match state.store.start_submission(submission, state.settings().storage_limit()).await? {
        Ok(()) => {}
        Err(Refusal::Gone) => return Err(gone()),
        Err(Refusal::Quota) => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "The owner of this file request has no room left for these files.",
            )
            .code("quota"));
        }
    }
    let urls: Vec<Value> = files
        .iter()
        .map(|file| {
            json!({
                "id": file.id,
                "url": format!("/uwu/v1/public/file-requests/{access_id}/submissions/{submission_id}/files/{}", file.id),
            })
        })
        .collect();
    Ok(Json(json!({ "object": "fileRequestSubmissionStarted", "id": submission_id, "files": urls })))
}

/// One file of a submission, exactly as large as announced, an EncArrayBuffer.
async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((access_id, sid, fid)): Path<(String, String, String)>,
    body: Body,
) -> ApiResult<StatusCode> {
    enabled(&state)?;
    let id = uploader(&state, &headers, &access_id)?;
    let size = state.store.pending_file(&id, &sid, &fid).await?.ok_or_else(gone)? as u64;
    let path = file_path(&state, &id, &fid)?;
    let dir = path.parent().expect("files have a folder").to_path_buf();
    tokio::fs::create_dir_all(&dir).await.map_err(ApiError::internal)?;
    if !uwulock_store::backups::has_room(&dir, size) {
        return Err(ApiError::bad("There is not enough room on the server for this file."));
    }
    let partial = dir.join(format!(".{fid}.{}.part", crate::files::new_file_id()));
    let received = async {
        let mut file = tokio::fs::File::create(&partial).await.map_err(ApiError::internal)?;
        let mut stream = body.into_data_stream();
        let mut written: u64 = 0;
        let stalled = std::time::Duration::from_secs(60);
        while let Some(chunk) = tokio::time::timeout(stalled, stream.next())
            .await
            .map_err(|_| ApiError::bad("The upload stalled.").code("incomplete"))?
        {
            let chunk = chunk.map_err(|_| ApiError::bad("The upload broke off.").code("incomplete"))?;
            if written == 0 && chunk.first().is_some_and(|byte| *byte != 2) {
                return Err(ApiError::bad("That is not an encrypted file.").code("invalid"));
            }
            written += chunk.len() as u64;
            if written > size {
                return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "The file is larger than announced.")
                    .code("too_large"));
            }
            file.write_all(&chunk).await.map_err(ApiError::internal)?;
        }
        if written < size {
            return Err(ApiError::bad("The file is smaller than announced.").code("incomplete"));
        }
        file.sync_all().await.map_err(ApiError::internal)?;
        Ok(())
    }
    .await;
    if let Err(error) = received {
        let _ = tokio::fs::remove_file(&partial).await;
        return Err(error);
    }
    tokio::fs::rename(&partial, &path).await.map_err(ApiError::internal)?;
    state.store.request_file_uploaded(&sid, &fid).await?;
    Ok(StatusCode::OK)
}

async fn complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((access_id, sid)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    enabled(&state)?;
    let id = uploader(&state, &headers, &access_id)?;
    let (request, mail) = match state.store.complete_submission(&id, &sid).await? {
        None => return Err(gone()),
        Some(Err(())) => return Err(ApiError::bad("A file of the submission is still missing.").code("incomplete")),
        Some(Ok(done)) => done,
    };
    if mail && let Ok(Some(owner)) = state.store.user(&request.user_id).await {
        let link = format!("{}/#/file-requests/{}", state.config.public, request.id);
        let mailer = state.mailer.clone();
        tokio::spawn(async move {
            let language = uwulock_mail::Language::from_code(&owner.language);
            if let Err(error) =
                mailer.send(&owner.email, &uwulock_mail::Mail::FileRequestArrived { link }, language).await
                && mailer.enabled()
            {
                tracing::warn!(%error, "the mail about a file request did not go out");
            }
        });
    }
    Ok(StatusCode::OK)
}

/// Requests past their deletion date go with everything in them, and submissions nobody
/// completed within a day; then files on disk nothing claims any more.
pub async fn sweep(state: &AppState) {
    match state.store.sweep_file_requests().await {
        Ok((requests, submissions)) => {
            for id in &requests {
                if let Ok(dir) = folder(state, id) {
                    let _ = tokio::fs::remove_dir_all(dir).await;
                }
            }
            for (request, files) in &submissions {
                for file in files {
                    if let Ok(path) = file_path(state, request, file) {
                        let _ = tokio::fs::remove_file(path).await;
                    }
                }
            }
            if !requests.is_empty() || !submissions.is_empty() {
                tracing::info!(
                    requests = requests.len(),
                    submissions = submissions.len(),
                    "old file requests were deleted"
                );
            }
        }
        Err(error) => tracing::warn!(%error, "sweeping up file requests did not work"),
    }
    let store = state.store.clone();
    let swept = crate::files::sweep(&state.config.data.join("file-requests"), |request, id| {
        let store = store.clone();
        async move { store.request_file_exists(&request, &id).await.unwrap_or(true) }
    })
    .await;
    if let Err(error) = swept {
        tracing::warn!(%error, "sweeping up the files of file requests did not work");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use axum::http::Request;

    fn body(password: Option<&str>) -> Value {
        json!({
            "name": type2(),
            "linkSecret": type2(),
            "publicInfo": type2(),
            "passwordHash": password,
            "expirationDate": clock::in_seconds(7 * 86_400),
            "maxSubmissions": 2,
            "maxFiles": 2,
            "maxFileBytes": 1000,
            "textAllowed": true,
        })
    }

    async fn request(server: &TestServer, token: &str, password: Option<&str>) -> Value {
        let response = server.call("POST", "/uwu/v1/file-requests", Some(token), body(password)).await;
        assert_eq!(response.status(), StatusCode::OK);
        json(response).await
    }

    /// Opens the link and answers the upload token.
    async fn open(server: &TestServer, access: &str, password: Option<&str>) -> String {
        let path = format!("/uwu/v1/public/file-requests/{access}/open");
        let opened = json(server.call("POST", &path, None, json!({ "passwordHash": password })).await).await;
        opened["token"].as_str().unwrap_or_else(|| panic!("{opened}")).to_string()
    }

    fn put_file(path: &str, token: &str, bytes: Vec<u8>) -> Request<Body> {
        Request::put(path).header("authorization", format!("Bearer {token}")).body(Body::from(bytes)).unwrap()
    }

    fn encrypted(size: usize) -> Vec<u8> {
        let mut bytes = vec![7u8; size];
        bytes[0] = 2;
        bytes
    }

    #[tokio::test]
    async fn somebody_uploads_and_the_owner_takes_it_into_an_item() {
        let server = TestServer::new().await;
        let owner = server.account("nyu@example.com").await;
        let made = request(&server, &owner.token, Some("hashed-password")).await;
        let (id, access) = (made["id"].as_str().unwrap(), made["accessId"].as_str().unwrap());
        assert_eq!(made["passwordSet"], true);
        assert!(made["deletionDate"].as_str().unwrap() > made["expirationDate"].as_str().unwrap());

        let public = format!("/uwu/v1/public/file-requests/{access}");
        assert_eq!(json(server.get(&public).await).await["passwordRequired"], true);
        let path = format!("{public}/open");
        let missing = json(server.call("POST", &path, None, json!({})).await).await;
        assert_eq!(missing["code"], "password_required");
        let wrong = json(server.call("POST", &path, None, json!({ "passwordHash": "wrong" })).await).await;
        assert_eq!(wrong["code"], "password_invalid");
        let token = open(&server, access, Some("hashed-password")).await;

        let submission = json!({
            "wrappedKey": type4(),
            "sender": type2(),
            "text": type2(),
            "files": [ { "fileName": type2(), "key": type2(), "size": 300 } ],
        });
        let without = server.call("POST", &format!("{public}/submissions"), None, submission.clone()).await;
        assert_eq!(without.status(), StatusCode::UNAUTHORIZED);
        let started = server.call_from("192.0.2.7", "POST", &format!("{public}/submissions"), &token, submission).await;
        let started = json(started).await;
        let sid = started["id"].as_str().unwrap().to_string();
        let url = started["files"][0]["url"].as_str().unwrap().to_string();

        let complete = format!("{public}/submissions/{sid}/complete");
        let early = server.call_from("192.0.2.7", "POST", &complete, &token, json!({})).await;
        assert_eq!(json(early).await["code"], "incomplete");
        assert_eq!(server.send(put_file(&url, &token, encrypted(301))).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(server.send(put_file(&url, &token, encrypted(299))).await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(server.send(put_file(&url, &token, vec![1; 300])).await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(server.send(put_file(&url, &token, encrypted(300))).await.status(), StatusCode::OK);
        assert_eq!(server.call_from("192.0.2.7", "POST", &complete, &token, json!({})).await.status(), StatusCode::OK);
        let mail =
            server.wait_for_mail(|mail| mail.to == "nyu@example.com" && mail.text.contains("file-requests")).await;
        assert!(mail.text.contains(&format!("/#/file-requests/{id}")), "{}", mail.text);

        // The owner sees it, and nobody else does.
        let other = server.account("mio@example.com").await;
        let listed = format!("/uwu/v1/file-requests/{id}/submissions");
        assert_eq!(server.get_as(&other.token, &listed).await.status(), StatusCode::NOT_FOUND);
        let list = json(server.get_as(&owner.token, &listed).await).await;
        let got = &list["data"][0];
        assert_eq!((got["seen"].as_bool(), got["files"][0]["size"].as_i64()), (Some(false), Some(300)));
        let summary = json(server.get_as(&owner.token, &format!("/uwu/v1/file-requests/{id}")).await).await;
        assert_eq!((summary["unseen"].as_i64(), summary["submissionCount"].as_i64()), (Some(1), Some(1)));
        let account = json(server.get_as(&owner.token, "/uwu/v1/account").await).await;
        assert_eq!(account["storage"]["usedBytes"], 300);

        let fid = got["files"][0]["id"].as_str().unwrap();
        let file = format!("{listed}/{sid}/files/{fid}");
        let downloaded = server.get_as(&owner.token, &file).await;
        let bytes = axum::body::to_bytes(downloaded.into_body(), usize::MAX).await.unwrap();
        assert_eq!(bytes.to_vec(), encrypted(300));
        let seen = server.call("POST", &format!("{listed}/{sid}/seen"), Some(&owner.token), json!({})).await;
        assert_eq!(seen.status(), StatusCode::OK);

        // Taken into an item: the same bytes, now an attachment.
        let item = json!({"type": 2, "name": type2(), "secureNote": {"type": 0}});
        let item = json(server.call("POST", "/api/ciphers", Some(&owner.token), item).await).await;
        let cipher_id = item["id"].as_str().unwrap();
        let theirs = json!({"type": 2, "name": type2(), "secureNote": {"type": 0}});
        let theirs = json(server.call("POST", "/api/ciphers", Some(&other.token), theirs).await).await;
        let attach = format!("{file}/attach");
        let foreign = json!({ "cipherId": theirs["id"], "fileName": type2(), "key": type2() });
        assert_eq!(server.call("POST", &attach, Some(&owner.token), foreign).await.status(), StatusCode::NOT_FOUND);
        let body = json!({ "cipherId": cipher_id, "fileName": type2(), "key": type2() });
        let attached = json(server.call("POST", &attach, Some(&owner.token), body.clone()).await).await;
        let attachment = attached["attachments"][0]["id"].as_str().unwrap_or_else(|| panic!("{attached}"));
        let moved = server.state.config.data.join("attachments").join(cipher_id).join(attachment);
        assert_eq!(std::fs::read(moved).unwrap(), encrypted(300));
        assert!(!server.state.config.data.join("file-requests").join(id).join(fid).exists());
        assert_eq!(
            server.call("POST", &attach, Some(&owner.token), body).await.status(),
            StatusCode::NOT_FOUND,
            "once"
        );

        let delete = server.call("DELETE", &format!("/uwu/v1/file-requests/{id}"), Some(&owner.token), json!({})).await;
        assert_eq!(delete.status(), StatusCode::OK);
        assert_eq!(json(server.get(&public).await).await["code"], "gone");
    }

    #[tokio::test]
    async fn closed_requests_look_like_none_and_limits_hold() {
        let server = TestServer::new().await;
        let owner = server.account("nyu@example.com").await;
        let made = request(&server, &owner.token, None).await;
        let (id, access) = (made["id"].as_str().unwrap().to_string(), made["accessId"].as_str().unwrap().to_string());
        let public = format!("/uwu/v1/public/file-requests/{access}");
        assert_eq!(json(server.get(&public).await).await["passwordRequired"], false);
        let token = open(&server, &access, None).await;

        let big = json!({ "wrappedKey": type4(), "files": [ { "fileName": type2(), "key": type2(), "size": 900 } ] });
        let mut too_big = big.clone();
        too_big["files"][0]["size"] = json!(1000 + FILE_OVERHEAD + 1);
        let refused = server.call_from("192.0.2.8", "POST", &format!("{public}/submissions"), &token, too_big).await;
        assert_eq!(refused.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let ok = server.call_from("192.0.2.8", "POST", &format!("{public}/submissions"), &token, big.clone()).await;
        assert_eq!(ok.status(), StatusCode::OK);
        // Two submissions at most; the third looks as if there were no request.
        let second = server.call_from("192.0.2.8", "POST", &format!("{public}/submissions"), &token, big.clone()).await;
        assert_eq!(second.status(), StatusCode::OK);
        let third = server.call_from("192.0.2.8", "POST", &format!("{public}/submissions"), &token, big).await;
        assert_eq!(json(third).await["code"], "gone");

        // Switched off by its owner: gone too.
        let mut off = body(None);
        off["disabled"] = json!(true);
        server.call("PUT", &format!("/uwu/v1/file-requests/{id}"), Some(&owner.token), off).await;
        assert_eq!(json(server.get(&public).await).await["code"], "gone");
        assert_eq!(json(server.get("/uwu/v1/public/file-requests/AAAAAAAAAAAAAAAAAAAAAA").await).await["code"], "gone");

        // Beyond what the settings allow.
        let mut long = body(None);
        long["expirationDate"] = json!(clock::in_seconds(400 * 86_400));
        let refused = server.call("POST", "/uwu/v1/file-requests", Some(&owner.token), long).await;
        assert_eq!(json(refused).await["code"], "invalid");
        let mut many = body(None);
        many["maxFiles"] = json!(21);
        assert_eq!(
            server.call("POST", "/uwu/v1/file-requests", Some(&owner.token), many).await.status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn the_owner_s_storage_bounds_what_arrives() {
        let server =
            TestServer::with_settings(crate::Settings { storage_per_user_mb: Some(1), ..crate::Settings::default() })
                .await;
        let owner = server.account("nyu@example.com").await;
        let mut big = body(None);
        big["maxFileBytes"] = json!(2 * 1024 * 1024);
        let made = json(server.call("POST", "/uwu/v1/file-requests", Some(&owner.token), big).await).await;
        let access = made["accessId"].as_str().unwrap();
        let token = open(&server, access, None).await;
        let submission =
            json!({ "wrappedKey": type4(), "files": [ { "fileName": type2(), "key": type2(), "size": 1_500_000 } ] });
        let path = format!("/uwu/v1/public/file-requests/{access}/submissions");
        let refused = server.call_from("192.0.2.9", "POST", &path, &token, submission).await;
        assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json(refused).await["code"], "quota");
    }

    #[tokio::test]
    async fn guessing_and_flooding_run_into_limits() {
        let server = TestServer::new().await.with_limits(crate::Limits::default()).behind_proxy();
        let owner = server.account("nyu@example.com").await;
        let made = request(&server, &owner.token, Some("the-right-one")).await;
        let access = made["accessId"].as_str().unwrap();
        let path = format!("/uwu/v1/public/file-requests/{access}/open");
        for n in 0..10 {
            let ip = format!("192.0.2.{n}");
            let wrong = server.call_from(&ip, "POST", &path, "", json!({ "passwordHash": "wrong" })).await;
            assert_eq!(json(wrong).await["code"], "password_invalid");
        }
        let right =
            server.call_from("198.51.100.1", "POST", &path, "", json!({ "passwordHash": "the-right-one" })).await;
        assert_eq!(right.status(), StatusCode::TOO_MANY_REQUESTS, "counted per request, from any address");

        let mut plain = body(None);
        plain["maxSubmissions"] = json!(null);
        let made = json(server.call("POST", "/uwu/v1/file-requests", Some(&owner.token), plain).await).await;
        let access = made["accessId"].as_str().unwrap();
        let token = open_from(&server, access).await;
        let path = format!("/uwu/v1/public/file-requests/{access}/submissions");
        let submission = json!({ "wrappedKey": type4(), "text": type2() });
        for _ in 0..10 {
            let started = server.call_from("203.0.113.5", "POST", &path, &token, submission.clone()).await;
            assert_eq!(started.status(), StatusCode::OK);
        }
        let flood = server.call_from("203.0.113.5", "POST", &path, &token, submission.clone()).await;
        assert_eq!(flood.status(), StatusCode::TOO_MANY_REQUESTS);
        let elsewhere = server.call_from("203.0.113.6", "POST", &path, &token, submission).await;
        assert_eq!(elsewhere.status(), StatusCode::OK);
    }

    async fn open_from(server: &TestServer, access: &str) -> String {
        let path = format!("/uwu/v1/public/file-requests/{access}/open");
        let opened = json(server.call_from("198.51.100.9", "POST", &path, "", json!({})).await).await;
        opened["token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn switched_off_it_is_not_there() {
        let mut settings = crate::Settings::default();
        settings.file_requests.enabled = false;
        let server = TestServer::with_settings(settings).await;
        let owner = server.account("nyu@example.com").await;
        let response = server.get_as(&owner.token, "/uwu/v1/file-requests").await;
        assert_eq!(json(response).await["code"], "feature_off");
        let info = json(server.get("/uwu/v1/info").await).await;
        assert!(!info["features"].as_array().unwrap().iter().any(|feature| feature == "file-requests"));
    }
}
