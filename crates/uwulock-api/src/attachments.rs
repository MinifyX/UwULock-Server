//! Files on items, the way Bitwarden's clients attach them.
//!
//! A client announces an attachment first (`attachment/v2`: its encrypted name, its key and its
//! size), gets back where to upload it, and uploads it there. Older clients upload in one step
//! (`attachment`). Downloads go by a link with a token, which the item's JSON carries and which a
//! client can ask for fresh.

use crate::auth::Session;
use crate::ciphers::{Found, cipher_json, find, found_json, json_text};
use crate::errors::{ApiError, ApiResult};
use crate::files::{self, LINK_SECONDS};
use crate::{AppState, json as out, notify};
use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_notify::Kind;
use uwulock_store::{Attachment, Cipher, Owner, clock};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/ciphers/{id}/attachment/v2", post(announce))
        .route("/api/ciphers/{id}/attachment/{attachment}", get(one).delete(delete))
        .route("/api/ciphers/{id}/attachment/{attachment}/renew", get(renew))
        .route("/api/ciphers/{id}/attachment/{attachment}/delete", post(delete))
        .route("/api/ciphers/{id}/attachment/{attachment}/delete-admin", post(delete))
        .route("/api/ciphers/{id}/attachment/{attachment}/admin", axum::routing::delete(delete))
        .route("/attachments/{id}/{attachment}", get(download))
}

/// Uploads: no body limit but the one for files, and no time limit but the connection's.
pub(crate) fn upload_routes() -> Router<AppState> {
    Router::new()
        .route("/api/ciphers/{id}/attachment/{attachment}", post(upload))
        .route("/api/ciphers/{id}/attachment", post(upload_legacy))
        .route("/api/ciphers/{id}/attachment-admin", post(upload_legacy))
}

/// Attachments as the clients read them, with a download link each that works for `seconds`.
pub(crate) fn render<'a>(
    state: &AppState,
    attachments: impl IntoIterator<Item = &'a Attachment>,
    seconds: i64,
) -> Value {
    Value::Array(attachments.into_iter().map(|attachment| render_one(state, attachment, seconds)).collect())
}

pub(crate) fn render_one(state: &AppState, attachment: &Attachment, seconds: i64) -> Value {
    let token = state.tokens.file_token(&format!("{}/{}", attachment.cipher_id, attachment.id), seconds);
    json!({
        "id": attachment.id,
        "url": format!("{}/attachments/{}/{}?token={token}", state.config.public, attachment.cipher_id, attachment.id),
        "fileName": attachment.file_name,
        "key": attachment.key,
        // A string: the phone apps read it as one.
        "size": attachment.size.to_string(),
        "sizeName": files::size_name(attachment.size),
        "object": "attachment",
    })
}

/// An item the user may attach to: their own, or an organisation's they may change. Whose it
/// is, and — for an organisation's — the collections it is in, for telling its members.
async fn changeable(state: &AppState, session: &Session, id: &str) -> ApiResult<(Cipher, Owner, Vec<String>)> {
    match find(state, session, id).await? {
        Found::Own(cipher) => Ok((cipher, Owner::User(session.user.id.clone()), Vec::new())),
        Found::Org(item) => {
            if item.access.read_only {
                return Err(ApiError::new(StatusCode::FORBIDDEN, "You don't have permission to change this item."));
            }
            let org = item.cipher.organization_id.clone().unwrap_or_default();
            Ok((item.cipher, Owner::Org(org), item.collection_ids))
        }
    }
}

/// The item as the user sees it now, after a change to its attachments; its readers hear of it.
async fn changed(state: &AppState, session: &Session, cipher: &Cipher, collections: &[String]) -> ApiResult<String> {
    match &cipher.organization_id {
        None => {
            notify::cipher(state, session, Kind::CipherUpdate, cipher);
            cipher_json(state, cipher).await
        }
        Some(org) => {
            let users = state.store.org_members_users(org).await?;
            crate::organizations::notify(state, session, Kind::CipherUpdate, cipher, collections, &users);
            let item = state
                .store
                .org_cipher(&session.user.id, &cipher.id)
                .await?
                .ok_or_else(|| ApiError::bad("Cipher doesn't exist"))?;
            crate::organizations::org_cipher_json(state, &item).await
        }
    }
}

async fn one(
    State(state): State<AppState>,
    session: Session,
    Path((id, attachment)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    find(&state, &session, &id).await?;
    let attachment = state
        .store
        .attachment(&id, &attachment)
        .await?
        .filter(|attachment| attachment.uploaded)
        .ok_or_else(|| ApiError::bad("Attachment doesn't exist"))?;
    Ok(Json(render_one(&state, &attachment, LINK_SECONDS)))
}

fn number_or_string<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    match Value::deserialize(deserializer)? {
        Value::Number(number) => number.as_i64().ok_or_else(|| serde::de::Error::custom("not a size")),
        Value::String(text) => text.trim().parse().map_err(|_| serde::de::Error::custom("not a size")),
        _ => Err(serde::de::Error::custom("not a size")),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Announce {
    key: String,
    file_name: String,
    #[serde(deserialize_with = "number_or_string")]
    file_size: i64,
    #[serde(default)]
    admin_request: Option<bool>,
    #[serde(default)]
    last_known_revision_date: Option<String>,
}

/// Where to upload an announced attachment, with the item as it is now.
fn upload_answer(cipher: &Cipher, attachment: &str, rendered: &str, admin: bool) -> Value {
    let mut answer = json!({
        "attachmentId": attachment,
        // Relative to the API, the way Bitwarden's server answers it for uploads it takes itself.
        "url": format!("/ciphers/{}/attachment/{attachment}", cipher.id),
        "fileUploadType": 0,
        "object": "attachment-fileUpload",
    });
    answer[if admin { "cipherMiniResponse" } else { "cipherResponse" }] =
        serde_json::from_str(rendered).unwrap_or(Value::Null);
    answer
}

async fn announce(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(data): Json<Announce>,
) -> ApiResult<Json<Value>> {
    let (cipher, owner, collections) = changeable(&state, &session, &id).await?;
    if let Some(known) = data.last_known_revision_date.as_deref().and_then(clock::parse)
        && let Some(stored) = clock::parse(&cipher.revision)
        && (stored - known).whole_seconds() > 1
    {
        return Err(ApiError::bad("The client copy of this cipher is out of date. Resync the client and try again."));
    }
    if data.file_size < 0 {
        return Err(ApiError::bad("Attachment size can't be negative"));
    }
    let limit = files::limit(&state);
    if data.file_size as u64 > limit {
        return Err(files::too_large(limit));
    }
    if data.file_name.len() > out::MAX_NOTE || data.key.len() > out::MAX_NOTE {
        return Err(ApiError::bad("The file name is too long."));
    }
    let attachment = Attachment {
        id: files::new_file_id(),
        cipher_id: cipher.id.clone(),
        file_name: data.file_name,
        key: Some(data.key),
        size: data.file_size,
        uploaded: false,
        created: clock::now(),
    };
    let attachment_id = attachment.id.clone();
    let cipher =
        state.store.add_attachment(&owner, attachment).await?.ok_or_else(|| ApiError::bad("Cipher doesn't exist"))?;
    let rendered = changed(&state, &session, &cipher, &collections).await?;
    Ok(Json(upload_answer(&cipher, &attachment_id, &rendered, data.admin_request == Some(true))))
}

/// Where to upload an announced attachment, asked again after the first try failed.
async fn renew(
    State(state): State<AppState>,
    session: Session,
    Path((id, attachment)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (cipher, ..) = changeable(&state, &session, &id).await?;
    let found =
        state.store.attachment(&id, &attachment).await?.ok_or_else(|| ApiError::bad("Attachment doesn't exist"))?;
    if found.uploaded {
        return Err(ApiError::bad("The attachment is uploaded already."));
    }
    let rendered = found_json(&state, &find(&state, &session, &id).await?).await?;
    Ok(Json(upload_answer(&cipher, &found.id, &rendered, false)))
}

/// Deviations from the announced size a client may upload: Bitwarden allows a MiB either way.
const LEEWAY: i64 = 1024 * 1024;

async fn upload(
    State(state): State<AppState>,
    session: Session,
    Path((id, attachment)): Path<(String, String)>,
    form: Multipart,
) -> ApiResult<StatusCode> {
    let (_, owner, collections) = changeable(&state, &session, &id).await?;
    let announced =
        state.store.attachment(&id, &attachment).await?.ok_or_else(|| ApiError::bad("Attachment doesn't exist"))?;
    if announced.uploaded {
        return Err(ApiError::bad("The attachment is uploaded already."));
    }
    let path = files::attachment_path(&state, &id, &attachment)?;
    let limit = files::limit(&state).min((announced.size + LEEWAY).max(0) as u64);
    let uploaded = files::receive(form, &path, limit).await?;
    if uploaded.size < announced.size - LEEWAY {
        files::discard(&path).await;
        return Err(ApiError::bad("The file is smaller than announced."));
    }
    files::keep(&path).await?;
    let cipher = state
        .store
        .attachment_uploaded(&owner, &id, &attachment, uploaded.size)
        .await?
        .ok_or_else(|| ApiError::bad("Cipher doesn't exist"))?;
    changed(&state, &session, &cipher, &collections).await?;
    Ok(StatusCode::OK)
}

/// The one-step upload of older clients: the key as a field, the encrypted name as the file's.
async fn upload_legacy(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    form: Multipart,
) -> ApiResult<Response> {
    let (_, owner, collections) = changeable(&state, &session, &id).await?;
    let attachment_id = files::new_file_id();
    let path = files::attachment_path(&state, &id, &attachment_id)?;
    let uploaded = files::receive(form, &path, files::limit(&state)).await?;
    let key = uploaded.fields.iter().find(|(name, _)| name == "key").map(|(_, key)| key.clone());
    let (Some(file_name), Some(key)) = (uploaded.file_name.filter(|name| !name.is_empty()), key) else {
        files::discard(&path).await;
        return Err(ApiError::bad("No file name or no key for the attachment."));
    };
    files::keep(&path).await?;
    let attachment = Attachment {
        id: attachment_id,
        cipher_id: id.clone(),
        file_name,
        key: Some(key),
        size: uploaded.size,
        uploaded: true,
        created: clock::now(),
    };
    let cipher =
        state.store.add_attachment(&owner, attachment).await?.ok_or_else(|| ApiError::bad("Cipher doesn't exist"))?;
    Ok(json_text(changed(&state, &session, &cipher, &collections).await?))
}

async fn delete(
    State(state): State<AppState>,
    session: Session,
    Path((id, attachment)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (_, owner, collections) = changeable(&state, &session, &id).await?;
    let cipher = state
        .store
        .delete_attachment(&owner, &id, &attachment)
        .await?
        .ok_or_else(|| ApiError::bad("Attachment doesn't exist"))?;
    let rendered: Value =
        serde_json::from_str(&changed(&state, &session, &cipher, &collections).await?).unwrap_or(Value::Null);
    Ok(Json(json!({ "cipher": rendered })))
}

#[derive(Deserialize)]
struct DownloadQuery {
    #[serde(default)]
    token: String,
}

/// The file, for whoever has a link with a token for it.
async fn download(
    State(state): State<AppState>,
    Path((id, attachment)): Path<(String, String)>,
    Query(query): Query<DownloadQuery>,
) -> ApiResult<Response> {
    if !state.tokens.check_file_token(&query.token, &format!("{id}/{attachment}")) {
        return Err(ApiError::unauthorized());
    }
    let found = state.store.attachment(&id, &attachment).await?.filter(|found| found.uploaded);
    if found.is_none() {
        return Err(ApiError::not_found("Attachment doesn't exist"));
    }
    files::serve(&files::attachment_path(&state, &id, &attachment)?).await
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::{Value, json};

    async fn item(server: &TestServer, token: &str) -> String {
        let body = json!({"type": 2, "name": "2.n|n|n", "secureNote": {"type": 0}});
        json(server.call("POST", "/api/ciphers", Some(token), body).await).await["id"].as_str().unwrap().to_string()
    }

    fn multipart(path: &str, token: &str, fields: &[(&str, &str)], file_name: &str, data: &[u8]) -> Request<Body> {
        let boundary = "uwulock-boundary";
        let mut body = Vec::new();
        for (name, value) in fields {
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"data\"; filename=\"{file_name}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        Request::post(path)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", format!("multipart/form-data; boundary={boundary}"))
            .body(Body::from(body))
            .unwrap()
    }

    async fn download(server: &TestServer, url: &str) -> (StatusCode, Vec<u8>) {
        let path = url.strip_prefix("https://vault.example.com").unwrap();
        let response = server.get(path).await;
        let status = response.status();
        (status, axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap().to_vec())
    }

    #[tokio::test]
    async fn an_attachment_is_announced_uploaded_synced_and_downloaded() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let id = item(&server, &account.token).await;
        let announce = json!({"key": "2.k|k|k", "fileName": "2.f|f|f", "fileSize": 5});
        let response =
            server.call("POST", &format!("/api/ciphers/{id}/attachment/v2"), Some(&account.token), announce).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        let answer = json(response).await;
        assert_eq!(answer["fileUploadType"], 0);
        assert_eq!(answer["cipherResponse"]["id"], id.as_str());
        let url = answer["url"].as_str().unwrap();
        assert!(url.starts_with(&format!("/ciphers/{id}/attachment/")), "{url}");

        let before = json(server.get_as(&account.token, "/api/sync").await).await;
        assert_eq!(before["ciphers"][0]["attachments"], json!(null), "nothing arrived yet");

        let upload = multipart(&format!("/api{url}"), &account.token, &[], "2.f|f|f", b"hello");
        let response = server.send(upload).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);

        let vault = json(server.get_as(&account.token, "/api/sync").await).await;
        let attachment = &vault["ciphers"][0]["attachments"][0];
        assert_eq!(attachment["fileName"], "2.f|f|f");
        assert_eq!(attachment["size"], "5");
        assert_eq!(attachment["key"], "2.k|k|k");
        let (status, body) = download(&server, attachment["url"].as_str().unwrap()).await;
        assert_eq!((status, body.as_slice()), (StatusCode::OK, b"hello".as_slice()));

        let path = format!("/api/ciphers/{id}/attachment/{}", attachment["id"].as_str().unwrap());
        let fresh = json(server.get_as(&account.token, &path).await).await;
        assert_eq!(download(&server, fresh["url"].as_str().unwrap()).await.0, StatusCode::OK);
        let (status, _) = download(&server, &fresh["url"].as_str().unwrap().replace("token=", "token=x")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let deleted = json(server.call("DELETE", &path, Some(&account.token), json!({})).await).await;
        assert_eq!(deleted["cipher"]["id"], id.as_str());
        let vault = json(server.get_as(&account.token, "/api/sync").await).await;
        assert_eq!(vault["ciphers"][0]["attachments"], json!(null));
    }

    #[tokio::test]
    async fn the_one_step_upload_of_older_clients() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let id = item(&server, &account.token).await;
        let upload = multipart(
            &format!("/api/ciphers/{id}/attachment"),
            &account.token,
            &[("key", "2.k|k|k")],
            "2.n|n|n",
            b"abc",
        );
        let response = server.send(upload).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        let cipher: Value = json(response).await;
        assert_eq!(cipher["attachments"][0]["fileName"], "2.n|n|n");
        assert_eq!(cipher["attachments"][0]["size"], "3");
    }

    #[tokio::test]
    async fn too_large_or_foreign_uploads_are_refused() {
        let settings = crate::Settings { max_file_mb: 1, ..crate::Settings::default() };
        let server = TestServer::with_settings(settings).await;
        let nyu = server.account("nyu@example.com").await;
        let other = server.account("other@example.com").await;
        let id = item(&server, &nyu.token).await;
        let big = json!({"key": "2.k|k|k", "fileName": "2.f|f|f", "fileSize": 2 * 1024 * 1024});
        let response = server.call("POST", &format!("/api/ciphers/{id}/attachment/v2"), Some(&nyu.token), big).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let small = json!({"key": "2.k|k|k", "fileName": "2.f|f|f", "fileSize": 3});
        let response =
            server.call("POST", &format!("/api/ciphers/{id}/attachment/v2"), Some(&other.token), small.clone()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "not their item");

        let answer =
            json(server.call("POST", &format!("/api/ciphers/{id}/attachment/v2"), Some(&nyu.token), small).await).await;
        let url = format!("/api{}", answer["url"].as_str().unwrap());
        let foreign = server.send(multipart(&url, &other.token, &[], "f", b"abc")).await;
        assert_eq!(foreign.status(), StatusCode::BAD_REQUEST);
        let too_big = server.send(multipart(&url, &nyu.token, &[], "f", &vec![0u8; 1024 * 1024 + 10])).await;
        assert_eq!(too_big.status(), StatusCode::BAD_REQUEST);
        let fine = server.send(multipart(&url, &nyu.token, &[], "f", b"abc")).await;
        assert_eq!(fine.status(), StatusCode::OK);
        let again = server.send(multipart(&url, &nyu.token, &[], "f", b"abc")).await;
        assert_eq!(again.status(), StatusCode::BAD_REQUEST, "once");
    }
}
