//! `/api/sync` and `/api/ciphers`: the whole vault at once, and items one by one or many at a
//! time — new, changed, into the trash and out, archived, moved, imported, gone.
//!
//! A save that carries the revision the client last saw is refused when the server has a newer
//! one, so an older copy never overwrites a newer one written elsewhere.

use crate::accounts::check_password;
use crate::auth::{Session, client_version};
use crate::errors::{ApiError, ApiResult};
use crate::{AppState, json as out};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use std::collections::HashMap;
use uwulock_store::{Bulk, Cipher, Folder, clock};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/sync", get(sync))
        .route("/api/ciphers", get(list).post(create).delete(bulk_delete))
        .route("/api/ciphers/create", post(create_wrapped))
        .route("/api/ciphers/admin", post(create_wrapped).delete(bulk_delete))
        .route("/api/ciphers/delete", post(bulk_delete).put(bulk_trash))
        .route("/api/ciphers/delete-admin", post(bulk_delete).put(bulk_trash))
        .route("/api/ciphers/restore", put(bulk_restore))
        .route("/api/ciphers/restore-admin", put(bulk_restore))
        .route("/api/ciphers/archive", put(bulk_archive))
        .route("/api/ciphers/unarchive", put(bulk_unarchive))
        .route("/api/ciphers/move", post(move_ciphers).put(move_ciphers))
        .route("/api/ciphers/purge", post(purge))
        .route("/api/ciphers/{id}", get(one).put(update).post(update).delete(hard_delete))
        .route("/api/ciphers/{id}/details", get(one))
        .route("/api/ciphers/{id}/admin", get(one).put(update).post(update).delete(hard_delete))
        .route("/api/ciphers/{id}/partial", put(partial).post(partial))
        .route("/api/ciphers/{id}/delete", put(trash).post(hard_delete))
        .route("/api/ciphers/{id}/delete-admin", put(trash).post(hard_delete))
        .route("/api/ciphers/{id}/restore", put(restore))
        .route("/api/ciphers/{id}/restore-admin", put(restore))
        .route("/api/ciphers/{id}/archive", put(archive))
        .route("/api/ciphers/{id}/unarchive", put(unarchive))
        .route("/api/ciphers/{id}/attachment/v2", post(no_attachments))
}

/// What brings a whole vault along, and may be large.
pub(crate) fn vault_routes() -> Router<AppState> {
    Router::new().route("/api/ciphers/import", post(import))
}

fn json_text(body: String) -> Response {
    ([(header::CONTENT_TYPE, "application/json; charset=utf-8")], body).into_response()
}

fn empty_as_none<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.filter(|text| !text.trim().is_empty()))
}

/// An item as the clients send it, for a new one, a change, an import or a key rotation.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CipherData {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "empty_as_none")]
    folder_id: Option<String>,
    #[serde(default, alias = "organizationID", deserialize_with = "empty_as_none")]
    organization_id: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    encrypted_for: Option<String>,
    #[serde(rename = "type")]
    kind: i64,
    name: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    fields: Option<Value>,
    #[serde(default)]
    login: Option<Value>,
    #[serde(default)]
    secure_note: Option<Value>,
    #[serde(default)]
    card: Option<Value>,
    #[serde(default)]
    identity: Option<Value>,
    #[serde(default)]
    ssh_key: Option<Value>,
    #[serde(default)]
    bank_account: Option<Value>,
    #[serde(default)]
    drivers_license: Option<Value>,
    #[serde(default)]
    passport: Option<Value>,
    #[serde(default)]
    favorite: Option<bool>,
    #[serde(default)]
    reprompt: Option<Value>,
    #[serde(default)]
    password_history: Option<Value>,
    #[serde(default)]
    last_known_revision_date: Option<String>,
    #[serde(default)]
    archived_date: Option<String>,
}

impl CipherData {
    fn type_object(&mut self) -> Option<Value> {
        match self.kind {
            1 => self.login.take(),
            2 => self.secure_note.take(),
            3 => self.card.take(),
            4 => self.identity.take(),
            5 => self.ssh_key.take(),
            6 => self.bank_account.take(),
            7 => self.drivers_license.take(),
            8 => self.passport.take(),
            _ => None,
        }
    }
}

/// `data` over `into`: everything an item is, except its id, owner and times.
pub(crate) fn apply(mut data: CipherData, mut into: Cipher) -> ApiResult<Cipher> {
    if data.organization_id.is_some() {
        return Err(ApiError::bad("Organisations are not available on this server yet."));
    }
    if out::type_key(data.kind).is_none() {
        return Err(ApiError::bad("Invalid type"));
    }
    if data.notes.as_ref().is_some_and(|notes| notes.len() > out::MAX_NOTE) {
        return Err(ApiError::bad("The field Notes exceeds the maximum encrypted value length of 10000 characters."));
    }
    let object = data.type_object();
    into.data = out::type_data(data.kind, object)?;
    into.kind = data.kind;
    into.name = data.name;
    into.notes = data.notes.filter(|notes| !notes.is_empty());
    into.key = data.key;
    into.fields = out::fields(data.fields);
    into.password_history = out::password_history(data.password_history);
    into.reprompt = match data.reprompt {
        Some(Value::Number(number)) if number.as_i64() == Some(1) => 1,
        Some(Value::String(text)) if text == "1" => 1,
        _ => 0,
    };
    into.folder_id = data.folder_id;
    if let Some(favorite) = data.favorite {
        into.favorite = favorite;
    }
    // Left out means not archived: Bitwarden's clients send what they have.
    into.archived = data.archived_date.as_deref().and_then(clock::parse).map(clock::format);
    Ok(into)
}

/// Checked before an import or a rotation writes anything: every item has to fit.
pub(crate) fn validate_batch(ciphers: &[CipherData]) -> ApiResult<()> {
    let mut errors = serde_json::Map::new();
    for (index, cipher) in ciphers.iter().enumerate() {
        if cipher.notes.as_ref().is_some_and(|notes| notes.len() > out::MAX_NOTE) {
            errors.insert(
                format!("Ciphers[{index}].Notes"),
                json!(["The field Notes exceeds the maximum encrypted value length of 10000 characters."]),
            );
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(ApiError::validation(errors)) }
}

fn new_cipher(user_id: &str) -> Cipher {
    let now = clock::now();
    Cipher {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        folder_id: None,
        kind: 1,
        name: String::new(),
        notes: None,
        key: None,
        data: "{}".into(),
        fields: None,
        password_history: None,
        favorite: false,
        reprompt: 0,
        created: now.clone(),
        revision: now,
        deleted: None,
        archived: None,
    }
}

async fn save(state: &AppState, cipher: Cipher) -> ApiResult<Cipher> {
    state.store.save_cipher(cipher).await?.ok_or_else(|| ApiError::bad("Invalid folder"))
}

async fn owned(state: &AppState, session: &Session, id: &str) -> ApiResult<Cipher> {
    state.store.cipher(&session.user.id, id).await?.ok_or_else(|| ApiError::bad("Cipher doesn't exist"))
}

// ── The whole vault ───────────────────────────────────────

#[derive(Deserialize)]
struct SyncQuery {
    #[serde(default, rename = "excludeDomains")]
    exclude_domains: Option<String>,
}

/// Everything, as one JSON: profile, folders, items (the trashed ones too), domains, and how the
/// user key is unlocked. Built as text, most of it copied from the database as it is.
async fn sync(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Query(query): Query<SyncQuery>,
) -> ApiResult<Response> {
    let user = &session.user;
    let (vault, two_factor) = tokio::try_join!(state.store.vault(&user.id), state.store.two_factors(&user.id))?;
    // SSH keys only for clients that know them; older ones break on them.
    let ssh = client_version(&headers).is_some_and(|version| version >= (2024, 12, 0));
    let exclude_domains = query
        .exclude_domains
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on"));

    let mut body = String::with_capacity(4096 + vault.ciphers.len() * 1200);
    body.push_str("{\"object\":\"sync\",\"profile\":");
    body.push_str(&out::profile(user, two_factor.iter().any(|factor| factor.enabled)).to_string());
    body.push_str(",\"folders\":");
    body.push_str(&Value::Array(vault.folders.iter().map(out::folder).collect()).to_string());
    body.push_str(",\"collections\":[],\"policies\":[],\"policiesNew\":[],\"sends\":[],\"ciphers\":[");
    let mut first = true;
    for cipher in vault.ciphers.iter().filter(|cipher| ssh || cipher.kind != 5) {
        if !first {
            body.push(',');
        }
        first = false;
        out::write_cipher(&mut body, cipher);
    }
    body.push_str("],\"domains\":");
    body.push_str(&if exclude_domains { Value::Null } else { crate::meta::domains(user, false) }.to_string());
    body.push_str(",\"userDecryption\":");
    body.push_str(
        &json!({
            "masterPasswordUnlock": {
                "kdf": out::kdf(user),
                "masterKeyEncryptedUserKey": user.user_key,
                "masterKeyWrappedUserKey": user.user_key,
                "salt": user.email,
            },
            "userKeyId": null,
        })
        .to_string(),
    );
    body.push('}');
    Ok(json_text(body))
}

async fn list(State(state): State<AppState>, session: Session) -> ApiResult<Response> {
    let ciphers = state.store.ciphers(&session.user.id).await?;
    Ok(json_text(out::cipher_list(&ciphers)))
}

async fn one(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Response> {
    Ok(json_text(out::cipher(&owned(&state, &session, &id).await?)))
}

// ── New and changed items ─────────────────────────────────

fn check_encrypted_for(session: &Session, data: &CipherData) -> ApiResult<()> {
    match &data.encrypted_for {
        Some(owner) if owner != &session.user.id => {
            Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "Invalid user cipher"))
        }
        _ => Ok(()),
    }
}

async fn create(State(state): State<AppState>, session: Session, Json(data): Json<CipherData>) -> ApiResult<Response> {
    check_encrypted_for(&session, &data)?;
    let cipher = apply(data, new_cipher(&session.user.id))?;
    Ok(json_text(out::cipher(&save(&state, cipher).await?)))
}

#[derive(Deserialize)]
struct Wrapped {
    #[serde(alias = "Cipher")]
    cipher: CipherData,
    #[serde(default, rename = "collectionIds", alias = "CollectionIds")]
    collection_ids: Vec<String>,
}

/// A new item that could belong to an organisation — and a copy of an item, which the clients
/// send this way too.
async fn create_wrapped(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<Wrapped>,
) -> ApiResult<Response> {
    if !data.collection_ids.is_empty() {
        return Err(ApiError::bad("Organisations are not available on this server yet."));
    }
    check_encrypted_for(&session, &data.cipher)?;
    let cipher = apply(data.cipher, new_cipher(&session.user.id))?;
    Ok(json_text(out::cipher(&save(&state, cipher).await?)))
}

async fn update(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(data): Json<CipherData>,
) -> ApiResult<Response> {
    let current = owned(&state, &session, &id).await?;
    if let Some(known) = data.last_known_revision_date.as_deref().and_then(clock::parse)
        && let Some(stored) = clock::parse(&current.revision)
        && (stored - known).whole_seconds() > 1
    {
        return Err(ApiError::bad("The client copy of this cipher is out of date. Resync the client and try again."));
    }
    let cipher = apply(data, current)?;
    Ok(json_text(out::cipher(&save(&state, cipher).await?)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Partial {
    #[serde(default, deserialize_with = "empty_as_none")]
    folder_id: Option<String>,
    favorite: bool,
}

/// Only the folder and the favourite star, which are the user's and not encrypted.
async fn partial(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(data): Json<Partial>,
) -> ApiResult<Response> {
    let mut cipher =
        state.store.cipher(&session.user.id, &id).await?.ok_or_else(|| ApiError::bad("Cipher does not exist"))?;
    cipher.folder_id = data.folder_id;
    cipher.favorite = data.favorite;
    Ok(json_text(out::cipher(&save(&state, cipher).await?)))
}

#[derive(Deserialize)]
struct Relationship {
    key: usize,
    value: usize,
}

#[derive(Deserialize)]
struct ImportFolder {
    name: String,
    #[serde(default, deserialize_with = "empty_as_none")]
    id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Import {
    ciphers: Vec<CipherData>,
    folders: Vec<ImportFolder>,
    folder_relationships: Vec<Relationship>,
}

/// A whole export at once: new folders, and items in them. All of it, or — if one item does not
/// fit — none.
async fn import(State(state): State<AppState>, session: Session, Json(data): Json<Import>) -> ApiResult<StatusCode> {
    validate_batch(&data.ciphers)?;
    let user = &session.user;
    let existing: Vec<String> = state.store.folders(&user.id).await?.into_iter().map(|folder| folder.id).collect();
    let now = clock::now();
    let mut new_folders = Vec::new();
    let folder_ids: Vec<String> = data
        .folders
        .into_iter()
        .map(|folder| match folder.id.filter(|id| existing.contains(id)) {
            Some(id) => id,
            None => {
                let id = uuid::Uuid::new_v4().to_string();
                new_folders.push(Folder {
                    id: id.clone(),
                    user_id: user.id.clone(),
                    name: folder.name,
                    created: now.clone(),
                    revision: now.clone(),
                });
                id
            }
        })
        .collect();
    let in_folder: HashMap<usize, usize> =
        data.folder_relationships.into_iter().map(|link| (link.key, link.value)).collect();
    let mut ciphers = Vec::with_capacity(data.ciphers.len());
    for (index, item) in data.ciphers.into_iter().enumerate() {
        let mut cipher = apply(item, new_cipher(&user.id))?;
        cipher.folder_id = in_folder.get(&index).and_then(|folder| folder_ids.get(*folder)).cloned();
        ciphers.push(cipher);
    }
    let count = ciphers.len();
    state.store.import(&user.id, new_folders, ciphers).await?;
    tracing::info!(user = %user.id, items = count, "vault imported");
    Ok(StatusCode::OK)
}

// ── Trash, archive, delete, move ──────────────────────────

#[derive(Deserialize)]
struct Ids {
    ids: Vec<String>,
}

async fn single(state: &AppState, session: &Session, id: String, what: Bulk) -> ApiResult<()> {
    if state.store.bulk(&session.user.id, vec![id], what).await?.is_empty() {
        return Err(ApiError::bad("Cipher doesn't exist"));
    }
    Ok(())
}

async fn trash(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<StatusCode> {
    single(&state, &session, id, Bulk::Trash).await.map(|()| StatusCode::OK)
}

async fn hard_delete(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<StatusCode> {
    single(&state, &session, id, Bulk::Delete).await.map(|()| StatusCode::OK)
}

async fn restore(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Response> {
    single(&state, &session, id.clone(), Bulk::Restore).await?;
    Ok(json_text(out::cipher(&owned(&state, &session, &id).await?)))
}

async fn archive(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Response> {
    single(&state, &session, id.clone(), Bulk::Archive).await?;
    Ok(json_text(out::cipher(&owned(&state, &session, &id).await?)))
}

async fn unarchive(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Response> {
    single(&state, &session, id.clone(), Bulk::Unarchive).await?;
    Ok(json_text(out::cipher(&owned(&state, &session, &id).await?)))
}

async fn bulk_trash(State(state): State<AppState>, session: Session, Json(data): Json<Ids>) -> ApiResult<StatusCode> {
    state.store.bulk(&session.user.id, data.ids, Bulk::Trash).await?;
    Ok(StatusCode::OK)
}

async fn bulk_delete(State(state): State<AppState>, session: Session, Json(data): Json<Ids>) -> ApiResult<StatusCode> {
    state.store.bulk(&session.user.id, data.ids, Bulk::Delete).await?;
    Ok(StatusCode::OK)
}

/// Several at once, answered with the items as they are afterwards.
async fn bulk_listed(state: &AppState, session: &Session, ids: Vec<String>, what: Bulk) -> ApiResult<Response> {
    let done = state.store.bulk(&session.user.id, ids, what).await?;
    let ciphers: Vec<Cipher> =
        state.store.ciphers(&session.user.id).await?.into_iter().filter(|cipher| done.contains(&cipher.id)).collect();
    Ok(json_text(out::cipher_list(&ciphers)))
}

async fn bulk_restore(State(state): State<AppState>, session: Session, Json(data): Json<Ids>) -> ApiResult<Response> {
    bulk_listed(&state, &session, data.ids, Bulk::Restore).await
}

async fn bulk_archive(State(state): State<AppState>, session: Session, Json(data): Json<Ids>) -> ApiResult<Response> {
    bulk_listed(&state, &session, data.ids, Bulk::Archive).await
}

async fn bulk_unarchive(State(state): State<AppState>, session: Session, Json(data): Json<Ids>) -> ApiResult<Response> {
    bulk_listed(&state, &session, data.ids, Bulk::Unarchive).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Move {
    #[serde(default, deserialize_with = "empty_as_none")]
    folder_id: Option<String>,
    ids: Vec<String>,
}

async fn move_ciphers(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<Move>,
) -> ApiResult<StatusCode> {
    let wanted = data.ids.len();
    let moved = state
        .store
        .move_ciphers(&session.user.id, data.ids, data.folder_id)
        .await?
        .ok_or_else(|| ApiError::bad("Invalid folder"))?;
    if moved < wanted {
        return Err(ApiError::bad(format!("Not all ciphers are moved! {moved} of the selected {wanted} were moved.")));
    }
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Purge {
    #[serde(default)]
    master_password_hash: Option<String>,
}

#[derive(Deserialize)]
struct PurgeQuery {
    #[serde(default, rename = "organizationId")]
    organization_id: Option<String>,
}

/// Every item and folder gone, after the master password.
async fn purge(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<PurgeQuery>,
    Json(data): Json<Purge>,
) -> ApiResult<StatusCode> {
    if query.organization_id.is_some() {
        return Err(ApiError::bad("Organisations are not available on this server yet."));
    }
    check_password(&state, &session.user, data.master_password_hash.as_deref()).await?;
    state.store.purge_vault(&session.user.id).await?;
    tracing::info!(user = %session.user.id, "vault emptied");
    Ok(StatusCode::OK)
}

async fn no_attachments() -> ApiError {
    ApiError::bad("Attachments are not available on this server yet.")
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::http::StatusCode;
    use serde_json::{Value, json};

    fn login_item(name: &str) -> Value {
        json!({
            "type": 1,
            "name": name,
            "notes": null,
            "favorite": false,
            "reprompt": 0,
            "folderId": null,
            "organizationId": null,
            "login": {"username": "2.u|u|u", "password": "2.p|p|p", "uris": [{"uri": "2.https|x|x", "match": null}], "totp": null},
            "fields": [{"name": "2.f|f|f", "value": "2.v|v|v", "type": 1}],
            "passwordHistory": null,
        })
    }

    async fn sync(server: &TestServer, token: &str) -> Value {
        let request = axum::http::Request::get("/api/sync")
            .header("authorization", format!("Bearer {token}"))
            .header("bitwarden-client-version", "2026.9.0")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = server.send(request).await;
        assert_eq!(response.status(), StatusCode::OK);
        json(response).await
    }

    #[tokio::test]
    async fn an_item_from_creation_to_the_trash_and_back() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let created = server.call("POST", "/api/ciphers", Some(&account.token), login_item("2.first|a|b")).await;
        assert_eq!(created.status(), StatusCode::OK, "{}", text(created).await);
        let created = json(created).await;
        let id = created["id"].as_str().unwrap().to_string();
        assert_eq!(created["login"]["uri"], "2.https|x|x");
        assert_eq!(created["fields"][0]["type"], 1);

        let vault = sync(&server, &account.token).await;
        assert_eq!(vault["object"], "sync");
        assert_eq!(vault["profile"]["email"], "nyu@example.com");
        assert_eq!(vault["ciphers"].as_array().unwrap().len(), 1);
        assert_eq!(vault["userDecryption"]["masterPasswordUnlock"]["salt"], "nyu@example.com");
        assert!(vault["domains"]["globalEquivalentDomains"].as_array().unwrap().len() > 50);

        let mut changed = login_item("2.second|a|b");
        changed["lastKnownRevisionDate"] = created["revisionDate"].clone();
        let response = server.call("PUT", &format!("/api/ciphers/{id}"), Some(&account.token), changed).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json(response).await["name"], "2.second|a|b");

        let mut stale = login_item("2.third|a|b");
        stale["lastKnownRevisionDate"] = json!("2020-01-01T00:00:00.000Z");
        let response = server.call("PUT", &format!("/api/ciphers/{id}"), Some(&account.token), stale).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "an old copy does not win");

        let response = server.call("PUT", &format!("/api/ciphers/{id}/delete"), Some(&account.token), json!({})).await;
        assert_eq!(response.status(), StatusCode::OK);
        let vault = sync(&server, &account.token).await;
        assert!(vault["ciphers"][0]["deletedDate"].is_string(), "the trash is in the sync");
        let restored =
            json(server.call("PUT", &format!("/api/ciphers/{id}/restore"), Some(&account.token), json!({})).await)
                .await;
        assert!(restored["deletedDate"].is_null());

        let archived =
            json(server.call("PUT", &format!("/api/ciphers/{id}/archive"), Some(&account.token), json!({})).await)
                .await;
        assert!(archived["archivedDate"].is_string());

        let response = server.call("POST", &format!("/api/ciphers/{id}/delete"), Some(&account.token), json!({})).await;
        assert_eq!(response.status(), StatusCode::OK, "POST is for good");
        assert!(sync(&server, &account.token).await["ciphers"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn items_of_somebody_else_stay_theirs() {
        let server = TestServer::new().await;
        let nyu = server.account("nyu@example.com").await;
        let other = server.account("other@example.com").await;
        let id = json(server.call("POST", "/api/ciphers", Some(&nyu.token), login_item("2.n|a|b")).await).await["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(server.get_as(&other.token, &format!("/api/ciphers/{id}")).await.status(), StatusCode::BAD_REQUEST);
        let response =
            server.call("PUT", &format!("/api/ciphers/{id}"), Some(&other.token), login_item("2.x|x|x")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = server.call("DELETE", "/api/ciphers", Some(&other.token), json!({"ids": [id]})).await;
        assert_eq!(response.status(), StatusCode::OK, "nothing of theirs to delete");
        assert_eq!(sync(&server, &nyu.token).await["ciphers"].as_array().unwrap().len(), 1);
        let mut foreign = login_item("2.x|x|x");
        foreign["encryptedFor"] = json!(nyu.id);
        let response = server.call("POST", "/api/ciphers", Some(&other.token), foreign).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn an_import_brings_folders_along_or_nothing() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let mut too_long = login_item("2.b|a|b");
        too_long["notes"] = json!("x".repeat(10_001));
        let bad = json!({"ciphers": [login_item("2.a|a|b"), too_long], "folders": [], "folderRelationships": []});
        let response = server.call("POST", "/api/ciphers/import", Some(&account.token), bad).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(json(response).await["validationErrors"]["Ciphers[1].Notes"].is_array());
        assert!(sync(&server, &account.token).await["ciphers"].as_array().unwrap().is_empty());

        let good = json!({
            "ciphers": [login_item("2.a|a|b"), login_item("2.b|a|b"), {"type": 2, "name": "2.note|a|b", "secureNote": {"type": 0}}],
            "folders": [{"name": "2.work|a|b"}],
            "folderRelationships": [{"key": 1, "value": 0}],
        });
        let response = server.call("POST", "/api/ciphers/import", Some(&account.token), good).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        let vault = sync(&server, &account.token).await;
        let folder = vault["folders"][0]["id"].as_str().unwrap();
        let in_folder = vault["ciphers"].as_array().unwrap().iter().filter(|c| c["folderId"] == folder).count();
        assert_eq!((vault["ciphers"].as_array().unwrap().len(), in_folder), (3, 1));
    }

    #[tokio::test]
    async fn moving_and_purging() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let folder =
            json(server.call("POST", "/api/folders", Some(&account.token), json!({"name": "2.f|f|f"})).await).await;
        let folder = folder["id"].as_str().unwrap();
        let mut ids = Vec::new();
        for name in ["2.a|a|a", "2.b|b|b"] {
            ids.push(
                json(server.call("POST", "/api/ciphers", Some(&account.token), login_item(name)).await).await["id"]
                    .clone(),
            );
        }
        let response = server
            .call("POST", "/api/ciphers/move", Some(&account.token), json!({"folderId": folder, "ids": ids}))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let vault = sync(&server, &account.token).await;
        assert!(vault["ciphers"].as_array().unwrap().iter().all(|c| c["folderId"] == folder));

        let wrong = json!({"masterPasswordHash": "wrong"});
        assert_eq!(
            server.call("POST", "/api/ciphers/purge", Some(&account.token), wrong).await.status(),
            StatusCode::BAD_REQUEST
        );
        let right = json!({"masterPasswordHash": password_hash("nyu@example.com")});
        assert_eq!(
            server.call("POST", "/api/ciphers/purge", Some(&account.token), right).await.status(),
            StatusCode::OK
        );
        let vault = sync(&server, &account.token).await;
        assert!(vault["ciphers"].as_array().unwrap().is_empty() && vault["folders"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn older_clients_do_not_get_ssh_keys() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let ssh = json!({"type": 5, "name": "2.k|k|k", "sshKey": {"privateKey": "2.a|a|a", "publicKey": "2.b|b|b", "keyFingerprint": "2.c|c|c"}});
        assert_eq!(server.call("POST", "/api/ciphers", Some(&account.token), ssh).await.status(), StatusCode::OK);
        assert_eq!(sync(&server, &account.token).await["ciphers"].as_array().unwrap().len(), 1);
        let old = json(server.get_as(&account.token, "/api/sync").await).await;
        assert!(old["ciphers"].as_array().unwrap().is_empty(), "no version header, no SSH keys");
    }

    #[tokio::test]
    async fn organisations_are_refused_for_now() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let mut item = login_item("2.a|a|a");
        item["organizationId"] = json!("5f7c2a1e-0000-4000-8000-000000000000");
        assert_eq!(
            server.call("POST", "/api/ciphers", Some(&account.token), item).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
}
