//! Organisations in the vault: what the sync shows of them, and their members saving items where
//! their collections let them — moving an item of their own in, too. Making and managing them is
//! in `families`, `org_members` and `org_collections`.

use crate::auth::Session;
use crate::ciphers::{CipherData, apply, json_text};
use crate::errors::{ApiError, ApiResult};
use crate::json::View;
use crate::{AppState, json as out};
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use uwulock_notify::{Kind, Subject, Update};
use uwulock_store::organizations::{Collection, Policy};
use uwulock_store::{Access, Attachment, Cipher, OrgCipher};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/collections", get(collections))
        .route("/api/organizations", get(organizations))
        .route("/api/ciphers/share", post(share_many).put(share_many))
        .route("/api/ciphers/{id}/share", post(share).put(share))
        .route("/api/ciphers/{id}/collections", post(set_collections).put(set_collections))
        .route("/api/ciphers/{id}/collections_v2", post(set_collections_v2).put(set_collections_v2))
        .route("/api/ciphers/{id}/collections-admin", post(set_collections).put(set_collections))
}

pub(crate) fn collection_json(collection: &Collection, access: &Access) -> Value {
    json!({
        "id": collection.id,
        "organizationId": collection.org_id,
        "name": collection.name,
        "externalId": collection.external_id,
        "readOnly": access.read_only,
        "hidePasswords": access.hide_passwords,
        "manage": access.manage,
        "object": "collectionDetails",
    })
}

pub(crate) fn policy_json(policy: &Policy) -> Value {
    json!({
        "id": policy.id,
        "organizationId": policy.org_id,
        "type": policy.kind,
        "data": policy.data.as_deref().and_then(|data| serde_json::from_str::<Value>(data).ok()),
        "enabled": policy.enabled,
        "object": "policy",
    })
}

/// The organisations the user is in, as the profile carries them.
pub(crate) async fn profile_organizations(state: &AppState, user_id: &str) -> ApiResult<Vec<Value>> {
    let vault = state.store.org_vault(user_id).await?;
    Ok(vault
        .memberships
        .iter()
        .map(|(org, member)| crate::families::profile_organization(state, org, member))
        .collect())
}

/// Attachments of organisations' items, as JSON by item id.
pub(crate) async fn attachments_of(state: &AppState, ciphers: &[OrgCipher]) -> ApiResult<HashMap<String, String>> {
    if ciphers.is_empty() {
        return Ok(HashMap::new());
    }
    let ids = ciphers.iter().map(|item| item.cipher.id.clone()).collect();
    let mut grouped: HashMap<String, Vec<Attachment>> = HashMap::new();
    for attachment in state.store.attachments_of(ids).await? {
        grouped.entry(attachment.cipher_id.clone()).or_default().push(attachment);
    }
    Ok(grouped
        .into_iter()
        .map(|(id, list)| (id, crate::attachments::render(state, &list, crate::files::SYNC_LINK_SECONDS).to_string()))
        .collect())
}

/// An organisation's item as the clients read it, for the user who asked.
pub(crate) async fn org_cipher_json(state: &AppState, item: &OrgCipher) -> ApiResult<String> {
    let attachments = state.store.attachments(&item.cipher.id).await?;
    let rendered = (!attachments.is_empty())
        .then(|| crate::attachments::render(state, &attachments, crate::files::SYNC_LINK_SECONDS).to_string());
    Ok(out::cipher(
        &item.cipher,
        &View { attachments: rendered.as_deref(), collection_ids: &item.collection_ids, access: item.access },
    ))
}

/// Tell every member who can see it that an organisation's item changed.
pub(crate) fn notify(
    state: &AppState,
    session: &Session,
    kind: Kind,
    cipher: &Cipher,
    collections: &[String],
    users: &[String],
) {
    for user in users {
        crate::notify::publish(
            state,
            Update {
                kind,
                user_id: user.clone(),
                subject: Subject::Cipher {
                    id: cipher.id.clone(),
                    organization_id: cipher.organization_id.clone(),
                    collection_ids: Some(collections.to_vec()),
                    revision: cipher.revision.clone(),
                },
                acting_device: Some(session.device.clone()),
            },
        );
    }
}

/// Refused unless the user may put items into every one of `collection_ids` of `org_id`, and
/// there is at least one.
pub(crate) async fn check_collections(
    state: &AppState,
    session: &Session,
    org_id: &str,
    collection_ids: &[String],
) -> ApiResult<()> {
    if collection_ids.is_empty() {
        return Err(ApiError::bad("An item of an organisation has to be in at least one collection."));
    }
    let writable = state.store.writable_collections(&session.user.id, org_id).await?;
    if collection_ids.iter().any(|id| !writable.contains(id)) {
        return Err(ApiError::bad("You cannot put items into one of these collections."));
    }
    Ok(())
}

async fn collections(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let vault = state.store.org_vault(&session.user.id).await?;
    Ok(Json(out::list(
        vault.collections.iter().map(|(collection, access)| collection_json(collection, access)).collect(),
    )))
}

async fn organizations(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    Ok(Json(out::list(profile_organizations(&state, &session.user.id).await?)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Share {
    #[serde(alias = "Cipher")]
    cipher: CipherData,
    #[serde(default, alias = "CollectionIds")]
    collection_ids: Vec<String>,
}

/// Move one of the user's items into an organisation: the client encrypted it again under the
/// organisation's key.
async fn share_one(state: &AppState, session: &Session, id: &str, data: Share) -> ApiResult<Cipher> {
    let current =
        state.store.cipher(&session.user.id, id).await?.ok_or_else(|| ApiError::bad("Cipher doesn't exist"))?;
    let org = data.cipher.organization_id().ok_or_else(|| ApiError::bad("Organization id not provided"))?;
    check_collections(state, session, &org, &data.collection_ids).await?;
    let keys = data.cipher.attachment_keys();
    let mut moved = apply(data.cipher, current, Some(&org))?;
    moved.organization_id = Some(org);
    let (saved, users) = state
        .store
        .share_cipher(&session.user.id, moved, data.collection_ids.clone(), keys)
        .await?
        .ok_or_else(|| ApiError::bad("Cipher doesn't exist"))?;
    notify(state, session, Kind::CipherUpdate, &saved, &data.collection_ids, &users);
    Ok(saved)
}

async fn share(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(data): Json<Share>,
) -> ApiResult<Response> {
    let saved = share_one(&state, &session, &id, data).await?;
    let item = state
        .store
        .org_cipher(&session.user.id, &saved.id)
        .await?
        .ok_or_else(|| ApiError::bad("Cipher doesn't exist"))?;
    Ok(json_text(org_cipher_json(&state, &item).await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShareMany {
    ciphers: Vec<CipherData>,
    collection_ids: Vec<String>,
}

async fn share_many(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<ShareMany>,
) -> ApiResult<Json<Value>> {
    crate::ciphers::validate_batch(&data.ciphers)?;
    let mut shared = Vec::new();
    for cipher in data.ciphers {
        let id = cipher.id.clone().ok_or_else(|| ApiError::bad("Cipher doesn't exist"))?;
        let saved =
            share_one(&state, &session, &id, Share { cipher, collection_ids: data.collection_ids.clone() }).await?;
        shared.push(saved.id);
    }
    let mut data = Vec::new();
    for id in shared {
        if let Some(item) = state.store.org_cipher(&session.user.id, &id).await? {
            data.push(serde_json::from_str::<Value>(&org_cipher_json(&state, &item).await?).unwrap_or(Value::Null));
        }
    }
    Ok(Json(out::list(data)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Collections {
    collection_ids: Vec<String>,
}

async fn change_collections(state: &AppState, session: &Session, id: &str, ids: Vec<String>) -> ApiResult<OrgCipher> {
    let item =
        state.store.org_cipher(&session.user.id, id).await?.ok_or_else(|| ApiError::bad("Cipher doesn't exist"))?;
    if item.access.read_only {
        return Err(ApiError::bad("You cannot change this item."));
    }
    let org = item.cipher.organization_id.clone().unwrap_or_default();
    // What the user cannot reach stays as it is; what they can, they choose.
    let writable = state.store.writable_collections(&session.user.id, &org).await?;
    let mut target: Vec<String> = item.collection_ids.iter().filter(|id| !writable.contains(*id)).cloned().collect();
    for id in ids {
        if !writable.contains(&id) {
            return Err(ApiError::bad("You cannot put items into one of these collections."));
        }
        if !target.contains(&id) {
            target.push(id);
        }
    }
    if target.is_empty() {
        return Err(ApiError::bad("An item of an organisation has to be in at least one collection."));
    }
    let (saved, users) =
        state.store.save_org_cipher(&session.user.id, item.cipher.clone(), Some(target.clone()), Vec::new()).await?;
    notify(state, session, Kind::CipherUpdate, &saved, &target, &users);
    state.store.org_cipher(&session.user.id, id).await?.ok_or_else(|| ApiError::bad("Cipher doesn't exist"))
}

async fn set_collections(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(data): Json<Collections>,
) -> ApiResult<Response> {
    let item = change_collections(&state, &session, &id, data.collection_ids).await?;
    Ok(json_text(org_cipher_json(&state, &item).await?))
}

async fn set_collections_v2(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(data): Json<Collections>,
) -> ApiResult<Json<Value>> {
    let item = change_collections(&state, &session, &id, data.collection_ids).await?;
    let cipher: Value = serde_json::from_str(&org_cipher_json(&state, &item).await?).unwrap_or(Value::Null);
    Ok(Json(json!({ "cipher": cipher, "unavailable": false, "object": "optionalCipherDetails" })))
}

#[cfg(test)]
mod tests {
    use crate::test_support::{Account, TestServer, json};
    use axum::http::StatusCode;
    use serde_json::{Value, json};
    use uwulock_store::Migration;
    use uwulock_store::organizations::{Collection, Member, Organization};

    const ORG: &str = "0e6c1d2a-0000-4000-8000-000000000001";
    const SHARED: &str = "0e6c1d2a-0000-4000-8000-0000000000c1";
    const PRIVATE: &str = "0e6c1d2a-0000-4000-8000-0000000000c2";

    /// An organisation as the import brings it: `owner` manages both collections, `reader` only
    /// reads the shared one, with the passwords hidden.
    async fn family(server: &TestServer, owner: &Account, reader: &Account) {
        let now = uwulock_store::clock::now();
        let member = |id: &str, user: &Account| Member {
            id: id.into(),
            org_id: ORG.into(),
            user_id: Some(user.id.clone()),
            email: None,
            key: Some("4.orgkey".into()),
            status: 2,
            kind: 2,
            access_all: false,
            permissions: "{}".into(),
            external_id: None,
            reset_password_key: None,
            created: now.clone(),
            revision: now.clone(),
        };
        let collection = |id: &str| Collection {
            id: id.into(),
            org_id: ORG.into(),
            name: "2.c|c|c".into(),
            external_id: None,
            created: now.clone(),
            revision: now.clone(),
        };
        let migration = Migration {
            organizations: vec![Organization {
                id: ORG.into(),
                name: "Familie".into(),
                billing_email: owner.email.clone(),
                public_key: None,
                private_key: None,
                plan_type: uwulock_store::organizations::FAMILY,
                created: now.clone(),
                revision: now.clone(),
            }],
            members: vec![member("m-owner", owner), member("m-reader", reader)],
            collections: vec![collection(SHARED), collection(PRIVATE)],
            collection_members: vec![
                (SHARED.into(), "m-owner".into(), false, false, true),
                (PRIVATE.into(), "m-owner".into(), false, false, true),
                (SHARED.into(), "m-reader".into(), true, true, false),
            ],
            ..Default::default()
        };
        server.state.store.migrate(migration).await.unwrap();
    }

    fn item(name: &str, org: Option<&str>) -> Value {
        json!({
            "type": 1, "name": name, "notes": null, "favorite": false, "reprompt": 0, "folderId": null,
            "organizationId": org,
            "login": {"username": "2.u|u|u", "password": "2.p|p|p", "uris": [], "totp": null},
        })
    }

    async fn sync(server: &TestServer, token: &str) -> Value {
        let response = server.get_as(token, "/api/sync").await;
        assert_eq!(response.status(), StatusCode::OK);
        json(response).await
    }

    async fn create(server: &TestServer, account: &Account, collections: &[&str]) -> (StatusCode, Value) {
        let body = json!({ "cipher": item("2.shared|s|s", Some(ORG)), "collectionIds": collections });
        let response = server.call("POST", "/api/ciphers/create", Some(&account.token), body).await;
        (response.status(), json(response).await)
    }

    #[tokio::test]
    async fn members_see_the_organisation_s_items_and_nobody_else_does() {
        let server = TestServer::new().await;
        let owner = server.account("nyu@example.com").await;
        let reader = server.account("mio@example.com").await;
        let outsider = server.account("rin@example.com").await;
        family(&server, &owner, &reader).await;

        let (status, created) = create(&server, &owner, &[SHARED]).await;
        assert_eq!(status, StatusCode::OK, "{created}");
        let id = created["id"].as_str().unwrap().to_string();
        assert_eq!(created["organizationId"], ORG);
        let (status, _) = create(&server, &owner, &[]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "an organisation's item is in a collection");

        let seen = sync(&server, &reader.token).await;
        assert_eq!(seen["profile"]["organizations"][0]["id"], ORG);
        assert_eq!(seen["profile"]["organizations"][0]["key"], "4.orgkey");
        let collections: Vec<&str> =
            seen["collections"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap()).collect();
        assert_eq!(collections, [SHARED], "only the collections the member is in");
        let shared = &seen["ciphers"][0];
        assert_eq!(shared["id"], id.as_str());
        assert_eq!(shared["collectionIds"], json!([SHARED]));
        assert_eq!((shared["edit"].as_bool(), shared["viewPassword"].as_bool()), (Some(false), Some(false)));
        assert_eq!(sync(&server, &owner.token).await["ciphers"][0]["edit"], true);

        let other = sync(&server, &outsider.token).await;
        assert!(other["ciphers"].as_array().unwrap().is_empty());
        assert!(other["profile"]["organizations"].as_array().unwrap().is_empty());
        let response = server.get_as(&outsider.token, &format!("/api/ciphers/{id}")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "as if there were no such item");
        let response = server.get_as(&reader.token, &format!("/api/ciphers/{id}")).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_reader_reads_and_files_but_does_not_change() {
        let server = TestServer::new().await;
        let owner = server.account("nyu@example.com").await;
        let reader = server.account("mio@example.com").await;
        family(&server, &owner, &reader).await;
        let (_, created) = create(&server, &owner, &[SHARED]).await;
        let id = created["id"].as_str().unwrap();

        let mut changed = item("2.changed|c|c", Some(ORG));
        changed["collectionIds"] = json!([SHARED]);
        let response = server.call("PUT", &format!("/api/ciphers/{id}"), Some(&reader.token), changed.clone()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = server.call("DELETE", &format!("/api/ciphers/{id}"), Some(&reader.token), Value::Null).await;
        assert!(response.status().is_client_error());
        let response = server
            .call(
                "PUT",
                &format!("/api/ciphers/{id}/collections_v2"),
                Some(&reader.token),
                json!({"collectionIds": [PRIVATE]}),
            )
            .await;
        assert!(response.status().is_client_error(), "nor move it");
        let response = server
            .call(
                "POST",
                &format!("/api/ciphers/{id}/attachment/v2"),
                Some(&reader.token),
                json!({"key": "2.k|k|k", "fileName": "2.f|f|f", "fileSize": 3}),
            )
            .await;
        assert!(response.status().is_client_error(), "nor attach to it");

        // A star and a folder are the reader's own.
        let response = server
            .call(
                "PUT",
                &format!("/api/ciphers/{id}/partial"),
                Some(&reader.token),
                json!({"favorite": true, "folderId": null}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(sync(&server, &reader.token).await["ciphers"][0]["favorite"], true);
        assert_eq!(sync(&server, &owner.token).await["ciphers"][0]["favorite"], false);

        let response = server.call("PUT", &format!("/api/ciphers/{id}"), Some(&owner.token), changed).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(sync(&server, &reader.token).await["ciphers"][0]["name"], "2.changed|c|c");
        let response = server
            .call(
                "POST",
                &format!("/api/ciphers/{id}/attachment/v2"),
                Some(&owner.token),
                json!({"key": "2.k|k|k", "fileName": "2.f|f|f", "fileSize": 3}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn sharing_moves_an_item_into_the_organisation() {
        let server = TestServer::new().await;
        let owner = server.account("nyu@example.com").await;
        let reader = server.account("mio@example.com").await;
        family(&server, &owner, &reader).await;
        let response = server.call("POST", "/api/ciphers", Some(&owner.token), item("2.mine|m|m", None)).await;
        let id = json(response).await["id"].as_str().unwrap().to_string();

        // Somebody who is not in the organisation cannot share into it.
        let shared = json!({ "cipher": item("2.mine|m|m", Some(ORG)), "collectionIds": [PRIVATE] });
        let response =
            server.call("PUT", &format!("/api/ciphers/{id}/share"), Some(&reader.token), shared.clone()).await;
        assert!(response.status().is_client_error());

        let response = server.call("PUT", &format!("/api/ciphers/{id}/share"), Some(&owner.token), shared).await;
        assert_eq!(response.status(), StatusCode::OK);
        let seen = sync(&server, &owner.token).await;
        assert_eq!(seen["ciphers"][0]["organizationId"], ORG);
        assert!(
            sync(&server, &reader.token).await["ciphers"].as_array().unwrap().is_empty(),
            "not in the reader's collection"
        );

        let response = server
            .call(
                "PUT",
                &format!("/api/ciphers/{id}/collections_v2"),
                Some(&owner.token),
                json!({"collectionIds": [SHARED]}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(sync(&server, &reader.token).await["ciphers"][0]["id"], id.as_str());
    }
}
