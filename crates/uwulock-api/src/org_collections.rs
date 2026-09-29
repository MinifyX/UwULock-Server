//! An organisation's collections, as Bitwarden's `CollectionsController` has them. Owners make,
//! rename and delete them and say who reaches each (`readOnly`, `hidePasswords`, `manage`);
//! members list the ones they reach. The names are encrypted under the organisation key.
//!
//! Putting items into collections is `organizations.rs` (sharing, `collections_v2`).

use crate::auth::Session;
use crate::errors::{ApiError, ApiResult};
use crate::families::{as_member, as_owner, not_found, tell};
use crate::{AppState, json as out};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use uwulock_notify::Kind;
use uwulock_store::organizations::{Collection, OWNER};
use uwulock_store::{Access, MemberAccess};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/organizations/{org}/collections", get(list).post(create).delete(delete_many))
        .route("/api/organizations/{org}/collections/delete", post(delete_many))
        .route("/api/organizations/{org}/collections/details", get(details))
        .route("/api/organizations/{org}/collections/{id}", get(one).put(update).post(update).delete(delete_one))
        .route("/api/organizations/{org}/collections/{id}/delete", post(delete_one))
        .route("/api/organizations/{org}/collections/{id}/details", get(one_details))
        .route("/api/organizations/{org}/collections/{id}/users", get(users))
}

fn collection_json(collection: &Collection) -> Value {
    json!({
        "id": collection.id,
        "organizationId": collection.org_id,
        "name": collection.name,
        "externalId": collection.external_id,
        "type": 0,
        "object": "collection",
    })
}

fn access_json(id: &str, access: &Access) -> Value {
    json!({ "id": id, "readOnly": access.read_only, "hidePasswords": access.hide_passwords, "manage": access.manage })
}

/// `collectionAccessDetails`: the collection, who reaches it (for an owner), and what the one
/// asking may do in it.
fn details_json(collection: &Collection, users: &[MemberAccess], mine: Option<&Access>, owner: bool) -> Value {
    let mut value = collection_json(collection);
    let access = mine.copied().unwrap_or_default();
    value["groups"] = json!([]);
    value["users"] = if owner {
        users.iter().map(|(id, access)| access_json(id, access)).collect::<Vec<_>>().into()
    } else {
        json!([])
    };
    value["assigned"] = mine.is_some().into();
    value["readOnly"] = access.read_only.into();
    value["hidePasswords"] = access.hide_passwords.into();
    value["manage"] = access.manage.into();
    value["object"] = "collectionAccessDetails".into();
    value
}

/// The collections of `org_id` the session reaches, and how.
async fn reached(state: &AppState, session: &Session, org_id: &str) -> ApiResult<HashMap<String, Access>> {
    let vault = state.store.org_vault(&session.user.id).await?;
    Ok(vault
        .collections
        .into_iter()
        .filter(|(collection, _)| collection.org_id == org_id)
        .map(|(collection, access)| (collection.id, access))
        .collect())
}

async fn list(State(state): State<AppState>, session: Session, Path(org): Path<String>) -> ApiResult<Json<Value>> {
    let (org, _) = as_member(&state, &session, &org).await?;
    let mine = reached(&state, &session, &org.id).await?;
    let all = state.store.collection_details(&org.id).await?;
    Ok(Json(out::list(
        all.iter()
            .filter(|(collection, _)| mine.contains_key(&collection.id))
            .map(|(c, _)| collection_json(c))
            .collect(),
    )))
}

async fn details(State(state): State<AppState>, session: Session, Path(org): Path<String>) -> ApiResult<Json<Value>> {
    let (org, me) = as_member(&state, &session, &org).await?;
    let owner = me.kind == OWNER;
    let mine = reached(&state, &session, &org.id).await?;
    let all = state.store.collection_details(&org.id).await?;
    Ok(Json(out::list(
        all.iter()
            .filter(|(collection, _)| owner || mine.contains_key(&collection.id))
            .map(|(collection, users)| details_json(collection, users, mine.get(&collection.id), owner))
            .collect(),
    )))
}

async fn find(state: &AppState, org_id: &str, id: &str) -> ApiResult<(Collection, Vec<MemberAccess>)> {
    state
        .store
        .collection_details(org_id)
        .await?
        .into_iter()
        .find(|(collection, _)| collection.id == id)
        .ok_or_else(|| ApiError::not_found("Collection not found."))
}

async fn one(
    State(state): State<AppState>,
    session: Session,
    Path((org, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (org, me) = as_member(&state, &session, &org).await?;
    let mine = reached(&state, &session, &org.id).await?;
    if me.kind != OWNER && !mine.contains_key(&id) {
        return Err(ApiError::not_found("Collection not found."));
    }
    Ok(Json(collection_json(&find(&state, &org.id, &id).await?.0)))
}

async fn one_details(
    State(state): State<AppState>,
    session: Session,
    Path((org, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (org, me) = as_member(&state, &session, &org).await?;
    let owner = me.kind == OWNER;
    let mine = reached(&state, &session, &org.id).await?;
    if !owner && !mine.contains_key(&id) {
        return Err(ApiError::not_found("Collection not found."));
    }
    let (collection, users) = find(&state, &org.id, &id).await?;
    Ok(Json(details_json(&collection, &users, mine.get(&id), owner)))
}

async fn users(
    State(state): State<AppState>,
    session: Session,
    Path((org, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (org, _) = as_owner(&state, &session, &org).await?;
    let (_, users) = find(&state, &org.id, &id).await?;
    Ok(Json(json!(users.iter().map(|(id, access)| access_json(id, access)).collect::<Vec<_>>())))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserAccess {
    id: String,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    hide_passwords: bool,
    #[serde(default)]
    manage: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectionData {
    name: String,
    #[serde(default)]
    external_id: Option<String>,
    #[serde(default)]
    groups: Vec<Value>,
    #[serde(default)]
    users: Option<Vec<UserAccess>>,
}

impl CollectionData {
    fn checked(self) -> ApiResult<(String, Option<String>, Option<Vec<MemberAccess>>)> {
        if !crate::keys::enc_string(&self.name, 2, 1000) {
            return Err(ApiError::bad("The collection's name has to be encrypted."));
        }
        if !self.groups.is_empty() {
            return Err(ApiError::bad("A family has no groups."));
        }
        let external = self.external_id.filter(|id| !id.trim().is_empty());
        if external.as_ref().is_some_and(|id| id.len() > 300) {
            return Err(ApiError::bad("The external id is at most 300 characters long."));
        }
        let users = self.users.map(|list| {
            list.into_iter()
                .map(|user| {
                    let access =
                        Access { read_only: user.read_only, hide_passwords: user.hide_passwords, manage: user.manage };
                    (user.id, access)
                })
                .collect()
        });
        Ok((self.name, external, users))
    }
}

async fn save(
    state: &AppState,
    session: &Session,
    org: &str,
    id: Option<String>,
    data: CollectionData,
) -> ApiResult<Json<Value>> {
    let (org, _) = as_owner(state, session, org).await?;
    let (name, external, users) = data.checked()?;
    let (collection, told) =
        state.store.save_collection(&org.id, id, name, external, users).await?.ok_or_else(not_found)?;
    tell(state, Some(session), &told, Kind::Vault);
    let (collection, users) = find(state, &org.id, &collection.id).await?;
    let mine = reached(state, session, &org.id).await?;
    Ok(Json(details_json(&collection, &users, mine.get(&collection.id), true)))
}

async fn create(
    State(state): State<AppState>,
    session: Session,
    Path(org): Path<String>,
    Json(data): Json<CollectionData>,
) -> ApiResult<Json<Value>> {
    save(&state, &session, &org, None, data).await
}

async fn update(
    State(state): State<AppState>,
    session: Session,
    Path((org, id)): Path<(String, String)>,
    Json(data): Json<CollectionData>,
) -> ApiResult<Json<Value>> {
    save(&state, &session, &org, Some(id), data).await
}

async fn delete(state: &AppState, session: &Session, org: &str, ids: Vec<String>) -> ApiResult<StatusCode> {
    let (org, _) = as_owner(state, session, org).await?;
    let (deleted, told) = state.store.delete_collections(&org.id, ids).await?;
    if deleted == 0 {
        return Err(ApiError::not_found("Collection not found."));
    }
    tell(state, Some(session), &told, Kind::Vault);
    Ok(StatusCode::OK)
}

async fn delete_one(
    State(state): State<AppState>,
    session: Session,
    Path((org, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    delete(&state, &session, &org, vec![id]).await
}

#[derive(Deserialize)]
struct Ids {
    ids: Vec<String>,
}

async fn delete_many(
    State(state): State<AppState>,
    session: Session,
    Path(org): Path<String>,
    Json(data): Json<Ids>,
) -> ApiResult<StatusCode> {
    delete(&state, &session, &org, data.ids.into_iter().take(100).collect()).await
}
