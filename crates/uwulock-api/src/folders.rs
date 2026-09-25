//! `/api/folders`: a user's folders. Their names are encrypted by the client; deleting one keeps
//! its items, in no folder.

use crate::auth::Session;
use crate::errors::{ApiError, ApiResult};
use crate::{AppState, json as out};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::Value;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/folders", get(list).post(create))
        .route("/api/folders/{id}", get(one).put(rename).post(rename).delete(delete))
        .route("/api/folders/{id}/delete", post(delete))
}

#[derive(Deserialize)]
struct FolderData {
    name: String,
}

async fn list(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let folders = state.store.folders(&session.user.id).await?;
    Ok(Json(out::list(folders.iter().map(out::folder).collect())))
}

async fn one(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let folder = state.store.folder(&session.user.id, &id).await?.ok_or_else(|| ApiError::bad("Invalid folder"))?;
    Ok(Json(out::folder(&folder)))
}

async fn create(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<FolderData>,
) -> ApiResult<Json<Value>> {
    let folder = state
        .store
        .save_folder(&session.user.id, None, data.name)
        .await?
        .ok_or_else(|| ApiError::bad("Invalid folder"))?;
    Ok(Json(out::folder(&folder)))
}

async fn rename(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(data): Json<FolderData>,
) -> ApiResult<Json<Value>> {
    let folder = state
        .store
        .save_folder(&session.user.id, Some(id), data.name)
        .await?
        .ok_or_else(|| ApiError::bad("Invalid folder"))?;
    Ok(Json(out::folder(&folder)))
}

async fn delete(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<StatusCode> {
    if !state.store.delete_folder(&session.user.id, &id).await? {
        return Err(ApiError::bad("Invalid folder"));
    }
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::http::StatusCode;
    use serde_json::json;

    #[tokio::test]
    async fn folders_are_made_renamed_and_deleted() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let folder =
            json(server.call("POST", "/api/folders", Some(&account.token), json!({"name": "2.a|a|a"})).await).await;
        assert_eq!(folder["object"], "folder");
        let id = folder["id"].as_str().unwrap();
        let renamed =
            server.call("PUT", &format!("/api/folders/{id}"), Some(&account.token), json!({"name": "2.b|b|b"})).await;
        assert_eq!(json(renamed).await["name"], "2.b|b|b");
        let list = json(server.get_as(&account.token, "/api/folders").await).await;
        assert_eq!(list["data"].as_array().unwrap().len(), 1);
        let other = server.account("other@example.com").await;
        assert_eq!(server.get_as(&other.token, &format!("/api/folders/{id}")).await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            server.call("DELETE", &format!("/api/folders/{id}"), Some(&account.token), json!({})).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            server.call("DELETE", &format!("/api/folders/{id}"), Some(&account.token), json!({})).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
}
