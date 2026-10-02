//! Entry versions (docs/uwu-api.md §8): the earlier states of an item, listed, shown and brought
//! back in the web vault and UwULock's desktop app. The server keeps them encrypted as the
//! clients wrote them and never knows what changed.

use crate::auth::Session;
use crate::ciphers::{Found, not_visible, visible};
use crate::errors::{ApiError, ApiResult};
use crate::json::TYPE_KEYS;
use crate::{AppState, json as out};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_notify::Kind;
use uwulock_store::{RestoreRefusal, Version};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/versions", get(personal))
        .route("/uwu/v1/ciphers/{id}/versions", get(list).delete(delete_all))
        .route("/uwu/v1/ciphers/{id}/versions/{version}", get(one).delete(delete_one))
        .route("/uwu/v1/ciphers/{id}/versions/{version}/restore", post(restore))
}

/// A version's content as the cipher in `/api/sync` has it: the same keys, the same encodings.
pub(crate) fn version_cipher(version: &Version) -> Value {
    let content: Value = serde_json::from_str(&version.content).unwrap_or(Value::Null);
    let text = |key: &str| content.get(key).and_then(Value::as_str);
    let parsed = |key: &str| text(key).and_then(|text| serde_json::from_str::<Value>(text).ok());
    let kind = content.get("type").and_then(Value::as_i64).unwrap_or(1);
    let mut cipher = json!({
        "type": kind,
        "organizationId": version.organization_id,
        "name": text("name"),
        "notes": text("notes"),
        "key": text("key"),
        "fields": parsed("fields").unwrap_or_else(|| json!([])),
        "passwordHistory": parsed("passwordHistory").unwrap_or_else(|| json!([])),
        "reprompt": content.get("reprompt").and_then(Value::as_i64).unwrap_or(0),
    });
    for (type_kind, key) in TYPE_KEYS {
        cipher[key] = if type_kind == kind { parsed("data").unwrap_or(Value::Null) } else { Value::Null };
    }
    cipher
}

pub(crate) fn version_json(version: &Version) -> Value {
    json!({
        "object": "cipherVersion",
        "id": version.id,
        "cipherId": version.cipher_id,
        "organizationId": version.organization_id,
        "revisionDate": version.revision,
        "replacedDate": version.replaced,
        "size": version.size,
        "cipher": version_cipher(version),
    })
}

/// The item, if the account may see its versions: their own, or an organisation's they may
/// change and see the passwords of. 404 otherwise.
async fn versioned(state: &AppState, session: &Session, id: &str) -> ApiResult<Found> {
    let found = visible(state, session, id).await?;
    if let Found::Org(item) = &found
        && (item.access.read_only || item.access.hide_passwords)
    {
        return Err(not_visible());
    }
    Ok(found)
}

fn no_version() -> ApiError {
    ApiError::not_found("There is no such version.").code("not_found")
}

async fn list(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    versioned(&state, &session, &id).await?;
    let versions = state.store.versions(&id).await?;
    Ok(Json(out::list(versions.iter().map(version_json).collect())))
}

async fn one(
    State(state): State<AppState>,
    session: Session,
    Path((id, version)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    versioned(&state, &session, &id).await?;
    let version = state.store.version(&id, &version).await?.ok_or_else(no_version)?;
    Ok(Json(version_json(&version)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Restore {
    last_known_revision_date: String,
}

/// The version's content in place of the item's; what the item held becomes a version itself.
/// Answered with the item as `PUT /api/ciphers/{id}` answers.
async fn restore(
    State(state): State<AppState>,
    session: Session,
    Path((id, version)): Path<(String, String)>,
    Json(body): Json<Restore>,
) -> ApiResult<Response> {
    let found = versioned(&state, &session, &id).await?;
    let (cipher, users) = match state.store.restore_version(&id, &version, &body.last_known_revision_date).await? {
        Ok(done) => done,
        Err(RestoreRefusal::Missing) => return Err(no_version()),
        Err(RestoreRefusal::Changed) => {
            return Err(ApiError::new(StatusCode::CONFLICT, "The item changed in the meantime. Sync, then try again.")
                .code("conflict"));
        }
    };
    match found {
        Found::Own(_) => crate::notify::cipher(&state, &session, Kind::CipherUpdate, &cipher),
        Found::Org(item) => {
            crate::organizations::notify(&state, &session, Kind::CipherUpdate, &cipher, &item.collection_ids, &users)
                .await
        }
    }
    let found = visible(&state, &session, &id).await?;
    Ok(crate::ciphers::json_text(crate::ciphers::found_json(&state, &found).await?))
}

async fn delete_one(
    State(state): State<AppState>,
    session: Session,
    Path((id, version)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    versioned(&state, &session, &id).await?;
    if state.store.delete_versions(&id, Some(version)).await? == 0 {
        return Err(no_version());
    }
    Ok(StatusCode::OK)
}

async fn delete_all(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<StatusCode> {
    versioned(&state, &session, &id).await?;
    state.store.delete_versions(&id, None).await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct Scope {
    #[serde(default)]
    scope: Option<String>,
}

/// Every version of the account's own items, for a key rotation (§8.5).
async fn personal(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<Scope>,
) -> ApiResult<Json<Value>> {
    if query.scope.as_deref().is_some_and(|scope| scope != "personal") {
        return Err(ApiError::bad("Only scope=personal is there.").code("invalid"));
    }
    let mut versions = state.store.personal_versions(&session.user.id).await?;
    // Those of items travel mode hides stay hidden (a rotation waits until it is off anyway).
    if state.store.travelling(&session.user.id).await? {
        let seen: std::collections::HashSet<String> =
            state.store.ciphers(&session.user.id).await?.into_iter().map(|cipher| cipher.id).collect();
        versions.retain(|version| seen.contains(&version.cipher_id));
    }
    Ok(Json(out::list(versions.iter().map(version_json).collect())))
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::http::StatusCode;
    use serde_json::{Value, json};

    fn item(name: &str, password: &str) -> Value {
        json!({
            "type": 1,
            "name": name,
            "login": {"username": "2.u|u|u", "password": password, "uris": null, "totp": null},
            "fields": [{"name": "2.f|f|f", "value": "2.v|v|v", "type": 0}],
        })
    }

    #[tokio::test]
    async fn changes_are_kept_listed_and_brought_back() {
        let server = TestServer::new().await;
        let nyu = server.account("nyu@example.com").await;
        let other = server.account("other@example.com").await;
        let created =
            json(server.call("POST", "/api/ciphers", Some(&nyu.token), item("2.a|a|a", "2.p1|p|p")).await).await;
        let id = created["id"].as_str().unwrap().to_string();
        let path = format!("/api/ciphers/{id}");
        let mut change = item("2.a|a|a", "2.p2|p|p");
        change["lastKnownRevisionDate"] = created["revisionDate"].clone();
        let changed = json(server.call("PUT", &path, Some(&nyu.token), change).await).await;

        let versions = json(server.get_as(&nyu.token, &format!("/uwu/v1/ciphers/{id}/versions")).await).await;
        let data = versions["data"].as_array().unwrap();
        assert_eq!(data.len(), 1);
        let version = &data[0];
        assert_eq!(version["object"], "cipherVersion");
        assert_eq!(version["revisionDate"], created["revisionDate"]);
        assert_eq!(version["cipher"]["login"]["password"], "2.p1|p|p");
        assert_eq!(version["cipher"]["fields"][0]["value"], "2.v|v|v");
        assert!(version["cipher"]["card"].is_null());
        let version_id = version["id"].as_str().unwrap();

        let theirs = server.get_as(&other.token, &format!("/uwu/v1/ciphers/{id}/versions")).await;
        assert_eq!(theirs.status(), StatusCode::NOT_FOUND, "not theirs");
        let one = format!("/uwu/v1/ciphers/{id}/versions/{version_id}");
        assert_eq!(server.get_as(&other.token, &one).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(json(server.get_as(&nyu.token, &one).await).await["id"], version_id);

        let restore = format!("{one}/restore");
        let stale = json!({"lastKnownRevisionDate": created["revisionDate"]});
        let response = server.call("POST", &restore, Some(&nyu.token), stale).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(json(response).await["code"], "conflict");
        let right = json!({"lastKnownRevisionDate": changed["revisionDate"]});
        assert_eq!(
            server.call("POST", &restore, Some(&other.token), right.clone()).await.status(),
            StatusCode::NOT_FOUND
        );
        let restored = json(server.call("POST", &restore, Some(&nyu.token), right).await).await;
        assert_eq!(restored["object"], "cipherDetails");
        assert_eq!(restored["login"]["password"], "2.p1|p|p");
        let versions = json(server.get_as(&nyu.token, &format!("/uwu/v1/ciphers/{id}/versions")).await).await;
        assert_eq!(versions["data"].as_array().unwrap().len(), 2, "what was replaced is a version now");
        assert_eq!(versions["data"][0]["cipher"]["login"]["password"], "2.p2|p|p", "newest first");

        let personal = json(server.get_as(&nyu.token, "/uwu/v1/versions?scope=personal").await).await;
        assert_eq!(personal["data"].as_array().unwrap().len(), 2);
        assert_eq!(server.call("DELETE", &one, Some(&other.token), json!({})).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(server.call("DELETE", &one, Some(&nyu.token), json!({})).await.status(), StatusCode::OK);
        let all = format!("/uwu/v1/ciphers/{id}/versions");
        assert_eq!(server.call("DELETE", &all, Some(&nyu.token), json!({})).await.status(), StatusCode::OK);
        assert!(json(server.get_as(&nyu.token, &all).await).await["data"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_move_to_another_folder_is_no_version() {
        let server = TestServer::new().await;
        let nyu = server.account("nyu@example.com").await;
        let created =
            json(server.call("POST", "/api/ciphers", Some(&nyu.token), item("2.a|a|a", "2.p|p|p")).await).await;
        let id = created["id"].as_str().unwrap();
        let folder =
            json(server.call("POST", "/api/folders", Some(&nyu.token), json!({"name": "2.f|f|f"})).await).await;
        let partial = json!({"folderId": folder["id"], "favorite": true});
        server.call("PUT", &format!("/api/ciphers/{id}/partial"), Some(&nyu.token), partial).await;
        let versions = json(server.get_as(&nyu.token, &format!("/uwu/v1/ciphers/{id}/versions")).await).await;
        assert!(versions["data"].as_array().unwrap().is_empty());
    }

    fn rotation(email: &str, ciphers: Value) -> Value {
        json!({
            "oldMasterKeyAuthenticationHash": password_hash(email),
            "accountUnlockData": {"masterPasswordUnlockData": {
                "kdfType": 0, "kdfIterations": 600000, "email": email,
                "masterKeyAuthenticationHash": password_hash(email),
                "masterKeyEncryptedUserKey": "2.newuserkey|k|k",
            }},
            "accountKeys": {"userKeyEncryptedAccountPrivateKey": "2.newprivate|p|p", "accountPublicKey": "MIIBpublic"},
            "accountData": {"ciphers": ciphers, "folders": [], "sends": []},
        })
    }

    #[tokio::test]
    async fn a_rotation_by_uwulock_re_encrypts_versions_and_an_official_one_drops_them() {
        let server = TestServer::new().await;
        let email = "nyu@example.com";
        let nyu = server.account(email).await;
        let created =
            json(server.call("POST", "/api/ciphers", Some(&nyu.token), item("2.a|a|a", "2.p1|p|p")).await).await;
        let id = created["id"].as_str().unwrap().to_string();
        server.call("PUT", &format!("/api/ciphers/{id}"), Some(&nyu.token), item("2.a|a|a", "2.p2|p|p")).await;
        let keys = json!({"userKeyWrapped": type2(), "privateKeyWrapped": type2()});
        assert_eq!(server.call("POST", "/uwu/v1/keys", Some(&nyu.token), keys).await.status(), StatusCode::OK);
        let versions = json(server.get_as(&nyu.token, "/uwu/v1/versions?scope=personal").await).await;
        let version = versions["data"][0].clone();
        let mut cipher_now = item("2.b|b|b", "2.p2|p|p");
        cipher_now["id"] = json!(id);

        let mut stale = json!({"rotation": rotation(email, json!([cipher_now])), "extrasKey": null, "versions": []});
        let response = server.call("POST", "/uwu/v1/accounts/rotate-keys", Some(&nyu.token), stale.clone()).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(json(response).await["code"], "versions_changed");

        let mut again = version["cipher"].clone();
        again["name"] = json!("2.rotated|r|r");
        stale["versions"] = json!([{"id": version["id"], "cipher": again}]);
        stale["extrasKey"] = json!({"userKeyWrapped": type2(), "privateKeyWrapped": type4()});
        let response = server.call("POST", "/uwu/v1/accounts/rotate-keys", Some(&nyu.token), stale.clone()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "never an RSA wrap");
        let private_wrap = rewrapped();
        stale["extrasKey"] = json!({"userKeyWrapped": type2(), "privateKeyWrapped": private_wrap});
        let response = server.call("POST", "/uwu/v1/accounts/rotate-keys", Some(&nyu.token), stale).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        assert_eq!(server.get_as(&nyu.token, "/api/sync").await.status(), StatusCode::UNAUTHORIZED, "logged out");
        let nyu = server.login(email, "device-2").await;
        let versions = json(server.get_as(&nyu.token, "/uwu/v1/versions").await).await;
        assert_eq!(versions["data"][0]["cipher"]["name"], "2.rotated|r|r");
        assert_eq!(versions["data"][0]["cipher"]["login"]["password"], "2.p1|p|p");
        let keys = json(server.get_as(&nyu.token, "/uwu/v1/keys").await).await;
        assert!(keys["extrasKey"]["userKeyWrapped"].is_string(), "wrapped for the new key");
        assert_eq!(keys["extrasKey"]["privateKeyWrapped"], private_wrap.as_str());

        let official = rotation(email, json!([cipher_now]));
        let response = server
            .call("POST", "/api/accounts/key-management/rotate-user-account-keys", Some(&nyu.token), official)
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        let nyu = server.login(email, "device-3").await;
        assert!(json(server.get_as(&nyu.token, "/uwu/v1/versions").await).await["data"].as_array().unwrap().is_empty());
        let keys = json(server.get_as(&nyu.token, "/uwu/v1/keys").await).await;
        assert!(keys["extrasKey"]["userKeyWrapped"].is_null());
        assert_eq!(keys["extrasKey"]["privateKeyWrapped"], private_wrap.as_str(), "the key pair's stays");
        assert_eq!(keys["lost"], false);
    }

    /// Another type 2 value than [`type2`], of the same form.
    fn rewrapped() -> String {
        use base64::Engine as _;
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        format!("2.{}|{}|{}", b64(&[5; 16]), b64(&[6; 32]), b64(&[7; 32]))
    }
}
