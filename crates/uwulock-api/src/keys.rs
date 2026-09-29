//! The extras key (docs/uwu-api.md §3): what UwULock encrypts beyond Bitwarden's own objects is
//! under one key per account, kept wrapped under the user key and under a key derived from the
//! account's private key. Both need a secret the server never holds, so it cannot hand out a key
//! of its own; an RSA wrap for the public key, which anyone who knows it can make, is never
//! taken. An official client that rotates the user key re-encrypts only what Bitwarden knows; the
//! rotation drops the first wrap, the second one survives (the key pair does), and the next
//! UwULock client wraps the key again.

use crate::AppState;
use crate::auth::{AnySession, ClientIp, Session};
use crate::errors::{ApiError, ApiResult};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_store::{ExtrasKey, clock};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/keys", get(keys).post(create).delete(reset))
        .route("/uwu/v1/keys/user-wrap", put(user_wrap))
        .route("/uwu/v1/keys/private-wrap", put(private_wrap))
}

/// An EncString of `kind` (`2` or `4`) as the clients write them, checked for its form only:
/// the parts in base64, a type 2's IV 16 bytes and MAC 32, its ciphertext whole blocks. At most
/// `most` characters.
pub(crate) fn enc_string(value: &str, kind: u8, most: usize) -> bool {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    if value.len() > most {
        return false;
    }
    let decode = |part: &str| STANDARD.decode(part).ok();
    match (kind, value.split_once('.')) {
        (2, Some(("2", rest))) => {
            let parts: Vec<&str> = rest.split('|').collect();
            let [iv, data, mac] = parts[..] else { return false };
            matches!((decode(iv), decode(data), decode(mac)),
                (Some(iv), Some(data), Some(mac)) if iv.len() == 16 && mac.len() == 32 && !data.is_empty() && data.len() % 16 == 0)
        }
        (4, Some(("4", rest))) => decode(rest).is_some_and(|key| (128..=1024).contains(&key.len())),
        _ => false,
    }
}

pub(crate) fn view(key: Option<(ExtrasKey, bool)>) -> Value {
    match key {
        Some((_, true)) => json!({ "object": "uwuKeys", "extrasKey": null, "lost": true }),
        Some((key, false)) => json!({
            "object": "uwuKeys",
            "extrasKey": {
                "userKeyWrapped": key.user_key_wrapped,
                "privateKeyWrapped": key.private_key_wrapped,
                "revisionDate": key.revision,
            },
            "lost": false,
        }),
        None => json!({ "object": "uwuKeys", "extrasKey": null, "lost": false }),
    }
}

async fn keys(State(state): State<AppState>, AnySession(session): AnySession) -> ApiResult<Json<Value>> {
    Ok(Json(view(state.store.extras_key(&session.user.id).await?)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewKey {
    user_key_wrapped: String,
    private_key_wrapped: String,
}

/// A wrap of the extras key as the server takes it: type 2 only.
pub(crate) fn wrap_ok(wrapped: &str) -> ApiResult<()> {
    if enc_string(wrapped, 2, 1000) {
        Ok(())
    } else {
        Err(ApiError::bad("The extras key is not wrapped the way it should be.").code("invalid"))
    }
}

async fn create(
    State(state): State<AppState>,
    AnySession(session): AnySession,
    ClientIp(ip): ClientIp,
    Json(body): Json<NewKey>,
) -> ApiResult<Json<Value>> {
    let Some(public_key) = session.user.public_key.clone() else {
        return Err(ApiError::bad("This account has no key pair.").code("no_key_pair"));
    };
    wrap_ok(&body.user_key_wrapped)?;
    wrap_ok(&body.private_key_wrapped)?;
    let key = ExtrasKey {
        user_key_wrapped: Some(body.user_key_wrapped),
        private_key_wrapped: Some(body.private_key_wrapped),
        public_key,
        revision: clock::now(),
    };
    if !state.store.create_extras_key(&session.user.id, key).await? {
        return Err(ApiError::new(StatusCode::CONFLICT, "There is an extras key already.").code("exists"));
    }
    changed(&state, &session, ip, "extrasKeyCreated").await;
    Ok(Json(view(state.store.extras_key(&session.user.id).await?)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserWrap {
    user_key_wrapped: String,
}

async fn user_wrap(
    State(state): State<AppState>,
    AnySession(session): AnySession,
    ClientIp(ip): ClientIp,
    Json(body): Json<UserWrap>,
) -> ApiResult<Json<Value>> {
    wrap_ok(&body.user_key_wrapped)?;
    if !state.store.set_extras_user_wrap(&session.user.id, &body.user_key_wrapped).await? {
        return Err(not_added(&state, &session, "The extras key is wrapped for the user key already.").await);
    }
    changed(&state, &session, ip, "extrasKeyRewrapped").await;
    Ok(Json(view(state.store.extras_key(&session.user.id).await?)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrivateWrap {
    private_key_wrapped: String,
}

/// The wrap under the private key's derived key, for a key made before it existed; the client
/// that opened the key with the user key adds it.
async fn private_wrap(
    State(state): State<AppState>,
    AnySession(session): AnySession,
    ClientIp(ip): ClientIp,
    Json(body): Json<PrivateWrap>,
) -> ApiResult<Json<Value>> {
    wrap_ok(&body.private_key_wrapped)?;
    if !state.store.set_extras_private_wrap(&session.user.id, &body.private_key_wrapped).await? {
        return Err(not_added(&state, &session, "The extras key is wrapped for the private key already.").await);
    }
    changed(&state, &session, ip, "extrasKeyRewrapped").await;
    Ok(Json(view(state.store.extras_key(&session.user.id).await?)))
}

/// Why a wrap was not added: it is there already (409 `exists`), or there is no key to add it
/// to — none, or a lost one (404).
async fn not_added(state: &AppState, session: &Session, exists: &str) -> ApiError {
    match state.store.extras_key(&session.user.id).await {
        Ok(Some((_, false))) => ApiError::new(StatusCode::CONFLICT, exists).code("exists"),
        Ok(_) => ApiError::not_found("There is no extras key to wrap.").code("not_found"),
        Err(error) => error.into(),
    }
}

/// The extras key changed: a notice, and the other devices hear it (area `uwu`).
async fn changed(state: &AppState, session: &Session, ip: std::net::IpAddr, kind: &str) {
    let context = crate::notices::Context::of(state, session, ip).await;
    crate::notices::record(state, &session.user, kind, &context, json!({})).await;
    crate::notify::live(state, &session.user.id, Some(session), uwulock_notify::realtime::Live::changed("uwu"));
}

/// Start over: the extras key goes, and everything under it. Only with the master password.
async fn reset(
    State(state): State<AppState>,
    session: Session,
    ClientIp(ip): ClientIp,
    Json(secret): Json<crate::two_factor::Secret>,
) -> ApiResult<StatusCode> {
    crate::accounts::check_password(&state, &session.user, secret.master_password_hash.as_deref()).await?;
    state.store.delete_extras_key(&session.user.id).await?;
    let context = crate::notices::Context::of(&state, &session, ip).await;
    crate::notices::record(&state, &session.user, "extrasKeyReset", &context, json!({})).await;
    crate::notify::live(&state, &session.user.id, Some(&session), uwulock_notify::realtime::Live::changed("uwu"));
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    #[test]
    fn only_enc_strings_of_the_right_form() {
        assert!(enc_string(&type2(), 2, 1000));
        assert!(enc_string(&type4(), 4, 1000));
        assert!(!enc_string(&type2(), 4, 1000));
        assert!(!enc_string(&type2(), 2, 10), "too long");
        for bad in ["2.x|y|z", "2.AAAA", "nonsense", "4.AAAA"] {
            assert!(!enc_string(bad, 2, 1000) && !enc_string(bad, 4, 1000), "{bad}");
        }
    }

    #[tokio::test]
    async fn made_once_wrapped_again_after_a_rotation_and_lost_with_the_key_pair() {
        let server = TestServer::new().await;
        let user = server.account("nyu@example.com").await;
        let body = json!({ "userKeyWrapped": type2(), "privateKeyWrapped": type2() });
        let none = json(server.get_as(&user.token, "/uwu/v1/keys").await).await;
        assert_eq!((none["extrasKey"].is_null(), none["lost"].as_bool()), (true, Some(false)));
        let made = json(server.call("POST", "/uwu/v1/keys", Some(&user.token), body.clone()).await).await;
        assert_eq!(made["extrasKey"]["userKeyWrapped"], type2().as_str());
        assert_eq!(made["extrasKey"]["privateKeyWrapped"], type2().as_str());
        let again = server.call("POST", "/uwu/v1/keys", Some(&user.token), body.clone()).await;
        assert_eq!(again.status(), StatusCode::CONFLICT);
        assert_eq!(json(again).await["code"], "exists");

        // What an official rotation does.
        server.state.store.drop_extras_user_wrap(&user.id).await.unwrap();
        let wrap = json!({ "userKeyWrapped": type2() });
        let rewrapped = json(server.call("PUT", "/uwu/v1/keys/user-wrap", Some(&user.token), wrap.clone()).await).await;
        assert!(rewrapped["extrasKey"]["userKeyWrapped"].is_string());
        let twice = server.call("PUT", "/uwu/v1/keys/user-wrap", Some(&user.token), wrap).await;
        assert_eq!(twice.status(), StatusCode::CONFLICT);

        // A new key pair: neither wrap opens.
        server.state.store.update_user(&user.id, |user| user.public_key = Some("another".into())).await.unwrap();
        let lost = json(server.get_as(&user.token, "/uwu/v1/keys").await).await;
        assert_eq!((lost["extrasKey"].is_null(), lost["lost"].as_bool()), (true, Some(true)));
        let wrong = json!({ "masterPasswordHash": "wrong" });
        assert!(server.call("DELETE", "/uwu/v1/keys", Some(&user.token), wrong).await.status().is_client_error());
        let secret = json!({ "masterPasswordHash": password_hash("nyu@example.com") });
        let reset = server.call("DELETE", "/uwu/v1/keys", Some(&user.token), secret).await;
        assert_eq!(reset.status(), StatusCode::OK);
        let notices = server.state.store.notices(&user.id, None, 10).await.unwrap();
        assert!(notices.iter().any(|notice| notice.kind == "extrasKeyReset"));
    }

    /// Only type 2 wraps: an RSA wrap for the public key is what anyone who knows it can make.
    #[tokio::test]
    async fn an_rsa_wrap_is_never_taken() {
        let server = TestServer::new().await;
        let user = server.account("nyu@example.com").await;
        for body in [
            json!({ "userKeyWrapped": type2(), "privateKeyWrapped": type4() }),
            json!({ "userKeyWrapped": type4(), "privateKeyWrapped": type2() }),
        ] {
            let response = server.call("POST", "/uwu/v1/keys", Some(&user.token), body).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(json(response).await["code"], "invalid");
        }
        let old = json!({ "userKeyWrapped": type2(), "publicKeyWrapped": type4() });
        assert!(server.call("POST", "/uwu/v1/keys", Some(&user.token), old).await.status().is_client_error());
        let keys = json(server.get_as(&user.token, "/uwu/v1/keys").await).await;
        assert!(keys["extrasKey"].is_null(), "nothing was kept");
        let wrap = json!({ "privateKeyWrapped": type4() });
        let response = server.call("PUT", "/uwu/v1/keys/private-wrap", Some(&user.token), wrap).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// A key from before `privateKeyWrapped` gets it once, from the user or a UwU app; without it
    /// an official rotation leaves nothing that opens the key.
    #[tokio::test]
    async fn the_private_keys_wrap_is_added_once() {
        let server = TestServer::new().await;
        let user = server.account("nyu@example.com").await;
        let wrap = json!({ "privateKeyWrapped": type2() });
        let response = server.call("PUT", "/uwu/v1/keys/private-wrap", Some(&user.token), wrap.clone()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "no key yet");

        let old_key = |public_key: String| ExtrasKey {
            user_key_wrapped: Some(type2()),
            private_key_wrapped: None,
            public_key,
            revision: clock::now(),
        };
        let public = server.state.store.user(&user.id).await.unwrap().unwrap().public_key.unwrap();
        assert!(server.state.store.create_extras_key(&user.id, old_key(public.clone())).await.unwrap());
        let before = json(server.get_as(&user.token, "/uwu/v1/keys").await).await;
        assert!(before["extrasKey"]["privateKeyWrapped"].is_null());

        let hash = password_hash("nyu@example.com");
        let form = [
            ("grant_type", "password"),
            ("username", "nyu@example.com"),
            ("password", hash.as_str()),
            ("scope", "uwu.suite offline_access"),
            ("client_id", "uwussh"),
            ("deviceType", "8"),
            ("deviceIdentifier", "ssh-device"),
            ("deviceName", "UwUSSH"),
        ];
        let login = json(server.form("/identity/connect/token", &form).await).await;
        let suite = login["access_token"].as_str().unwrap().to_string();
        let added = server.call("PUT", "/uwu/v1/keys/private-wrap", Some(&suite), wrap.clone()).await;
        assert_eq!(added.status(), StatusCode::OK, "a UwU app may add it");
        let added = json(added).await;
        assert_eq!(added["extrasKey"]["privateKeyWrapped"], type2().as_str());
        assert_eq!(added["extrasKey"]["userKeyWrapped"], type2().as_str());
        let twice = server.call("PUT", "/uwu/v1/keys/private-wrap", Some(&user.token), wrap.clone()).await;
        assert_eq!(twice.status(), StatusCode::CONFLICT);
        assert_eq!(json(twice).await["code"], "exists");
        let notices = server.state.store.notices(&user.id, None, 10).await.unwrap();
        assert!(notices.iter().any(|notice| notice.kind == "extrasKeyRewrapped"));

        // Without the private key's wrap, an official rotation leaves nothing that opens it.
        server.state.store.delete_extras_key(&user.id).await.unwrap();
        assert!(server.state.store.create_extras_key(&user.id, old_key(public)).await.unwrap());
        server.state.store.drop_extras_user_wrap(&user.id).await.unwrap();
        let lost = json(server.get_as(&user.token, "/uwu/v1/keys").await).await;
        assert_eq!((lost["extrasKey"].is_null(), lost["lost"].as_bool()), (true, Some(true)));
        let response = server.call("PUT", "/uwu/v1/keys/private-wrap", Some(&user.token), wrap).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "nothing to add it to");
        let rewrap = json!({ "userKeyWrapped": type2() });
        let response = server.call("PUT", "/uwu/v1/keys/user-wrap", Some(&user.token), rewrap).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let fresh = json!({ "userKeyWrapped": type2(), "privateKeyWrapped": type2() });
        let made = server.call("POST", "/uwu/v1/keys", Some(&user.token), fresh).await;
        assert_eq!(made.status(), StatusCode::OK, "a new key makes way");
    }
}
