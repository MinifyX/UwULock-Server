//! The extras key (docs/uwu-api.md §3): what UwULock encrypts beyond Bitwarden's own objects is
//! under one key per account, kept wrapped under the user key and for the account's public key.
//! An official client that rotates the user key re-encrypts only what Bitwarden knows; the
//! rotation drops the first wrap, the second one survives, and the next UwULock client wraps the
//! key again. The server never holds anything that opens it.

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
                "publicKeyWrapped": key.public_key_wrapped,
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
    public_key_wrapped: String,
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
    if !enc_string(&body.user_key_wrapped, 2, 1000) || !enc_string(&body.public_key_wrapped, 4, 2000) {
        return Err(ApiError::bad("The extras key is not wrapped the way it should be.").code("invalid"));
    }
    let key = ExtrasKey {
        user_key_wrapped: Some(body.user_key_wrapped),
        public_key_wrapped: body.public_key_wrapped,
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
    if !enc_string(&body.user_key_wrapped, 2, 1000) {
        return Err(ApiError::bad("The extras key is not wrapped the way it should be.").code("invalid"));
    }
    if !state.store.set_extras_user_wrap(&session.user.id, &body.user_key_wrapped).await? {
        return Err(
            ApiError::new(StatusCode::CONFLICT, "The extras key is wrapped for the user key already.").code("exists")
        );
    }
    changed(&state, &session, ip, "extrasKeyRewrapped").await;
    Ok(Json(view(state.store.extras_key(&session.user.id).await?)))
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
        let body = json!({ "userKeyWrapped": type2(), "publicKeyWrapped": type4() });
        let none = json(server.get_as(&user.token, "/uwu/v1/keys").await).await;
        assert_eq!((none["extrasKey"].is_null(), none["lost"].as_bool()), (true, Some(false)));
        let made = json(server.call("POST", "/uwu/v1/keys", Some(&user.token), body.clone()).await).await;
        assert_eq!(made["extrasKey"]["userKeyWrapped"], type2().as_str());
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
}
