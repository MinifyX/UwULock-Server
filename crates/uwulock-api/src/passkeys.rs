//! Passkeys that log in to the web vault — and, where the passkey has the PRF extension, unlock
//! it too: the user key is kept wrapped for a key pair whose private key only the passkey's PRF
//! output opens. Bitwarden's endpoints for it, `/api/webauthn` and the `webauthn` grant.

use crate::accounts::check_password;
use crate::auth::{self, ClientIp, Session};
use crate::errors::{ApiError, ApiResult};
use crate::identity::{Login, TokenForm, finish_login};
use crate::{AppState, json as out, webauthn};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_store::{Passkey, StoreError, clock};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/webauthn", get(list).post(create).put(update_keys))
        .route("/api/webauthn/attestation-options", post(attestation_options))
        .route("/api/webauthn/assertion-options", post(assertion_options))
        .route("/api/webauthn/{id}/delete", post(delete))
        .route("/identity/accounts/webauthn/assertion-options", get(login_options))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Secret {
    #[serde(default, alias = "secret")]
    master_password_hash: Option<String>,
}

fn render(passkey: &Passkey) -> Value {
    // 0 unlocks the vault, 1 could but does not yet, 2 cannot.
    let prf = match (passkey.supports_prf, passkey.encrypted_user_key.is_some()) {
        (true, true) => 0,
        (true, false) => 1,
        (false, _) => 2,
    };
    json!({
        "id": passkey.id,
        "name": passkey.name,
        "prfStatus": prf,
        "encryptedUserKey": passkey.encrypted_user_key,
        "encryptedPublicKey": passkey.encrypted_public_key,
        "creationDate": passkey.created,
        "object": "webauthnCredential",
    })
}

async fn list(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let passkeys = state.store.passkeys(&session.user.id).await?;
    Ok(Json(out::list(passkeys.iter().map(render).collect())))
}

async fn attestation_options(
    State(state): State<AppState>,
    session: Session,
    Json(secret): Json<Secret>,
) -> ApiResult<Json<Value>> {
    check_password(&state, &session.user, secret.master_password_hash.as_deref()).await?;
    let known: Vec<Vec<u8>> = state
        .store
        .passkeys(&session.user.id)
        .await?
        .iter()
        .filter_map(|passkey| webauthn::unb64(&passkey.id))
        .collect();
    let challenge = webauthn::challenge();
    let user = &session.user;
    let options =
        webauthn::creation_options(&state.party, &user.id, &user.email, user.name.as_deref(), &challenge, &known, true);
    let token = auth::random_token(24);
    state.challenges.put(format!("passkey-create:{}:{token}", user.id), challenge);
    Ok(Json(json!({ "options": options, "token": token, "object": "webauthnCredentialCreateOptions" })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Create {
    device_response: webauthn::Attestation,
    name: String,
    token: String,
    #[serde(default)]
    supports_prf: bool,
    #[serde(default)]
    encrypted_user_key: Option<String>,
    #[serde(default)]
    encrypted_public_key: Option<String>,
    #[serde(default)]
    encrypted_private_key: Option<String>,
}

fn keys(
    user: Option<String>,
    public: Option<String>,
    private: Option<String>,
) -> ApiResult<Option<(String, String, String)>> {
    match (
        user.filter(|key| !key.is_empty()),
        public.filter(|key| !key.is_empty()),
        private.filter(|key| !key.is_empty()),
    ) {
        (None, None, None) => Ok(None),
        (Some(user), Some(public), Some(private))
            if [&user, &public, &private].iter().all(|key| key.len() <= out::MAX_NOTE) =>
        {
            Ok(Some((user, public, private)))
        }
        _ => Err(ApiError::bad("The passkey's keys are not complete.")),
    }
}

async fn create(State(state): State<AppState>, session: Session, Json(data): Json<Create>) -> ApiResult<StatusCode> {
    let challenge = state
        .challenges
        .take(&format!("passkey-create:{}:{}", session.user.id, data.token))
        .ok_or_else(|| ApiError::bad("The passkey took too long. Try again."))?;
    let registered = webauthn::register(&data.device_response, &challenge, &state.party, true)
        .map_err(|reason| ApiError::bad(format!("The passkey was not accepted: {reason}.")))?;
    let keys = keys(data.encrypted_user_key, data.encrypted_public_key, data.encrypted_private_key)?;
    let name: String = data.name.trim().chars().take(50).collect();
    let passkey = Passkey {
        id: webauthn::b64(&registered.credential_id),
        user_id: session.user.id.clone(),
        name: if name.is_empty() { "Passkey".into() } else { name },
        public_key: webauthn::b64(&registered.public_key),
        counter: i64::from(registered.counter),
        supports_prf: data.supports_prf,
        encrypted_user_key: keys.as_ref().map(|(user, _, _)| user.clone()),
        encrypted_public_key: keys.as_ref().map(|(_, public, _)| public.clone()),
        encrypted_private_key: keys.map(|(_, _, private)| private),
        created: clock::now(),
        last_used: None,
    };
    match state.store.add_passkey(passkey).await {
        Ok(()) => Ok(StatusCode::OK),
        Err(StoreError::Exists) => Err(ApiError::bad(format!(
            "This passkey is set up already, or the account has {} of them.",
            uwulock_store::MAX_PASSKEYS
        ))),
        Err(error) => Err(error.into()),
    }
}

async fn assertion_options(
    State(state): State<AppState>,
    session: Session,
    Json(secret): Json<Secret>,
) -> ApiResult<Json<Value>> {
    check_password(&state, &session.user, secret.master_password_hash.as_deref()).await?;
    let known: Vec<Vec<u8>> = state
        .store
        .passkeys(&session.user.id)
        .await?
        .iter()
        .filter_map(|passkey| webauthn::unb64(&passkey.id))
        .collect();
    let challenge = webauthn::challenge();
    let mut options = webauthn::request_options(&state.party, &challenge, &known);
    options["userVerification"] = json!("required");
    let token = auth::random_token(24);
    state.challenges.put(format!("passkey-update:{}:{token}", session.user.id), challenge);
    Ok(Json(json!({ "options": options, "token": token, "object": "webAuthnLoginAssertionOptions" })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateKeys {
    device_response: webauthn::Assertion,
    token: String,
    encrypted_user_key: Option<String>,
    encrypted_public_key: Option<String>,
    encrypted_private_key: Option<String>,
}

/// Turn on unlocking with a passkey that can: the passkey proves itself, and brings its keys.
async fn update_keys(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<UpdateKeys>,
) -> ApiResult<StatusCode> {
    let challenge = state
        .challenges
        .take(&format!("passkey-update:{}:{}", session.user.id, data.token))
        .ok_or_else(|| ApiError::bad("The passkey took too long. Try again."))?;
    let (user_key, public_key, private_key) =
        keys(data.encrypted_user_key, data.encrypted_public_key, data.encrypted_private_key)?
            .ok_or_else(|| ApiError::bad("The passkey's keys are not complete."))?;
    let id = data.device_response.credential_id().map(|id| webauthn::b64(&id)).unwrap_or_default();
    let passkey = state
        .store
        .passkey(&id)
        .await?
        .filter(|passkey| passkey.user_id == session.user.id)
        .ok_or_else(|| ApiError::bad("This passkey is not set up for this account."))?;
    let stored = webauthn::unb64(&passkey.public_key).unwrap_or_default();
    let counter =
        webauthn::assert(&data.device_response, &challenge, &state.party, &stored, passkey.counter as u32, true)
            .map_err(|reason| ApiError::bad(format!("The passkey was not accepted: {reason}.")))?;
    state.store.passkey_used(&passkey.id, i64::from(counter)).await?;
    state.store.set_passkey_keys(&session.user.id, &passkey.id, user_key, public_key, private_key).await?;
    Ok(StatusCode::OK)
}

async fn delete(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(secret): Json<Secret>,
) -> ApiResult<StatusCode> {
    check_password(&state, &session.user, secret.master_password_hash.as_deref()).await?;
    if !state.store.delete_passkey(&session.user.id, &id).await? {
        return Err(ApiError::bad("This passkey is not set up for this account."));
    }
    Ok(StatusCode::OK)
}

// ── Logging in with one ───────────────────────────────────

/// A challenge for a passkey the browser picks. Nobody is logged in yet; the token says which
/// challenge the answer is for.
async fn login_options(State(state): State<AppState>, ClientIp(ip): ClientIp) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let challenge = webauthn::challenge();
    let options = webauthn::request_options(&state.party, &challenge, &[]);
    let token = auth::random_token(24);
    state.challenges.put(format!("passkey-login:{token}"), challenge);
    Ok(Json(json!({ "options": options, "token": token, "object": "webAuthnLoginAssertionOptions" })))
}

/// The `webauthn` grant: logged in with a passkey, which verified who is there — so no second
/// step. The answer carries the passkey's keys, which unlock the vault with its PRF output.
pub(crate) async fn grant(state: &AppState, ip: std::net::IpAddr, form: &TokenForm) -> ApiResult<Response> {
    let token = form.get("token").ok_or_else(|| ApiError::bad("token cannot be blank"))?;
    let response = form.get("deviceresponse").ok_or_else(|| ApiError::bad("device_response cannot be blank"))?;
    let device_id = form.get("deviceidentifier").ok_or_else(|| ApiError::bad("device_identifier cannot be blank"))?;
    let device_name = form.get("devicename").ok_or_else(|| ApiError::bad("device_name cannot be blank"))?;
    let device_type: i64 = form.get("devicetype").and_then(|kind| kind.trim().parse().ok()).unwrap_or(14);
    if device_name.len() > 256 || device_id.len() > 256 {
        return Err(ApiError::bad("The device is not valid."));
    }
    // A suite app logs in with its password or SSO only; a passkey is for Bitwarden's clients.
    if crate::suite::space_of_client(form.get("clientid").unwrap_or_default()).is_some() {
        return Err(ApiError::json(
            serde_json::json!({ "error": "invalid_client", "error_description": "invalid_client" }),
        ));
    }
    if !state.limits.login.check(ip) {
        return Err(ApiError::too_many("Too many login requests. Wait a minute and try again."));
    }
    let refused = || ApiError::bad("The passkey did not log in. Try again.");
    let challenge = state.challenges.take(&format!("passkey-login:{token}")).ok_or_else(refused)?;
    let assertion: webauthn::Assertion = serde_json::from_str(response).map_err(|_| refused())?;
    let id = assertion.credential_id().map(|id| webauthn::b64(&id)).ok_or_else(refused)?;
    let passkey = state.store.passkey(&id).await?.ok_or_else(refused)?;
    // The browser says whose passkey it is; it has to be the one it belongs to.
    let handle = assertion.response.user_handle.as_deref().and_then(webauthn::unb64);
    let owner = uuid::Uuid::parse_str(&passkey.user_id).map(|id| id.as_bytes().to_vec()).ok();
    if handle.is_some() && handle != owner {
        return Err(refused());
    }
    let stored = webauthn::unb64(&passkey.public_key).unwrap_or_default();
    let counter = webauthn::assert(&assertion, &challenge, &state.party, &stored, passkey.counter as u32, true)
        .map_err(|reason| {
            tracing::info!(%reason, "a passkey login was refused");
            refused()
        })?;
    state.store.passkey_used(&passkey.id, i64::from(counter)).await?;
    let user = state.store.user(&passkey.user_id).await?.ok_or_else(refused)?;
    if user.disabled {
        return Err(ApiError::bad("This account has been disabled."));
    }
    let known = state.store.device(&user.id, device_id).await?.is_some();
    crate::sso::password_allowed(state, &user)?;
    let login = Login { device_id, device_name, device_type, known, remember: None, by_request: false, sso: false };
    let mut body = finish_login(state, &user, ip, form, login).await?;
    if let (Some(user_key), Some(private_key)) = (&passkey.encrypted_user_key, &passkey.encrypted_private_key) {
        body["UserDecryptionOptions"]["WebAuthnPrfOption"] =
            json!({ "EncryptedPrivateKey": private_key, "EncryptedUserKey": user_key });
    }
    Ok(Json(body).into_response())
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use crate::webauthn::tests::SoftKey;
    use axum::http::StatusCode;
    use serde_json::json;

    const ORIGIN: &str = "https://vault.example.com";

    #[tokio::test]
    async fn a_passkey_logs_in_and_unlocks() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        server.state.store.set_two_factor(&account.id, 0, "JBSWY3DPEHPK3PXP".into(), "RECOVER".into()).await.unwrap();
        let secret = json!({"masterPasswordHash": password_hash("nyu@example.com")});
        let offer =
            json(server.call("POST", "/api/webauthn/attestation-options", Some(&account.token), secret.clone()).await)
                .await;
        assert_eq!(offer["options"]["authenticatorSelection"]["residentKey"], "required");
        let mut key = SoftKey::new();
        let body = json!({
            "deviceResponse": key.create(&offer["options"], ORIGIN),
            "name": "Phone",
            "token": offer["token"],
            "supportsPrf": true,
            "encryptedUserKey": "4.user",
            "encryptedPublicKey": "2.public|a|b",
            "encryptedPrivateKey": "2.private|a|b",
        });
        let response = server.call("POST", "/api/webauthn", Some(&account.token), body).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        let listed = json(server.get_as(&account.token, "/api/webauthn").await).await;
        assert_eq!(listed["data"][0]["prfStatus"], 0);

        let options = json(server.get("/identity/accounts/webauthn/assertion-options").await).await;
        let answer = key.get(
            &options["options"],
            ORIGIN,
            Some(&crate::webauthn::b64(uuid::Uuid::parse_str(&account.id).unwrap().as_bytes())),
        );
        let fields = [
            ("grant_type", "webauthn".to_string()),
            ("token", options["token"].as_str().unwrap().to_string()),
            ("deviceResponse", answer.to_string()),
            ("scope", "api offline_access".into()),
            ("client_id", "web".into()),
            ("deviceType", "9".into()),
            ("deviceIdentifier", "web-2".into()),
            ("deviceName", "chrome".into()),
        ];
        let form: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let response = server.form("/identity/connect/token", &form).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        let body = json(response).await;
        assert_eq!(body["UserDecryptionOptions"]["WebAuthnPrfOption"]["EncryptedUserKey"], "4.user");
        assert_eq!(
            server.form("/identity/connect/token", &form).await.status(),
            StatusCode::BAD_REQUEST,
            "the challenge is used up"
        );

        let response = server
            .call(
                "POST",
                &format!("/api/webauthn/{}/delete", listed["data"][0]["id"].as_str().unwrap()),
                Some(&account.token),
                secret,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_security_key_is_the_second_step() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let secret = json!({"masterPasswordHash": password_hash("nyu@example.com")});
        let options = json(
            server.call("POST", "/api/two-factor/get-webauthn-challenge", Some(&account.token), secret.clone()).await,
        )
        .await;
        let mut key = SoftKey::new();
        key.verified = false;
        let body = json!({"id": 1, "name": "YubiKey", "deviceResponse": key.create(&options, ORIGIN), "masterPasswordHash": password_hash("nyu@example.com")});
        let response = server.call("PUT", "/api/two-factor/webauthn", Some(&account.token), body).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        assert_eq!(json(response).await["keys"][0]["name"], "YubiKey");

        let response = server.form("/identity/connect/token", &login_form("nyu@example.com", "d2")).await;
        let required = json(response).await;
        assert_eq!(required["TwoFactorProviders"], json!(["7"]));
        let request = &required["TwoFactorProviders2"]["7"];
        let answer = key.get(request, ORIGIN, None).to_string();
        let mut form = login_form("nyu@example.com", "d2");
        form.extend([("twoFactorProvider", "7"), ("twoFactorToken", answer.as_str())]);
        let response = server.form("/identity/connect/token", &form).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);

        let body = json!({"id": 1, "masterPasswordHash": password_hash("nyu@example.com")});
        let response = server.call("DELETE", "/api/two-factor/webauthn", Some(&account.token), body).await;
        assert_eq!(json(response).await["enabled"], false);
        let response = server.form("/identity/connect/token", &login_form("nyu@example.com", "d3")).await;
        assert_eq!(response.status(), StatusCode::OK, "no second step any more");
    }
}
