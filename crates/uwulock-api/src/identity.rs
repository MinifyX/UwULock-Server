//! `/identity`: logging in, staying logged in, and registering.
//!
//! - `POST /identity/connect/token` with the master password hash logs a device in — after the
//!   second step, if the account has two-step login — and with the refresh token keeps it
//!   logged in.
//! - The prelogin tells a client how to derive the master key for an address. For an address
//!   without an account it answers the same as for one, so it tells nobody which exist.
//! - Registering takes an invitation. Its link carries a token; the official clients' "create
//!   account" sends the invitation mail again.

use crate::auth::{self, ClientIp, refresh_days};
use crate::errors::{ApiError, ApiResult};
use crate::{AppState, two_factor};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Form, Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use uwulock_mail::{Language, Mail};
use uwulock_store::{DeviceLogin, Event, Kdf, NewUser, StoreError, User, clock, normalize_email};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/identity/connect/token", post(token))
        .route("/identity/accounts/prelogin", post(prelogin))
        .route("/identity/accounts/prelogin/password", post(prelogin))
        .route("/api/accounts/prelogin", post(prelogin))
        .route("/identity/accounts/register/send-verification-email", post(send_verification_email))
        .route("/identity/accounts/register/finish", post(register_finish))
        .route("/identity/accounts/register", post(register_without_invitation))
        .route("/api/accounts/register", post(register_without_invitation))
}

/// The form of a token request, with its names written one way: `device_identifier`,
/// `deviceIdentifier` and `DeviceIdentifier` all become `deviceidentifier`.
pub(crate) struct TokenForm(HashMap<String, String>);

impl TokenForm {
    fn new(raw: HashMap<String, String>) -> Self {
        TokenForm(raw.into_iter().map(|(key, value)| (key.to_ascii_lowercase().replace('_', ""), value)).collect())
    }

    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str).filter(|value| !value.is_empty())
    }

    fn require(&self, name: &str, label: &str) -> ApiResult<&str> {
        self.get(name).ok_or_else(|| ApiError::bad(format!("{label} cannot be blank")))
    }
}

async fn token(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Form(raw): Form<HashMap<String, String>>,
) -> ApiResult<Response> {
    let form = TokenForm::new(raw);
    match form.get("granttype") {
        Some("password") => password_login(&state, ip, &headers, &form).await,
        Some("refresh_token") => refresh(&state, ip, &form).await,
        Some("client_credentials") => Err(ApiError::bad("Logging in with an API key is not available yet.")),
        _ => Err(ApiError::bad("Invalid type")),
    }
}

async fn password_login(
    state: &AppState,
    ip: std::net::IpAddr,
    headers: &HeaderMap,
    form: &TokenForm,
) -> ApiResult<Response> {
    form.require("clientid", "client_id")?;
    let password = form.require("password", "password")?;
    let scope = form.require("scope", "scope")?;
    let username = form.require("username", "username")?;
    let device_id = form.require("deviceidentifier", "device_identifier")?;
    let device_name = form.require("devicename", "device_name")?;
    let device_type: i64 = form.require("devicetype", "device_type")?.trim().parse().unwrap_or(14);
    if scope != "api offline_access" {
        return Err(ApiError::bad(format!("Scope ({scope}) not supported")));
    }
    if !state.limits.login.check(ip) {
        return Err(ApiError::too_many("Too many login requests. Wait a minute and try again."));
    }

    let user = state.store.user_by_email(username).await?;
    let known = user.as_ref().map(|user| user.password_hash.as_str());
    if !auth::verify_password(state.config.hash_cost, known, password).await {
        log(state, "login-failed", user.as_ref(), username, ip, device_type, "wrong email or password").await;
        return Err(ApiError::bad("Username or password is incorrect. Try again"));
    }
    let user = user.expect("a password matched, so there is a user");
    if user.disabled {
        log(state, "login-failed", Some(&user), username, ip, device_type, "account disabled").await;
        return Err(ApiError::bad("This account has been disabled."));
    }

    let known_device = state.store.device(&user.id, device_id).await?;
    let remember = match two_factor::check_login(state, &user, form, known_device.as_ref(), ip, headers).await {
        Ok(remember) => remember,
        Err(error) => {
            if error.status == StatusCode::BAD_REQUEST && form.get("twofactortoken").is_some() {
                log(state, "two-factor-failed", Some(&user), username, ip, device_type, "wrong code").await;
            }
            return Err(error);
        }
    };

    let refresh_token = auth::random_token(64);
    let first_device = known_device.is_none() && state.store.devices(&user.id).await?.is_empty();
    let new = state
        .store
        .log_in_device(DeviceLogin {
            user_id: user.id.clone(),
            id: device_id.to_string(),
            name: device_name.to_string(),
            kind: device_type,
            ip: Some(ip.to_string()),
            refresh_hash: auth::sha256(refresh_token.as_bytes()),
            refresh_expires: clock::in_seconds(refresh_days(device_type) * 86_400),
            remember: remember
                .as_ref()
                .map(|token| (auth::sha256(token.as_bytes()), clock::in_seconds(auth::REMEMBER_DAYS * 86_400))),
        })
        .await?;
    log(state, "login", Some(&user), username, ip, device_type, device_name).await;
    if new && !first_device && state.settings().new_device_mail && state.mailer.enabled() {
        let mail = Mail::NewDevice {
            device: format!("{device_name} ({})", auth::device_type_name(device_type)),
            ip: ip.to_string(),
            time: format_time(&clock::now()),
        };
        send_later(state, &user.email, mail, Language::from_code(&user.language));
    }

    let client_id = form.get("clientid").unwrap_or("undefined");
    let (access_token, expires_in) = state.tokens.access_token(&user, device_id, device_type, client_id);
    let mut body = login_response(&user, access_token, expires_in);
    body["refresh_token"] = refresh_token.into();
    if let Some(remember) = remember {
        body["TwoFactorToken"] = remember.into();
    }
    Ok(Json(body).into_response())
}

/// What a successful password login answers, Bitwarden's mix of casings and all.
fn login_response(user: &User, access_token: String, expires_in: i64) -> Value {
    let kdf = json!({
        "KdfType": user.kdf.kind,
        "Iterations": user.kdf.iterations,
        "Memory": user.kdf.memory,
        "Parallelism": user.kdf.parallelism,
    });
    json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "scope": "api offline_access",
        "Key": user.user_key,
        "PrivateKey": user.private_key,
        "Kdf": user.kdf.kind,
        "KdfIterations": user.kdf.iterations,
        "KdfMemory": user.kdf.memory,
        "KdfParallelism": user.kdf.parallelism,
        "ResetMasterPassword": false,
        "ForcePasswordReset": false,
        "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
        "AccountKeys": match &user.private_key {
            Some(private) => json!({
                "publicKeyEncryptionKeyPair": {
                    "wrappedPrivateKey": private,
                    "publicKey": user.public_key,
                    "Object": "publicKeyEncryptionKeyPair",
                },
                "Object": "privateKeys",
            }),
            None => Value::Null,
        },
        "UserDecryptionOptions": {
            "HasMasterPassword": true,
            "MasterPasswordUnlock": {
                "Kdf": kdf,
                "MasterKeyEncryptedUserKey": user.user_key,
                "MasterKeyWrappedUserKey": user.user_key,
                "Salt": user.email,
            },
            "Object": "userDecryptionOptions",
        },
    })
}

/// A refused refresh has to be exactly this, or the clients do not log out cleanly.
fn invalid_grant() -> ApiError {
    ApiError::json(json!({ "error": "invalid_grant" }))
}

async fn refresh(state: &AppState, ip: std::net::IpAddr, form: &TokenForm) -> ApiResult<Response> {
    let Some(token) = form.get("refreshtoken") else { return Err(invalid_grant()) };
    let device = state
        .store
        .refresh_device(
            auth::sha256(token.trim().as_bytes()),
            |kind| clock::in_seconds(refresh_days(kind) * 86_400),
            Some(ip.to_string()),
        )
        .await?
        .ok_or_else(invalid_grant)?;
    let session = state.store.session_user(&device.user_id).await?.ok_or_else(invalid_grant)?;
    if session.user.disabled {
        return Err(invalid_grant());
    }
    let client_id = form.get("clientid").unwrap_or("undefined");
    let (access_token, expires_in) = state.tokens.access_token(&session.user, &device.id, device.kind, client_id);
    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "refresh_token": token.trim(),
        "scope": "api offline_access",
    }))
    .into_response())
}

async fn log(
    state: &AppState,
    kind: &str,
    user: Option<&User>,
    email: &str,
    ip: std::net::IpAddr,
    device_type: i64,
    detail: &str,
) {
    let event = Event {
        kind: kind.into(),
        user_id: user.map(|user| user.id.clone()),
        email: Some(normalize_email(email)),
        ip: Some(ip.to_string()),
        device_type: Some(device_type),
        detail: Some(detail.chars().take(200).collect()),
        ..Event::default()
    };
    if let Err(error) = state.store.log_event(event).await {
        tracing::warn!(%error, "could not write an event");
    }
    if kind != "login" {
        tracing::info!(%ip, email = %normalize_email(email), kind, detail, "login refused");
    }
}

/// Send a mail without making the request wait for the mail server.
pub(crate) fn send_later(state: &AppState, to: &str, mail: Mail, language: Language) {
    let mailer = state.mailer.clone();
    let to = to.to_string();
    tokio::spawn(async move {
        if let Err(error) = mailer.send(&to, &mail, language).await {
            tracing::warn!(%error, "a mail did not go out");
        }
    });
}

/// `2026-09-25 14:03 UTC`, for a mail.
pub(crate) fn format_time(text: &str) -> String {
    clock::parse(text).map_or_else(
        || text.to_string(),
        |when| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02} UTC",
                when.year(),
                u8::from(when.month()),
                when.day(),
                when.hour(),
                when.minute()
            )
        },
    )
}

// ── Prelogin ──────────────────────────────────────────────

#[derive(Deserialize)]
struct PreloginRequest {
    #[serde(alias = "Email")]
    email: String,
}

async fn prelogin(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(request): Json<PreloginRequest>,
) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let kdf = state.store.user_by_email(&request.email).await?.map(|user| user.kdf).unwrap_or(Kdf {
        kind: 0,
        iterations: 600_000,
        memory: None,
        parallelism: None,
    });
    Ok(Json(json!({
        "kdf": kdf.kind,
        "kdfIterations": kdf.iterations,
        "kdfMemory": kdf.memory,
        "kdfParallelism": kdf.parallelism,
        "kdfSettings": {
            "kdfType": kdf.kind,
            "iterations": kdf.iterations,
            "memory": kdf.memory,
            "parallelism": kdf.parallelism,
        },
        "salt": null,
    })))
}

// ── Registering ───────────────────────────────────────────

/// A KDF as the clients send it, in either of Bitwarden's spellings.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KdfData {
    #[serde(alias = "kdfType")]
    pub kdf: i64,
    #[serde(alias = "iterations")]
    pub kdf_iterations: i64,
    #[serde(default, alias = "memory")]
    pub kdf_memory: Option<i64>,
    #[serde(default, alias = "parallelism")]
    pub kdf_parallelism: Option<i64>,
}

impl KdfData {
    /// Checked against what Bitwarden allows, with a ceiling a login can still finish under.
    pub(crate) fn check(self) -> ApiResult<Kdf> {
        match self.kdf {
            0 => {
                if self.kdf_iterations < 100_000 {
                    return Err(ApiError::bad("PBKDF2 KDF iterations must be at least 100000."));
                }
                if self.kdf_iterations > 2_000_000 {
                    return Err(ApiError::bad("PBKDF2 KDF iterations must be at most 2000000."));
                }
                Ok(Kdf { kind: 0, iterations: self.kdf_iterations, memory: None, parallelism: None })
            }
            1 => {
                if !(2..=10).contains(&self.kdf_iterations) {
                    return Err(ApiError::bad("Argon2 KDF iterations must be between 2 and 10."));
                }
                let memory = self.kdf_memory.ok_or_else(|| ApiError::bad("Argon2 memory parameter is required."))?;
                if !(15..=1024).contains(&memory) {
                    return Err(ApiError::bad("Argon2 memory must be between 15 MB and 1024 MB."));
                }
                let parallelism =
                    self.kdf_parallelism.ok_or_else(|| ApiError::bad("Argon2 parallelism parameter is required."))?;
                if !(1..=16).contains(&parallelism) {
                    return Err(ApiError::bad("Argon2 parallelism must be between 1 and 16."));
                }
                Ok(Kdf {
                    kind: 1,
                    iterations: self.kdf_iterations,
                    memory: Some(memory),
                    parallelism: Some(parallelism),
                })
            }
            _ => Err(ApiError::bad("This key derivation is not supported.")),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Keys {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MasterPasswordAuthentication {
    kdf: KdfData,
    salt: String,
    #[serde(alias = "masterPasswordAuthenticationHash")]
    hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MasterPasswordUnlock {
    kdf: KdfData,
    salt: String,
    #[serde(alias = "masterKeyWrappedUserKey")]
    key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterData {
    email: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    master_password_hint: Option<String>,
    #[serde(default, alias = "userAsymmetricKeys")]
    keys: Option<Keys>,
    #[serde(default)]
    email_verification_token: Option<String>,
    #[serde(default)]
    master_password_hash: Option<String>,
    #[serde(default, alias = "userSymmetricKey")]
    key: Option<String>,
    #[serde(default, alias = "kdfType")]
    kdf: Option<i64>,
    #[serde(default, alias = "iterations")]
    kdf_iterations: Option<i64>,
    #[serde(default, alias = "memory")]
    kdf_memory: Option<i64>,
    #[serde(default, alias = "parallelism")]
    kdf_parallelism: Option<i64>,
    #[serde(default)]
    master_password_authentication: Option<MasterPasswordAuthentication>,
    #[serde(default)]
    master_password_unlock: Option<MasterPasswordUnlock>,
}

const BY_INVITATION: &str = "Registration is by invitation only. Open the link from your invitation.";

/// A trimmed hint, or none. Refused when hints are off.
pub(crate) fn clean_hint(state: &AppState, hint: Option<String>) -> ApiResult<Option<String>> {
    let hint = hint.map(|hint| hint.trim().to_string()).filter(|hint| !hint.is_empty());
    if hint.is_some() && !state.settings().password_hints {
        return Err(ApiError::bad("Password hints are turned off on this server. Remove the hint and try again."));
    }
    if hint.as_ref().is_some_and(|hint| hint.chars().count() > 50) {
        return Err(ApiError::bad("The password hint can be at most 50 characters long."));
    }
    Ok(hint)
}

async fn register_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(data): Json<RegisterData>,
) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let email = normalize_email(&data.email);
    let token = data.email_verification_token.as_deref().ok_or_else(|| ApiError::bad(BY_INVITATION))?;
    let invitation = state
        .store
        .invitation_by_token(auth::sha256(token.trim().as_bytes()))
        .await?
        .filter(|invitation| invitation.email == email)
        .ok_or_else(|| ApiError::bad("This invitation is not valid (any more). Ask for a new one."))?;

    let (password, key, kdf) = match (data.master_password_authentication, data.master_password_unlock) {
        (Some(authentication), Some(unlock)) => {
            if authentication.kdf != unlock.kdf
                || normalize_email(&authentication.salt) != email
                || normalize_email(&unlock.salt) != email
            {
                return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "Unexpected RegisterData format"));
            }
            (authentication.hash, unlock.key, unlock.kdf)
        }
        _ => {
            let missing = || ApiError::bad("Registration is missing required parameters");
            let kdf = KdfData {
                kdf: data.kdf.ok_or_else(missing)?,
                kdf_iterations: data.kdf_iterations.ok_or_else(missing)?,
                kdf_memory: data.kdf_memory,
                kdf_parallelism: data.kdf_parallelism,
            };
            (data.master_password_hash.ok_or_else(missing)?, data.key.ok_or_else(missing)?, kdf)
        }
    };
    let kdf = kdf.check()?;
    let name = data.name.map(|name| name.trim().to_string()).filter(|name| !name.is_empty());
    if name.as_ref().is_some_and(|name| name.len() > 50) {
        return Err(ApiError::bad("The field Name must be a string with a maximum length of 50."));
    }
    let hint = clean_hint(&state, data.master_password_hint)?;
    let (private_key, public_key) = match data.keys {
        Some(keys) => (Some(keys.encrypted_private_key), Some(keys.public_key)),
        None => (None, None),
    };
    let new = NewUser {
        email: email.clone(),
        name,
        password_hash: auth::hash_password(state.config.hash_cost, &password).await?,
        password_hint: hint,
        user_key: key,
        private_key,
        public_key,
        kdf,
        language: invitation.language.clone(),
        admin: invitation.admin,
    };
    let user = match state.store.create_user(new).await {
        Ok(user) => user,
        Err(StoreError::Exists) => return Err(ApiError::bad("There is an account for this address already.")),
        Err(error) => return Err(error.into()),
    };
    tracing::info!(email = %user.email, admin = user.admin, "account registered");
    let event = Event {
        kind: "register".into(),
        user_id: Some(user.id.clone()),
        email: Some(user.email.clone()),
        ip: Some(ip.to_string()),
        ..Event::default()
    };
    let _ = state.store.log_event(event).await;
    Ok(Json(json!({ "object": "register", "captchaBypassToken": "" })))
}

#[derive(Deserialize)]
struct VerificationRequest {
    email: String,
}

/// The official clients' "create account": for an invited address, the invitation mail goes out
/// again, with a new link. Everybody else is told registering needs an invitation.
async fn send_verification_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(request): Json<VerificationRequest>,
) -> ApiResult<Response> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let email = normalize_email(&request.email);
    let invitation = state.store.invitation(&email).await?.filter(|invitation| invitation.expires > clock::now());
    let Some(invitation) = invitation else { return Err(ApiError::bad(BY_INVITATION)) };
    if !state.mailer.enabled() {
        return Err(ApiError::bad(BY_INVITATION));
    }
    crate::admin::invite(&state, &email, invitation.admin, invitation.invited_by.clone()).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn register_without_invitation() -> ApiError {
    ApiError::bad(BY_INVITATION)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::http::StatusCode;
    use serde_json::json;

    #[tokio::test]
    async fn an_invitation_registers_one_account_that_logs_in() {
        let server = TestServer::new().await;
        let token = server.invite("nyu@example.com", false).await;
        let response = server
            .call("POST", "/identity/accounts/register/finish", None, register_body("Nyu@Example.com", &token))
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        assert_eq!(json(response).await["object"], "register");
        let again = server
            .call("POST", "/identity/accounts/register/finish", None, register_body("nyu@example.com", &token))
            .await;
        assert_eq!(again.status(), StatusCode::BAD_REQUEST, "the invitation is used up");

        let response = server.form("/identity/connect/token", &login_form("nyu@example.com", "d1")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["Key"], "2.userkey|userkey|userkey");
        assert_eq!(body["PrivateKey"], "2.private|private|private");
        assert_eq!(body["Kdf"], 0);
        assert_eq!(body["KdfIterations"], 600000);
        assert_eq!(body["UserDecryptionOptions"]["MasterPasswordUnlock"]["Salt"], "nyu@example.com");
        assert_eq!(body["MasterPasswordPolicy"]["Object"], "masterPasswordPolicy");
        assert!(body["refresh_token"].as_str().unwrap().len() > 60);
    }

    #[tokio::test]
    async fn nobody_registers_without_an_invitation() {
        let server = TestServer::new().await;
        let token = server.invite("nyu@example.com", false).await;
        for (email, token) in [("other@example.com", token.as_str()), ("nyu@example.com", "made-up")] {
            let response =
                server.call("POST", "/identity/accounts/register/finish", None, register_body(email, token)).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{email}");
        }
        let mut body = register_body("nyu@example.com", &token);
        body.as_object_mut().unwrap().remove("emailVerificationToken");
        for path in ["/identity/accounts/register/finish", "/identity/accounts/register", "/api/accounts/register"] {
            let response = server.call("POST", path, None, body.clone()).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        }
    }

    #[tokio::test]
    async fn the_new_form_of_registering_works_too() {
        let server = TestServer::new().await;
        let token = server.invite("nyu@example.com", false).await;
        let kdf = json!({"kdfType": 1, "iterations": 3, "memory": 64, "parallelism": 4});
        let body = json!({
            "email": "nyu@example.com",
            "masterPasswordAuthentication": {"kdf": kdf, "salt": "nyu@example.com", "masterPasswordAuthenticationHash": password_hash("nyu@example.com")},
            "masterPasswordUnlock": {"kdf": kdf, "salt": "nyu@example.com", "masterKeyWrappedUserKey": "2.k|k|k"},
            "userAsymmetricKeys": {"encryptedPrivateKey": "2.p|p|p", "publicKey": "pub"},
            "emailVerificationToken": token,
        });
        let response = server.call("POST", "/identity/accounts/register/finish", None, body).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        let prelogin =
            json(server.call("POST", "/identity/accounts/prelogin", None, json!({"email": "NYU@example.com"})).await)
                .await;
        assert_eq!((prelogin["kdf"].clone(), prelogin["kdfMemory"].clone()), (json!(1), json!(64)));
        assert_eq!(prelogin["kdfSettings"]["parallelism"], 4);
    }

    #[tokio::test]
    async fn a_cheap_or_unknown_kdf_is_refused() {
        let server = TestServer::new().await;
        for (kdf, iterations, memory) in
            [(0, 5000, None), (0, 5_000_000, None), (1, 3, Some(4)), (1, 3, None), (7, 3, None)]
        {
            let token = server.invite("nyu@example.com", false).await;
            let mut body = register_body("nyu@example.com", &token);
            body["kdf"] = json!(kdf);
            body["kdfIterations"] = json!(iterations);
            body["kdfMemory"] = json!(memory);
            body["kdfParallelism"] = json!(4);
            let response = server.call("POST", "/identity/accounts/register/finish", None, body).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{kdf} {iterations} {memory:?}");
        }
    }

    #[tokio::test]
    async fn a_prelogin_tells_nobody_who_has_an_account() {
        let server = TestServer::new().await;
        let unknown =
            json(server.call("POST", "/api/accounts/prelogin", None, json!({"email": "nobody@example.com"})).await)
                .await;
        assert_eq!(unknown["kdf"], 0);
        assert_eq!(unknown["kdfIterations"], 600000);
    }

    #[tokio::test]
    async fn a_wrong_password_is_refused_and_written_down() {
        let server = TestServer::new().await;
        server.account("nyu@example.com").await;
        let mut form = login_form("nyu@example.com", "d2");
        form[2].1 = "wrong";
        let response = server.form("/identity/connect/token", &form).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(response).await["message"], "Username or password is incorrect. Try again");
        let unknown = server.form("/identity/connect/token", &login_form("nobody@example.com", "d2")).await;
        assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
        let events = server.state.store.events(Some("login-failed".into()), None, 10).await.unwrap();
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn a_refresh_token_keeps_a_device_logged_in_until_it_logs_out() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let response = server
            .form(
                "/identity/connect/token",
                &[("grant_type", "refresh_token"), ("client_id", "browser"), ("refresh_token", &account.refresh)],
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["refresh_token"], account.refresh.as_str());
        let fresh = body["access_token"].as_str().unwrap().to_string();
        assert_eq!(server.get_as(&fresh, "/api/accounts/revision-date").await.status(), StatusCode::OK);

        server.state.store.log_out_device(&account.id, &account.device).await.unwrap();
        let response = server
            .form("/identity/connect/token", &[("grant_type", "refresh_token"), ("refresh_token", &account.refresh)])
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(response).await, json!({"error": "invalid_grant"}));
        assert_eq!(
            server.get_as(&fresh, "/api/accounts/revision-date").await.status(),
            StatusCode::UNAUTHORIZED,
            "its access token ends too"
        );
    }

    #[tokio::test]
    async fn a_new_device_gets_a_mail_but_the_first_does_not() {
        let server = TestServer::new().await;
        server.account("nyu@example.com").await;
        tokio::task::yield_now().await;
        assert!(server.mails().iter().all(|mail| !mail.subject.contains("Anmeldung")), "the first device");
        server.login("nyu@example.com", "device-2").await;
        server.wait_for_mail(|mail| mail.to == "nyu@example.com" && mail.subject.contains("Neue Anmeldung")).await;
    }

    #[tokio::test]
    async fn a_disabled_account_does_not_log_in() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        server.state.store.update_user(&account.id, |user| user.disabled = true).await.unwrap();
        let response = server.form("/identity/connect/token", &login_form("nyu@example.com", "d3")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(server.get_as(&account.token, "/api/sync").await.status(), StatusCode::UNAUTHORIZED);
    }
}
