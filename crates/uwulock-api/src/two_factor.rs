//! Two-step login: an authenticator app, or codes by mail — and the recovery code for the day
//! the phone is gone.
//!
//! Setting either up goes the way Bitwarden's clients do it: the client asks for a secret (or
//! for a code to the address), shows it, and sends back the first code to prove it works. Only
//! then is it on. The first way of two-step login also makes the account's recovery code.

use crate::accounts::check_password;
use crate::auth::{self, ClientIp, Session, client_version};
use crate::errors::{ApiError, ApiResult};
use crate::identity::{TokenForm, mail_allowed, mail_failed, send_later};
use crate::{AppState, totp, webauthn};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use uwulock_mail::{Language, Mail};
use uwulock_store::{CodeRefusal, Device, Event, TwoFactor, User, clock};

pub const AUTHENTICATOR: i64 = 0;
pub const EMAIL: i64 = 1;
const REMEMBER: i64 = 5;
pub const WEBAUTHN: i64 = 7;
/// How many security keys one account may have for the second step, like at Bitwarden.
const MAX_KEYS: usize = 5;
const RECOVERY: i64 = 8;

/// How long a code by mail works.
const CODE_SECONDS: i64 = 10 * 60;
const LOGIN_CODE: &str = "two-factor-login";
const SETUP_CODE: &str = "two-factor-setup";

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/two-factor", get(list))
        .route("/api/two-factor/get-recover", post(get_recover))
        .route("/api/two-factor/disable", post(disable).put(disable))
        .route("/api/two-factor/get-authenticator", post(get_authenticator))
        .route(
            "/api/two-factor/authenticator",
            post(activate_authenticator).put(activate_authenticator).delete(delete_authenticator),
        )
        .route("/api/two-factor/get-email", post(get_email))
        .route("/api/two-factor/send-email", post(send_setup_code))
        .route("/api/two-factor/email", axum::routing::put(activate_email))
        .route("/api/two-factor/send-email-login", post(send_login_code))
        .route("/api/two-factor/get-device-verification-settings", get(device_verification))
        .route("/api/two-factor/get-webauthn", post(get_webauthn))
        .route("/api/two-factor/get-webauthn-challenge", post(webauthn_challenge))
        .route("/api/two-factor/webauthn", post(activate_webauthn).put(activate_webauthn).delete(delete_webauthn))
}

/// Numbers some clients send as strings, and the other way round.
pub(crate) fn number_or_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    Ok(match Value::deserialize(deserializer)? {
        Value::String(text) => text,
        Value::Number(number) => number.to_string(),
        _ => String::new(),
    })
}

/// `ny***@example.com`: enough to recognise the address, not enough to learn it.
pub(crate) fn obscure_email(email: &str) -> String {
    let Some((local, domain)) = email.rsplit_once('@') else { return email.to_string() };
    let shown: String = if local.chars().count() <= 3 { String::new() } else { local.chars().take(2).collect() };
    let hidden = "*".repeat(local.chars().count() - shown.chars().count());
    format!("{shown}{hidden}@{domain}")
}

/// The address codes by mail go to, from the stored data.
fn code_address(data: &str) -> Option<String> {
    serde_json::from_str::<Value>(data).ok()?.get("email")?.as_str().map(str::to_string)
}

fn recovery_code() -> String {
    totp::base32_encode(&auth::random_bytes(20))
}

/// While travel mode is on, two-step login stays as it is and keeps its secrets: it is what
/// switches travel mode off, and a device taken at a border has the session and, often, the
/// master password (docs/uwu-api.md §9.3). So no provider is set up, replaced or removed, and
/// neither the authenticator key nor the recovery code is shown.
async fn unchanged_while_travelling(state: &AppState, user: &User) -> ApiResult<()> {
    if state.store.travelling(&user.id).await? {
        return Err(ApiError::bad("Travel mode is on. Two-step login can be changed again once it is off.")
            .code("travel_active"));
    }
    Ok(())
}

/// A security notice about a provider switched on or off, from this session.
async fn noted(state: &AppState, session: &Session, ip: std::net::IpAddr, kind: &str, provider: i64) {
    let context = crate::notices::Context::of(state, session, ip).await;
    crate::notices::record(state, &session.user, kind, &context, json!({ "provider": provider })).await;
}

// ── At login ──────────────────────────────────────────────

/// The second step of a password login. `Ok(None)` when the account has no two-step login or
/// it was passed; `Ok(Some(token))` when it was passed and the device is to be remembered.
/// Otherwise the answer that asks for a code, or says the code was wrong.
pub(crate) async fn check_login(
    state: &AppState,
    user: &User,
    form: &TokenForm,
    device: Option<&Device>,
    ip: std::net::IpAddr,
    headers: &HeaderMap,
) -> ApiResult<Option<String>> {
    let factors: Vec<_> =
        state.store.two_factors(&user.id).await?.into_iter().filter(|factor| factor.enabled).collect();
    if factors.is_empty() {
        return Ok(None);
    }
    let usable: Vec<_> = factors
        .iter()
        .filter(|factor| {
            factor.kind == AUTHENTICATOR || factor.kind == WEBAUTHN || (factor.kind == EMAIL && state.mailer.enabled())
        })
        .collect();
    if usable.is_empty() {
        return Err(ApiError::bad(
            "Two-step login by mail is on for this account, but the server cannot send mail. Use the recovery code, or ask an admin.",
        ));
    }
    let required = || {
        let mut providers2 = serde_json::Map::new();
        for factor in &usable {
            let details = match factor.kind {
                EMAIL => json!({ "Email": obscure_email(&code_address(&factor.data).unwrap_or_default()) }),
                WEBAUTHN => {
                    let challenge = webauthn::challenge();
                    let allow: Vec<Vec<u8>> = security_keys(&factor.data)
                        .iter()
                        .filter_map(|key| webauthn::unb64(&key.credential_id))
                        .collect();
                    let options = webauthn::request_options(&state.party, &challenge, &allow);
                    state.challenges.put(format!("2fa:{}", user.id), challenge);
                    options
                }
                _ => Value::Null,
            };
            providers2.insert(factor.kind.to_string(), details);
        }
        ApiError::json(json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": usable.iter().map(|factor| factor.kind.to_string()).collect::<Vec<_>>(),
            "TwoFactorProviders2": providers2,
            "MasterPasswordPolicy": state.settings().policies.master_password_policy(),
        }))
    };

    let provider = form.get("twofactorprovider").and_then(|value| value.trim().parse::<i64>().ok());
    let Some(code) = form.get("twofactortoken").map(str::trim) else {
        // Older clients do not ask for the mail themselves: when mail is the only way, it goes
        // out with this answer.
        if usable.len() == 1
            && usable[0].kind == EMAIL
            && client_version(headers).is_none_or(|version| version < (2025, 5, 0))
        {
            send_code(state, user, &usable[0].data).await?;
        }
        return Err(required());
    };
    let provider = provider.unwrap_or(usable[0].kind);
    // Whoever gets here knows the password. What stops them guessing six digits from many
    // addresses is this limit per account.
    // Taken now and given back for a right code, so codes sent at once all count.
    if !state.limits.two_factor.take(user.id.clone()) {
        return Err(ApiError::too_many("Too many wrong codes. Wait a few minutes and try again."));
    }
    // Whether the code was right, and a device may be remembered for it.
    let checked: ApiResult<bool> = async {
        match provider {
            REMEMBER => {
                let remembered = device.is_some_and(|device| {
                    device
                        .remember_hash
                        .as_deref()
                        .is_some_and(|hash| auth::constant_time_eq(hash, &auth::sha256(code.as_bytes())))
                        && device.remember_expires.as_deref().is_some_and(|expires| expires > clock::now().as_str())
                });
                if !remembered {
                    return Err(required());
                }
                // The device stays remembered; no new token.
                return Ok(false);
            }
            RECOVERY => {
                let given = code.replace(' ', "").to_lowercase();
                let right = user.recovery_code.as_ref().is_some_and(|stored| {
                    auth::constant_time_eq(stored.replace(' ', "").to_lowercase().as_bytes(), given.as_bytes())
                });
                if !right {
                    return Err(ApiError::bad("Recovery code is incorrect. Try again."));
                }
                // It would take two-step login away, and with it what switches travel mode off.
                if state.store.travelling(&user.id).await? {
                    return Err(ApiError::bad(
                        "Travel mode is on, so the recovery code does not work now. Use the second step, or ask an admin.",
                    ));
                }
                state.store.remove_two_factor(&user.id, None).await?;
                let event = Event {
                    kind: "two-factor-recovered".into(),
                    user_id: Some(user.id.clone()),
                    email: Some(user.email.clone()),
                    ip: Some(ip.to_string()),
                    ..Event::default()
                };
                let _ = state.store.log_event(event).await;
                if state.mailer.enabled() {
                    send_later(state, &user.email, Mail::RecoveryUsed, Language::from_code(&user.language));
                }
                // Mailed already, just now: listed, not mailed again.
                let context = crate::notices::Context::ip(ip);
                crate::notices::record_mailed(
                    state,
                    user,
                    "twoFactorDisabled",
                    &context,
                    json!({ "provider": RECOVERY }),
                    state.mailer.enabled(),
                )
                .await;
                return Ok(false);
            }
            AUTHENTICATOR | WEBAUTHN | EMAIL if usable.iter().any(|factor| factor.kind == provider) => {
                verify_code(state, user, &factors, provider, code, &format!("2fa:{}", user.id), LOGIN_CODE).await?;
            }
            _ => return Err(required()),
        }
        Ok(true)
    }
    .await;
    if checked.is_ok() {
        state.limits.two_factor.give_back(&user.id);
    }
    match checked {
        Ok(true) => {}
        Ok(false) => return Ok(None),
        Err(error) => return Err(error),
    }
    let remember = form.get("twofactorremember") == Some("1") && state.settings().remember_two_factor;
    Ok(remember.then(|| auth::random_token(32)))
}

/// A second-step `code` from `provider` (authenticator, security key or mail), checked against
/// the account's `factors`: the WebAuthn challenge waits under `challenge`, a mailed code under
/// `purpose`. For the login, and for what asks for the second step again, like switching travel
/// mode off.
pub(crate) async fn verify_code(
    state: &AppState,
    user: &User,
    factors: &[TwoFactor],
    provider: i64,
    code: &str,
    challenge: &str,
    purpose: &str,
) -> ApiResult<()> {
    let factor = factors
        .iter()
        .find(|factor| factor.enabled && factor.kind == provider)
        .ok_or_else(|| ApiError::bad("This way of two-step login is not set up."))?;
    match provider {
        AUTHENTICATOR => {
            let secret = totp::base32_decode(&factor.data).unwrap_or_default();
            let step = totp::matching_step(&secret, code, auth::now_seconds())
                .ok_or_else(|| ApiError::bad("The code from the authenticator app is wrong. Try again."))?;
            if !state.store.use_totp_step(&user.id, step).await? {
                return Err(ApiError::bad("This code was used already. Wait for the next one."));
            }
        }
        WEBAUTHN => {
            let wrong = || ApiError::bad("The security key did not answer as expected. Try again.");
            let assertion: webauthn::Assertion = serde_json::from_str(code).map_err(|_| wrong())?;
            let challenge = state.challenges.take(challenge).ok_or_else(wrong)?;
            let mut keys = security_keys(&factor.data);
            let used = assertion.credential_id().map(|id| webauthn::b64(&id)).unwrap_or_default();
            let key = keys.iter_mut().find(|key| key.credential_id == used).ok_or_else(wrong)?;
            let public_key = webauthn::unb64(&key.public_key).unwrap_or_default();
            key.counter = webauthn::assert(&assertion, &challenge, &state.party, &public_key, key.counter, false)
                .map_err(|reason| {
                    tracing::info!(user = %user.id, %reason, "a security key was refused");
                    wrong()
                })?;
            state
                .store
                .set_two_factor_data(&user.id, WEBAUTHN, serde_json::to_string(&keys).expect("keys serialize"))
                .await?;
        }
        EMAIL => match state.store.take_code(&user.id, purpose, auth::sha256(code.as_bytes())).await? {
            Ok(_) => {}
            Err(CodeRefusal::Wrong) => return Err(ApiError::bad("The code from the mail is wrong. Try again.")),
            Err(CodeRefusal::Missing | CodeRefusal::TooManyAttempts) => {
                return Err(ApiError::bad("There is no valid code any more. Send a new one."));
            }
            Err(CodeRefusal::Expired) => return Err(ApiError::bad("The code has expired. Send a new one.")),
        },
        _ => return Err(ApiError::bad("This way of two-step login is not set up.")),
    }
    Ok(())
}

/// A new code by mail, for `purpose`, to the address two-step login by mail goes to.
pub(crate) async fn send_code_for(state: &AppState, user: &User, data: &str, purpose: &str) -> ApiResult<()> {
    let address = code_address(data).ok_or_else(|| ApiError::internal("two-step login by mail has no address"))?;
    mail_allowed(state, &address, None)?;
    let code = auth::random_code(6);
    state
        .store
        .put_code(&user.id, purpose, auth::sha256(code.as_bytes()), None, clock::in_seconds(CODE_SECONDS))
        .await?;
    state
        .mailer
        .send(&address, &Mail::TwoFactorCode { code }, Language::from_code(&user.language))
        .await
        .map_err(|error| ApiError::internal(format!("sending a login code: {error}")))
}

/// WebAuthn assertion options for the account's security keys, the challenge kept under `key`.
pub(crate) fn webauthn_options(state: &AppState, factor: &TwoFactor, key: String) -> Value {
    let challenge = webauthn::challenge();
    let allow: Vec<Vec<u8>> =
        security_keys(&factor.data).iter().filter_map(|key| webauthn::unb64(&key.credential_id)).collect();
    let options = webauthn::request_options(&state.party, &challenge, &allow);
    state.challenges.put(key, challenge);
    options
}

/// A new login code, to the address two-step login by mail goes to.
async fn send_code(state: &AppState, user: &User, data: &str) -> ApiResult<()> {
    send_code_for(state, user, data, LOGIN_CODE).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginCodeRequest {
    #[serde(default, alias = "Email")]
    email: Option<String>,
    #[serde(default, alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
}

/// "Send me the code by mail" on the second step of a login. The password comes along, so this
/// cannot fill somebody's inbox with codes.
async fn send_login_code(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(request): Json<LoginCodeRequest>,
) -> ApiResult<StatusCode> {
    if !state.limits.login.check(ip) {
        return Err(ApiError::too_many("Too many login requests. Wait a minute and try again."));
    }
    let wrong = || ApiError::bad("Username or password is incorrect. Try again");
    let email = request.email.filter(|email| !email.is_empty()).ok_or_else(wrong)?;
    let password = request
        .master_password_hash
        .filter(|hash| !hash.is_empty())
        .ok_or_else(|| ApiError::bad("No password hash has been submitted."))?;
    let user = state.store.user_by_email(&email).await?;
    if !auth::verify_password(state.config.hash_cost, user.as_ref().map(|user| user.password_hash.as_str()), &password)
        .await
    {
        return Err(wrong());
    }
    let user = user.expect("a password matched");
    if !state.mailer.enabled() {
        return Err(ApiError::bad("This server cannot send mail."));
    }
    let factor = state
        .store
        .two_factors(&user.id)
        .await?
        .into_iter()
        .find(|factor| factor.kind == EMAIL && factor.enabled)
        .ok_or_else(|| ApiError::bad("Two-step login by mail is not set up for this account."))?;
    send_code(&state, &user, &factor.data).await?;
    Ok(StatusCode::OK)
}

// ── Settings ──────────────────────────────────────────────

async fn list(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let factors = state.store.two_factors(&session.user.id).await?;
    let data = factors
        .iter()
        .filter(|factor| {
            factor.enabled
                && (factor.kind == AUTHENTICATOR
                    || factor.kind == WEBAUTHN
                    || (factor.kind == EMAIL && state.mailer.enabled()))
        })
        .map(|factor| json!({ "enabled": true, "type": factor.kind, "object": "twoFactorProvider" }))
        .collect();
    Ok(Json(crate::json::list(data)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Secret {
    #[serde(default, alias = "MasterPasswordHash")]
    pub master_password_hash: Option<String>,
}

async fn get_recover(
    State(state): State<AppState>,
    session: Session,
    Json(secret): Json<Secret>,
) -> ApiResult<Json<Value>> {
    unchanged_while_travelling(&state, &session.user).await?;
    check_password(&state, &session.user, secret.master_password_hash.as_deref()).await?;
    Ok(Json(json!({ "code": session.user.recovery_code, "object": "twoFactorRecover" })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Disable {
    #[serde(default)]
    master_password_hash: Option<String>,
    #[serde(rename = "type", deserialize_with = "number_or_string")]
    kind: String,
}

async fn disable(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(request): Json<Disable>,
) -> ApiResult<Json<Value>> {
    unchanged_while_travelling(&state, &session.user).await?;
    check_password(&state, &session.user, request.master_password_hash.as_deref()).await?;
    let kind: i64 = request.kind.parse().map_err(|_| ApiError::bad("Invalid two factor provider"))?;
    state.store.remove_two_factor(&session.user.id, Some(kind)).await?;
    state.store.forget_remembered_devices(&session.user.id).await?;
    noted(&state, &session, ip, "twoFactorDisabled", kind).await;
    Ok(Json(json!({ "enabled": false, "type": kind, "object": "twoFactorProvider" })))
}

async fn get_authenticator(
    State(state): State<AppState>,
    session: Session,
    Json(secret): Json<Secret>,
) -> ApiResult<Json<Value>> {
    unchanged_while_travelling(&state, &session.user).await?;
    check_password(&state, &session.user, secret.master_password_hash.as_deref()).await?;
    let current =
        state.store.two_factors(&session.user.id).await?.into_iter().find(|factor| factor.kind == AUTHENTICATOR);
    Ok(Json(match current {
        Some(factor) => json!({ "enabled": factor.enabled, "key": factor.data, "object": "twoFactorAuthenticator" }),
        // Not stored: the client sends it back with the first code.
        None => {
            json!({ "enabled": false, "key": totp::base32_encode(&auth::random_bytes(20)), "object": "twoFactorAuthenticator" })
        }
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivateAuthenticator {
    key: String,
    #[serde(deserialize_with = "number_or_string")]
    token: String,
    #[serde(default)]
    master_password_hash: Option<String>,
}

async fn activate_authenticator(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(request): Json<ActivateAuthenticator>,
) -> ApiResult<Json<Value>> {
    unchanged_while_travelling(&state, &session.user).await?;
    check_password(&state, &session.user, request.master_password_hash.as_deref()).await?;
    let secret = totp::base32_decode(&request.key).ok_or_else(|| ApiError::bad("Invalid totp secret"))?;
    if secret.len() != 20 {
        return Err(ApiError::bad("Invalid key length"));
    }
    let step = totp::matching_step(&secret, &request.token, auth::now_seconds())
        .ok_or_else(|| ApiError::bad("The code from the authenticator app is wrong. Try again."))?;
    let key = totp::base32_encode(&secret);
    state.store.set_two_factor(&session.user.id, AUTHENTICATOR, key, recovery_code()).await?;
    state.store.use_totp_step(&session.user.id, step).await?;
    noted(&state, &session, ip, "twoFactorEnabled", AUTHENTICATOR).await;
    Ok(Json(json!({ "enabled": true, "key": request.key, "object": "twoFactorAuthenticator" })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteAuthenticator {
    key: String,
    #[serde(default)]
    master_password_hash: Option<String>,
}

async fn delete_authenticator(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(request): Json<DeleteAuthenticator>,
) -> ApiResult<Json<Value>> {
    unchanged_while_travelling(&state, &session.user).await?;
    check_password(&state, &session.user, request.master_password_hash.as_deref()).await?;
    let current =
        state.store.two_factors(&session.user.id).await?.into_iter().find(|factor| factor.kind == AUTHENTICATOR);
    if let Some(factor) = current {
        if !factor.data.eq_ignore_ascii_case(request.key.trim()) {
            return Err(ApiError::bad("This is not the authenticator key of the account."));
        }
        state.store.remove_two_factor(&session.user.id, Some(AUTHENTICATOR)).await?;
        state.store.forget_remembered_devices(&session.user.id).await?;
        noted(&state, &session, ip, "twoFactorDisabled", AUTHENTICATOR).await;
    }
    Ok(Json(json!({ "enabled": false, "type": AUTHENTICATOR, "object": "twoFactorProvider" })))
}

async fn get_email(
    State(state): State<AppState>,
    session: Session,
    Json(secret): Json<Secret>,
) -> ApiResult<Json<Value>> {
    unchanged_while_travelling(&state, &session.user).await?;
    check_password(&state, &session.user, secret.master_password_hash.as_deref()).await?;
    let current = state.store.two_factors(&session.user.id).await?.into_iter().find(|factor| factor.kind == EMAIL);
    Ok(Json(match current {
        Some(factor) => {
            json!({ "email": code_address(&factor.data), "enabled": factor.enabled, "object": "twoFactorEmail" })
        }
        None => json!({ "email": null, "enabled": false, "object": "twoFactorEmail" }),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetupCode {
    email: String,
    #[serde(default)]
    master_password_hash: Option<String>,
}

async fn send_setup_code(
    State(state): State<AppState>,
    session: Session,
    Json(request): Json<SetupCode>,
) -> ApiResult<StatusCode> {
    unchanged_while_travelling(&state, &session.user).await?;
    check_password(&state, &session.user, request.master_password_hash.as_deref()).await?;
    if !state.mailer.enabled() {
        return Err(ApiError::bad("This server cannot send mail, so two-step login by mail is not available."));
    }
    let address = request.email.trim().to_string();
    if !address.contains('@') || address.chars().any(char::is_control) {
        return Err(ApiError::bad("That is not an email address."));
    }
    mail_allowed(&state, &address, Some(&session.user.id))?;
    let code = auth::random_code(6);
    state
        .store
        .put_code(
            &session.user.id,
            SETUP_CODE,
            auth::sha256(code.as_bytes()),
            Some(address.clone()),
            clock::in_seconds(CODE_SECONDS),
        )
        .await?;
    state
        .mailer
        .send(&address, &Mail::TwoFactorSetup { code }, Language::from_code(&session.user.language))
        .await
        .map_err(mail_failed)?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivateEmail {
    email: String,
    #[serde(deserialize_with = "number_or_string")]
    token: String,
    #[serde(default)]
    master_password_hash: Option<String>,
}

async fn activate_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(request): Json<ActivateEmail>,
) -> ApiResult<Json<Value>> {
    unchanged_while_travelling(&state, &session.user).await?;
    check_password(&state, &session.user, request.master_password_hash.as_deref()).await?;
    let address =
        match state.store.take_code(&session.user.id, SETUP_CODE, auth::sha256(request.token.trim().as_bytes())).await?
        {
            Ok(Some(address)) => address,
            Ok(None) | Err(CodeRefusal::Missing | CodeRefusal::TooManyAttempts) => {
                return Err(ApiError::bad("There is no valid code any more. Send a new one."));
            }
            Err(CodeRefusal::Wrong) => return Err(ApiError::bad("Token is invalid")),
            Err(CodeRefusal::Expired) => return Err(ApiError::bad("The code has expired. Send a new one.")),
        };
    if !address.eq_ignore_ascii_case(request.email.trim()) {
        return Err(ApiError::bad("The code was sent to another address."));
    }
    state
        .store
        .set_two_factor(&session.user.id, EMAIL, json!({ "email": address }).to_string(), recovery_code())
        .await?;
    noted(&state, &session, ip, "twoFactorEnabled", EMAIL).await;
    Ok(Json(json!({ "email": address, "enabled": true, "object": "twoFactorEmail" })))
}

// ── Security keys ─────────────────────────────────────────

/// A security key for the second step, as it is kept in the two-step login's data.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SecurityKey {
    /// 1 to 5: the slot the clients show it in.
    pub id: i64,
    pub name: String,
    /// base64url.
    pub credential_id: String,
    /// The COSE key, base64url.
    pub public_key: String,
    pub counter: u32,
    #[serde(default)]
    pub migrated: bool,
}

pub(crate) fn security_keys(data: &str) -> Vec<SecurityKey> {
    serde_json::from_str(data).unwrap_or_default()
}

async fn keys_of(state: &AppState, user: &User) -> ApiResult<Vec<SecurityKey>> {
    Ok(state
        .store
        .two_factors(&user.id)
        .await?
        .into_iter()
        .find(|factor| factor.kind == WEBAUTHN)
        .map(|factor| security_keys(&factor.data))
        .unwrap_or_default())
}

fn keys_answer(keys: &[SecurityKey]) -> Value {
    json!({
        "enabled": !keys.is_empty(),
        "keys": keys.iter().map(|key| json!({ "id": key.id, "name": key.name, "migrated": key.migrated })).collect::<Vec<_>>(),
        "object": "twoFactorWebAuthn",
    })
}

async fn get_webauthn(
    State(state): State<AppState>,
    session: Session,
    Json(secret): Json<Secret>,
) -> ApiResult<Json<Value>> {
    check_password(&state, &session.user, secret.master_password_hash.as_deref()).await?;
    Ok(Json(keys_answer(&keys_of(&state, &session.user).await?)))
}

async fn webauthn_challenge(
    State(state): State<AppState>,
    session: Session,
    Json(secret): Json<Secret>,
) -> ApiResult<Json<Value>> {
    unchanged_while_travelling(&state, &session.user).await?;
    check_password(&state, &session.user, secret.master_password_hash.as_deref()).await?;
    let known: Vec<Vec<u8>> =
        keys_of(&state, &session.user).await?.iter().filter_map(|key| webauthn::unb64(&key.credential_id)).collect();
    let challenge = webauthn::challenge();
    let user = &session.user;
    let options = webauthn::creation_options(
        &state.party,
        &user.id,
        &user.email,
        user.name.as_deref(),
        &challenge,
        &known,
        false,
    );
    state.challenges.put(format!("2fa-register:{}", user.id), challenge);
    Ok(Json(options))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivateWebauthn {
    #[serde(deserialize_with = "number_or_string")]
    id: String,
    name: String,
    device_response: webauthn::Attestation,
    #[serde(default)]
    master_password_hash: Option<String>,
}

async fn activate_webauthn(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(request): Json<ActivateWebauthn>,
) -> ApiResult<Json<Value>> {
    unchanged_while_travelling(&state, &session.user).await?;
    check_password(&state, &session.user, request.master_password_hash.as_deref()).await?;
    let slot: i64 = request.id.parse().map_err(|_| ApiError::bad("Invalid key slot"))?;
    if !(1..=MAX_KEYS as i64).contains(&slot) {
        return Err(ApiError::bad("Invalid key slot"));
    }
    let challenge = state
        .challenges
        .take(&format!("2fa-register:{}", session.user.id))
        .ok_or_else(|| ApiError::bad("The security key took too long. Try again."))?;
    let registered = webauthn::register(&request.device_response, &challenge, &state.party, false)
        .map_err(|reason| ApiError::bad(format!("The security key was not accepted: {reason}.")))?;
    let mut keys = keys_of(&state, &session.user).await?;
    keys.retain(|key| key.id != slot);
    if keys.iter().any(|key| key.credential_id == webauthn::b64(&registered.credential_id)) {
        return Err(ApiError::bad("This security key is set up already."));
    }
    keys.push(SecurityKey {
        id: slot,
        name: request.name.trim().chars().take(50).collect(),
        credential_id: webauthn::b64(&registered.credential_id),
        public_key: webauthn::b64(&registered.public_key),
        counter: registered.counter,
        migrated: false,
    });
    keys.sort_by_key(|key| key.id);
    let data = serde_json::to_string(&keys).expect("keys serialize");
    state.store.set_two_factor(&session.user.id, WEBAUTHN, data, recovery_code()).await?;
    noted(&state, &session, ip, "twoFactorEnabled", WEBAUTHN).await;
    Ok(Json(keys_answer(&keys)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteWebauthn {
    #[serde(deserialize_with = "number_or_string")]
    id: String,
    #[serde(default)]
    master_password_hash: Option<String>,
}

async fn delete_webauthn(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(request): Json<DeleteWebauthn>,
) -> ApiResult<Json<Value>> {
    unchanged_while_travelling(&state, &session.user).await?;
    check_password(&state, &session.user, request.master_password_hash.as_deref()).await?;
    let slot: i64 = request.id.parse().map_err(|_| ApiError::bad("Invalid key slot"))?;
    let mut keys = keys_of(&state, &session.user).await?;
    keys.retain(|key| key.id != slot);
    if keys.is_empty() {
        state.store.remove_two_factor(&session.user.id, Some(WEBAUTHN)).await?;
        state.store.forget_remembered_devices(&session.user.id).await?;
        noted(&state, &session, ip, "twoFactorDisabled", WEBAUTHN).await;
    } else {
        let data = serde_json::to_string(&keys).expect("keys serialize");
        state.store.set_two_factor_data(&session.user.id, WEBAUTHN, data).await?;
    }
    Ok(Json(keys_answer(&keys)))
}

async fn device_verification(_session: Session) -> Json<Value> {
    Json(json!({
        "isDeviceVerificationSectionEnabled": false,
        "unknownDeviceVerificationEnabled": false,
        "object": "deviceVerificationSettings",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    fn now_code(key: &str) -> String {
        totp::code(&totp::base32_decode(key).unwrap(), auth::now_seconds() / 30)
    }

    #[test]
    fn addresses_are_obscured() {
        assert_eq!(obscure_email("bytes@example.com"), "by***@example.com");
        assert_eq!(obscure_email("byt@example.com"), "***@example.com");
    }

    async fn with_authenticator(server: &TestServer, account: &Account) -> String {
        let secret = json!({ "masterPasswordHash": password_hash(&account.email) });
        let got =
            json(server.call("POST", "/api/two-factor/get-authenticator", Some(&account.token), secret).await).await;
        assert_eq!(got["enabled"], false);
        let key = got["key"].as_str().unwrap().to_string();
        let body = json!({ "key": key, "token": now_code(&key), "masterPasswordHash": password_hash(&account.email) });
        let response = server.call("PUT", "/api/two-factor/authenticator", Some(&account.token), body).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        key
    }

    #[tokio::test]
    async fn an_authenticator_asks_for_its_code_at_login() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let key = with_authenticator(&server, &account).await;

        let response = server.form("/identity/connect/token", &login_form("nyu@example.com", "d2")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json(response).await;
        assert_eq!(body["error"], "invalid_grant");
        assert_eq!(body["TwoFactorProviders"], json!(["0"]));
        assert!(body["TwoFactorProviders2"]["0"].is_null());

        // The step used to set it up is used up; the next one logs in. So wait for it here by
        // taking the one after.
        let secret = totp::base32_decode(&key).unwrap();
        let next = totp::code(&secret, auth::now_seconds() / 30 + 1);
        let mut form = login_form("nyu@example.com", "d2");
        form.extend([("twoFactorProvider", "0"), ("twoFactorToken", next.as_str()), ("twoFactorRemember", "1")]);
        let response = server.form("/identity/connect/token", &form).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        let remember = json(response).await["TwoFactorToken"].as_str().unwrap().to_string();

        let again = server.form("/identity/connect/token", &form).await;
        assert_eq!(again.status(), StatusCode::BAD_REQUEST, "a code counts once");

        let mut remembered = login_form("nyu@example.com", "d2");
        remembered.extend([("twoFactorProvider", "5"), ("twoFactorToken", remember.as_str())]);
        assert_eq!(server.form("/identity/connect/token", &remembered).await.status(), StatusCode::OK);
        let mut elsewhere = login_form("nyu@example.com", "d3");
        elsewhere.extend([("twoFactorProvider", "5"), ("twoFactorToken", remember.as_str())]);
        assert_eq!(
            server.form("/identity/connect/token", &elsewhere).await.status(),
            StatusCode::BAD_REQUEST,
            "only on its device"
        );
    }

    #[tokio::test]
    async fn the_recovery_code_turns_two_step_login_off() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        with_authenticator(&server, &account).await;
        let secret = json!({ "masterPasswordHash": password_hash(&account.email) });
        let code =
            json(server.call("POST", "/api/two-factor/get-recover", Some(&account.token), secret).await).await["code"]
                .as_str()
                .unwrap()
                .to_string();
        assert_eq!(code.len(), 32);

        let mut form = login_form("nyu@example.com", "d2");
        form.extend([("twoFactorProvider", "8"), ("twoFactorToken", "WRONGWRONG")]);
        assert_eq!(server.form("/identity/connect/token", &form).await.status(), StatusCode::BAD_REQUEST);
        let lower = code.to_lowercase();
        let mut form = login_form("nyu@example.com", "d2");
        form.extend([("twoFactorProvider", "8"), ("twoFactorToken", lower.as_str())]);
        assert_eq!(server.form("/identity/connect/token", &form).await.status(), StatusCode::OK);
        assert!(server.state.store.two_factors(&account.id).await.unwrap().is_empty());
        assert_eq!(
            server.form("/identity/connect/token", &login_form("nyu@example.com", "d4")).await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn codes_by_mail_from_setup_to_login() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let body = json!({ "email": "codes@example.com", "masterPasswordHash": password_hash(&account.email) });
        assert_eq!(
            server.call("POST", "/api/two-factor/send-email", Some(&account.token), body).await.status(),
            StatusCode::OK
        );
        let mail = server.mails().pop().unwrap();
        assert_eq!(mail.to, "codes@example.com");
        let code: String = mail.text.chars().filter(char::is_ascii_digit).take(6).collect();
        let wrong = json!({ "email": "codes@example.com", "token": "000000", "masterPasswordHash": password_hash(&account.email) });
        assert_eq!(
            server.call("PUT", "/api/two-factor/email", Some(&account.token), wrong).await.status(),
            StatusCode::BAD_REQUEST
        );
        let right = json!({ "email": "codes@example.com", "token": code.as_str(), "masterPasswordHash": password_hash(&account.email) });
        let response = server.call("PUT", "/api/two-factor/email", Some(&account.token), right).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);

        let response = server.form("/identity/connect/token", &login_form("nyu@example.com", "d2")).await;
        let body = json(response).await;
        assert_eq!(body["TwoFactorProviders2"]["1"]["Email"], "co***@example.com");
        let ask = json!({ "email": "nyu@example.com", "masterPasswordHash": password_hash("nyu@example.com") });
        assert_eq!(server.call("POST", "/api/two-factor/send-email-login", None, ask).await.status(), StatusCode::OK);
        let mail = server.mails().pop().unwrap();
        let code: String = mail.subject.chars().filter(char::is_ascii_digit).collect();
        let mut form = login_form("nyu@example.com", "d2");
        form.extend([("twoFactorProvider", "1"), ("twoFactorToken", code.as_str())]);
        assert_eq!(server.form("/identity/connect/token", &form).await.status(), StatusCode::OK);
        assert_eq!(server.form("/identity/connect/token", &form).await.status(), StatusCode::BAD_REQUEST, "used up");

        let list = json(server.get_as(&account.token, "/api/two-factor").await).await;
        assert_eq!(list["data"][0]["type"], 1);
        let off = json!({ "masterPasswordHash": password_hash(&account.email), "type": "1" });
        assert_eq!(
            server.call("POST", "/api/two-factor/disable", Some(&account.token), off).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            server.form("/identity/connect/token", &login_form("nyu@example.com", "d5")).await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn nothing_is_set_up_without_the_password() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let wrong = json!({ "masterPasswordHash": "wrong" });
        for path in ["/api/two-factor/get-authenticator", "/api/two-factor/get-recover", "/api/two-factor/get-email"] {
            let response = server.call("POST", path, Some(&account.token), wrong.clone()).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        }
    }
}
