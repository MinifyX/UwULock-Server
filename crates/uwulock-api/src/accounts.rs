//! `/api/accounts` and `/api/devices`: the profile, a new master password, KDF or address, new
//! keys, ending every session, deleting the account — and the devices an account is logged in
//! on.
//!
//! Everything that changes how the account is unlocked asks for the current master password
//! hash first, and ends every session: the clients log in again with what is new.

use crate::auth::{self, ClientIp, Session};
use crate::ciphers::{CipherData, apply};
use crate::errors::{ApiError, ApiResult};
use crate::identity::{KdfData, clean_hint};
use crate::two_factor::number_or_string;
use crate::{AppState, json as out};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use uwulock_mail::{Language, Mail};
use uwulock_store::{CodeRefusal, User, clock, normalize_email};

const EMAIL_CODE: &str = "email-change";

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/accounts/profile", get(profile).put(update_profile).post(update_profile))
        .route("/api/accounts/avatar", put(avatar))
        .route("/api/accounts/keys", post(set_keys))
        .route("/api/accounts/key-management/user-key-id", post(set_user_key_id))
        .route("/api/users/{id}/public-key", get(public_key))
        .route("/api/accounts/password", post(change_password))
        .route("/api/accounts/kdf", post(change_kdf))
        .route("/api/accounts/security-stamp", post(new_security_stamp))
        .route("/api/accounts/email-token", post(email_token))
        .route("/api/accounts/email", post(change_email))
        .route("/api/accounts/verify-email", post(already_verified))
        .route("/api/accounts/verify-email-token", post(already_verified))
        .route("/api/accounts/delete", post(delete_account))
        .route("/api/accounts", axum::routing::delete(delete_account))
        .route("/api/accounts/revision-date", get(revision_date))
        .route("/api/accounts/password-hint", post(password_hint))
        .route("/api/accounts/verify-password", post(verify_password))
        .route("/api/accounts/request-otp", post(no_otp))
        .route("/api/accounts/verify-otp", post(no_otp))
        .route("/api/devices", get(devices))
        .route("/api/devices/knowndevice", get(known_device))
        .route("/api/devices/identifier/{id}", get(device))
        .route("/api/devices/identifier/{id}/token", put(push_token).post(push_token))
        .route("/api/devices/identifier/{id}/clear-token", put(clear_push_token).post(clear_push_token))
}

/// What brings a whole vault along, and may be large.
pub(crate) fn vault_routes() -> Router<AppState> {
    Router::new().route("/api/accounts/key-management/rotate-user-account-keys", post(rotate_keys))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserKeyId {
    user_key_id: String,
}

/// Newer clients name the user key once, after their first login with it, and send the name
/// here. It comes back in every sync; a key rotation clears it.
async fn set_user_key_id(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<UserKeyId>,
) -> ApiResult<StatusCode> {
    if session.user.user_key_id.is_some() {
        return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "Unexpected data"));
    }
    let id = data.user_key_id;
    state.store.update_user(&session.user.id, move |user| user.user_key_id = Some(id)).await?;
    Ok(StatusCode::OK)
}

/// Refused unless `hash` is the account's master password hash.
pub(crate) async fn check_password(state: &AppState, user: &User, hash: Option<&str>) -> ApiResult<()> {
    let Some(hash) = hash.filter(|hash| !hash.is_empty()) else {
        return Err(ApiError::bad("No validation provided"));
    };
    if auth::verify_password(state.config.hash_cost, Some(&user.password_hash), hash).await {
        Ok(())
    } else {
        Err(ApiError::bad("Invalid password"))
    }
}

async fn two_factor_on(state: &AppState, user: &User) -> ApiResult<bool> {
    Ok(state.store.two_factors(&user.id).await?.iter().any(|factor| factor.enabled))
}

// ── Profile ───────────────────────────────────────────────

async fn profile(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let two_factor = two_factor_on(&state, &session.user).await?;
    Ok(Json(out::profile(&session.user, two_factor)))
}

#[derive(Deserialize)]
struct ProfileData {
    #[serde(default)]
    name: Option<String>,
}

async fn update_profile(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<ProfileData>,
) -> ApiResult<Json<Value>> {
    let name = data.name.map(|name| name.trim().to_string()).filter(|name| !name.is_empty());
    if name.as_ref().is_some_and(|name| name.len() > 50) {
        return Err(ApiError::bad("The field Name must be a string with a maximum length of 50."));
    }
    let user = state
        .store
        .update_user(&session.user.id, move |user| user.name = name)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    let two_factor = two_factor_on(&state, &user).await?;
    Ok(Json(out::profile(&user, two_factor)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AvatarData {
    #[serde(default)]
    avatar_color: Option<String>,
}

async fn avatar(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<AvatarData>,
) -> ApiResult<Json<Value>> {
    if let Some(color) = &data.avatar_color
        && (color.len() != 7 || !color.starts_with('#') || !color[1..].chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(ApiError::bad("The field AvatarColor must be a HTML/Hex color code with a length of 7 characters"));
    }
    let user = state
        .store
        .update_user(&session.user.id, move |user| user.avatar_color = data.avatar_color)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    let two_factor = two_factor_on(&state, &user).await?;
    Ok(Json(out::profile(&user, two_factor)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeysData {
    encrypted_private_key: String,
    public_key: String,
}

/// Keys for an account that has none yet. One that has some keeps them: replacing them here
/// would lock it out of everything shared with it.
async fn set_keys(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<KeysData>,
) -> ApiResult<Json<Value>> {
    if session.user.private_key.is_some() {
        return Err(ApiError::bad("This account has its keys already."));
    }
    let (private, public) = (data.encrypted_private_key.clone(), data.public_key.clone());
    state
        .store
        .update_user(&session.user.id, move |user| {
            user.private_key = Some(private);
            user.public_key = Some(public);
            user.revision = clock::now();
        })
        .await?;
    Ok(Json(json!({ "privateKey": data.encrypted_private_key, "publicKey": data.public_key, "object": "keys" })))
}

async fn public_key(
    State(state): State<AppState>,
    _session: Session,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let user = state.store.user(&id).await?.ok_or_else(|| ApiError::not_found("User doesn't exist"))?;
    let key = user.public_key.ok_or_else(|| ApiError::not_found("User has no public_key"))?;
    Ok(Json(json!({ "userId": user.id, "publicKey": key, "object": "userKey" })))
}

// ── Password, KDF, keys ───────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticationData {
    salt: String,
    kdf: KdfData,
    master_password_authentication_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnlockData {
    salt: String,
    kdf: KdfData,
    master_key_wrapped_user_key: String,
}

/// The new master password, KDF and wrapped user key, from Bitwarden's newer shape or its older
/// flat one.
fn new_credentials(
    user: &User,
    authentication: Option<AuthenticationData>,
    unlock: Option<UnlockData>,
    flat_hash: Option<String>,
    flat_key: Option<String>,
) -> ApiResult<(String, String, Option<KdfData>)> {
    match (authentication, unlock) {
        (Some(authentication), Some(unlock)) => {
            if authentication.kdf != unlock.kdf {
                return Err(ApiError::bad("KDF settings must be equal for authentication and unlock"));
            }
            if normalize_email(&authentication.salt) != user.email || normalize_email(&unlock.salt) != user.email {
                return Err(ApiError::bad("Invalid master password salt"));
            }
            Ok((
                authentication.master_password_authentication_hash,
                unlock.master_key_wrapped_user_key,
                Some(unlock.kdf),
            ))
        }
        _ => match (flat_hash, flat_key) {
            (Some(hash), Some(key)) => Ok((hash, key, None)),
            _ => Err(ApiError::bad("Invalid request!")),
        },
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePassword {
    master_password_hash: String,
    #[serde(default)]
    master_password_hint: Option<String>,
    #[serde(default)]
    authentication_data: Option<AuthenticationData>,
    #[serde(default)]
    unlock_data: Option<UnlockData>,
    #[serde(default)]
    new_master_password_hash: Option<String>,
    #[serde(default)]
    key: Option<String>,
}

async fn change_password(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<ChangePassword>,
) -> ApiResult<StatusCode> {
    check_password(&state, &session.user, Some(&data.master_password_hash)).await?;
    let (hash, key, _) = new_credentials(
        &session.user,
        data.authentication_data,
        data.unlock_data,
        data.new_master_password_hash,
        data.key,
    )?;
    let hint = clean_hint(&state, data.master_password_hint)?;
    let password_hash = auth::hash_password(state.config.hash_cost, &hash).await?;
    state
        .store
        .update_user(&session.user.id, move |user| {
            user.password_hash = password_hash;
            user.user_key = key;
            user.password_hint = hint;
            user.security_stamp = uuid::Uuid::new_v4().to_string();
            user.revision = clock::now();
        })
        .await?;
    tracing::info!(user = %session.user.id, "master password changed");
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeKdf {
    master_password_hash: String,
    #[serde(default)]
    authentication_data: Option<AuthenticationData>,
    #[serde(default)]
    unlock_data: Option<UnlockData>,
    #[serde(default)]
    new_master_password_hash: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default, alias = "kdfType")]
    kdf: Option<i64>,
    #[serde(default, alias = "iterations")]
    kdf_iterations: Option<i64>,
    #[serde(default, alias = "memory")]
    kdf_memory: Option<i64>,
    #[serde(default, alias = "parallelism")]
    kdf_parallelism: Option<i64>,
}

async fn change_kdf(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<ChangeKdf>,
) -> ApiResult<StatusCode> {
    check_password(&state, &session.user, Some(&data.master_password_hash)).await?;
    let flat_kdf = match (data.kdf, data.kdf_iterations) {
        (Some(kdf), Some(kdf_iterations)) => {
            Some(KdfData { kdf, kdf_iterations, kdf_memory: data.kdf_memory, kdf_parallelism: data.kdf_parallelism })
        }
        _ => None,
    };
    let (hash, key, kdf) = new_credentials(
        &session.user,
        data.authentication_data,
        data.unlock_data,
        data.new_master_password_hash,
        data.key,
    )?;
    let kdf = kdf.or(flat_kdf).ok_or_else(|| ApiError::bad("Invalid request!"))?.check()?;
    let password_hash = auth::hash_password(state.config.hash_cost, &hash).await?;
    state
        .store
        .update_user(&session.user.id, move |user| {
            user.kdf = kdf;
            user.password_hash = password_hash;
            user.user_key = key;
            user.security_stamp = uuid::Uuid::new_v4().to_string();
            user.revision = clock::now();
        })
        .await?;
    tracing::info!(user = %session.user.id, "key derivation changed");
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MasterPasswordUnlockData {
    kdf_type: i64,
    kdf_iterations: i64,
    #[serde(default)]
    kdf_memory: Option<i64>,
    #[serde(default)]
    kdf_parallelism: Option<i64>,
    email: String,
    master_key_authentication_hash: String,
    master_key_encrypted_user_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountUnlockData {
    master_password_unlock_data: MasterPasswordUnlockData,
    #[serde(default)]
    emergency_access_unlock_data: Vec<Value>,
    #[serde(default)]
    organization_account_recovery_unlock_data: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountKeys {
    user_key_encrypted_account_private_key: String,
    account_public_key: String,
}

#[derive(Deserialize)]
struct FolderKeyData {
    #[serde(default)]
    id: Option<String>,
    name: String,
}

#[derive(Deserialize)]
struct AccountData {
    ciphers: Vec<CipherData>,
    folders: Vec<FolderKeyData>,
    #[serde(default)]
    sends: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateKeys {
    old_master_key_authentication_hash: String,
    account_unlock_data: AccountUnlockData,
    account_keys: AccountKeys,
    account_data: AccountData,
}

/// A new user key: every item and folder name encrypted again, the private key wrapped again,
/// the user key under the (maybe new) master password. All of it in one step, or nothing.
async fn rotate_keys(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<RotateKeys>,
) -> ApiResult<StatusCode> {
    let user = &session.user;
    check_password(&state, user, Some(&data.old_master_key_authentication_hash)).await?;
    let unlock = data.account_unlock_data.master_password_unlock_data;
    if unlock.kdf_type != user.kdf.kind
        || unlock.kdf_iterations != user.kdf.iterations
        || unlock.kdf_memory != user.kdf.memory
        || unlock.kdf_parallelism != user.kdf.parallelism
        || normalize_email(&unlock.email) != user.email
    {
        return Err(ApiError::bad("Changing the kdf variant or email is not supported during key rotation"));
    }
    if Some(&data.account_keys.account_public_key) != user.public_key.as_ref() {
        return Err(ApiError::bad("Changing the asymmetric keypair is not possible during key rotation"));
    }
    if !data.account_unlock_data.emergency_access_unlock_data.is_empty()
        || !data.account_unlock_data.organization_account_recovery_unlock_data.is_empty()
        || !data.account_data.sends.is_empty()
    {
        return Err(ApiError::bad("This server has no emergency access, organisations or sends to rotate."));
    }
    crate::ciphers::validate_batch(&data.account_data.ciphers)?;

    let existing: HashMap<String, uwulock_store::Cipher> =
        state.store.ciphers(&user.id).await?.into_iter().map(|cipher| (cipher.id.clone(), cipher)).collect();
    let mut ciphers = Vec::with_capacity(data.account_data.ciphers.len());
    for item in data.account_data.ciphers {
        let id = item.id.clone().ok_or_else(|| ApiError::bad("Cipher doesn't exist"))?;
        let current = existing.get(&id).cloned().ok_or_else(|| ApiError::bad("Cipher doesn't exist"))?;
        ciphers.push(apply(item, current)?);
    }
    let folders: Vec<(String, String)> = data
        .account_data
        .folders
        .into_iter()
        .filter_map(|folder| Some((folder.id.filter(|id| !id.is_empty())?, folder.name)))
        .collect();

    let mut rotated = (**user).clone();
    rotated.private_key = Some(data.account_keys.user_key_encrypted_account_private_key);
    rotated.user_key = unlock.master_key_encrypted_user_key;
    rotated.password_hash = auth::hash_password(state.config.hash_cost, &unlock.master_key_authentication_hash).await?;
    rotated.security_stamp = uuid::Uuid::new_v4().to_string();
    if !state.store.rotate_keys(rotated, folders, ciphers).await? {
        return Err(ApiError::bad("All existing ciphers and folders must be included in the rotation"));
    }
    tracing::info!(user = %user.id, "user key rotated");
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretData {
    #[serde(default, alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
}

/// "Log out everywhere": a new stamp, and every device forgotten.
async fn new_security_stamp(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<SecretData>,
) -> ApiResult<StatusCode> {
    check_password(&state, &session.user, data.master_password_hash.as_deref()).await?;
    state.store.update_user(&session.user.id, |user| user.security_stamp = uuid::Uuid::new_v4().to_string()).await?;
    for device in state.store.devices(&session.user.id).await? {
        state.store.delete_device(&session.user.id, &device.id).await?;
    }
    Ok(StatusCode::OK)
}

// ── A new address ─────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailToken {
    master_password_hash: String,
    new_email: String,
}

async fn email_token(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<EmailToken>,
) -> ApiResult<StatusCode> {
    check_password(&state, &session.user, Some(&data.master_password_hash)).await?;
    if !state.mailer.enabled() {
        return Err(ApiError::bad("Changing the address needs mail, and this server cannot send any."));
    }
    let new_email = normalize_email(&data.new_email);
    if !new_email.contains('@') {
        return Err(ApiError::bad("That is not an email address."));
    }
    if state.store.user_by_email(&new_email).await?.is_some() {
        return Err(ApiError::bad("Email already in use"));
    }
    let code = auth::random_code(6);
    state
        .store
        .put_code(
            &session.user.id,
            EMAIL_CODE,
            auth::sha256(code.as_bytes()),
            Some(new_email.clone()),
            clock::in_seconds(600),
        )
        .await?;
    state
        .mailer
        .send(&new_email, &Mail::EmailChange { code }, Language::from_code(&session.user.language))
        .await
        .map_err(|error| ApiError::bad(format!("The mail did not go out: {error}")))?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeEmail {
    master_password_hash: String,
    new_email: String,
    key: String,
    new_master_password_hash: String,
    #[serde(deserialize_with = "number_or_string")]
    token: String,
}

/// The address is the salt of the master key, so a new one comes with a new hash and a user key
/// wrapped under the new master key.
async fn change_email(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<ChangeEmail>,
) -> ApiResult<StatusCode> {
    check_password(&state, &session.user, Some(&data.master_password_hash)).await?;
    let new_email = normalize_email(&data.new_email);
    let pending =
        match state.store.take_code(&session.user.id, EMAIL_CODE, auth::sha256(data.token.trim().as_bytes())).await? {
            Ok(Some(pending)) => pending,
            Ok(None) | Err(CodeRefusal::Missing | CodeRefusal::TooManyAttempts) => {
                return Err(ApiError::bad("No email change pending"));
            }
            Err(CodeRefusal::Wrong) => return Err(ApiError::bad("Token mismatch")),
            Err(CodeRefusal::Expired) => return Err(ApiError::bad("The code has expired. Ask for a new one.")),
        };
    if pending != new_email {
        return Err(ApiError::bad("Email change mismatch"));
    }
    if state.store.user_by_email(&new_email).await?.is_some() {
        return Err(ApiError::bad("Email already in use"));
    }
    let password_hash = auth::hash_password(state.config.hash_cost, &data.new_master_password_hash).await?;
    let key = data.key;
    state
        .store
        .update_user(&session.user.id, move |user| {
            user.email = new_email;
            user.password_hash = password_hash;
            user.user_key = key;
            user.security_stamp = uuid::Uuid::new_v4().to_string();
            user.revision = clock::now();
        })
        .await?;
    tracing::info!(user = %session.user.id, "address changed");
    Ok(StatusCode::OK)
}

/// Addresses are proven by the invitation, so there is nothing left to verify.
async fn already_verified() -> StatusCode {
    StatusCode::OK
}

async fn no_otp() -> ApiError {
    ApiError::bad("Use your master password.")
}

// ── The rest ──────────────────────────────────────────────

async fn delete_account(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<SecretData>,
) -> ApiResult<StatusCode> {
    check_password(&state, &session.user, data.master_password_hash.as_deref()).await?;
    if session.user.admin && state.store.admin_count().await? <= 1 {
        return Err(ApiError::bad("You are the last admin. Make somebody else an admin first."));
    }
    state.store.delete_user(&session.user.id).await?;
    tracing::info!(user = %session.user.id, "account deleted");
    Ok(StatusCode::OK)
}

/// When the vault last changed, in milliseconds. From memory: the clients ask all the time.
async fn revision_date(session: Session) -> Json<i64> {
    Json(clock::millis(&session.user.revision).unwrap_or(0))
}

#[derive(Deserialize)]
struct HintRequest {
    email: String,
}

async fn password_hint(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(data): Json<HintRequest>,
) -> ApiResult<StatusCode> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    if !state.settings().password_hints {
        return Err(ApiError::bad("This server does not give out password hints."));
    }
    if !state.mailer.enabled() {
        return Err(ApiError::bad("This server cannot send mail, so it cannot send your hint either."));
    }
    match state.store.user_by_email(&data.email).await? {
        Some(user) => {
            let mail = Mail::PasswordHint { hint: user.password_hint.clone() };
            crate::identity::send_later(&state, &user.email, mail, Language::from_code(&user.language));
        }
        // As long as a mail would have taken, so the answer does not tell which addresses have
        // an account.
        None => {
            tokio::time::sleep(std::time::Duration::from_millis(300 + u64::from(auth::random_bytes(1)[0]) * 3)).await
        }
    }
    Ok(StatusCode::OK)
}

async fn verify_password(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<SecretData>,
) -> ApiResult<Json<Value>> {
    check_password(&state, &session.user, data.master_password_hash.as_deref()).await?;
    Ok(Json(json!({ "Object": "masterPasswordPolicy" })))
}

// ── Devices ───────────────────────────────────────────────

async fn devices(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let devices = state.store.devices(&session.user.id).await?;
    Ok(Json(out::list(devices.iter().filter(|device| device.logged_in).map(out::device).collect())))
}

async fn device(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let device = state.store.device(&session.user.id, &id).await?.ok_or_else(|| ApiError::bad("No device found"))?;
    Ok(Json(out::device(&device)))
}

/// Whether this address has logged in on this device before. The clients ask before a login.
async fn known_device(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
) -> ApiResult<Json<bool>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok()).map(str::trim);
    let email = header("x-request-email").ok_or_else(|| ApiError::bad("X-Request-Email value is required"))?;
    let email = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(email.trim_end_matches('='))
        .map_err(|_| ApiError::bad("X-Request-Email value failed to decode as base64url"))?;
    let email =
        String::from_utf8(email).map_err(|_| ApiError::bad("X-Request-Email value failed to decode as UTF-8"))?;
    let device = header("x-device-identifier").ok_or_else(|| ApiError::bad("X-Device-Identifier value is required"))?;
    let known = match state.store.user_by_email(&email).await? {
        Some(user) => state.store.device(&user.id, device).await?.is_some(),
        None => false,
    };
    Ok(Json(known))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushToken {
    push_token: String,
}

/// The phone apps register for push notifications. Kept for when the push relay comes; the
/// token goes to the device the request comes from.
async fn push_token(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<PushToken>,
) -> ApiResult<StatusCode> {
    state.store.set_push_token(&session.user.id, &session.device, Some(data.push_token)).await?;
    Ok(StatusCode::OK)
}

async fn clear_push_token() -> StatusCode {
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::http::StatusCode;
    use base64::Engine as _;
    use serde_json::json;

    #[tokio::test]
    async fn the_profile_is_bitwarden_s() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let profile = json(server.get_as(&account.token, "/api/accounts/profile").await).await;
        assert_eq!(profile["object"], "profile");
        assert_eq!(profile["email"], "nyu@example.com");
        assert_eq!(profile["key"], "2.userkey|userkey|userkey");
        assert_eq!(profile["accountKeys"]["publicKeyEncryptionKeyPair"]["publicKey"], "MIIBpublic");
        assert_eq!(profile["twoFactorEnabled"], false);
        assert_eq!(profile["culture"], "de-DE");

        let renamed =
            json(server.call("PUT", "/api/accounts/profile", Some(&account.token), json!({"name": "Mika"})).await)
                .await;
        assert_eq!(renamed["name"], "Mika");
        let colored =
            server.call("PUT", "/api/accounts/avatar", Some(&account.token), json!({"avatarColor": "#8b5cf6"})).await;
        assert_eq!(json(colored).await["avatarColor"], "#8b5cf6");
        let wrong =
            server.call("PUT", "/api/accounts/avatar", Some(&account.token), json!({"avatarColor": "purple"})).await;
        assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_new_password_ends_every_session() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let wrong = json!({"masterPasswordHash": "wrong", "newMasterPasswordHash": "new", "key": "2.new|new|new"});
        assert_eq!(
            server.call("POST", "/api/accounts/password", Some(&account.token), wrong).await.status(),
            StatusCode::BAD_REQUEST
        );
        let body = json!({
            "masterPasswordHash": password_hash("nyu@example.com"),
            "newMasterPasswordHash": "new hash",
            "masterPasswordHint": "a new cat",
            "key": "2.new|new|new",
        });
        assert_eq!(
            server.call("POST", "/api/accounts/password", Some(&account.token), body).await.status(),
            StatusCode::OK
        );
        assert_eq!(server.get_as(&account.token, "/api/sync").await.status(), StatusCode::UNAUTHORIZED);
        let response = server
            .form("/identity/connect/token", &[("grant_type", "refresh_token"), ("refresh_token", &account.refresh)])
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut form = login_form("nyu@example.com", "d2");
        form[2].1 = "new hash";
        let response = server.form("/identity/connect/token", &form).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json(response).await["Key"], "2.new|new|new");
    }

    #[tokio::test]
    async fn a_new_kdf_in_bitwarden_s_newer_shape() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let kdf = json!({"kdfType": 1, "iterations": 3, "memory": 64, "parallelism": 4});
        let body = json!({
            "masterPasswordHash": password_hash("nyu@example.com"),
            "authenticationData": {"salt": "nyu@example.com", "kdf": kdf, "masterPasswordAuthenticationHash": "argon hash"},
            "unlockData": {"salt": "nyu@example.com", "kdf": kdf, "masterKeyWrappedUserKey": "2.argon|argon|argon"},
        });
        let response = server.call("POST", "/api/accounts/kdf", Some(&account.token), body).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        let prelogin =
            json(server.call("POST", "/identity/accounts/prelogin", None, json!({"email": "nyu@example.com"})).await)
                .await;
        assert_eq!(prelogin["kdf"], 1);
        assert_eq!(prelogin["kdfMemory"], 64);

        let cheap = json!({"kdfType": 0, "iterations": 1000});
        let body = json!({
            "masterPasswordHash": "argon hash",
            "authenticationData": {"salt": "nyu@example.com", "kdf": cheap, "masterPasswordAuthenticationHash": "x"},
            "unlockData": {"salt": "nyu@example.com", "kdf": cheap, "masterKeyWrappedUserKey": "2.x|x|x"},
        });
        let account = server.login_with("nyu@example.com", "argon hash", "d2").await;
        assert_eq!(
            server.call("POST", "/api/accounts/kdf", Some(&account), body).await.status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn moving_to_a_new_address_takes_the_code_from_it() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let ask = json!({"masterPasswordHash": password_hash("nyu@example.com"), "newEmail": "New@Example.com"});
        assert_eq!(
            server.call("POST", "/api/accounts/email-token", Some(&account.token), ask).await.status(),
            StatusCode::OK
        );
        let mail = server.mails().pop().unwrap();
        assert_eq!(mail.to, "new@example.com");
        let code: String = mail.text.chars().filter(char::is_ascii_digit).collect::<String>();
        let code = &code[..6];
        let change = json!({
            "masterPasswordHash": password_hash("nyu@example.com"),
            "newEmail": "new@example.com",
            "key": "2.moved|moved|moved",
            "newMasterPasswordHash": "moved hash",
            "token": code,
        });
        let response = server.call("POST", "/api/accounts/email", Some(&account.token), change).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        assert!(server.state.store.user_by_email("new@example.com").await.unwrap().is_some());
        assert!(server.state.store.user_by_email("nyu@example.com").await.unwrap().is_none());
        server.login_with("new@example.com", "moved hash", "d2").await;
    }

    #[tokio::test]
    async fn revision_date_and_devices() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let millis = json(server.get_as(&account.token, "/api/accounts/revision-date").await).await;
        assert!(millis.as_i64().unwrap() > 1_700_000_000_000);
        let devices = json(server.get_as(&account.token, "/api/devices").await).await;
        assert_eq!(devices["data"][0]["identifier"], account.device.as_str());

        let email = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("nyu@example.com");
        let known = |device: &'static str| {
            axum::http::Request::get("/api/devices/knowndevice")
                .header("x-request-email", email.clone())
                .header("x-device-identifier", device)
                .body(axum::body::Body::empty())
                .unwrap()
        };
        assert_eq!(json(server.send(known("device-1")).await).await, json!(true));
        assert_eq!(json(server.send(known("elsewhere")).await).await, json!(false));
    }

    #[tokio::test]
    async fn logging_out_everywhere_and_deleting() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let secret = json!({"masterPasswordHash": password_hash("nyu@example.com")});
        assert_eq!(
            server.call("POST", "/api/accounts/security-stamp", Some(&account.token), secret.clone()).await.status(),
            StatusCode::OK
        );
        assert_eq!(server.get_as(&account.token, "/api/sync").await.status(), StatusCode::UNAUTHORIZED);
        let again = server.login("nyu@example.com", "d2").await;
        assert_eq!(server.call("DELETE", "/api/accounts", Some(&again.token), secret).await.status(), StatusCode::OK);
        assert!(server.state.store.user_by_email("nyu@example.com").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_hint_goes_by_mail() {
        let server = TestServer::new().await;
        server.account("nyu@example.com").await;
        let response =
            server.call("POST", "/api/accounts/password-hint", None, json!({"email": "nyu@example.com"})).await;
        assert_eq!(response.status(), StatusCode::OK);
        server.wait_for_mail(|mail| mail.text.contains("the cat")).await;
        let unknown =
            server.call("POST", "/api/accounts/password-hint", None, json!({"email": "nobody@example.com"})).await;
        assert_eq!(unknown.status(), StatusCode::OK, "tells nothing");
    }
}
