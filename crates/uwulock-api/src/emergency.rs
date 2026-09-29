//! Emergency access, the way Bitwarden's clients ask for it.
//!
//! The grantor names somebody by address; whoever has an account with it accepts, from the mail
//! or in their own settings; the grantor confirms them and hands over the user key,
//! wrapped for the contact's public key. When the contact asks for access, the grantor is told,
//! and unless they say no within the wait, the contact may see the vault — or, for a takeover,
//! set a new master password for it.

use crate::auth::{self, ClientIp, Session};
use crate::ciphers::attachments_by_cipher;
use crate::errors::{ApiError, ApiResult};
use crate::identity::send_later;
use crate::{AppState, json as out};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_mail::{Language, Mail};
use uwulock_store::emergency::{ACCEPTED, CONFIRMED, INVITED, RECOVERY_APPROVED, RECOVERY_ASKED, TAKEOVER, VIEW};
use uwulock_store::{EmergencyAccess, Event, User, clock, normalize_email};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/emergency-access/trusted", get(trusted))
        .route("/api/emergency-access/granted", get(granted))
        .route("/api/emergency-access/invite", post(invite))
        .route("/api/emergency-access/{id}", get(one).put(update).post(update).delete(delete))
        .route("/api/emergency-access/{id}/delete", post(delete))
        .route("/api/emergency-access/{id}/reinvite", post(reinvite))
        .route("/api/emergency-access/{id}/accept", post(accept))
        .route("/api/emergency-access/{id}/confirm", post(confirm))
        .route("/api/emergency-access/{id}/initiate", post(initiate))
        .route("/api/emergency-access/{id}/approve", post(approve))
        .route("/api/emergency-access/{id}/reject", post(reject))
        .route("/api/emergency-access/{id}/view", post(view))
        .route("/api/emergency-access/{id}/takeover", post(takeover))
        .route("/api/emergency-access/{id}/password", post(password))
        .route("/api/emergency-access/{id}/policies", get(policies))
        .route("/api/emergency-access/{id}/{cipher}/attachment/{attachment}", get(attachment))
}

/// How a person is named in a mail: their name, or their address.
fn called(user: &User) -> String {
    user.name.clone().unwrap_or_else(|| user.email.clone())
}

fn invalid() -> ApiError {
    ApiError::bad("Emergency access not valid.")
}

/// The contact, as the grantor sees them.
async fn render_grantee(state: &AppState, access: &EmergencyAccess) -> ApiResult<Value> {
    let grantee = match &access.grantee_id {
        Some(id) => state.store.user(id).await?,
        None => None,
    };
    Ok(json!({
        "id": access.id,
        "granteeId": access.grantee_id,
        "name": grantee.as_ref().and_then(|user| user.name.clone()),
        "email": grantee.as_ref().map_or(access.email.clone(), |user| user.email.clone()),
        "avatarColor": grantee.as_ref().and_then(|user| user.avatar_color.clone()),
        "type": access.kind,
        "status": access.status,
        "waitTimeDays": access.wait_days,
        "creationDate": access.created,
        "object": "emergencyAccessGranteeDetails",
    }))
}

/// The grantor, as the contact sees them.
async fn render_grantor(state: &AppState, access: &EmergencyAccess) -> ApiResult<Value> {
    let grantor = state.store.user(&access.grantor_id).await?;
    Ok(json!({
        "id": access.id,
        "grantorId": access.grantor_id,
        "name": grantor.as_ref().and_then(|user| user.name.clone()),
        "email": grantor.as_ref().map(|user| user.email.clone()),
        "avatarColor": grantor.as_ref().and_then(|user| user.avatar_color.clone()),
        "type": access.kind,
        "status": access.status,
        "waitTimeDays": access.wait_days,
        "creationDate": access.created,
        "object": "emergencyAccessGrantorDetails",
    }))
}

/// One of the session's own grants, as grantor.
async fn as_grantor(state: &AppState, session: &Session, id: &str) -> ApiResult<EmergencyAccess> {
    state.store.emergency_access(id).await?.filter(|access| access.grantor_id == session.user.id).ok_or_else(invalid)
}

/// One where the session is the contact.
async fn as_grantee(state: &AppState, session: &Session, id: &str) -> ApiResult<EmergencyAccess> {
    state
        .store
        .emergency_access(id)
        .await?
        .filter(|access| access.grantee_id.as_deref() == Some(session.user.id.as_str()))
        .ok_or_else(invalid)
}

fn tell(state: &AppState, user: &User, mail: Mail) {
    if state.mailer.enabled() {
        send_later(state, &user.email, mail, Language::from_code(&user.language));
    }
}

async fn log(state: &AppState, session: &Session, detail: String) {
    let event = Event {
        kind: "emergency-access".into(),
        user_id: Some(session.user.id.clone()),
        email: Some(session.user.email.clone()),
        detail: Some(detail),
        ..Event::default()
    };
    let _ = state.store.log_event(event).await;
}

async fn trusted(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let mut data = Vec::new();
    for access in state.store.emergency_trusted(&session.user.id).await? {
        data.push(render_grantee(&state, &access).await?);
    }
    Ok(Json(out::list(data)))
}

async fn granted(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let mut data = Vec::new();
    for access in state.store.emergency_granted(&session.user.id, &session.user.email).await? {
        data.push(render_grantor(&state, &access).await?);
    }
    Ok(Json(out::list(data)))
}

async fn one(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let access = as_grantor(&state, &session, &id).await?;
    Ok(Json(render_grantee(&state, &access).await?))
}

fn number_or_string<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    match Value::deserialize(deserializer)? {
        Value::Number(number) => number.as_i64().ok_or_else(|| serde::de::Error::custom("not a number")),
        Value::String(text) => text.trim().parse().map_err(|_| serde::de::Error::custom("not a number")),
        _ => Err(serde::de::Error::custom("not a number")),
    }
}

fn check_terms(kind: i64, wait_days: i64) -> ApiResult<()> {
    if kind != VIEW && kind != TAKEOVER {
        return Err(ApiError::bad("Invalid emergency access type."));
    }
    if !(1..=90).contains(&wait_days) {
        return Err(ApiError::bad("The waiting time can be from 1 to 90 days."));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Invite {
    email: String,
    #[serde(rename = "type", deserialize_with = "number_or_string")]
    kind: i64,
    #[serde(deserialize_with = "number_or_string")]
    wait_time_days: i64,
}

/// A new token for the invitation link; its hash goes into `access`.
fn new_token(access: &mut EmergencyAccess) -> String {
    let token = auth::random_token(32);
    access.token_hash = Some(auth::sha256(token.as_bytes()));
    token
}

fn invitation_link(state: &AppState, access: &EmergencyAccess, grantor: &User, token: &str) -> String {
    let encode = |text: &str| -> String {
        text.bytes()
            .map(|byte| match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (byte as char).to_string(),
                other => format!("%{other:02X}"),
            })
            .collect()
    };
    format!(
        "{}/#/accept-emergency?id={}&name={}&email={}&token={}",
        state.config.public,
        access.id,
        encode(&called(grantor)),
        encode(&access.email),
        encode(token)
    )
}

/// Write back a change to `access`, or say that it changed in between.
async fn save(state: &AppState, access: EmergencyAccess) -> ApiResult<EmergencyAccess> {
    state
        .store
        .save_emergency_access(access)
        .await?
        .ok_or_else(|| ApiError::bad("This emergency access changed in the meantime. Load it again and try once more."))
}

/// Tell the contact about an invitation — by mail, when there is an account with the address and
/// the server sends mail. The answer is the same whether there is one or not, so nobody learns
/// here which addresses have an account; whoever has one also finds the invitation in their
/// settings, and accepts it there.
async fn send_invitation(state: &AppState, grantor: &User, access: &mut EmergencyAccess) -> ApiResult<()> {
    // Counted before anything is looked up, so a list of addresses cannot be tried quickly.
    if !state.limits.mail.take(format!("emergency-invite:{}", grantor.id)) {
        return Err(ApiError::too_many("Too many invitations. Wait a few minutes and try again."));
    }
    let grantee = state.store.user_by_email(&access.email).await?;
    let Some(grantee) = grantee.filter(|_| state.mailer.enabled()) else { return Ok(()) };
    if crate::identity::mail_allowed(state, &access.email, Some(&grantor.id)).is_err() {
        return Ok(());
    }
    let token = new_token(access);
    *access = save(state, access.clone()).await?;
    let link = invitation_link(state, access, grantor, &token);
    tell(state, &grantee, Mail::EmergencyInvited { grantor: called(grantor), link });
    Ok(())
}

async fn invite(State(state): State<AppState>, session: Session, Json(data): Json<Invite>) -> ApiResult<StatusCode> {
    check_terms(data.kind, data.wait_time_days)?;
    let email = normalize_email(&data.email);
    if email == session.user.email {
        return Err(ApiError::bad("You can not set yourself as an emergency contact."));
    }
    if state.store.emergency_by_email(&session.user.id, &email).await?.is_some() {
        return Err(ApiError::bad(format!("Grantee user already invited: {email}")));
    }
    let now = clock::now();
    let access = EmergencyAccess {
        id: uuid::Uuid::new_v4().to_string(),
        grantor_id: session.user.id.clone(),
        grantee_id: None,
        email,
        key_encrypted: None,
        kind: data.kind,
        status: INVITED,
        wait_days: data.wait_time_days,
        token_hash: None,
        recovery_asked: None,
        last_notification: None,
        created: now.clone(),
        revision: now,
    };
    let mut access = state.store.add_emergency_access(access).await?;
    send_invitation(&state, &session.user, &mut access).await?;
    log(&state, &session, format!("invited {}", access.email)).await;
    Ok(StatusCode::OK)
}

async fn reinvite(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let mut access = as_grantor(&state, &session, &id).await?;
    if access.status != INVITED {
        return Err(ApiError::bad("The emergency contact accepted already."));
    }
    send_invitation(&state, &session.user, &mut access).await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Update {
    #[serde(rename = "type", deserialize_with = "number_or_string")]
    kind: i64,
    #[serde(deserialize_with = "number_or_string")]
    wait_time_days: i64,
    #[serde(default)]
    key_encrypted: Option<String>,
}

async fn update(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(data): Json<Update>,
) -> ApiResult<Json<Value>> {
    check_terms(data.kind, data.wait_time_days)?;
    let mut access = as_grantor(&state, &session, &id).await?;
    access.kind = data.kind;
    access.wait_days = data.wait_time_days;
    if let Some(key) = data.key_encrypted.filter(|key| !key.is_empty()) {
        access.key_encrypted = Some(key);
    }
    let access = save(&state, access).await?;
    Ok(Json(render_grantee(&state, &access).await?))
}

/// Either side may end it, and whoever it is for may turn an invitation down.
async fn delete(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let access = state.store.emergency_access(&id).await?.ok_or_else(invalid)?;
    // An invitation to the session's address may be turned down too.
    let invited = access.grantee_id.is_none() && access.status == INVITED && access.email == session.user.email;
    if access.grantor_id != session.user.id
        && access.grantee_id.as_deref() != Some(session.user.id.as_str())
        && !invited
    {
        return Err(invalid());
    }
    state.store.delete_emergency_access(&id).await?;
    log(&state, &session, format!("ended emergency access {id}")).await;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct Accept {
    /// From the mail's link; without it, the invitation is accepted from the contact's own
    /// settings, logged in with the address it is for.
    #[serde(default)]
    token: Option<String>,
}

/// The contact accepts, from the link in the mail or in their settings, logged in with the
/// address the invitation is for.
async fn accept(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(data): Json<Accept>,
) -> ApiResult<StatusCode> {
    let mut access = state.store.emergency_access(&id).await?.ok_or_else(invalid)?;
    let token_ok = match data.token.as_deref().map(str::trim).filter(|token| !token.is_empty()) {
        Some(token) => access
            .token_hash
            .as_deref()
            .is_some_and(|hash| auth::constant_time_eq(hash, &auth::sha256(token.as_bytes()))),
        None => true,
    };
    let days = i64::from(state.settings().invitation_days);
    let fresh = access.revision > clock::in_seconds(-days * 86_400);
    if access.status != INVITED || !token_ok || !fresh {
        return Err(ApiError::bad("This invitation is not valid (any more). Ask for a new one."));
    }
    if access.email != session.user.email {
        return Err(ApiError::bad("The invitation is for another address. Log in with the one it went to."));
    }
    access.grantee_id = Some(session.user.id.clone());
    access.status = ACCEPTED;
    access.token_hash = None;
    let access = save(&state, access).await?;
    if let Some(grantor) = state.store.user(&access.grantor_id).await? {
        tell(&state, &grantor, Mail::EmergencyAccepted { grantee: called(&session.user) });
    }
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct Confirm {
    key: String,
}

/// The grantor confirms an accepted contact and hands over the wrapped user key.
async fn confirm(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(data): Json<Confirm>,
) -> ApiResult<Json<Value>> {
    let mut access = as_grantor(&state, &session, &id).await?;
    if access.status != ACCEPTED || data.key.is_empty() || data.key.len() > out::MAX_NOTE {
        return Err(invalid());
    }
    let grantee = state.store.user(access.grantee_id.as_deref().unwrap_or_default()).await?.ok_or_else(invalid)?;
    access.status = CONFIRMED;
    access.key_encrypted = Some(data.key);
    let access = save(&state, access).await?;
    tell(&state, &grantee, Mail::EmergencyConfirmed { grantor: called(&session.user) });
    log(&state, &session, format!("confirmed {} as emergency contact", grantee.email)).await;
    Ok(Json(render_grantee(&state, &access).await?))
}

/// The contact asks for access; the grantor hears of it.
async fn initiate(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let mut access = as_grantee(&state, &session, &id).await?;
    if access.status != CONFIRMED {
        return Err(invalid());
    }
    let grantor = state.store.user(&access.grantor_id).await?.ok_or_else(invalid)?;
    let now = clock::now();
    access.status = RECOVERY_ASKED;
    access.recovery_asked = Some(now.clone());
    access.last_notification = Some(now);
    let access = save(&state, access).await?;
    tell(
        &state,
        &grantor,
        Mail::EmergencyAsked {
            grantee: called(&session.user),
            takeover: access.kind == TAKEOVER,
            days: access.wait_days,
            reminder: false,
        },
    );
    log(&state, &session, format!("asked for emergency access to {}", grantor.email)).await;
    let context = crate::notices::Context::of(&state, &session, ip).await;
    // The grantor had a mail about it just now: listed, not mailed again.
    let mailed = state.mailer.enabled();
    crate::notices::record_mailed(
        &state,
        &grantor,
        "emergencyAccessRequested",
        &context,
        json!({ "grantee": session.user.email }),
        mailed,
    )
    .await;
    Ok(Json(render_grantor(&state, &access).await?))
}

async fn approve(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let mut access = as_grantor(&state, &session, &id).await?;
    if access.status != RECOVERY_ASKED {
        return Err(invalid());
    }
    access.status = RECOVERY_APPROVED;
    let access = save(&state, access).await?;
    if let Some(grantee) = state.store.user(access.grantee_id.as_deref().unwrap_or_default()).await? {
        tell(&state, &grantee, Mail::EmergencyApproved { grantor: called(&session.user) });
    }
    Ok(Json(render_grantee(&state, &access).await?))
}

async fn reject(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let mut access = as_grantor(&state, &session, &id).await?;
    if access.status != RECOVERY_ASKED && access.status != RECOVERY_APPROVED {
        return Err(invalid());
    }
    access.status = CONFIRMED;
    access.recovery_asked = None;
    let access = save(&state, access).await?;
    if let Some(grantee) = state.store.user(access.grantee_id.as_deref().unwrap_or_default()).await? {
        tell(&state, &grantee, Mail::EmergencyRejected { grantor: called(&session.user) });
    }
    Ok(Json(render_grantee(&state, &access).await?))
}

/// Access of `kind` that is approved, for the contact of the session.
async fn approved(state: &AppState, session: &Session, id: &str, kind: i64) -> ApiResult<(EmergencyAccess, User)> {
    let access = as_grantee(state, session, id).await?;
    if access.status != RECOVERY_APPROVED || access.kind != kind {
        return Err(invalid());
    }
    let grantor = state.store.user(&access.grantor_id).await?.ok_or_else(invalid)?;
    Ok((access, grantor))
}

/// The grantor's items, for a contact that may see them, with the key to open them.
async fn view(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let (access, grantor) = approved(&state, &session, &id, VIEW).await?;
    let ciphers = state.store.ciphers(&grantor.id).await?;
    let attachments = attachments_by_cipher(&state, &grantor.id).await?;
    let list: Value =
        serde_json::from_str(&out::cipher_list(ciphers.iter().filter(|c| c.deleted.is_none()), &attachments))
            .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "keyEncrypted": access.key_encrypted,
        "ciphers": list["data"],
        "object": "emergencyAccessView",
    })))
}

async fn attachment(
    State(state): State<AppState>,
    session: Session,
    Path((id, cipher, attachment)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    let (_, grantor) = approved(&state, &session, &id, VIEW).await?;
    state.store.cipher(&grantor.id, &cipher).await?.ok_or_else(invalid)?;
    let found =
        state.store.attachment(&cipher, &attachment).await?.filter(|found| found.uploaded).ok_or_else(invalid)?;
    Ok(Json(crate::attachments::render_one(&state, &found, crate::files::LINK_SECONDS)))
}

/// What a contact needs to set a new master password for the grantor: the KDF and the key.
async fn takeover(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let (access, grantor) = approved(&state, &session, &id, TAKEOVER).await?;
    Ok(Json(json!({
        "keyEncrypted": access.key_encrypted,
        "kdf": grantor.kdf.kind,
        "kdfIterations": grantor.kdf.iterations,
        "kdfMemory": grantor.kdf.memory,
        "kdfParallelism": grantor.kdf.parallelism,
        "object": "emergencyAccessTakeover",
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewPassword {
    new_master_password_hash: String,
    key: String,
    /// UwULock's web vault sends a key derivation of its own when the grantor's is weaker than
    /// today's defaults: a new password should not be cheap to guess. Bitwarden's apps keep the
    /// grantor's.
    #[serde(default, flatten)]
    kdf: Option<crate::identity::KdfData>,
}

/// A new master password for the grantor, set by the contact. Two-step login goes, every
/// session ends, organisations the grantor does not own let go of them, and the grantor gets a
/// mail.
async fn password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(id): Path<String>,
    Json(data): Json<NewPassword>,
) -> ApiResult<StatusCode> {
    let (_, grantor) = approved(&state, &session, &id, TAKEOVER).await?;
    if data.new_master_password_hash.is_empty() || data.key.is_empty() {
        return Err(ApiError::bad("Invalid request!"));
    }
    let kdf = data.kdf.map(crate::identity::KdfData::check).transpose()?;
    if let Some(kdf) = &kdf {
        state.settings().policies.check_kdf(kdf)?;
    }
    let password_hash = auth::hash_password(state.config.hash_cost, &data.new_master_password_hash).await?;
    let key = data.key;
    state
        .store
        .update_user(&grantor.id, move |user| {
            if let Some(kdf) = kdf {
                user.kdf = kdf;
            }
            user.password_hash = password_hash;
            user.user_key = key;
            user.password_hint = None;
            user.security_stamp = uuid::Uuid::new_v4().to_string();
            user.revision = clock::now();
        })
        .await?;
    state.store.remove_two_factor(&grantor.id, None).await?;
    // What others shared with the grantor through an organisation is not the contact's to have.
    for user in state.store.leave_organizations(&grantor.id).await? {
        if user != grantor.id {
            crate::notify::user(&state, &user, None, uwulock_notify::Kind::Vault);
        }
    }
    crate::notify::logout(&state, &grantor.id, None, "securityStamp");
    tell(&state, &grantor, Mail::EmergencyTakenOver { grantee: called(&session.user) });
    log(&state, &session, format!("took over {}", grantor.email)).await;
    let context = crate::notices::Context::of(&state, &session, ip).await;
    // The grantor had a mail about it just now: listed, not mailed again.
    let mailed = state.mailer.enabled();
    crate::notices::record_mailed(
        &state,
        &grantor,
        "emergencyAccessTakenOver",
        &context,
        json!({ "grantee": session.user.email }),
        mailed,
    )
    .await;
    tracing::info!(grantor = %grantor.id, grantee = %session.user.id, "account taken over by emergency access");
    Ok(StatusCode::OK)
}

async fn policies(_session: Session) -> Json<Value> {
    Json(out::list(Vec::new()))
}

/// What the server does by itself for emergency access, every hour: approve recoveries whose
/// wait is over, and remind grantors of those still waiting once a day.
pub async fn tend(state: &AppState) -> ApiResult<()> {
    for access in state.store.approve_waited_recoveries().await? {
        let (Some(grantor), Some(grantee)) = (
            state.store.user(&access.grantor_id).await?,
            state.store.user(access.grantee_id.as_deref().unwrap_or_default()).await?,
        ) else {
            continue;
        };
        tell(state, &grantor, Mail::EmergencyWaited { grantee: called(&grantee) });
        tell(state, &grantee, Mail::EmergencyApproved { grantor: called(&grantor) });
    }
    for access in state.store.recoveries_to_remind().await? {
        let (Some(grantor), Some(grantee)) = (
            state.store.user(&access.grantor_id).await?,
            state.store.user(access.grantee_id.as_deref().unwrap_or_default()).await?,
        ) else {
            continue;
        };
        let asked = access.recovery_asked.as_deref().and_then(clock::parse);
        let left = asked.map_or(access.wait_days, |asked| {
            let over = asked + time::Duration::days(access.wait_days);
            (over - time::OffsetDateTime::now_utc()).whole_days().max(1)
        });
        tell(
            state,
            &grantor,
            Mail::EmergencyAsked {
                grantee: called(&grantee),
                takeover: access.kind == TAKEOVER,
                days: left,
                reminder: true,
            },
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn bitwarden_s_apps_keep_the_grantor_s_key_derivation() {
        let plain: super::NewPassword =
            serde_json::from_value(json!({"newMasterPasswordHash": "h", "key": "k"})).unwrap();
        assert!(plain.kdf.is_none());
        let ours: super::NewPassword = serde_json::from_value(
            json!({"newMasterPasswordHash": "h", "key": "k", "kdf": 0, "kdfIterations": 600000}),
        )
        .unwrap();
        assert_eq!(ours.kdf.unwrap().kdf_iterations, 600_000);
    }
    use axum::http::StatusCode;
    use serde_json::{Value, json};

    /// The token from the invitation mail's link.
    fn token_from(mail: &uwulock_mail::Sent) -> (String, String) {
        let link = mail.text.split_whitespace().find(|word| word.contains("accept-emergency")).unwrap();
        let query = link.split_once('?').unwrap().1;
        let get =
            |name: &str| query.split('&').find_map(|pair| pair.strip_prefix(&format!("{name}="))).unwrap().to_string();
        (get("id"), get("token"))
    }

    #[tokio::test]
    async fn from_invitation_to_viewing_the_vault() {
        let server = TestServer::new().await;
        let nyu = server.account("nyu@example.com").await;
        let friend = server.account("friend@example.com").await;
        server
            .call(
                "POST",
                "/api/ciphers",
                Some(&nyu.token),
                json!({"type": 2, "name": "2.n|n|n", "secureNote": {"type": 0}}),
            )
            .await;

        let invite = json!({"email": "Friend@example.com", "type": 0, "waitTimeDays": 1});
        let response = server.call("POST", "/api/emergency-access/invite", Some(&nyu.token), invite.clone()).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        let again = server.call("POST", "/api/emergency-access/invite", Some(&nyu.token), invite).await;
        assert_eq!(again.status(), StatusCode::BAD_REQUEST, "once per address");
        let mail = server
            .wait_for_mail(|mail| mail.to == "friend@example.com" && mail.text.contains("accept-emergency"))
            .await;
        let (id, token) = token_from(&mail);

        let wrong = server
            .call("POST", &format!("/api/emergency-access/{id}/accept"), Some(&nyu.token), json!({"token": token}))
            .await;
        assert_eq!(wrong.status(), StatusCode::BAD_REQUEST, "only the invited address accepts");
        let response = server
            .call("POST", &format!("/api/emergency-access/{id}/accept"), Some(&friend.token), json!({"token": token}))
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        server.wait_for_mail(|mail| mail.to == "nyu@example.com" && mail.subject.contains("Notfallkontakt")).await;

        let trusted = json(server.get_as(&nyu.token, "/api/emergency-access/trusted").await).await;
        assert_eq!(trusted["data"][0]["status"], 1);
        assert_eq!(trusted["data"][0]["granteeId"], friend.id.as_str());
        let response = server
            .call("POST", &format!("/api/emergency-access/{id}/confirm"), Some(&nyu.token), json!({"key": "4.wrapped"}))
            .await;
        assert_eq!(json(response).await["status"], 2);

        let early =
            server.call("POST", &format!("/api/emergency-access/{id}/view"), Some(&friend.token), json!({})).await;
        assert_eq!(early.status(), StatusCode::BAD_REQUEST, "not before it is approved");
        let asked = json(
            server.call("POST", &format!("/api/emergency-access/{id}/initiate"), Some(&friend.token), json!({})).await,
        )
        .await;
        assert_eq!(asked["status"], 3);
        let foreign =
            server.call("POST", &format!("/api/emergency-access/{id}/approve"), Some(&friend.token), json!({})).await;
        assert_eq!(foreign.status(), StatusCode::BAD_REQUEST, "the contact cannot approve themselves");
        let approved = json(
            server.call("POST", &format!("/api/emergency-access/{id}/approve"), Some(&nyu.token), json!({})).await,
        )
        .await;
        assert_eq!(approved["status"], 4);

        let view: Value = json(
            server.call("POST", &format!("/api/emergency-access/{id}/view"), Some(&friend.token), json!({})).await,
        )
        .await;
        assert_eq!(view["keyEncrypted"], "4.wrapped");
        assert_eq!(view["ciphers"].as_array().unwrap().len(), 1);
        let takeover =
            server.call("POST", &format!("/api/emergency-access/{id}/takeover"), Some(&friend.token), json!({})).await;
        assert_eq!(takeover.status(), StatusCode::BAD_REQUEST, "a view is no takeover");
        let granted = json(server.get_as(&friend.token, "/api/emergency-access/granted").await).await;
        assert_eq!(granted["data"][0]["email"], "nyu@example.com");
    }

    #[tokio::test]
    async fn a_takeover_after_the_wait_sets_a_new_password() {
        let server = TestServer::new().await;
        let nyu = server.account("nyu@example.com").await;
        let friend = server.account("friend@example.com").await;
        let invite = json!({"email": "friend@example.com", "type": "1", "waitTimeDays": "1"});
        server.call("POST", "/api/emergency-access/invite", Some(&nyu.token), invite).await;
        let mail = server
            .wait_for_mail(|mail| mail.to == "friend@example.com" && mail.text.contains("accept-emergency"))
            .await;
        let (id, token) = token_from(&mail);
        server
            .call("POST", &format!("/api/emergency-access/{id}/accept"), Some(&friend.token), json!({"token": token}))
            .await;
        server
            .call("POST", &format!("/api/emergency-access/{id}/confirm"), Some(&nyu.token), json!({"key": "4.k"}))
            .await;
        server.call("POST", &format!("/api/emergency-access/{id}/initiate"), Some(&friend.token), json!({})).await;

        // Two days pass.
        let mut access = server.state.store.emergency_access(&id).await.unwrap().unwrap();
        access.recovery_asked = Some(uwulock_store::clock::in_seconds(-2 * 86_400));
        server.state.store.save_emergency_access(access).await.unwrap().unwrap();
        super::tend(&server.state).await.unwrap();
        server
            .wait_for_mail(|mail| mail.to == "nyu@example.com" && mail.subject.contains("hat jetzt Notfallzugriff"))
            .await;

        let takeover = json(
            server.call("POST", &format!("/api/emergency-access/{id}/takeover"), Some(&friend.token), json!({})).await,
        )
        .await;
        assert_eq!((takeover["kdf"].clone(), takeover["keyEncrypted"].clone()), (json!(0), json!("4.k")));
        let body = json!({"newMasterPasswordHash": "new hash", "key": "2.newkey|a|b",
            "kdf": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4});
        let response =
            server.call("POST", &format!("/api/emergency-access/{id}/password"), Some(&friend.token), body).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(server.get_as(&nyu.token, "/api/sync").await.status(), StatusCode::UNAUTHORIZED, "logged out");
        server.login_with("nyu@example.com", "new hash", "device-9").await;
        let kdf = server.state.store.user(&nyu.id).await.unwrap().unwrap().kdf;
        assert_eq!((kdf.kind, kdf.memory), (1, Some(64)), "the stronger key derivation came along");
    }

    #[tokio::test]
    async fn an_invitation_says_nothing_about_accounts_and_is_accepted_in_the_settings() {
        let server = TestServer::new().await;
        let nyu = server.account("nyu@example.com").await;
        let friend = server.account("friend@example.com").await;
        for (email, kind, days) in [("nyu@example.com", 0, 1), ("x@example.com", 5, 1)] {
            let invite = json!({"email": email, "type": kind, "waitTimeDays": days});
            let response = server.call("POST", "/api/emergency-access/invite", Some(&nyu.token), invite).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{email}");
        }
        for email in ["nobody@example.com", "friend@example.com"] {
            let invite = json!({"email": email, "type": 0, "waitTimeDays": 1});
            let response = server.call("POST", "/api/emergency-access/invite", Some(&nyu.token), invite).await;
            assert_eq!(response.status(), StatusCode::OK, "{email}: the same answer, account or not");
        }
        let trusted = json(server.get_as(&nyu.token, "/api/emergency-access/trusted").await).await;
        assert!(trusted["data"].as_array().unwrap().iter().all(|contact| contact["status"] == 0), "nobody accepted");

        // The invitation waits in the contact's settings, and is accepted there.
        let granted = json(server.get_as(&friend.token, "/api/emergency-access/granted").await).await;
        assert_eq!(granted["data"][0]["status"], 0);
        let id = granted["data"][0]["id"].as_str().unwrap().to_string();
        let path = format!("/api/emergency-access/{id}/accept");
        assert_eq!(server.call("POST", &path, Some(&nyu.token), json!({})).await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(server.call("POST", &path, Some(&friend.token), json!({})).await.status(), StatusCode::OK);
        let trusted = json(server.get_as(&nyu.token, "/api/emergency-access/trusted").await).await;
        let friend_row =
            trusted["data"].as_array().unwrap().iter().find(|c| c["email"] == "friend@example.com").unwrap();
        assert_eq!(friend_row["status"], 1);
    }

    #[tokio::test]
    async fn two_steps_at_once_do_not_undo_each_other() {
        let server = TestServer::new().await;
        let nyu = server.account("nyu@example.com").await;
        let invite = json!({"email": "friend@example.com", "type": 0, "waitTimeDays": 1});
        server.call("POST", "/api/emergency-access/invite", Some(&nyu.token), invite).await;
        let id = json(server.get_as(&nyu.token, "/api/emergency-access/trusted").await).await["data"][0]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let read = server.state.store.emergency_access(&id).await.unwrap().unwrap();
        server.state.store.delete_emergency_access(&id).await.unwrap();
        assert!(server.state.store.save_emergency_access(read).await.unwrap().is_none(), "a deleted one stays gone");
        assert!(server.state.store.emergency_access(&id).await.unwrap().is_none());
    }
}
