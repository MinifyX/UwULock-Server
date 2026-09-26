//! `/uwu/v1/admin`: what the admin portal does. Only for accounts that are admins; everything an
//! admin changes is written to the event log.
//!
//! An admin sees accounts, devices and numbers — never anything inside a vault. That is
//! encrypted with keys only the account's owner has.

use crate::auth::{self, Admin, device_type_name};
use crate::errors::{ApiError, ApiResult};
use crate::{AppState, Settings};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_mail::{Language, Mail};
use uwulock_store::{Event, UserOverview, backups, clock, normalize_email, with_suffix};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/admin/overview", get(overview))
        .route("/uwu/v1/admin/users", get(users))
        .route("/uwu/v1/admin/users/{id}", delete(delete_user))
        .route("/uwu/v1/admin/users/{id}/{action}", post(user_action))
        .route("/uwu/v1/admin/users/{id}/devices", get(user_devices))
        .route("/uwu/v1/admin/users/{id}/devices/{device}", delete(delete_device))
        .route("/uwu/v1/admin/invitations", get(invitations).post(create_invitation))
        .route("/uwu/v1/admin/invitations/{email}", delete(delete_invitation))
        .route("/uwu/v1/admin/settings", get(get_settings).put(put_settings))
        .route("/uwu/v1/admin/settings/test-mail", post(test_mail))
        .route("/uwu/v1/admin/events", get(events))
        .route("/uwu/v1/admin/logs", get(logs))
        .route("/uwu/v1/admin/backups", get(list_backups).post(create_backup))
        .route("/uwu/v1/admin/backups/{name}", post(download_backup))
}

async fn record(state: &AppState, admin: &Admin, detail: String) {
    let event = Event {
        kind: "admin".into(),
        user_id: Some(admin.0.user.id.clone()),
        email: Some(admin.0.user.email.clone()),
        detail: Some(detail.clone()),
        ..Event::default()
    };
    if let Err(error) = state.store.log_event(event).await {
        tracing::warn!(%error, "could not write an event");
    }
    tracing::info!(admin = %admin.0.user.email, "{detail}");
}

// ── Invitations ───────────────────────────────────────────

/// An invitation that was made: its token (only ever here, and in the mail), the link with it,
/// and whether the mail went out.
#[derive(Debug, Clone)]
pub struct Invited {
    pub email: String,
    /// For tests; everybody else takes the link.
    #[cfg_attr(not(test), allow(dead_code))]
    pub token: String,
    pub link: String,
    pub mailed: bool,
    pub expires: String,
}

/// Invite `email`, or invite it again with a new link. By an admin (`invited_by`) or from the
/// command line (none). The mail goes out if the server can send any; the link comes back
/// either way, to be passed on by hand.
pub async fn invite(state: &AppState, email: &str, admin: bool, invited_by: Option<String>) -> ApiResult<Invited> {
    let email = normalize_email(email);
    let (local, domain) = email.split_once('@').unwrap_or_default();
    if local.is_empty() || !domain.contains('.') || email.chars().any(char::is_whitespace) {
        return Err(ApiError::bad("That is not an email address."));
    }
    if state.store.user_by_email(&email).await?.is_some() {
        return Err(ApiError::bad("There is an account for this address already."));
    }
    let settings = state.settings();
    let token = auth::random_token(32);
    let expires = clock::in_seconds(i64::from(settings.invitation_days) * 86_400);
    let language = settings.default_language;
    let invitation = state
        .store
        .invite(&email, auth::sha256(token.as_bytes()), admin, invited_by.clone(), language.code(), expires)
        .await?;
    let link = format!("{}/#/finish-signup?token={token}&email={}", state.config.public, encode(&email));
    let mut mailed = false;
    if state.mailer.enabled() {
        let inviter = match &invited_by {
            Some(id) => state.store.user(id).await?.map(|user| user.name.unwrap_or(user.email)),
            None => None,
        };
        let mail = Mail::Invitation {
            link: link.clone(),
            server: state.host().to_string(),
            invited_by: inviter,
            expires: long_date(&invitation.expires, language),
        };
        match state.mailer.send(&email, &mail, language).await {
            Ok(()) => mailed = true,
            Err(error) => tracing::warn!(%error, %email, "the invitation mail did not go out"),
        }
    }
    Ok(Invited { email, token, link, mailed, expires: invitation.expires })
}

fn encode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (byte as char).to_string(),
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// `2. Oktober 2026` or `October 2, 2026`.
fn long_date(text: &str, language: Language) -> String {
    let Some(when) = clock::parse(text) else { return text.to_string() };
    const DE: [&str; 12] = [
        "Januar",
        "Februar",
        "März",
        "April",
        "Mai",
        "Juni",
        "Juli",
        "August",
        "September",
        "Oktober",
        "November",
        "Dezember",
    ];
    const EN: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let month = usize::from(u8::from(when.month())) - 1;
    match language {
        Language::De => format!("{}. {} {}", when.day(), DE[month], when.year()),
        Language::En => format!("{} {}, {}", EN[month], when.day(), when.year()),
    }
}

async fn invitations(State(state): State<AppState>, _admin: Admin) -> ApiResult<Json<Value>> {
    let now = clock::now();
    let mut list = Vec::new();
    for invitation in state.store.invitations().await? {
        let invited_by = match &invitation.invited_by {
            Some(id) => state.store.user(id).await?.map(|user| user.email),
            None => None,
        };
        list.push(json!({
            "email": invitation.email,
            "admin": invitation.admin,
            "invitedBy": invited_by,
            "language": invitation.language,
            "created": invitation.created,
            "expires": invitation.expires,
            "expired": invitation.expires <= now,
        }));
    }
    Ok(Json(json!(list)))
}

#[derive(Deserialize)]
struct NewInvitation {
    email: String,
    #[serde(default)]
    admin: bool,
}

async fn create_invitation(
    State(state): State<AppState>,
    admin: Admin,
    Json(data): Json<NewInvitation>,
) -> ApiResult<Json<Value>> {
    let invited = invite(&state, &data.email, data.admin, Some(admin.0.user.id.clone())).await?;
    record(&state, &admin, format!("invited {}{}", invited.email, if data.admin { " as admin" } else { "" })).await;
    Ok(Json(
        json!({ "email": invited.email, "link": invited.link, "mailed": invited.mailed, "expires": invited.expires }),
    ))
}

async fn delete_invitation(
    State(state): State<AppState>,
    admin: Admin,
    Path(email): Path<String>,
) -> ApiResult<StatusCode> {
    if !state.store.uninvite(&email).await? {
        return Err(ApiError::not_found("There is no invitation for this address."));
    }
    record(&state, &admin, format!("withdrew the invitation for {}", normalize_email(&email))).await;
    Ok(StatusCode::OK)
}

// ── Users ─────────────────────────────────────────────────

fn user_json(overview: &UserOverview) -> Value {
    let user = &overview.user;
    json!({
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "admin": user.admin,
        "disabled": user.disabled,
        "language": user.language,
        "created": user.created,
        "lastLogin": user.last_login,
        "revision": user.revision,
        "devices": overview.devices,
        "ciphers": overview.ciphers,
        "twoFactor": overview.two_factor,
        "kdf": if user.kdf.kind == 1 { "Argon2id" } else { "PBKDF2" },
    })
}

async fn users(State(state): State<AppState>, _admin: Admin) -> ApiResult<Json<Value>> {
    let users = state.store.users().await?;
    Ok(Json(json!(users.iter().map(user_json).collect::<Vec<_>>())))
}

async fn user_action(
    State(state): State<AppState>,
    admin: Admin,
    Path((id, action)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let target = state.store.user(&id).await?.ok_or_else(|| ApiError::not_found("No such account."))?;
    let yourself = target.id == admin.0.user.id;
    let last_admin = target.admin && state.store.admin_count().await? <= 1;
    match action.as_str() {
        "disable" => {
            if yourself {
                return Err(ApiError::bad("You cannot disable your own account."));
            }
            state
                .store
                .update_user(&id, |user| {
                    user.disabled = true;
                    user.security_stamp = uuid::Uuid::new_v4().to_string();
                })
                .await?;
        }
        "enable" => {
            state.store.update_user(&id, |user| user.disabled = false).await?;
        }
        "make-admin" => {
            state.store.update_user(&id, |user| user.admin = true).await?;
        }
        "remove-admin" => {
            if last_admin {
                return Err(ApiError::bad("This is the last admin. Make somebody else an admin first."));
            }
            state.store.update_user(&id, |user| user.admin = false).await?;
        }
        "log-out" => {
            state.store.update_user(&id, |user| user.security_stamp = uuid::Uuid::new_v4().to_string()).await?;
        }
        "reset-two-factor" => {
            state.store.remove_two_factor(&id, None).await?;
        }
        _ => return Err(ApiError::not_found("Not found.")),
    }
    record(&state, &admin, format!("{action} for {}", target.email)).await;
    let overview = state
        .store
        .users()
        .await?
        .into_iter()
        .find(|overview| overview.user.id == id)
        .ok_or_else(|| ApiError::not_found("No such account."))?;
    Ok(Json(user_json(&overview)))
}

async fn delete_user(State(state): State<AppState>, admin: Admin, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let target = state.store.user(&id).await?.ok_or_else(|| ApiError::not_found("No such account."))?;
    if target.id == admin.0.user.id {
        return Err(ApiError::bad("Delete your own account in your settings, not here."));
    }
    state.store.delete_user(&id).await?;
    record(&state, &admin, format!("deleted the account {}", target.email)).await;
    Ok(StatusCode::OK)
}

async fn user_devices(State(state): State<AppState>, _admin: Admin, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let devices = state.store.devices(&id).await?;
    let list: Vec<Value> = devices
        .iter()
        .map(|device| {
            json!({
                "id": device.id,
                "name": device.name,
                "type": device.kind,
                "typeName": device_type_name(device.kind),
                "created": device.created,
                "lastSeen": device.last_seen,
                "lastIp": device.last_ip,
                "loggedIn": device.logged_in,
            })
        })
        .collect();
    Ok(Json(json!(list)))
}

async fn delete_device(
    State(state): State<AppState>,
    admin: Admin,
    Path((id, device)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    if !state.store.delete_device(&id, &device).await? {
        return Err(ApiError::not_found("No such device."));
    }
    record(&state, &admin, format!("logged out device {device} of {id}")).await;
    Ok(StatusCode::OK)
}

// ── Settings ──────────────────────────────────────────────

/// The settings as the portal shows them: the mail password is never sent back, only whether
/// there is one.
fn settings_json(settings: &Settings) -> Value {
    let mut value = serde_json::to_value(settings).expect("settings serialize");
    if let Some(smtp) = value.get_mut("smtp").and_then(Value::as_object_mut) {
        let set =
            smtp.remove("password").is_some_and(|password| password.as_str().is_some_and(|text| !text.is_empty()));
        smtp.insert("passwordSet".into(), set.into());
    }
    value["mailEnabled"] = settings.smtp.as_ref().is_some_and(|smtp| smtp.is_set()).into();
    value
}

async fn get_settings(State(state): State<AppState>, _admin: Admin) -> Json<Value> {
    Json(settings_json(&state.settings()))
}

async fn put_settings(
    State(state): State<AppState>,
    admin: Admin,
    Json(mut new): Json<Settings>,
) -> ApiResult<Json<Value>> {
    let current = state.settings();
    // A password left out means: keep the one there is — for the same account on the same mail
    // server only. Otherwise whoever holds an admin session could point the settings at a server
    // of their own, and the stored password would log in there.
    if let (Some(smtp), Some(old)) = (new.smtp.as_mut(), current.smtp.as_ref())
        && smtp.password.as_deref().is_none_or(str::is_empty)
        && old.password.as_deref().is_some_and(|password| !password.is_empty())
    {
        let same_server = smtp.host.trim().eq_ignore_ascii_case(old.host.trim())
            && smtp.port == old.port
            && smtp.security == old.security;
        if same_server && smtp.username == old.username {
            smtp.password = old.password.clone();
        } else if !smtp.host.trim().is_empty() && smtp.username.as_deref().is_some_and(|name| !name.is_empty()) {
            return Err(ApiError::bad("The mail server changed: enter its password again."));
        }
    }
    if let Some(smtp) = &new.smtp
        && smtp.host.trim().is_empty()
    {
        new.smtp = None;
    }
    new.check().map_err(ApiError::bad)?;
    state.mailer.configure(new.smtp.as_ref()).map_err(|error| ApiError::bad(error.to_string()))?;
    new.save(&state.store).await?;
    *state.settings.write() = new.clone();
    record(&state, &admin, "changed the settings".into()).await;
    Ok(Json(settings_json(&new)))
}

#[derive(Deserialize)]
struct TestMail {
    to: String,
}

async fn test_mail(State(state): State<AppState>, admin: Admin, Json(data): Json<TestMail>) -> ApiResult<StatusCode> {
    if !state.mailer.enabled() {
        return Err(ApiError::bad("There is no mail server set up yet. Save the settings first."));
    }
    let language = Language::from_code(&admin.0.user.language);
    state.mailer.send(data.to.trim(), &Mail::Test, language).await.map_err(|error| ApiError::bad(error.to_string()))?;
    Ok(StatusCode::OK)
}

// ── What happened ─────────────────────────────────────────

#[derive(Deserialize)]
struct EventQuery {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    before: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

async fn events(
    State(state): State<AppState>,
    _admin: Admin,
    Query(query): Query<EventQuery>,
) -> ApiResult<Json<Value>> {
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let kind = query.kind.filter(|kind| !kind.is_empty());
    let events = state.store.events(kind, query.before, limit).await?;
    let list: Vec<Value> = events
        .iter()
        .map(|event| {
            json!({
                "id": event.id,
                "time": event.time,
                "kind": event.kind,
                "userId": event.user_id,
                "email": event.email,
                "ip": event.ip,
                "deviceType": event.device_type.map(device_type_name),
                "detail": event.detail,
            })
        })
        .collect();
    Ok(Json(json!(list)))
}

#[derive(Deserialize)]
struct LogQuery {
    #[serde(default)]
    after: u64,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn logs(State(state): State<AppState>, _admin: Admin, Query(query): Query<LogQuery>) -> Json<Value> {
    let lines =
        state.logs.lines(query.after, query.level.as_deref().unwrap_or("info"), query.limit.unwrap_or(500).min(2000));
    Json(json!(lines))
}

async fn overview(State(state): State<AppState>, _admin: Admin) -> ApiResult<Json<Value>> {
    let stats = state.store.stats().await?;
    let database = state.store.path().to_path_buf();
    let size = |path: &std::path::Path| std::fs::metadata(path).map_or(0, |meta| meta.len());
    let database_size = size(&database) + size(&with_suffix(&database, "-wal"));
    let list = backups::list(&state.config.backups);
    let update = state.update.read().clone();
    Ok(Json(json!({
        "version": state.version,
        "uptimeSeconds": state.started.elapsed().as_secs(),
        "users": stats.users,
        "admins": stats.admins,
        "disabled": stats.disabled,
        "invitations": stats.invitations,
        "devices": stats.devices,
        "ciphers": stats.ciphers,
        "trashed": stats.trashed,
        "folders": stats.folders,
        "twoFactor": stats.two_factor,
        "failedLoginsDay": stats.failed_logins_day,
        "databaseBytes": database_size,
        "backups": list.len(),
        "backupBytes": list.iter().map(|(_, bytes)| bytes).sum::<u64>(),
        "lastBackup": list.last().map(|(name, _)| name),
        "mail": state.mailer.enabled(),
        "webVault": crate::web::is_built(),
        "update": update,
    })))
}

// ── Backups ───────────────────────────────────────────────

async fn list_backups(State(state): State<AppState>, _admin: Admin) -> Json<Value> {
    let list: Vec<Value> = backups::list(&state.config.backups)
        .into_iter()
        .rev()
        .map(|(name, bytes)| json!({ "name": name, "bytes": bytes, "time": backups::stamp_of(&name) }))
        .collect();
    Json(json!(list))
}

async fn create_backup(State(state): State<AppState>, admin: Admin) -> ApiResult<Json<Value>> {
    let path = backups::write(&state.store, &state.config.backups, None).await.map_err(ApiError::bad)?;
    backups::keep_newest(&state.config.backups, backups::KEPT);
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    record(&state, &admin, format!("wrote the backup {name}")).await;
    let bytes = std::fs::metadata(&path).map_or(0, |meta| meta.len());
    Ok(Json(json!({ "name": name, "bytes": bytes })))
}

/// A backup to take home. Only names the list has: nothing else on the disk comes out here.
///
/// A backup is the whole database — every vault, and the server's own keys, the one that signs
/// access tokens among them — so it takes the admin's master password as well as a session: a
/// session token that got away is not enough to carry everything off.
async fn download_backup(
    State(state): State<AppState>,
    admin: Admin,
    Path(name): Path<String>,
    Json(secret): Json<crate::two_factor::Secret>,
) -> ApiResult<Response> {
    crate::accounts::check_password(&state, &admin.0.user, secret.master_password_hash.as_deref()).await?;
    if !backups::list(&state.config.backups).iter().any(|(known, _)| *known == name) {
        return Err(ApiError::not_found("There is no such backup."));
    }
    let bytes = tokio::fs::read(state.config.backups.join(&name)).await.map_err(ApiError::internal)?;
    record(&state, &admin, format!("downloaded the backup {name}")).await;
    Ok((
        [
            (header::CONTENT_TYPE, "application/vnd.sqlite3".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
        ],
        bytes,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    async fn admin(server: &TestServer) -> Account {
        let token = server.invite("admin@example.com", true).await;
        let response = server
            .call("POST", "/identity/accounts/register/finish", None, register_body("admin@example.com", &token))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        server.login("admin@example.com", "admin-device").await
    }

    #[test]
    fn dates_for_mails() {
        assert_eq!(long_date("2026-10-02T12:00:00.000000Z", Language::De), "2. Oktober 2026");
        assert_eq!(long_date("2026-10-02T12:00:00.000000Z", Language::En), "October 2, 2026");
    }

    #[tokio::test]
    async fn only_admins_get_in() {
        let server = TestServer::new().await;
        let user = server.account("nyu@example.com").await;
        assert_eq!(server.get_as(&user.token, "/uwu/v1/admin/users").await.status(), StatusCode::FORBIDDEN);
        assert_eq!(server.get("/uwu/v1/admin/users").await.status(), StatusCode::UNAUTHORIZED);
        let admin = admin(&server).await;
        let users = json(server.get_as(&admin.token, "/uwu/v1/admin/users").await).await;
        assert_eq!(users.as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn an_invitation_by_mail_and_by_link() {
        let server = TestServer::new().await;
        let admin = admin(&server).await;
        let response = server
            .call("POST", "/uwu/v1/admin/invitations", Some(&admin.token), json!({"email": "New@Example.com"}))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let invited = json(response).await;
        assert_eq!(invited["mailed"], true);
        let link = invited["link"].as_str().unwrap();
        assert!(link.starts_with("https://vault.example.com/#/finish-signup?token="), "{link}");
        let mail = server.mails().into_iter().find(|mail| mail.to == "new@example.com").unwrap();
        assert!(mail.text.contains(link));
        assert!(mail.text.contains("Nyu hat dich"), "{}", mail.text);

        let list = json(server.get_as(&admin.token, "/uwu/v1/admin/invitations").await).await;
        assert_eq!(list[0]["invitedBy"], "admin@example.com");
        let exists = server
            .call("POST", "/uwu/v1/admin/invitations", Some(&admin.token), json!({"email": "admin@example.com"}))
            .await;
        assert_eq!(exists.status(), StatusCode::BAD_REQUEST);
        let gone =
            server.call("DELETE", "/uwu/v1/admin/invitations/new@example.com", Some(&admin.token), json!({})).await;
        assert_eq!(gone.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_admin_disables_logs_out_and_deletes() {
        let server = TestServer::new().await;
        let admin = admin(&server).await;
        let user = server.account("nyu@example.com").await;
        let path = |action: &str| format!("/uwu/v1/admin/users/{}/{action}", user.id);
        let response = server.call("POST", &path("disable"), Some(&admin.token), json!({})).await;
        assert_eq!(json(response).await["disabled"], true);
        assert_eq!(server.get_as(&user.token, "/api/sync").await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            server.form("/identity/connect/token", &login_form("nyu@example.com", "d9")).await.status(),
            StatusCode::BAD_REQUEST
        );
        server.call("POST", &path("enable"), Some(&admin.token), json!({})).await;
        let again = server.login("nyu@example.com", "d9").await;
        server.call("POST", &path("log-out"), Some(&admin.token), json!({})).await;
        assert_eq!(server.get_as(&again.token, "/api/sync").await.status(), StatusCode::UNAUTHORIZED);

        let yourself = format!("/uwu/v1/admin/users/{}/disable", admin.id);
        assert_eq!(
            server.call("POST", &yourself, Some(&admin.token), json!({})).await.status(),
            StatusCode::BAD_REQUEST
        );
        let last = format!("/uwu/v1/admin/users/{}/remove-admin", admin.id);
        assert_eq!(server.call("POST", &last, Some(&admin.token), json!({})).await.status(), StatusCode::BAD_REQUEST);

        let response =
            server.call("DELETE", &format!("/uwu/v1/admin/users/{}", user.id), Some(&admin.token), json!({})).await;
        assert_eq!(response.status(), StatusCode::OK);
        let events = json(server.get_as(&admin.token, "/uwu/v1/admin/events?kind=admin").await).await;
        assert!(events.as_array().unwrap().len() >= 4);
    }

    /// The settings as the portal sends them back, with the password left out.
    fn again_body(settings: &Settings) -> Value {
        let mut body = serde_json::to_value(settings).unwrap();
        body["smtp"]["password"] = Value::Null;
        body
    }

    #[tokio::test]
    async fn settings_keep_the_mail_password_to_themselves() {
        let server = TestServer::new().await;
        let admin = admin(&server).await;
        let smtp = json!({"host": "mail.example.com", "port": 587, "security": "starttls", "username": "vault", "password": "s3cret", "from": "vault@example.com"});
        let body = json!({"smtp": smtp, "defaultLanguage": "en", "invitationDays": 3, "newDeviceMail": false, "passwordHints": true, "rememberTwoFactor": true});
        let saved = json(server.call("PUT", "/uwu/v1/admin/settings", Some(&admin.token), body.clone()).await).await;
        assert_eq!(saved["smtp"]["passwordSet"], true);
        assert!(saved["smtp"].get("password").is_none());

        let mut again = body;
        again["smtp"]["password"] = Value::Null;
        again["invitationDays"] = json!(5);
        server.call("PUT", "/uwu/v1/admin/settings", Some(&admin.token), again).await;
        let stored = Settings::load(&server.state.store, &Settings::default()).await.unwrap();
        assert_eq!(stored.smtp.as_ref().unwrap().password.as_deref(), Some("s3cret"), "kept");
        assert_eq!(stored.invitation_days, 5);

        let mut elsewhere = again_body(&stored);
        elsewhere["smtp"]["host"] = json!("mail.attacker.example");
        let response = server.call("PUT", "/uwu/v1/admin/settings", Some(&admin.token), elsewhere).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "the password does not go to another server");
        let stored = Settings::load(&server.state.store, &Settings::default()).await.unwrap();
        assert_eq!(stored.smtp.unwrap().host, "mail.example.com");

        let wrong = json!({"invitationDays": 0});
        assert_eq!(
            server.call("PUT", "/uwu/v1/admin/settings", Some(&admin.token), wrong).await.status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn backups_are_written_listed_and_handed_out() {
        let server = TestServer::new().await;
        let admin = admin(&server).await;
        let written = json(server.call("POST", "/uwu/v1/admin/backups", Some(&admin.token), json!({})).await).await;
        let name = written["name"].as_str().unwrap();
        let list = json(server.get_as(&admin.token, "/uwu/v1/admin/backups").await).await;
        assert_eq!(list[0]["name"], name);
        let path = format!("/uwu/v1/admin/backups/{name}");
        let wrong = server.call("POST", &path, Some(&admin.token), json!({"masterPasswordHash": "wrong"})).await;
        assert_eq!(wrong.status(), StatusCode::BAD_REQUEST, "not without the master password");
        let secret = json!({"masterPasswordHash": password_hash("admin@example.com")});
        let download = server.call("POST", &path, Some(&admin.token), secret.clone()).await;
        assert_eq!(download.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(download.into_body(), usize::MAX).await.unwrap();
        assert!(bytes.starts_with(b"SQLite format 3"));
        let sneaky = server.call("POST", "/uwu/v1/admin/backups/..%2Fuwulock.db", Some(&admin.token), secret).await;
        assert_eq!(sneaky.status(), StatusCode::NOT_FOUND);
        let overview = json(server.get_as(&admin.token, "/uwu/v1/admin/overview").await).await;
        assert_eq!(overview["backups"], 1);
        assert_eq!(overview["users"], 1);
    }
}
