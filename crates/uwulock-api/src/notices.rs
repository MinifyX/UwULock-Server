//! Security notices (docs/uwu-api.md §12): what happened on an account — failed logins, changed
//! credentials, a new device, an export — listed in the web vault under *Settings → Security*
//! with device, address and time, and mailed in the account's language.
//!
//! Mails are bundled so an attack does not become a flood of them: the notices of an account are
//! collected for five minutes after the first, then one mail lists them all (failed attempts
//! summed up), and an account gets at most one such mail every fifteen minutes; the rest waits
//! for the next. The admin switches kinds off for mail; they are listed all the same. The mail
//! about a new device goes out at once, as it did before this list existed.

use crate::AppState;
use crate::auth::{ClientIp, Session, device_type_name};
use crate::errors::{ApiError, ApiResult};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::IpAddr;
use uwulock_mail::{Language, Mail, NoticeLine};
use uwulock_store::notices::{MAIL_NONE, MAIL_SENT, MAIL_WAITING};
use uwulock_store::{Notice, User, clock};

/// Every kind of notice there is (§12.1); the later stages write some of them.
pub const KINDS: [&str; 24] = [
    "failedLogins",
    "failedTwoFactor",
    "newDevice",
    "passwordChanged",
    "emailChanged",
    "kdfChanged",
    "keysRotated",
    "twoFactorEnabled",
    "twoFactorDisabled",
    "apiKeyCreated",
    "apiKeyRotated",
    "maskedApiKeyCreated",
    "emergencyAccessRequested",
    "emergencyAccessTakenOver",
    "loginWithDeviceRequested",
    "vaultExported",
    "travelModeEnabled",
    "travelModeDisabled",
    "travelDisableFailed",
    "extrasKeyReset",
    "kdfBelowMinimum",
    "ssoLinked",
    "maskedConnected",
    "maskedDisconnected",
];

/// How many wrong tries within [`BURST_SECONDS`] make a notice.
pub const BURST_TRIES: i64 = 3;
pub const BURST_SECONDS: i64 = 15 * 60;
/// A bundle waits this long after its first notice…
pub const GATHER_SECONDS: i64 = 5 * 60;
/// …and an account gets at most one every this long.
pub const SPACING_SECONDS: i64 = 15 * 60;

/// Where something happened: the address, and the device and app where there is one.
#[derive(Debug, Clone, Default)]
pub struct Context {
    pub ip: Option<IpAddr>,
    pub device_type: Option<i64>,
    pub device_name: Option<String>,
    pub app: Option<String>,
}

impl Context {
    pub fn ip(ip: IpAddr) -> Self {
        Context { ip: Some(ip), ..Context::default() }
    }

    /// The device of a session, from where it asks now.
    pub async fn of(state: &AppState, session: &Session, ip: IpAddr) -> Self {
        let device = state.store.device(&session.user.id, &session.device).await.ok().flatten();
        Context {
            ip: Some(ip),
            device_type: device.as_ref().map(|device| device.kind),
            device_name: device.map(|device| device.name),
            app: Some(session.client_id.clone()),
        }
    }
}

/// Whether a notice of `kind` goes out by mail at all.
fn mailed(state: &AppState, kind: &str) -> bool {
    state.mailer.enabled() && !state.settings().security_notices.mail_off.iter().any(|off| off == kind)
}

fn notice(user: &User, kind: &str, context: &Context, detail: Value, mail: i64) -> Notice {
    Notice {
        user_id: user.id.clone(),
        kind: kind.to_string(),
        ip: context.ip.map(|ip| ip.to_string()),
        device_type: context.device_type,
        device_name: context.device_name.clone(),
        app: context.app.clone(),
        detail: detail.to_string(),
        mail,
        ..Notice::default()
    }
}

/// Write a notice for `user`; it waits for the next bundled mail, unless its kind is off.
pub async fn record(state: &AppState, user: &User, kind: &str, context: &Context, detail: Value) {
    let mail = if mailed(state, kind) { MAIL_WAITING } else { MAIL_NONE };
    if let Err(error) = state.store.add_notice(notice(user, kind, context, detail, mail)).await {
        tracing::warn!(%error, kind, "a security notice could not be written");
    }
}

/// Write a notice whose mail went out already, like the one for a new device.
pub async fn record_mailed(state: &AppState, user: &User, kind: &str, context: &Context, detail: Value, sent: bool) {
    let mut notice = notice(user, kind, context, detail, if sent { MAIL_SENT } else { MAIL_NONE });
    let now = clock::now();
    notice.time = now.clone();
    match state.store.add_notice(notice).await {
        Ok(id) if sent => {
            let _ = state.store.notices_mailed(vec![id], &now, true).await;
        }
        Ok(_) => {}
        Err(error) => tracing::warn!(%error, kind, "a security notice could not be written"),
    }
}

/// After a wrong password (`failedLogins`, from the event `login-failed`) or second step
/// (`failedTwoFactor`, from `two-factor-failed`): from the third within a quarter of an hour, a
/// notice that counts them for as long as the burst lasts.
pub async fn failed(state: &AppState, user: &User, kind: &str, event: &str, context: &Context, provider: Option<i64>) {
    let mut detail = json!({});
    if let Some(provider) = provider {
        detail["provider"] = provider.into();
    }
    let mail = if mailed(state, kind) { MAIL_WAITING } else { MAIL_NONE };
    let notice = notice(user, kind, context, detail, mail);
    if let Err(error) = state.store.burst_notice(notice, event, BURST_SECONDS, BURST_TRIES).await {
        tracing::warn!(%error, kind, "a security notice could not be written");
    }
}

/// `kdfBelowMinimum`, once — until the account's KDF changes again.
pub async fn kdf_below_minimum(state: &AppState, user: &User, context: &Context) {
    if !state.settings().policies.kdf_below_minimum(&user.kdf) {
        return;
    }
    match state.store.has_notice_since(&user.id, "kdfBelowMinimum", "kdfChanged").await {
        Ok(false) => record(state, user, "kdfBelowMinimum", context, json!({})).await,
        Ok(true) => {}
        Err(error) => tracing::warn!(%error, "security notices could not be read"),
    }
}

/// The line of a notice in a mail.
fn line(notice: &Notice) -> NoticeLine {
    let detail: Value = serde_json::from_str(&notice.detail).unwrap_or(Value::Null);
    let device = match (&notice.device_name, notice.device_type) {
        (Some(name), Some(kind)) => Some(format!("{name} ({})", device_type_name(kind))),
        (Some(name), None) => Some(name.clone()),
        (None, Some(kind)) => Some(device_type_name(kind).to_string()),
        (None, None) => None,
    };
    NoticeLine {
        kind: notice.kind.clone(),
        time: crate::identity::format_time(&notice.time),
        ip: notice.ip.clone(),
        device,
        count: detail["count"].as_i64(),
        about: detail["grantee"]
            .as_str()
            .or_else(|| detail["format"].as_str())
            .or_else(|| detail["issuer"].as_str())
            .map(str::to_string),
    }
}

/// Send the bundles that are due at `now`. The maintenance job calls it every minute.
pub async fn deliver_due(state: &AppState, now: &str) {
    let due = match state.store.notices_due(now, GATHER_SECONDS, SPACING_SECONDS).await {
        Ok(due) => due,
        Err(error) => {
            tracing::warn!(%error, "security notices could not be read");
            return;
        }
    };
    for user_id in due {
        let Ok(Some(user)) = state.store.user(&user_id).await else { continue };
        let Ok(waiting) = state.store.waiting_notices(&user_id).await else { continue };
        if waiting.is_empty() {
            continue;
        }
        let ids: Vec<i64> = waiting.iter().map(|notice| notice.id).collect();
        if !state.mailer.enabled() {
            let _ = state.store.notices_mailed(ids, now, false).await;
            continue;
        }
        // Failed attempts are one line each per kind, their counts summed.
        let mut lines: Vec<NoticeLine> = Vec::new();
        for notice in &waiting {
            let next = line(notice);
            match lines.iter_mut().find(|line| line.kind == next.kind && next.kind.starts_with("failed")) {
                Some(same) => {
                    same.count = Some(same.count.unwrap_or(0) + next.count.unwrap_or(0));
                    same.time = next.time;
                    same.ip = next.ip;
                }
                None => lines.push(next),
            }
        }
        let mail =
            Mail::SecurityNotices { notices: lines, link: format!("{}/#/settings/security", state.config.public) };
        match state.mailer.send(&user.email, &mail, Language::from_code(&user.language)).await {
            Ok(()) => {
                let _ = state.store.notices_mailed(ids, now, true).await;
            }
            // Stays waiting: the next minute tries again.
            Err(error) => tracing::warn!(%error, "a mail with security notices did not go out"),
        }
    }
}

/// `emailChanged` goes to the old address as well, at once: whoever took the account will not
/// be reading it there.
pub fn tell_old_address(state: &AppState, old: &str, user: &User, context: &Context) {
    if !mailed(state, "emailChanged") {
        return;
    }
    let notice = notice(user, "emailChanged", context, json!({}), MAIL_NONE);
    let mail = Mail::SecurityNotices {
        notices: vec![NoticeLine { time: crate::identity::format_time(&clock::now()), ..line(&notice) }],
        link: state.config.public.clone(),
    };
    crate::identity::send_later(state, old, mail, Language::from_code(&user.language));
}

// ── The web vault ─────────────────────────────────────────

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/security/notices", get(list))
        .route("/uwu/v1/security/notices/seen", post(seen))
        .route("/uwu/v1/security/notices/report", post(report))
        .route("/events/collect", post(collect))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListQuery {
    #[serde(default)]
    continuation_token: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

fn render(notice: &Notice) -> Value {
    json!({
        "object": "securityNotice",
        "id": notice.id.to_string(),
        "kind": notice.kind,
        "date": notice.time,
        "ip": notice.ip,
        "deviceType": notice.device_type,
        "deviceName": notice.device_name,
        "app": notice.app,
        "detail": serde_json::from_str::<Value>(&notice.detail).unwrap_or_else(|_| json!({})),
        "mailed": notice.mail == MAIL_SENT,
        "seen": notice.seen,
    })
}

async fn list(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let before = match query.continuation_token.as_deref().filter(|token| !token.is_empty()) {
        Some(token) => Some(token.parse::<i64>().map_err(|_| ApiError::bad("That is not a continuation token."))?),
        None => None,
    };
    let notices = state.store.notices(&session.user.id, before, limit).await?;
    let next = (notices.len() as i64 == limit).then(|| notices.last().map(|notice| notice.id.to_string())).flatten();
    let unseen = state.store.unseen_notices(&session.user.id).await?;
    Ok(Json(json!({
        "object": "list",
        "data": notices.iter().map(render).collect::<Vec<_>>(),
        "continuationToken": next,
        "unseen": unseen,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Seen {
    up_to_id: String,
}

async fn seen(State(state): State<AppState>, session: Session, Json(data): Json<Seen>) -> ApiResult<StatusCode> {
    let up_to = data.up_to_id.trim().parse::<i64>().map_err(|_| ApiError::bad("That is not a notice id."))?;
    state.store.see_notices(&session.user.id, up_to).await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct Report {
    kind: String,
    #[serde(default)]
    detail: Value,
}

/// A client says it exported the vault. Only that can be reported, ten times an hour.
async fn report(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(data): Json<Report>,
) -> ApiResult<StatusCode> {
    if data.kind != "vaultExported" {
        return Err(ApiError::bad("Only vaultExported can be reported."));
    }
    let format = data.detail["format"].as_str().unwrap_or_default();
    if !matches!(format, "json" | "encrypted_json" | "csv") {
        return Err(ApiError::bad("The format is json, encrypted_json or csv."));
    }
    if !state.limits.reports.take(session.user.id.clone()) {
        return Err(ApiError::too_many("Too many reports. Wait a while."));
    }
    let context = Context::of(&state, &session, ip).await;
    record(&state, &session.user, "vaultExported", &context, json!({ "format": format })).await;
    Ok(StatusCode::OK)
}

/// Bitwarden's `/events/collect`: the official clients report what they did. Of all of it only
/// an export (event 1007, `User_ClientExportedVault`) is kept, as a notice.
async fn collect(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Result<Session, ApiError>,
    body: axum::body::Bytes,
) -> StatusCode {
    let Ok(session) = session else { return StatusCode::OK };
    let events: Vec<Value> = serde_json::from_slice(&body).unwrap_or_default();
    let exported = events
        .iter()
        .any(|event| event.get("type").or_else(|| event.get("Type")).and_then(Value::as_i64) == Some(1007));
    if exported && state.limits.reports.take(session.user.id.clone()) {
        let context = Context::of(&state, &session, ip).await;
        record(&state, &session.user, "vaultExported", &context, json!({ "format": "json" })).await;
    }
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    #[tokio::test]
    async fn wrong_passwords_become_one_notice_and_one_mail() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let mut wrong = login_form("nyu@example.com", "attacker");
        wrong[2].1 = "wrong";
        for _ in 0..5 {
            let refused = server.form("/identity/connect/token", &wrong).await;
            assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        }
        // The notice is written beside the answer: wait for it to count all five.
        for _ in 0..1000 {
            let notices = server.state.store.notices(&account.id, None, 10).await.unwrap();
            if notices.iter().any(|notice| notice.kind == "failedLogins" && notice.detail.contains("5")) {
                break;
            }
            tokio::task::yield_now().await;
        }
        let listed = json(server.get_as(&account.token, "/uwu/v1/security/notices").await).await;
        let failed: Vec<&Value> =
            listed["data"].as_array().unwrap().iter().filter(|notice| notice["kind"] == "failedLogins").collect();
        assert_eq!(failed.len(), 1, "{listed}");
        assert_eq!(failed[0]["detail"]["count"], 5);
        assert_eq!(failed[0]["ip"], "0.0.0.0");
        assert_eq!(failed[0]["mailed"], false);
        assert!(listed["unseen"].as_i64().unwrap() >= 1);

        // Nothing before the five minutes are over; then one mail with all of it.
        deliver_due(&server.state, &clock::now()).await;
        assert!(!server.mails().iter().any(|mail| mail.subject.contains("Fehlgeschlagene")));
        deliver_due(&server.state, &clock::in_seconds(GATHER_SECONDS + 1)).await;
        let mails: Vec<_> =
            server.mails().into_iter().filter(|mail| mail.subject.contains("Fehlgeschlagene")).collect();
        assert_eq!(mails.len(), 1);
        assert!(mails[0].text.contains("5 falsche Master-Passwörter"), "{}", mails[0].text);
        assert!(mails[0].text.contains("https://vault.example.com/#/settings/security"));
        deliver_due(&server.state, &clock::in_seconds(GATHER_SECONDS + 2)).await;
        assert_eq!(server.mails().iter().filter(|mail| mail.subject.contains("Fehlgeschlagene")).count(), 1);

        let listed = json(server.get_as(&account.token, "/uwu/v1/security/notices").await).await;
        let newest = listed["data"][0]["id"].as_str().unwrap().to_string();
        let response =
            server.call("POST", "/uwu/v1/security/notices/seen", Some(&account.token), json!({"upToId": newest})).await;
        assert_eq!(response.status(), StatusCode::OK);
        let me = json(server.get_as(&account.token, "/uwu/v1/account").await).await;
        assert_eq!(me["securityNoticesUnseen"], 0);
    }

    #[tokio::test]
    async fn changes_are_listed_and_kinds_can_be_kept_out_of_mail() {
        let mut settings = crate::Settings::default();
        settings.security_notices.mail_off = vec!["passwordChanged".into()];
        let server = TestServer::with_settings(settings).await;
        let account = server.account("nyu@example.com").await;
        let body = json!({
            "masterPasswordHash": password_hash("nyu@example.com"),
            "newMasterPasswordHash": "new hash",
            "key": "2.new|new|new",
        });
        let changed = server.call("POST", "/api/accounts/password", Some(&account.token), body).await;
        assert_eq!(changed.status(), StatusCode::OK);
        let notices = server.state.store.notices(&account.id, None, 10).await.unwrap();
        let notice = notices.iter().find(|notice| notice.kind == "passwordChanged").unwrap();
        assert_eq!(notice.mail, MAIL_NONE, "switched off for mail");
        assert_eq!(notice.device_name.as_deref(), Some("firefox"));
        assert_eq!(notice.app.as_deref(), Some("browser"));
    }

    #[tokio::test]
    async fn exports_are_reported_by_ours_and_bitwarden_s_clients() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let body = json!({"kind": "vaultExported", "detail": {"format": "csv"}});
        let response = server.call("POST", "/uwu/v1/security/notices/report", Some(&account.token), body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let other = json!({"kind": "passwordChanged", "detail": {}});
        let refused = server.call("POST", "/uwu/v1/security/notices/report", Some(&account.token), other).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        let events = json!([{"type": 1007, "date": "2026-09-28T12:00:00Z"}, {"type": 1100}]);
        let collected = server.call("POST", "/events/collect", Some(&account.token), events.clone()).await;
        assert_eq!(collected.status(), StatusCode::OK);
        assert_eq!(server.call("POST", "/events/collect", None, events).await.status(), StatusCode::OK);
        let listed = json(server.get_as(&account.token, "/uwu/v1/security/notices").await).await;
        let exports: Vec<&Value> =
            listed["data"].as_array().unwrap().iter().filter(|notice| notice["kind"] == "vaultExported").collect();
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[1]["detail"]["format"], "csv");
    }

    #[tokio::test]
    async fn pages_go_back_in_time() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let user = server.state.store.user(&account.id).await.unwrap().unwrap();
        for _ in 0..3 {
            record(&server.state, &user, "keysRotated", &Context::default(), json!({})).await;
        }
        let first = json(server.get_as(&account.token, "/uwu/v1/security/notices?limit=2").await).await;
        assert_eq!(first["data"].as_array().unwrap().len(), 2);
        let token = first["continuationToken"].as_str().unwrap();
        let rest = json(
            server.get_as(&account.token, &format!("/uwu/v1/security/notices?limit=2&continuationToken={token}")).await,
        )
        .await;
        assert_eq!(rest["data"].as_array().unwrap().len(), 1);
        assert!(rest["continuationToken"].is_null());
    }
}
