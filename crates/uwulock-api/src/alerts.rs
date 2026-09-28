//! Admin notifications (docs/uwu-api.md §21.3, docs/notifications.md): when something on the
//! server needs someone — a backup failed, the certificate runs out, the disk fills up — the
//! admins hear of it by mail, ntfy, Gotify or Matrix, each channel with the events it wants.
//!
//! Once a minute the server looks at how things are ([`tick`]). An event that starts is sent to
//! its channels, at most once an hour per channel however often it comes and goes; one that is
//! over is sent once more, as resolved. A channel that does not take a message keeps it and is
//! tried again, a minute later, then two, four, up to an hour; the overview shows it failing.
//! Messages name no account, only counts, dates and sizes.
//!
//! The channels' tokens stay on the server: the portal only learns whether there is one.

use crate::AppState;
use crate::auth::Admin;
use crate::errors::{ApiError, ApiResult};
use crate::outbound;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use uwulock_mail::{Language, Mail};
use uwulock_store::{Channel, clock};

/// Every event a channel can ask for.
pub const EVENTS: [&str; 8] = [
    "backupFailed",
    "backupStale",
    "certificateExpiring",
    "updateAvailable",
    "manyFailedLogins",
    "diskLow",
    "pushRelayFailing",
    "mailFailing",
];

/// An event is sent to a channel at most this often while it comes and goes.
const SPACING: Duration = Duration::from_secs(60 * 60);
/// A message that no channel took for this long is given up.
const GIVE_UP: Duration = Duration::from_secs(24 * 60 * 60);
/// Failed logins in an hour, across all accounts, that make an event.
pub const MANY_FAILED_LOGINS: i64 = 50;
/// No backup for this long is too old.
pub const BACKUP_STALE_HOURS: u64 = 48;
/// A certificate with less than this left makes an event.
pub const CERTIFICATE_DAYS: i64 = 14;

/// A text in both languages: the channels speak the server's, the portal the admin's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Detail {
    pub de: String,
    pub en: String,
}

impl Detail {
    pub fn new(de: impl Into<String>, en: impl Into<String>) -> Self {
        Detail { de: de.into(), en: en.into() }
    }

    pub fn in_language(&self, language: Language) -> &str {
        match language {
            Language::De => &self.de,
            Language::En => &self.en,
        }
    }
}

/// An event that is going on.
#[derive(Debug, Clone)]
pub struct Active {
    pub since: String,
    pub severity: &'static str,
    pub detail: Detail,
}

#[derive(Debug, Clone)]
struct Outgoing {
    event: String,
    resolved: bool,
    detail: Detail,
    made: Instant,
}

#[derive(Debug, Default)]
struct ChannelState {
    /// When each event was last sent here.
    sent: HashMap<String, Instant>,
    /// Events whose start went out here, so their end does too.
    announced: HashSet<String>,
    queue: VecDeque<Outgoing>,
    attempts: u32,
    retry_at: Option<Instant>,
    last_success: Option<String>,
    last_error: Option<(String, String)>,
}

/// The alerts' state while the server runs.
#[derive(Default)]
pub struct Alerts {
    /// What jobs report themselves, like a failed backup: by event.
    reported: Mutex<BTreeMap<String, (&'static str, Detail)>>,
    /// When the last off-site backup worked, as seconds since 1970 (Stufe 4b, off-site backups).
    offsite_success: Mutex<Option<u64>>,
    active: Mutex<BTreeMap<String, Active>>,
    channels: Mutex<HashMap<String, ChannelState>>,
}

impl Alerts {
    /// A job says `event` is going on (`Some`), or is over (`None`). Taken up at the next tick.
    pub fn report(&self, event: &str, now: Option<(&'static str, Detail)>) {
        let mut reported = self.reported.lock();
        match now {
            Some(state) => {
                reported.insert(event.to_string(), state);
            }
            None => {
                reported.remove(event);
            }
        }
    }

    /// The off-site backup worked at `when` (seconds since 1970).
    pub fn offsite_succeeded(&self, when: u64) {
        *self.offsite_success.lock() = Some(when);
    }

    pub fn offsite_success(&self) -> Option<u64> {
        *self.offsite_success.lock()
    }

    /// The events going on now.
    pub fn active(&self) -> BTreeMap<String, Active> {
        self.active.lock().clone()
    }
}

// ── What is going on ──────────────────────────────────────

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

fn date_of(seconds: u64) -> String {
    let when = time::OffsetDateTime::from_unix_timestamp(seconds as i64).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    crate::identity::format_time(&clock::format(when))
}

/// Everything that is wrong right now, by event.
pub async fn evaluate(state: &AppState) -> BTreeMap<String, (&'static str, Detail)> {
    let mut found = state.alerts.reported.lock().clone();
    let now = unix_now();

    // Backups: a week of them is kept locally; the newest should be from the last two days.
    let newest = uwulock_store::backups::newest(&state.config.backups);
    let created = state.store.created().await.ok().and_then(|created| clock::parse(&created));
    let old_enough = created
        .is_some_and(|created| (time::OffsetDateTime::now_utc() - created).whole_hours() >= BACKUP_STALE_HOURS as i64);
    match newest {
        Some(newest) if now.saturating_sub(newest) > BACKUP_STALE_HOURS * 3600 => {
            let when = date_of(newest);
            found.insert(
                "backupStale".into(),
                (
                    "warning",
                    Detail::new(
                        format!("Das neueste Backup ist vom {when}."),
                        format!("The newest backup is from {when}."),
                    ),
                ),
            );
        }
        None if old_enough => {
            found.insert(
                "backupStale".into(),
                ("warning", Detail::new("Es gibt noch kein Backup.", "There is no backup yet.")),
            );
        }
        _ => {}
    }

    // The off-site backups: the last one failed, or the last good one is too old. Beside a
    // local problem of the same kind, both are said.
    for (event, severity, detail) in crate::offsite::problems(state).await {
        match found.get_mut(event) {
            Some((_, known)) => {
                known.de = format!("{} {}", known.de, detail.de);
                known.en = format!("{} {}", known.en, detail.en);
            }
            None => {
                found.insert(event.into(), (severity, detail));
            }
        }
    }

    if let Some(expires) = state.certificate.read().as_ref().and_then(|seen| seen.expires) {
        let left = (expires - now as i64) / 86_400;
        if left < CERTIFICATE_DAYS {
            let when = date_of(expires.max(0) as u64);
            found.insert(
                "certificateExpiring".into(),
                (
                    if left < 3 { "error" } else { "warning" },
                    Detail::new(
                        format!("Das Zertifikat gilt bis {when}."),
                        format!("The certificate is valid until {when}."),
                    ),
                ),
            );
        }
    }

    if let Some(newer) = state.update.read().newer.clone() {
        found.insert(
            "updateAvailable".into(),
            (
                "info",
                Detail::new(
                    format!("UwULock Server {newer} ist erschienen."),
                    format!("UwULock Server {newer} is out."),
                ),
            ),
        );
    }

    if let Ok(failed) = state.store.recent_events_of(&["login-failed", "two-factor-failed"], 3600).await
        && failed >= MANY_FAILED_LOGINS
    {
        found.insert(
            "manyFailedLogins".into(),
            (
                "warning",
                Detail::new(
                    format!("{failed} fehlgeschlagene Anmeldungen in der letzten Stunde."),
                    format!("{failed} failed logins in the last hour."),
                ),
            ),
        );
    }

    if let Some((free, total)) = state.config.data.ancestors().find_map(uwulock_store::backups::disk_space)
        && total > 0
        && (free < total / 20 || free < 1024 * 1024 * 1024)
    {
        let (gb, percent) = (free as f64 / 1e9, free as f64 * 100.0 / total as f64);
        found.insert(
            "diskLow".into(),
            (
                if free < total / 50 { "error" } else { "warning" },
                Detail::new(
                    format!("Noch {gb:.1} GB frei ({percent:.0} %)."),
                    format!("{gb:.1} GB left ({percent:.0} %)."),
                ),
            ),
        );
    }

    // A service is failing when its last attempt, within the hour, did not work.
    let failing = |success: Option<u64>, error: &Option<(u64, String)>| {
        error.as_ref().filter(|(at, _)| now.saturating_sub(*at) < 3600 && success.is_none_or(|ok| ok < *at)).cloned()
    };
    let relay = state.relay.health();
    if state.settings().push.is_some()
        && let Some((_, error)) = failing(relay.last_success, &relay.last_error)
    {
        found.insert(
            "pushRelayFailing".into(),
            ("warning", Detail::new(format!("Das Push-Relay sagt: {error}"), format!("The push relay says: {error}"))),
        );
    }
    let mail = state.mailer.health();
    if let Some((_, error)) = failing(mail.last_success, &mail.last_error) {
        found.insert(
            "mailFailing".into(),
            ("warning", Detail::new(format!("Der Mailserver sagt: {error}"), format!("The mail server says: {error}"))),
        );
    }
    found
}

/// Look at how things are, queue what changed for the channels, and send what is due.
pub async fn tick(state: &AppState) {
    let found = evaluate(state).await;
    let channels = match state.store.channels().await {
        Ok(channels) => channels,
        Err(error) => {
            tracing::warn!(%error, "the notification channels could not be read");
            return;
        }
    };
    let (started, ended) = {
        let mut active = state.alerts.active.lock();
        let started: Vec<(String, Detail)> = found
            .iter()
            .filter(|(event, _)| !active.contains_key(*event))
            .map(|(event, (_, detail))| (event.clone(), detail.clone()))
            .collect();
        let ended: Vec<(String, Detail)> = active
            .iter()
            .filter(|(event, _)| !found.contains_key(*event))
            .map(|(event, active)| (event.clone(), active.detail.clone()))
            .collect();
        for (event, _) in &ended {
            active.remove(event);
        }
        for (event, (severity, detail)) in &found {
            let entry = active.entry(event.clone()).or_insert_with(|| Active {
                since: clock::now(),
                severity,
                detail: detail.clone(),
            });
            entry.detail = detail.clone();
            entry.severity = severity;
        }
        (started, ended)
    };
    for (event, _) in &started {
        tracing::warn!(event, "an admin alert started");
    }
    for (event, _) in &ended {
        tracing::info!(event, "an admin alert is over");
    }
    {
        let now = Instant::now();
        let mut states = state.alerts.channels.lock();
        states.retain(|id, _| channels.iter().any(|channel| &channel.id == id));
        for channel in channels.iter().filter(|channel| channel.enabled) {
            let wanted = events_of(channel);
            let entry = states.entry(channel.id.clone()).or_default();
            for (event, detail) in &started {
                if !wanted.contains(event) {
                    continue;
                }
                if entry.sent.get(event).is_some_and(|at| now.duration_since(*at) < SPACING) {
                    continue;
                }
                entry.sent.insert(event.clone(), now);
                entry.announced.insert(event.clone());
                entry.queue.push_back(Outgoing {
                    event: event.clone(),
                    resolved: false,
                    detail: detail.clone(),
                    made: now,
                });
            }
            for (event, detail) in &ended {
                if entry.announced.remove(event) {
                    entry.queue.push_back(Outgoing {
                        event: event.clone(),
                        resolved: true,
                        detail: detail.clone(),
                        made: now,
                    });
                }
            }
            entry.queue.retain(|outgoing| now.duration_since(outgoing.made) < GIVE_UP);
        }
    }
    for channel in channels.iter().filter(|channel| channel.enabled) {
        deliver(state, channel).await;
    }
}

/// Send what waits for `channel`, if it is its turn.
async fn deliver(state: &AppState, channel: &Channel) {
    // Mail to the admins without a mail server is nothing to try again: the server was never
    // set up to send any. (Its test says so.)
    if channel.kind == "mail" && !state.mailer.enabled() {
        if let Some(entry) = state.alerts.channels.lock().get_mut(&channel.id) {
            entry.queue.clear();
        }
        return;
    }
    loop {
        let next = {
            let states = state.alerts.channels.lock();
            let Some(entry) = states.get(&channel.id) else { return };
            if entry.retry_at.is_some_and(|at| at > Instant::now()) {
                return;
            }
            match entry.queue.front() {
                Some(next) => next.clone(),
                None => return,
            }
        };
        let result = send(
            state,
            channel,
            &next.event,
            next.detail.in_language(state.settings().default_language),
            next.resolved,
        )
        .await;
        let mut states = state.alerts.channels.lock();
        let Some(entry) = states.get_mut(&channel.id) else { return };
        match result {
            Ok(()) => {
                entry.queue.pop_front();
                entry.attempts = 0;
                entry.retry_at = None;
                entry.last_success = Some(clock::now());
                entry.last_error = None;
            }
            Err(error) => {
                entry.attempts += 1;
                let wait = Duration::from_secs(60 * 2u64.saturating_pow(entry.attempts.saturating_sub(1))).min(SPACING);
                entry.retry_at = Some(Instant::now() + wait);
                if entry.last_error.is_none() {
                    tracing::warn!(channel = %channel.name, %error, "a notification channel does not take messages");
                }
                entry.last_error = Some((clock::now(), error));
                return;
            }
        }
    }
}

fn events_of(channel: &Channel) -> HashSet<String> {
    serde_json::from_str::<Vec<String>>(&channel.events).unwrap_or_default().into_iter().collect()
}

// ── Sending ───────────────────────────────────────────────

/// ntfy: the server, the topic, an access token, a priority from 1 to 5.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct NtfyConfig {
    url: String,
    topic: String,
    token: Option<String>,
    priority: Option<u8>,
}

/// Gotify: the server, an application token, a priority from 0 to 10.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct GotifyConfig {
    url: String,
    token: Option<String>,
    priority: Option<u8>,
}

/// Matrix: the homeserver, the room, the access token of the account that writes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct MatrixConfig {
    homeserver: String,
    room_id: String,
    access_token: Option<String>,
}

/// Send one message to a channel. `event` is one of [`EVENTS`], or `test`.
async fn send(state: &AppState, channel: &Channel, event: &str, detail: &str, resolved: bool) -> Result<(), String> {
    let language = state.settings().default_language;
    let server = state.host().to_string();
    let (title, text) = uwulock_mail::alert_text(event, detail, resolved, &server, language);
    let client = outbound::client()?;
    let request = match channel.kind.as_str() {
        "mail" => {
            if !state.mailer.enabled() {
                return Err("There is no mail server set up.".into());
            }
            let admins = state.store.admin_addresses().await.map_err(|error| error.to_string())?;
            for (email, language) in admins {
                let mail = Mail::AdminAlert {
                    event: event.to_string(),
                    detail: detail.to_string(),
                    resolved,
                    server: server.clone(),
                };
                state
                    .mailer
                    .send(&email, &mail, Language::from_code(&language))
                    .await
                    .map_err(|error| error.to_string())?;
            }
            return Ok(());
        }
        "ntfy" => {
            let config: NtfyConfig = serde_json::from_str(&channel.config).map_err(|error| error.to_string())?;
            let tags = if resolved {
                "white_check_mark"
            } else if event == "test" {
                "wave"
            } else {
                "warning"
            };
            let body = json!({
                "topic": config.topic,
                "title": title,
                "message": if text.is_empty() { title.clone() } else { text.clone() },
                "priority": config.priority.unwrap_or(3),
                "tags": [tags],
            });
            let mut request = client.post(&config.url).json(&body);
            if let Some(token) = config.token.filter(|token| !token.is_empty()) {
                request = request.bearer_auth(token);
            }
            request
        }
        "gotify" => {
            let config: GotifyConfig = serde_json::from_str(&channel.config).map_err(|error| error.to_string())?;
            let body = json!({ "title": title, "message": text, "priority": config.priority.unwrap_or(5) });
            client
                .post(format!("{}/message", config.url))
                .header("X-Gotify-Key", config.token.unwrap_or_default())
                .json(&body)
        }
        "matrix" => {
            let config: MatrixConfig = serde_json::from_str(&channel.config).map_err(|error| error.to_string())?;
            let body = if text.is_empty() { title.clone() } else { format!("{title}\n\n{text}") };
            let url = format!(
                "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
                config.homeserver,
                encode(&config.room_id),
                uuid::Uuid::new_v4()
            );
            client
                .put(url)
                .bearer_auth(config.access_token.unwrap_or_default())
                .json(&json!({ "msgtype": "m.text", "body": body }))
        }
        other => return Err(format!("{other} is no kind of channel this server knows.")),
    };
    let response = request.send().await.map_err(|error| outbound::error_text(&error))?;
    if response.status().is_success() { Ok(()) } else { Err(outbound::refused(response).await) }
}

/// A path segment, percent-encoded.
fn encode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (byte as char).to_string(),
            other => format!("%{other:02X}"),
        })
        .collect()
}

// ── The admin portal ──────────────────────────────────────

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/admin/notifications", get(list).post(create))
        .route("/uwu/v1/admin/notifications/{id}", put(update).delete(remove))
        .route("/uwu/v1/admin/notifications/{id}/test", post(test))
}

/// A channel as the portal sees it: secrets only as whether there is one.
fn render(state: &AppState, channel: &Channel) -> Value {
    let mut config: Value = serde_json::from_str(&channel.config).unwrap_or_else(|_| json!({}));
    if let Some(config) = config.as_object_mut() {
        for (secret, flag) in [("token", "tokenSet"), ("accessToken", "accessTokenSet")] {
            if let Some(value) = config.remove(secret) {
                config.insert(flag.into(), value.as_str().is_some_and(|text| !text.is_empty()).into());
            } else if matches!(
                (channel.kind.as_str(), secret),
                ("ntfy" | "gotify", "token") | ("matrix", "accessToken")
            ) {
                config.insert(flag.into(), false.into());
            }
        }
    }
    let status = state.alerts.channels.lock().get(&channel.id).map(|entry| {
        json!({
            "lastSuccess": entry.last_success,
            "lastError": entry.last_error.as_ref().map(|(_, error)| error),
            "lastErrorDate": entry.last_error.as_ref().map(|(at, _)| at),
            "queued": entry.queue.len(),
        })
    });
    json!({
        "object": "notificationChannel",
        "id": channel.id,
        "kind": channel.kind,
        "name": channel.name,
        "enabled": channel.enabled,
        "events": serde_json::from_str::<Value>(&channel.events).unwrap_or_else(|_| json!([])),
        "config": config,
        "status": status.unwrap_or_else(|| json!({ "lastSuccess": null, "lastError": null, "lastErrorDate": null, "queued": 0 })),
    })
}

/// Failing channels, for the overview.
pub fn failing_channels(state: &AppState) -> Vec<(String, String)> {
    state
        .alerts
        .channels
        .lock()
        .iter()
        .filter_map(|(id, entry)| entry.last_error.as_ref().map(|(_, error)| (id.clone(), error.clone())))
        .collect()
}

async fn list(State(state): State<AppState>, _admin: Admin) -> ApiResult<Json<Value>> {
    let channels = state.store.channels().await?;
    Ok(Json(json!({
        "object": "notificationChannels",
        "channels": channels.iter().map(|channel| render(&state, channel)).collect::<Vec<_>>(),
        "events": EVENTS,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChannelData {
    kind: String,
    name: String,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    events: Vec<String>,
    #[serde(default)]
    config: Value,
}

fn yes() -> bool {
    true
}

/// A checked config for `data`, the secrets of `old` kept where the target stayed the same.
fn checked(data: &ChannelData, old: Option<&Channel>) -> ApiResult<String> {
    let bad = |message: String| ApiError::bad(message);
    let name = data.name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(ApiError::bad("A channel needs a name of up to 64 characters."));
    }
    if let Some(event) = data.events.iter().find(|event| !EVENTS.contains(&event.as_str())) {
        return Err(ApiError::bad(format!("{event} is no event this server knows.")));
    }
    let old_config = old.filter(|old| old.kind == data.kind).map(|old| old.config.clone()).unwrap_or_default();
    let secret = |given: Option<String>, old: Option<String>, same_target: bool| -> Option<String> {
        match given.map(|given| given.trim().to_string()) {
            Some(given) if !given.is_empty() => Some(given),
            _ if same_target => old.filter(|old| !old.is_empty()),
            _ => None,
        }
    };
    let config = match data.kind.as_str() {
        "mail" => json!({}),
        "ntfy" => {
            let given: NtfyConfig =
                serde_json::from_value(data.config.clone()).map_err(|error| bad(error.to_string()))?;
            let url = outbound::checked_url(&given.url, "ntfy").map_err(bad)?;
            let topic = given.topic.trim().to_string();
            if topic.is_empty()
                || topic.len() > 64
                || !topic.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(ApiError::bad("An ntfy topic is 1 to 64 letters, digits, - and _."));
            }
            let old: NtfyConfig = serde_json::from_str(&old_config).unwrap_or_default();
            let same = old.url == url && old.topic == topic;
            let priority = given.priority.unwrap_or(3);
            if !(1..=5).contains(&priority) {
                return Err(ApiError::bad("An ntfy priority is from 1 to 5."));
            }
            serde_json::to_value(NtfyConfig {
                url,
                topic,
                token: secret(given.token, old.token, same),
                priority: Some(priority),
            })
            .expect("config serializes")
        }
        "gotify" => {
            let given: GotifyConfig =
                serde_json::from_value(data.config.clone()).map_err(|error| bad(error.to_string()))?;
            let url = outbound::checked_url(&given.url, "Gotify").map_err(bad)?;
            let old: GotifyConfig = serde_json::from_str(&old_config).unwrap_or_default();
            let token = secret(given.token, old.token, old.url == url)
                .ok_or_else(|| ApiError::bad("Gotify needs the application's token."))?;
            let priority = given.priority.unwrap_or(5);
            if priority > 10 {
                return Err(ApiError::bad("A Gotify priority is from 0 to 10."));
            }
            serde_json::to_value(GotifyConfig { url, token: Some(token), priority: Some(priority) })
                .expect("config serializes")
        }
        "matrix" => {
            let given: MatrixConfig =
                serde_json::from_value(data.config.clone()).map_err(|error| bad(error.to_string()))?;
            let homeserver = outbound::checked_url(&given.homeserver, "Matrix").map_err(bad)?;
            let room_id = given.room_id.trim().to_string();
            if !room_id.starts_with('!') || !room_id.contains(':') || room_id.len() > 255 {
                return Err(ApiError::bad("A Matrix room id looks like !abc:example.org."));
            }
            let old: MatrixConfig = serde_json::from_str(&old_config).unwrap_or_default();
            let access_token = secret(given.access_token, old.access_token, old.homeserver == homeserver)
                .ok_or_else(|| ApiError::bad("Matrix needs the access token of the account that writes."))?;
            serde_json::to_value(MatrixConfig { homeserver, room_id, access_token: Some(access_token) })
                .expect("config serializes")
        }
        _ => return Err(ApiError::bad("A channel is mail, ntfy, gotify or matrix.")),
    };
    Ok(config.to_string())
}

async fn create(State(state): State<AppState>, admin: Admin, Json(data): Json<ChannelData>) -> ApiResult<Json<Value>> {
    let config = checked(&data, None)?;
    let channel = Channel {
        id: uuid::Uuid::new_v4().to_string(),
        kind: data.kind.clone(),
        name: data.name.trim().to_string(),
        enabled: data.enabled,
        events: serde_json::to_string(&data.events).expect("events serialize"),
        config,
        created: String::new(),
    };
    state.store.put_channel(channel.clone()).await?;
    crate::admin::record(&state, &admin, format!("added the notification channel {} ({})", channel.name, channel.kind))
        .await;
    let saved = state.store.channel(&channel.id).await?.ok_or_else(|| ApiError::internal("the channel is gone"))?;
    Ok(Json(render(&state, &saved)))
}

async fn update(
    State(state): State<AppState>,
    admin: Admin,
    Path(id): Path<String>,
    Json(data): Json<ChannelData>,
) -> ApiResult<Json<Value>> {
    let old = state.store.channel(&id).await?.ok_or_else(|| ApiError::not_found("No such channel."))?;
    let config = checked(&data, Some(&old))?;
    let channel = Channel {
        kind: data.kind.clone(),
        name: data.name.trim().to_string(),
        enabled: data.enabled,
        events: serde_json::to_string(&data.events).expect("events serialize"),
        config,
        ..old
    };
    state.store.put_channel(channel.clone()).await?;
    crate::admin::record(&state, &admin, format!("changed the notification channel {}", channel.name)).await;
    Ok(Json(render(&state, &channel)))
}

async fn remove(State(state): State<AppState>, admin: Admin, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let old = state.store.channel(&id).await?.ok_or_else(|| ApiError::not_found("No such channel."))?;
    state.store.delete_channel(&id).await?;
    state.alerts.channels.lock().remove(&id);
    crate::admin::record(&state, &admin, format!("removed the notification channel {}", old.name)).await;
    Ok(StatusCode::OK)
}

async fn test(State(state): State<AppState>, admin: Admin, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let channel = state.store.channel(&id).await?.ok_or_else(|| ApiError::not_found("No such channel."))?;
    let language = Language::from_code(&admin.0.user.language);
    let detail = match language {
        Language::De => "Wenn das ankommt, erreichen dich die Benachrichtigungen deines UwULock Servers hier.",
        Language::En => "If this arrives, your UwULock Server's notifications reach you here.",
    };
    send(&state, &channel, "test", detail, false)
        .await
        .map_err(|error| ApiError::upstream(format!("{} did not take the message: {error}", channel.name)))?;
    Ok(Json(json!({ "object": "notificationTest", "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    /// A server on this machine that answers everything with 200 (or `status`) and hands on what
    /// it was sent: method, path, headers and body.
    async fn fake(
        status: u16,
    ) -> (String, tokio::sync::mpsc::UnboundedReceiver<(String, String, axum::http::HeaderMap, Value)>) {
        let (tell, told) = tokio::sync::mpsc::unbounded_channel();
        let app = axum::Router::new().fallback(
            move |method: axum::http::Method, uri: axum::http::Uri, headers: axum::http::HeaderMap, body: String| {
                let tell = tell.clone();
                async move {
                    let _ = tell.send((
                        method.to_string(),
                        uri.path().to_string(),
                        headers,
                        serde_json::from_str(&body).unwrap_or(Value::Null),
                    ));
                    StatusCode::from_u16(status).unwrap()
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), told)
    }

    async fn admin(server: &TestServer) -> Account {
        let token = server.invite("admin@example.com", true).await;
        server
            .call("POST", "/identity/accounts/register/finish", None, register_body("admin@example.com", &token))
            .await;
        server.login("admin@example.com", "admin-device").await
    }

    #[tokio::test]
    async fn channels_keep_their_secrets_and_the_test_reaches_them() {
        let server = TestServer::new().await;
        let admin = admin(&server).await;
        let (ntfy, mut ntfy_told) = fake(200).await;
        let body = json!({"kind": "ntfy", "name": "Phone", "events": ["backupFailed"],
            "config": {"url": ntfy, "topic": "uwulock", "token": "tk_secret", "priority": 4}});
        let created =
            json(server.call("POST", "/uwu/v1/admin/notifications", Some(&admin.token), body.clone()).await).await;
        assert_eq!(created["config"]["tokenSet"], true);
        assert!(!created.to_string().contains("tk_secret"), "the token never comes back");
        let id = created["id"].as_str().unwrap().to_string();

        let test =
            server.call("POST", &format!("/uwu/v1/admin/notifications/{id}/test"), Some(&admin.token), json!({})).await;
        assert_eq!(test.status(), StatusCode::OK);
        let (method, path, headers, sent) = ntfy_told.recv().await.unwrap();
        assert_eq!((method.as_str(), path.as_str()), ("POST", "/"));
        assert_eq!(headers["authorization"], "Bearer tk_secret");
        assert_eq!(sent["topic"], "uwulock");
        assert_eq!(sent["priority"], 4);

        // Saved without the token: kept for the same server and topic, not for another.
        let mut again = body.clone();
        again["config"]["token"] = Value::Null;
        let path = format!("/uwu/v1/admin/notifications/{id}");
        let kept = json(server.call("PUT", &path, Some(&admin.token), again.clone()).await).await;
        assert_eq!(kept["config"]["tokenSet"], true);
        again["config"]["url"] = json!("http://198.51.100.1:9");
        let moved = json(server.call("PUT", &path, Some(&admin.token), again).await).await;
        assert_eq!(moved["config"]["tokenSet"], false, "the token does not go to another server");

        let list = json(server.get_as(&admin.token, "/uwu/v1/admin/notifications").await).await;
        assert_eq!(list["channels"].as_array().unwrap().len(), 2, "mail, and the new one");
        assert_eq!(list["events"].as_array().unwrap().len(), EVENTS.len());
        let wrong = json!({"kind": "gotify", "name": "x", "config": {"url": "ftp://gotify.example.com", "token": "t"}});
        let refused = server.call("POST", "/uwu/v1/admin/notifications", Some(&admin.token), wrong).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(server.call("DELETE", &path, Some(&admin.token), json!({})).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_failing_test_says_why() {
        let server = TestServer::new().await;
        let admin = admin(&server).await;
        let (gotify, _told) = fake(401).await;
        let body = json!({"kind": "gotify", "name": "Gotify", "config": {"url": gotify, "token": "app"}});
        let created = json(server.call("POST", "/uwu/v1/admin/notifications", Some(&admin.token), body).await).await;
        let id = created["id"].as_str().unwrap();
        let test =
            server.call("POST", &format!("/uwu/v1/admin/notifications/{id}/test"), Some(&admin.token), json!({})).await;
        assert_eq!(test.status(), StatusCode::BAD_GATEWAY);
        let error = json(test).await;
        assert_eq!(error["code"], "upstream");
        assert!(error["message"].as_str().unwrap().contains("401"), "{error}");
    }

    #[tokio::test]
    async fn an_event_goes_out_once_and_its_end_too() {
        let server = TestServer::new().await;
        let admin = admin(&server).await;
        let (gotify, mut gotify_told) = fake(200).await;
        let (matrix, mut matrix_told) = fake(200).await;
        for body in [
            json!({"kind": "gotify", "name": "Gotify", "events": ["backupFailed"], "config": {"url": gotify, "token": "app"}}),
            json!({"kind": "matrix", "name": "Matrix", "events": ["backupFailed"],
                "config": {"homeserver": matrix, "roomId": "!room:example.org", "accessToken": "syt_x"}}),
        ] {
            server.call("POST", "/uwu/v1/admin/notifications", Some(&admin.token), body).await;
        }
        server.state.alerts.report("backupFailed", Some(("error", Detail::new("Platte voll", "disk full"))));
        tick(&server.state).await;
        let (_, path, headers, sent) = gotify_told.recv().await.unwrap();
        assert_eq!(path, "/message");
        assert_eq!(headers["x-gotify-key"], "app");
        assert!(sent["title"].as_str().unwrap().contains("Das Backup ist fehlgeschlagen"), "{sent}");
        assert_eq!(sent["message"], "Platte voll", "in the server's language");
        let (method, path, headers, sent) = matrix_told.recv().await.unwrap();
        assert_eq!(method, "PUT");
        assert!(path.starts_with("/_matrix/client/v3/rooms/%21room%3Aexample.org/send/m.room.message/"), "{path}");
        assert_eq!(headers["authorization"], "Bearer syt_x");
        assert_eq!(sent["msgtype"], "m.text");
        // The admin mail channel wants it too.
        server.wait_for_mail(|mail| mail.to == "admin@example.com" && mail.subject.contains("Backup")).await;

        let overview = json(server.get_as(&admin.token, "/uwu/v1/admin/overview").await).await;
        let alerts = overview["alerts"].as_array().unwrap();
        assert!(
            alerts.iter().any(|alert| alert["kind"] == "backupFailed" && alert["severity"] == "error"),
            "{alerts:?}"
        );

        // Still going on: nothing new.
        tick(&server.state).await;
        assert!(gotify_told.try_recv().is_err());
        // Over: once more, as resolved.
        server.state.alerts.report("backupFailed", None);
        tick(&server.state).await;
        let (_, _, _, sent) = gotify_told.recv().await.unwrap();
        assert!(sent["title"].as_str().unwrap().contains("wieder in Ordnung"), "{sent}");
    }

    #[tokio::test]
    async fn a_channel_that_does_not_answer_is_tried_again_later() {
        let server = TestServer::new().await;
        let admin = admin(&server).await;
        let (ntfy, mut told) = fake(503).await;
        let body =
            json!({"kind": "ntfy", "name": "ntfy", "events": ["backupFailed"], "config": {"url": ntfy, "topic": "t"}});
        let created = json(server.call("POST", "/uwu/v1/admin/notifications", Some(&admin.token), body).await).await;
        server.state.alerts.report("backupFailed", Some(("error", Detail::new("a", "b"))));
        tick(&server.state).await;
        told.recv().await.unwrap();
        tick(&server.state).await;
        assert!(told.try_recv().is_err(), "not again before its time");
        let list = json(server.get_as(&admin.token, "/uwu/v1/admin/notifications").await).await;
        let channel = list["channels"].as_array().unwrap().iter().find(|c| c["id"] == created["id"]).unwrap().clone();
        assert_eq!(channel["status"]["queued"], 1);
        assert!(channel["status"]["lastError"].as_str().unwrap().contains("503"));
        let overview = json(server.get_as(&admin.token, "/uwu/v1/admin/overview").await).await;
        assert_eq!(overview["failingChannels"][0]["id"], created["id"]);
    }
}
