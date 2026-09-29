//! The server's log lines to a Grafana Loki (docs/deployment.md, docs/uwu-api.md §21.7), like
//! UwUMail Server's.
//!
//! Every line is the same JSON the server writes with `UWULOCK_LOG_FORMAT=json`, so one set of
//! queries works whichever way the lines reach Loki. They wait in a bounded queue and go out in
//! batches — after a second, or at a mebibyte — through Loki's push API. Loki being away never
//! holds a request up: past the limit the oldest lines are dropped and counted.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

/// Lines waiting for Loki. Minutes of a busy server; after that the oldest go.
const QUEUE_LIMIT: usize = 10_000;
/// A batch goes out after this long, or once it holds [`BATCH_BYTES`].
const BATCH_DELAY: Duration = Duration::from_secs(1);
const BATCH_BYTES: usize = 1024 * 1024;
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// `loki` in the settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LokiSettings {
    pub enabled: bool,
    /// Loki's address, e.g. `http://192.0.2.20:3100`. `/loki/api/v1/push` is added when it has no
    /// path of its own.
    pub url: String,
    /// `X-Scope-OrgID`, for a Loki with more than one tenant.
    pub tenant: Option<String>,
    /// Basic authentication, e.g. for Grafana Cloud or a proxy in front of Loki.
    pub username: Option<String>,
    /// Never shown to the portal: `passwordSet` says whether there is one.
    pub password: Option<String>,
    /// The streams' labels. Never anything of a user.
    pub labels: BTreeMap<String, String>,
}

impl Default for LokiSettings {
    fn default() -> Self {
        LokiSettings {
            enabled: false,
            url: String::new(),
            tenant: None,
            username: None,
            password: None,
            labels: BTreeMap::from([("job".to_string(), "uwulock".to_string())]),
        }
    }
}

impl LokiSettings {
    pub fn check(&self) -> Result<(), String> {
        if self.enabled || !self.url.trim().is_empty() {
            self.target()?;
        }
        Ok(())
    }

    /// Where and how to push, checked.
    pub fn target(&self) -> Result<Target, String> {
        let url = push_url(&self.url)?;
        for (name, value) in &self.labels {
            let plain = name.chars().next().is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !name.starts_with("__");
            if !plain || value.trim().is_empty() || value.len() > 128 {
                return Err(format!("The Loki label {name}={value} is not a plain name with a value."));
            }
            if name == "level" {
                return Err("The Loki label level is set by the server itself.".into());
            }
        }
        let username = self.username.as_deref().map(str::trim).filter(|name| !name.is_empty());
        let password = self.password.as_deref().filter(|password| !password.is_empty());
        if password.is_some() && username.is_none() {
            return Err("A Loki password needs a username.".into());
        }
        Ok(Target {
            url,
            username: username.map(str::to_string),
            password: password.map(str::to_string),
            tenant: self.tenant.as_deref().map(str::trim).filter(|tenant| !tenant.is_empty()).map(str::to_string),
            labels: self.labels.clone(),
        })
    }
}

/// The push address for what someone typed: the base address of a Loki, or already the whole
/// path.
fn push_url(typed: &str) -> Result<String, String> {
    let checked = crate::outbound::checked_url(typed, "Loki")?;
    let url = reqwest::Url::parse(&checked).map_err(|error| error.to_string())?;
    if url.query().is_some() {
        return Err("Loki: the address cannot have a query.".into());
    }
    Ok(if url.path().trim_end_matches('/').is_empty() { format!("{checked}/loki/api/v1/push") } else { checked })
}

/// Where the lines go, checked. Never printed with its password.
#[derive(Clone, PartialEq, Eq)]
pub struct Target {
    url: String,
    username: Option<String>,
    password: Option<String>,
    tenant: Option<String>,
    labels: BTreeMap<String, String>,
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Target").field("url", &self.url).finish_non_exhaustive()
    }
}

/// How pushing goes, for the portal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LokiStatus {
    pub enabled: bool,
    pub queued: usize,
    /// Lines Loki took since the start.
    pub sent: u64,
    /// Lines dropped because Loki was away too long, or refused them.
    pub dropped: u64,
    pub last_success: Option<String>,
    /// What went wrong with the last push, while it still goes wrong.
    pub error: Option<String>,
}

/// One line: when (nanoseconds since 1970), its level, and the JSON.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub nanos: u128,
    pub level: &'static str,
    pub line: String,
}

#[derive(Default)]
struct Inner {
    target: Option<Arc<Target>>,
    queue: VecDeque<Entry>,
    bytes: usize,
    status: LokiStatus,
}

#[derive(Default)]
pub struct Loki {
    inner: Mutex<Inner>,
    /// Whether lines are wanted at all, read without a lock on every log line.
    on: AtomicBool,
    arrived: Notify,
    full: Notify,
}

impl Loki {
    /// Push to `settings` from now on, or stop. Switching off forgets what was waiting.
    pub fn configure(&self, settings: &LokiSettings) {
        let target = if settings.enabled {
            match settings.target() {
                Ok(target) => Some(target),
                Err(error) => {
                    tracing::warn!(%error, "the Loki settings do not work; no lines go to Loki");
                    None
                }
            }
        } else {
            None
        };
        let mut inner = self.inner.lock();
        if inner.target.as_deref() == target.as_ref() {
            return;
        }
        inner.status.enabled = target.is_some();
        inner.status.error = None;
        if target.is_none() {
            inner.queue.clear();
            inner.bytes = 0;
        }
        inner.target = target.map(Arc::new);
        self.on.store(inner.target.is_some(), Ordering::Relaxed);
    }

    pub fn wanted(&self) -> bool {
        self.on.load(Ordering::Relaxed)
    }

    pub fn status(&self) -> LokiStatus {
        let inner = self.inner.lock();
        LokiStatus { queued: inner.queue.len(), ..inner.status.clone() }
    }

    /// Takes a line. Never waits for anything but a short lock.
    pub(crate) fn offer(&self, entry: Entry) {
        let mut inner = self.inner.lock();
        if inner.target.is_none() {
            return;
        }
        if inner.queue.len() >= QUEUE_LIMIT
            && let Some(dropped) = inner.queue.pop_front()
        {
            inner.bytes -= dropped.line.len();
            inner.status.dropped += 1;
        }
        inner.bytes += entry.line.len();
        inner.queue.push_back(entry);
        let full = inner.bytes >= BATCH_BYTES;
        drop(inner);
        self.arrived.notify_one();
        if full {
            self.full.notify_one();
        }
    }

    /// Sends what waits, for as long as the server runs.
    pub fn spawn(self: &Arc<Self>) {
        let loki = self.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            loop {
                loki.arrived.notified().await;
                tokio::select! {
                    _ = tokio::time::sleep(BATCH_DELAY) => {}
                    _ = loki.full.notified() => {}
                }
                loop {
                    match loki.send_batch().await {
                        Sent::Nothing => break,
                        Sent::Some => backoff = Duration::from_secs(1),
                        Sent::Failed => {
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(MAX_BACKOFF);
                        }
                    }
                }
            }
        });
    }

    /// Push up to a mebibyte of what waits.
    pub(crate) async fn send_batch(&self) -> Sent {
        let (target, batch) = {
            let mut inner = self.inner.lock();
            let Some(target) = inner.target.clone() else { return Sent::Nothing };
            let mut bytes = 0;
            let mut take = 0;
            for entry in &inner.queue {
                if take > 0 && bytes + entry.line.len() > BATCH_BYTES {
                    break;
                }
                bytes += entry.line.len();
                take += 1;
            }
            if take == 0 {
                return Sent::Nothing;
            }
            inner.bytes -= bytes;
            (target, inner.queue.drain(..take).collect::<Vec<_>>())
        };
        let result = push(&target, &batch).await;
        let mut inner = self.inner.lock();
        // Switched over or off meanwhile: what this did no longer matters.
        if !inner.target.as_ref().is_some_and(|current| Arc::ptr_eq(current, &target)) {
            return Sent::Some;
        }
        match result {
            Ok(()) => {
                inner.status.sent += batch.len() as u64;
                inner.status.last_success = Some(uwulock_store::clock::now());
                inner.status.error = None;
                Sent::Some
            }
            Err((message, retry)) => {
                inner.status.error = Some(message);
                if retry {
                    for entry in batch.into_iter().rev() {
                        if inner.queue.len() >= QUEUE_LIMIT {
                            inner.status.dropped += 1;
                        } else {
                            inner.bytes += entry.line.len();
                            inner.queue.push_front(entry);
                        }
                    }
                    Sent::Failed
                } else {
                    inner.status.dropped += batch.len() as u64;
                    Sent::Some
                }
            }
        }
    }

    /// One line to `settings` right away, to try the address and the credentials.
    pub async fn test(&self, settings: &LokiSettings) -> Result<(), String> {
        let target = settings.target()?;
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let line = json_line(
            &uwulock_store::clock::now(),
            "info",
            "uwulock_api::loki",
            "a test line from the UwULock admin portal",
            serde_json::Map::new(),
        );
        push(&target, &[Entry { nanos, level: "info", line }]).await.map_err(|(message, _)| message)
    }
}

pub(crate) enum Sent {
    Nothing,
    Some,
    Failed,
}

/// A log line as `UWULOCK_LOG_FORMAT=json` writes it (tracing-subscriber's JSON format).
pub(crate) fn json_line(
    time: &str,
    level: &str,
    target: &str,
    message: &str,
    mut fields: serde_json::Map<String, Value>,
) -> String {
    let mut all = serde_json::Map::new();
    all.insert("message".into(), Value::String(message.to_string()));
    all.append(&mut fields);
    json!({ "timestamp": time, "level": level.to_ascii_uppercase(), "fields": all, "target": target }).to_string()
}

/// One stream per level; the error says whether to try again.
async fn push(target: &Target, entries: &[Entry]) -> Result<(), (String, bool)> {
    let mut streams: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    for entry in entries {
        streams.entry(entry.level).or_default().push(json!([entry.nanos.to_string(), entry.line]));
    }
    let streams: Vec<Value> = streams
        .into_iter()
        .map(|(level, values)| {
            let mut labels = serde_json::Map::new();
            for (name, value) in &target.labels {
                labels.insert(name.clone(), json!(value));
            }
            labels.insert("level".into(), json!(level));
            json!({ "stream": labels, "values": values })
        })
        .collect();
    let client = crate::outbound::client().map_err(|error| (error, false))?;
    let mut request = client.post(&target.url).json(&json!({ "streams": streams }));
    if let Some(username) = &target.username {
        request = request.basic_auth(username, target.password.as_deref());
    }
    if let Some(tenant) = &target.tenant {
        request = request.header("X-Scope-OrgID", tenant);
    }
    let response = request.send().await.map_err(|error| (crate::outbound::error_text(&error), true))?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    // Too many, or Loki itself in trouble: later. Anything else would be refused again.
    let retry = status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
    Err((format!("Loki {}", crate::outbound::refused(response).await), retry))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(url: &str) -> LokiSettings {
        LokiSettings { enabled: true, url: url.into(), ..LokiSettings::default() }
    }

    fn entry(level: &'static str, message: &str) -> Entry {
        Entry {
            nanos: 1_700_000_000_123_000_000,
            level,
            line: json_line(
                "2026-09-28T12:00:00.000000Z",
                level,
                "uwulock_api::identity",
                message,
                serde_json::Map::new(),
            ),
        }
    }

    #[test]
    fn addresses_get_the_push_path_when_they_have_none() {
        assert_eq!(push_url("http://192.0.2.20:3100").unwrap(), "http://192.0.2.20:3100/loki/api/v1/push");
        assert_eq!(push_url("https://logs.example.net/").unwrap(), "https://logs.example.net/loki/api/v1/push");
        assert_eq!(
            push_url("https://proxy.example.net/loki/api/v1/push").unwrap(),
            "https://proxy.example.net/loki/api/v1/push"
        );
        assert!(push_url("loki:3100").is_err());
        assert!(push_url("https://logs.example.net/?x=1").is_err());
        let mut labels = settings("http://192.0.2.20:3100");
        labels.labels.insert("level".into(), "x".into());
        assert!(labels.check().is_err());
        labels.labels = BTreeMap::from([("1x".to_string(), "y".to_string())]);
        assert!(labels.check().is_err());
        assert!(LokiSettings { password: Some("p".into()), ..settings("http://192.0.2.20:3100") }.check().is_err());
        assert!(
            !format!(
                "{:?}",
                LokiSettings {
                    username: Some("u".into()),
                    password: Some("secret".into()),
                    ..settings("http://192.0.2.20:3100")
                }
                .target()
                .unwrap()
            )
            .contains("secret")
        );
    }

    #[test]
    fn the_queue_stays_bounded_and_off_forgets_it() {
        let loki = Loki::default();
        loki.offer(entry("info", "before it was on"));
        assert_eq!(loki.status().queued, 0);
        loki.configure(&settings("http://192.0.2.20:3100"));
        assert!(loki.wanted());
        for _ in 0..QUEUE_LIMIT + 5 {
            loki.offer(entry("info", "a lot"));
        }
        let status = loki.status();
        assert_eq!((status.queued, status.dropped), (QUEUE_LIMIT, 5));
        loki.configure(&LokiSettings::default());
        assert!(!loki.wanted());
        assert_eq!(loki.status().queued, 0);
    }

    /// A Loki on this machine: answers each push with the next status and hands on the headers and
    /// the body.
    async fn fake(answers: Vec<u16>) -> (String, tokio::sync::mpsc::UnboundedReceiver<(axum::http::HeaderMap, Value)>) {
        let (tell, told) = tokio::sync::mpsc::unbounded_channel();
        let answers = Arc::new(Mutex::new(VecDeque::from(answers)));
        let app = axum::Router::new().route(
            "/loki/api/v1/push",
            axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
                let (tell, answers) = (tell.clone(), answers.clone());
                async move {
                    let _ = tell.send((headers, serde_json::from_str(&body).unwrap_or(Value::Null)));
                    axum::http::StatusCode::from_u16(answers.lock().pop_front().unwrap_or(204)).unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), told)
    }

    #[tokio::test]
    async fn lines_go_out_as_json_with_labels_and_come_back_after_a_failure() {
        let (url, mut told) = fake(vec![503, 204]).await;
        let loki = Loki::default();
        loki.configure(&LokiSettings {
            username: Some("u".into()),
            password: Some("p".into()),
            tenant: Some("home".into()),
            ..settings(&url)
        });
        loki.offer(entry("warn", "login refused"));
        loki.offer(entry("info", "account registered"));
        assert!(matches!(loki.send_batch().await, Sent::Failed));
        let (headers, _) = told.recv().await.unwrap();
        assert_eq!(headers["authorization"], "Basic dTpw");
        assert_eq!(headers["x-scope-orgid"], "home");
        assert_eq!(loki.status().queued, 2, "back in the queue");
        assert!(loki.status().error.unwrap().contains("503"));

        assert!(matches!(loki.send_batch().await, Sent::Some));
        let (_, body) = told.recv().await.unwrap();
        let streams = body["streams"].as_array().unwrap();
        assert_eq!(streams.len(), 2, "one stream per level");
        assert_eq!(streams[0]["stream"], json!({"job": "uwulock", "level": "info"}));
        assert_eq!(streams[1]["values"][0][0], "1700000000123000000");
        let line: Value = serde_json::from_str(streams[1]["values"][0][1].as_str().unwrap()).unwrap();
        assert_eq!(
            line,
            json!({"timestamp": "2026-09-28T12:00:00.000000Z", "level": "WARN",
                "fields": {"message": "login refused"}, "target": "uwulock_api::identity"})
        );
        let status = loki.status();
        assert_eq!((status.sent, status.queued, status.error), (2, 0, None));
        assert!(matches!(loki.send_batch().await, Sent::Nothing));
    }

    #[tokio::test]
    async fn a_refused_push_is_dropped_and_the_test_says_why() {
        let (url, _told) = fake(vec![401, 400]).await;
        let loki = Loki::default();
        let error = loki.test(&settings(&url)).await.unwrap_err();
        assert!(error.contains("401"), "{error}");
        loki.configure(&settings(&url));
        loki.offer(entry("info", "x"));
        assert!(matches!(loki.send_batch().await, Sent::Some), "not tried again");
        assert_eq!((loki.status().dropped, loki.status().queued), (1, 0));
    }

    #[tokio::test]
    async fn the_portal_switches_it_on_tests_it_and_never_sees_the_password() {
        use crate::test_support::*;
        let (url, mut told) = fake(vec![204, 204]).await;
        let server = TestServer::new().await;
        let token = server.invite("admin@example.com", true).await;
        server
            .call("POST", "/identity/accounts/register/finish", None, register_body("admin@example.com", &token))
            .await;
        let admin = server.login("admin@example.com", "admin-device").await;
        let mut settings = json(server.get_as(&admin.token, "/uwu/v1/admin/settings").await).await;
        settings["loki"] = json!({"enabled": true, "url": url, "username": "grafana", "password": "glc_secret",
            "labels": {"job": "uwulock", "env": "home"}});
        let saved =
            json(server.call("PUT", "/uwu/v1/admin/settings", Some(&admin.token), settings.clone()).await).await;
        assert_eq!(saved["loki"]["passwordSet"], true);
        assert!(!saved.to_string().contains("glc_secret"));
        assert!(server.state.logs.loki().wanted());

        // Tried with what is typed, the password left out: the stored one, for the same Loki.
        let mut typed = saved["loki"].clone();
        typed["password"] = Value::Null;
        let tested = server.call("POST", "/uwu/v1/admin/settings/test-loki", Some(&admin.token), typed).await;
        assert_eq!(tested.status(), axum::http::StatusCode::OK);
        let (headers, body) = told.recv().await.unwrap();
        assert_eq!(headers["authorization"], "Basic Z3JhZmFuYTpnbGNfc2VjcmV0");
        assert_eq!(body["streams"][0]["stream"]["env"], "home");

        let mut off = saved.clone();
        off["loki"]["enabled"] = json!(false);
        server.call("PUT", "/uwu/v1/admin/settings", Some(&admin.token), off).await;
        assert!(!server.state.logs.loki().wanted());
        let stored = crate::Settings::load(&server.state.store, &crate::Settings::default(), &server.state.secret)
            .await
            .unwrap();
        assert_eq!(stored.loki.password.as_deref(), Some("glc_secret"), "kept for later");
    }
}
