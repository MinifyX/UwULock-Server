//! `GET /metrics` for Prometheus (docs/metrics.md, docs/uwu-api.md §22), in the text exposition
//! format, written by hand.
//!
//! Off unless an admin switches it on. Then either on the public address with a bearer token —
//! compared in constant time against the SHA-256 the settings keep — or only on an address of
//! its own (`metrics.listen`, e.g. `127.0.0.1:9100`), without a token, and 404 on the public one.
//!
//! No label ever carries an address, a name, a host or an id: routes are their templates
//! (`/api/ciphers/{id}`), everything else a small fixed set of words.

use crate::AppState;
use crate::auth::{ClientIp, constant_time_eq, sha256};
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Instant;

/// The shortest token accepted, so it cannot be guessed within the rate limits.
pub const MIN_TOKEN_CHARS: usize = 16;

/// `metrics` in the settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MetricsSettings {
    pub enabled: bool,
    /// Hex SHA-256 of the token scrapers send. Never shown; the portal sees `tokenSet`.
    pub token_hash: Option<String>,
    /// A new token, write-only: hashed on save, never stored as it is. Empty removes the token.
    #[serde(skip_serializing)]
    pub token: Option<String>,
    /// Serve `/metrics` only on this address of its own, like `127.0.0.1:9100`.
    pub listen: Option<String>,
}

impl MetricsSettings {
    pub fn check(&self) -> Result<(), String> {
        if let Some(listen) = &self.listen
            && listen.trim().parse::<std::net::SocketAddr>().is_err()
        {
            return Err(format!("The metrics address {listen} is not an address with a port, like 127.0.0.1:9100."));
        }
        if self.enabled && self.token_hash.is_none() && self.listen.is_none() {
            return Err("Metrics need a token or an address of their own; otherwise anybody could read them.".into());
        }
        Ok(())
    }

    /// Takes a new token that came with a save into its hash; none keeps the one there is.
    pub fn take_token(&mut self, current: &MetricsSettings) -> Result<(), String> {
        match self.token.take().map(|token| token.trim().to_string()) {
            None => self.token_hash = current.token_hash.clone(),
            Some(token) if token.is_empty() => self.token_hash = None,
            Some(token) if token.chars().count() < MIN_TOKEN_CHARS => {
                return Err(format!("The metrics token needs at least {MIN_TOKEN_CHARS} characters."));
            }
            Some(token) => self.token_hash = Some(hex(&sha256(token.as_bytes()))),
        }
        self.listen = self.listen.take().map(|listen| listen.trim().to_string()).filter(|listen| !listen.is_empty());
        Ok(())
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Request durations, in seconds.
const BUCKETS: [f64; 11] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

#[derive(Debug, Clone, Default)]
struct Histogram {
    counts: [u64; BUCKETS.len()],
    count: u64,
    sum: f64,
}

impl Histogram {
    fn observe(&mut self, seconds: f64) {
        for (bucket, count) in BUCKETS.iter().zip(self.counts.iter_mut()) {
            if seconds <= *bucket {
                *count += 1;
            }
        }
        self.count += 1;
        self.sum += seconds;
    }
}

/// What the server counts while it runs. Starts at 0 with every start, which `rate()` knows.
#[derive(Default)]
pub struct Metrics {
    requests: Mutex<BTreeMap<(String, String, u16), u64>>,
    durations: Mutex<BTreeMap<(String, String), Histogram>>,
    logins: Mutex<BTreeMap<(&'static str, &'static str), u64>>,
    syncs: Mutex<BTreeMap<&'static str, Histogram>>,
    icon_fetches: Mutex<BTreeMap<&'static str, u64>>,
}

impl Metrics {
    fn request(&self, route: &str, method: &str, status: u16, seconds: f64) {
        *self.requests.lock().entry((route.to_string(), method.to_string(), status)).or_default() += 1;
        self.durations.lock().entry((route.to_string(), method.to_string())).or_default().observe(seconds);
    }

    /// A login with `grant` (`password`, `refresh_token`, …) ended as `result` (`success`,
    /// `failure`, `two_factor`).
    pub fn login(&self, grant: &'static str, result: &'static str) {
        *self.logins.lock().entry((grant, result)).or_default() += 1;
    }

    /// A website's icon was fetched: `found`, `none`, `refused` or `error`.
    pub fn icon_fetch(&self, result: &'static str) {
        *self.icon_fetches.lock().entry(result).or_default() += 1;
    }

    /// A sync of `kind` (`bitwarden`, `full`, `delta`) took `seconds`.
    pub fn sync(&self, kind: &'static str, seconds: f64) {
        self.syncs.lock().entry(kind).or_default().observe(seconds);
    }
}

/// The middleware that counts every request by its route's template.
pub(crate) async fn track(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let started = Instant::now();
    let route = request.extensions().get::<MatchedPath>().map_or("other", MatchedPath::as_str).to_string();
    let method = request.method().as_str().to_string();
    let response = next.run(request).await;
    let seconds = started.elapsed().as_secs_f64();
    if route == "/api/sync" && response.status().is_success() {
        state.metrics.sync("bitwarden", seconds);
    }
    state.metrics.request(&route, &method, response.status().as_u16(), seconds);
    response
}

fn plain(status: StatusCode, text: &'static str) -> Response {
    (status, text).into_response()
}

/// `/metrics` on the public address.
pub(crate) async fn public(State(state): State<AppState>, ClientIp(ip): ClientIp, headers: HeaderMap) -> Response {
    let settings = state.settings().metrics;
    if !settings.enabled || settings.listen.is_some() {
        return crate::errors::not_found().await.into_response();
    }
    let Some(hash) = settings.token_hash else { return crate::errors::not_found().await.into_response() };
    let sent = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim().to_string());
    let right =
        sent.as_deref().is_some_and(|sent| constant_time_eq(hex(&sha256(sent.as_bytes())).as_bytes(), hash.as_bytes()));
    if !right {
        // Guessing tokens counts against the address like any anonymous request.
        if sent.is_some() && !state.limits.anonymous.check(ip) {
            return plain(StatusCode::TOO_MANY_REQUESTS, "too many attempts\n");
        }
        let mut response = plain(StatusCode::UNAUTHORIZED, "a bearer token is needed\n");
        response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return response;
    }
    answer(&state).await
}

/// `/metrics` on its own address: no token, whoever reaches the address may read.
pub(crate) async fn separate(State(state): State<AppState>) -> Response {
    let settings = state.settings().metrics;
    if !settings.enabled || settings.listen.is_none() {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    answer(&state).await
}

async fn answer(state: &AppState) -> Response {
    match render(state).await {
        Ok(text) => {
            let mut response = text.into_response();
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"));
            response
        }
        Err(error) => {
            tracing::warn!(%error, "collecting the metrics failed");
            plain(StatusCode::INTERNAL_SERVER_ERROR, "collecting the metrics failed\n")
        }
    }
}

/// Writes metric families: help, type, samples.
struct Out(String);

impl Out {
    fn head(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}");
        let _ = writeln!(self.0, "# TYPE {name} {kind}");
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: impl std::fmt::Display) {
        self.0.push_str(name);
        if !labels.is_empty() {
            self.0.push('{');
            for (index, (label, value)) in labels.iter().enumerate() {
                if index > 0 {
                    self.0.push(',');
                }
                let _ = write!(self.0, "{label}=\"{}\"", escape(value));
            }
            self.0.push('}');
        }
        let _ = writeln!(self.0, " {value}");
    }

    fn histogram(&mut self, name: &str, labels: &[(&str, &str)], histogram: &Histogram) {
        for (bucket, count) in BUCKETS.iter().zip(histogram.counts.iter()) {
            let le = bucket.to_string();
            let mut with = labels.to_vec();
            with.push(("le", &le));
            self.sample(&format!("{name}_bucket"), &with, count);
        }
        let mut with = labels.to_vec();
        with.push(("le", "+Inf"));
        self.sample(&format!("{name}_bucket"), &with, histogram.count);
        self.sample(&format!("{name}_sum"), labels, histogram.sum);
        self.sample(&format!("{name}_count"), labels, histogram.count);
    }
}

/// Label values escape backslash, double quote and line feed.
fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// Everything, in the text format.
pub async fn render(state: &AppState) -> Result<String, uwulock_store::StoreError> {
    let (stats, (attachments, sends)) = tokio::try_join!(state.store.stats(), state.store.file_bytes())?;
    let mut out = Out(String::with_capacity(16 * 1024));

    out.head("uwulock_build_info", "gauge", "Always 1; the version that runs.");
    out.sample("uwulock_build_info", &[("version", state.version)], 1);

    out.head("uwulock_http_requests_total", "counter", "Requests answered, by route template, method and status.");
    for ((route, method, status), count) in state.metrics.requests.lock().iter() {
        out.sample(
            "uwulock_http_requests_total",
            &[("route", route), ("method", method), ("status", &status.to_string())],
            count,
        );
    }
    out.head("uwulock_http_request_duration_seconds", "histogram", "How long requests took to answer.");
    for ((route, method), histogram) in state.metrics.durations.lock().iter() {
        out.histogram("uwulock_http_request_duration_seconds", &[("route", route), ("method", method)], histogram);
    }

    out.head("uwulock_logins_total", "counter", "Logins by grant and result.");
    for ((grant, result), count) in state.metrics.logins.lock().iter() {
        out.sample("uwulock_logins_total", &[("grant", grant), ("result", result)], count);
    }
    out.head("uwulock_sync_duration_seconds", "histogram", "How long a sync took.");
    for (kind, histogram) in state.metrics.syncs.lock().iter() {
        out.histogram("uwulock_sync_duration_seconds", &[("kind", kind)], histogram);
    }

    let (signalr, anonymous) = state.hub.connection_counts();
    out.head("uwulock_live_connections", "gauge", "Open live-update connections.");
    out.sample("uwulock_live_connections", &[("channel", "signalr")], signalr);
    out.sample("uwulock_live_connections", &[("channel", "anonymous")], anonymous);

    let relay = state.relay.health();
    out.head("uwulock_push_relay_errors_total", "counter", "Requests the push relay did not take.");
    out.sample("uwulock_push_relay_errors_total", &[], relay.errors);
    let mail = state.mailer.health();
    out.head("uwulock_mail_errors_total", "counter", "Mails the mail server did not take.");
    out.sample("uwulock_mail_errors_total", &[], mail.errors);
    out.head("uwulock_mail_sent_total", "counter", "Mails that went out.");
    out.sample("uwulock_mail_sent_total", &[], mail.sent);

    let database = state.store.path().to_path_buf();
    let size = |path: &std::path::Path| std::fs::metadata(path).map_or(0, |meta| meta.len());
    out.head("uwulock_database_bytes", "gauge", "Size of the database, with its write-ahead log.");
    out.sample("uwulock_database_bytes", &[], size(&database) + size(&uwulock_store::with_suffix(&database, "-wal")));
    out.head("uwulock_files_bytes", "gauge", "Size of the stored files, by kind.");
    out.sample("uwulock_files_bytes", &[("kind", "attachments")], attachments);
    out.sample("uwulock_files_bytes", &[("kind", "sends")], sends);
    out.sample(
        "uwulock_files_bytes",
        &[("kind", "file_requests")],
        state.store.file_request_bytes().await.unwrap_or(0),
    );
    out.sample(
        "uwulock_files_bytes",
        &[("kind", "icons")],
        state.icons.bytes().await as i64 + state.store.own_icon_bytes().await.unwrap_or(0),
    );
    out.head("uwulock_icon_fetches_total", "counter", "Websites' icons fetched, by result.");
    for (result, count) in state.metrics.icon_fetches.lock().iter() {
        out.sample("uwulock_icon_fetches_total", &[("result", result)], count);
    }

    out.head("uwulock_accounts", "gauge", "Accounts.");
    out.sample("uwulock_accounts", &[], stats.users);
    out.head("uwulock_items", "gauge", "Items, those in the trash included.");
    out.sample("uwulock_items", &[], stats.ciphers);

    out.head("uwulock_backup_last_success_timestamp_seconds", "gauge", "When the last backup was written.");
    if let Some(newest) = uwulock_store::backups::newest(&state.config.backups) {
        out.sample("uwulock_backup_last_success_timestamp_seconds", &[("target", "local")], newest);
    }
    if let Some(offsite) = state.alerts.offsite_success() {
        out.sample("uwulock_backup_last_success_timestamp_seconds", &[("target", "offsite")], offsite);
    }

    out.head("uwulock_certificate_expiry_timestamp_seconds", "gauge", "When the certificate clients see expires.");
    if let Some(seen) = state.certificate.read().as_ref().and_then(|seen| seen.expires) {
        out.sample("uwulock_certificate_expiry_timestamp_seconds", &[("domain", "main")], seen);
    }

    let loki = state.logs.loki().status();
    out.head("uwulock_loki_dropped_total", "counter", "Log lines dropped because Loki was away or refused them.");
    out.sample("uwulock_loki_dropped_total", &[], loki.dropped);

    process(&mut out, state);
    Ok(out.0)
}

/// The usual `process_*` metrics, from `/proc` on Linux.
fn process(out: &mut Out, state: &AppState) {
    let started = crate::auth::now_seconds() - state.started.elapsed().as_secs() as i64;
    out.head("process_start_time_seconds", "gauge", "Start time of the process since unix epoch in seconds.");
    out.sample("process_start_time_seconds", &[], started);
    #[cfg(target_os = "linux")]
    {
        // SAFETY: sysconf only reads a configuration value.
        let (ticks, page) = unsafe { (libc::sysconf(libc::_SC_CLK_TCK), libc::sysconf(libc::_SC_PAGESIZE)) };
        if let Ok(stat) = std::fs::read_to_string("/proc/self/stat")
            && let Some((_, rest)) = stat.rsplit_once(')')
        {
            // After the name: state is field 3; utime 14, stime 15, vsize 23, rss 24.
            let fields: Vec<&str> = rest.split_whitespace().collect();
            let field = |n: usize| fields.get(n - 3).and_then(|value| value.parse::<u64>().ok());
            if let (Some(user), Some(system)) = (field(14), field(15))
                && ticks > 0
            {
                out.head("process_cpu_seconds_total", "counter", "Total user and system CPU time spent in seconds.");
                out.sample("process_cpu_seconds_total", &[], (user + system) as f64 / ticks as f64);
            }
            if let Some(virtual_bytes) = field(23) {
                out.head("process_virtual_memory_bytes", "gauge", "Virtual memory size in bytes.");
                out.sample("process_virtual_memory_bytes", &[], virtual_bytes);
            }
            if let Some(pages) = field(24)
                && page > 0
            {
                out.head("process_resident_memory_bytes", "gauge", "Resident memory size in bytes.");
                out.sample("process_resident_memory_bytes", &[], pages * page as u64);
            }
        }
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            out.head("process_open_fds", "gauge", "Number of open file descriptors.");
            out.sample("process_open_fds", &[], entries.count());
        }
        if let Ok(limits) = std::fs::read_to_string("/proc/self/limits")
            && let Some(most) = limits
                .lines()
                .find(|line| line.starts_with("Max open files"))
                .and_then(|line| line.split_whitespace().nth(3))
                .and_then(|value| value.parse::<u64>().ok())
        {
            out.head("process_max_fds", "gauge", "Maximum number of open file descriptors.");
            out.sample("process_max_fds", &[], most);
        }
    }
}

/// Serves `/metrics` on `metrics.listen` while that is set, and moves when it changes. Runs for
/// as long as the server.
pub fn spawn_listener(state: AppState) {
    tokio::spawn(async move {
        let mut bound: Option<(String, tokio::task::JoinHandle<()>)> = None;
        loop {
            let wanted = {
                let metrics = state.settings().metrics;
                metrics.listen.filter(|_| metrics.enabled)
            };
            if bound.as_ref().map(|(address, _)| address) != wanted.as_ref() {
                if let Some((address, task)) = bound.take() {
                    task.abort();
                    tracing::info!(%address, "metrics no longer served on their own address");
                }
                if let Some(address) = wanted {
                    match tokio::net::TcpListener::bind(&address).await {
                        Ok(listener) => {
                            tracing::info!(%address, "metrics served on their own address");
                            let app = axum::Router::new()
                                .route("/metrics", axum::routing::get(separate))
                                .with_state(state.clone());
                            let task = tokio::spawn(async move {
                                if let Err(error) = axum::serve(listener, app).await {
                                    tracing::warn!(%error, "the metrics address stopped");
                                }
                            });
                            bound = Some((address, task));
                        }
                        Err(error) => tracing::warn!(%address, %error, "cannot serve metrics on this address"),
                    }
                }
            }
            state.settings_changed.notified().await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Settings;
    use crate::test_support::*;
    use axum::body::Body;
    use serde_json::json;

    async fn admin(server: &TestServer) -> Account {
        let token = server.invite("admin@example.com", true).await;
        server
            .call("POST", "/identity/accounts/register/finish", None, register_body("admin@example.com", &token))
            .await;
        server.login("admin@example.com", "admin-device").await
    }

    async fn scrape(server: &TestServer, token: Option<&str>) -> axum::http::Response<Body> {
        let mut request = axum::http::Request::get("/metrics");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        server.send(request.body(Body::empty()).unwrap()).await
    }

    #[tokio::test]
    async fn off_until_switched_on_and_then_only_with_the_token() {
        let server = TestServer::new().await;
        assert_eq!(scrape(&server, None).await.status(), StatusCode::NOT_FOUND);
        let admin = admin(&server).await;
        let token = "a-long-token-for-prometheus";
        let mut settings = json(server.get_as(&admin.token, "/uwu/v1/admin/settings").await).await;
        settings["metrics"] = json!({"enabled": true});
        let refused = server.call("PUT", "/uwu/v1/admin/settings", Some(&admin.token), settings.clone()).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "neither a token nor an address");
        settings["metrics"] = json!({"enabled": true, "token": "short"});
        let refused = server.call("PUT", "/uwu/v1/admin/settings", Some(&admin.token), settings.clone()).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "too short");
        settings["metrics"] = json!({"enabled": true, "token": token});
        let saved =
            json(server.call("PUT", "/uwu/v1/admin/settings", Some(&admin.token), settings.clone()).await).await;
        assert_eq!(saved["metrics"], json!({"enabled": true, "tokenSet": true, "listen": null}), "never the token");
        let stored = Settings::load(&server.state.store, &Settings::default()).await.unwrap();
        assert!(!serde_json::to_string(&stored).unwrap().contains(token), "only its hash is kept");

        assert_eq!(scrape(&server, None).await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(scrape(&server, Some("a-wrong-token-for-prometheus")).await.status(), StatusCode::UNAUTHORIZED);
        server.get_as(&admin.token, "/api/sync").await;
        server.form("/identity/connect/token", &login_form("admin@example.com", "d2")).await;
        let response = scrape(&server, Some(token)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers()["content-type"].to_str().unwrap().starts_with("text/plain; version=0.0.4"));
        let text = text(response).await;
        assert!(text.contains("uwulock_build_info{version=\"0.0.0-test\"} 1"));
        assert!(text.contains("uwulock_accounts 1"));
        assert!(text.contains("uwulock_logins_total{grant=\"password\",result=\"success\"}"), "{text}");
        assert!(text.contains("uwulock_sync_duration_seconds_count{kind=\"bitwarden\"} 1"));
        assert!(text.contains("uwulock_http_requests_total{route=\"/api/sync\",method=\"GET\",status=\"200\"} 1"));
        assert!(!text.contains("admin@example.com"), "no addresses in labels");

        // Saved again without a token: the one there is stays.
        let mut again = saved.clone();
        again["metrics"] = json!({"enabled": true});
        let kept = server.call("PUT", "/uwu/v1/admin/settings", Some(&admin.token), again).await;
        assert_eq!(kept.status(), StatusCode::OK);
        assert_eq!(scrape(&server, Some(token)).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn on_an_address_of_their_own_they_leave_the_public_one() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        drop(listener);
        let settings = Settings {
            metrics: MetricsSettings { enabled: true, listen: Some(address.clone()), ..MetricsSettings::default() },
            ..Settings::default()
        };
        let server = TestServer::with_settings(settings).await;
        assert_eq!(scrape(&server, None).await.status(), StatusCode::NOT_FOUND, "not on the public address");
        spawn_listener(server.state.clone());
        // Bound once the task ran; the connection is tried until then.
        let mut text = None;
        for _ in 0..500 {
            if let Ok(mut stream) = tokio::net::TcpStream::connect(&address).await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                stream.write_all(b"GET /metrics HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n").await.unwrap();
                let mut answer = String::new();
                stream.read_to_string(&mut answer).await.unwrap();
                text = Some(answer);
                break;
            }
            tokio::task::yield_now().await;
        }
        let text = text.expect("the metrics address answers");
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("uwulock_build_info"));
    }

    #[test]
    fn histograms_count_into_every_bucket_above() {
        let mut histogram = Histogram::default();
        histogram.observe(0.02);
        histogram.observe(3.0);
        assert_eq!(histogram.counts[1], 0);
        assert_eq!(histogram.counts[2], 1, "0.025");
        assert_eq!(histogram.counts[BUCKETS.len() - 1], 2, "10");
        assert_eq!(histogram.count, 2);
        let _ = json!(null);
    }
}
