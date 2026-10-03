//! The password check's breach sources beyond Have I Been Pwned's passwords (docs/uwu-api.md
//! §15.1–§15.5). Each has its own switch in the settings (`breaches`); one that is off answers
//! 404 `feature_off`.
//!
//! - **XposedOrNot's passwords** (`/uwu/v1/xon/{prefix}`): the browser hashes a password with
//!   Keccak-512 and sends the first ten hex digits; this server asks XposedOrNot and hands back
//!   only how often it was seen. Like the HIBP proxy (`hibp.rs`): kept a day per account, never
//!   written anywhere, never next to an account. XposedOrNot allows only a few such questions a
//!   second for a whole server, so they wait in one queue for the server (one a second), and a
//!   429 is waited out as long as XposedOrNot asks (`Retry-After`) and asked again, a few times.
//! - **Breached sites** (`/uwu/v1/breaches/sites`): the public lists of Have I Been Pwned and
//!   XposedOrNot, fetched by the server the first time somebody asks and then once a day,
//!   merged by domain. The clients compare them with their logins themselves: the server never
//!   learns which sites are in a vault.
//! - **Addresses** (`/uwu/v1/breaches/emails`): the only source an address leaves the server
//!   for, so it needs the admin's switch and the account's consent. XposedOrNot allows a whole
//!   server 2 a second, 25 an hour and 100 a day; one queue here keeps to that, every account
//!   gets a share, and answers are kept a week under a salted hash of the address. No address
//!   is ever logged.
//! - **Change-password pages** (`/uwu/v1/change-password/{host}`): whether a site has
//!   `/.well-known/change-password`, asked by the server through the icons' checked client
//!   (never the local network) and kept a week per account. The browser never talks to the site
//!   before the person opens it.

use crate::auth::Session;
use crate::errors::{ApiError, ApiResult};
use crate::{AppState, icon_fetch};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uwulock_store::clock;

/// Have I Been Pwned's public list of breaches: no key needed, CC BY 4.0.
pub const HIBP_BREACHES: &str = "https://haveibeenpwned.com/api/v3/breaches";
/// XposedOrNot's public list of breaches.
pub const XON_BREACHES: &str = "https://api.xposedornot.com/v1/breaches";
/// XposedOrNot's passwords, by the first ten hex digits of a Keccak-512.
pub const XON_PASSWORDS: &str = "https://passwords.xposedornot.com/api/v1/pass/anon";
/// XposedOrNot's check of an address.
pub const XON_EMAIL: &str = "https://api.xposedornot.com/v1/check-email";

/// A list of breaches is about a megabyte; far more is not one.
const LIST_BYTES: usize = 16 * 1024 * 1024;
/// Breaches past this many per source are not taken.
const MOST_BREACHES: usize = 20_000;
/// One answer about a password or an address.
const ANSWER_BYTES: usize = 256 * 1024;
/// Breaches of one domain at the most: a real list has a handful, and merging compares each
/// with every other.
const MOST_PER_DOMAIN: usize = 100;
/// Breaches of two sources for one domain within this many days are one breach.
const SAME_BREACH_DAYS: i64 = 90;
/// Addresses checked in one request at the most, and how many of them may be asked anew.
const MOST_EMAILS: usize = 50;
const FRESH_PER_REQUEST: usize = 5;
/// How long an address's answer is kept.
const EMAIL_KEEP: i64 = 7 * 24 * 60 * 60;
/// How long the answer about a change-password page is kept, and for how many at most.
const PAGE_KEEP: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MOST_PAGES: usize = 8192;
/// What a request about addresses waits at most for its turn and its answers together.
const EMAIL_WAIT: Duration = Duration::from_secs(30);

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/xon/{prefix}", get(xon_password))
        .route("/uwu/v1/breaches/sites", get(sites))
        .route("/uwu/v1/breaches/emails", post(emails))
        .route("/uwu/v1/breaches/emails/opt-in", get(opt_in).put(set_opt_in))
        .route("/uwu/v1/change-password/{host}", get(change_password))
}

/// Which source is on: the admin's switches, for `/uwu/v1/info` and the checks below.
pub fn info(state: &AppState) -> Value {
    let settings = state.settings();
    let breaches = settings.breaches;
    json!({
        "hibp": settings.hibp,
        "xonPasswords": breaches.xon_passwords,
        "siteBreaches": breaches.site_breaches,
        "emailCheck": breaches.email_check,
        "changePassword": breaches.change_password,
    })
}

fn off() -> ApiError {
    ApiError::not_found("This is switched off on this server.").code("feature_off")
}

// ── State ─────────────────────────────────────────────────

/// What the breach sources keep while the server runs.
pub struct Breaches {
    /// XposedOrNot's answers about passwords, per account and prefix, a day.
    xon: crate::hibp::Cache,
    sites: SiteList,
    budget: Budget,
    /// The queue for XposedOrNot's passwords.
    xon_queue: XonQueue,
    /// Change-password pages: per account and host, whether there is one.
    pages: Mutex<HashMap<String, (Option<String>, Instant)>>,
    /// The salt of the addresses' hashes, opened.
    salt: tokio::sync::OnceCell<Vec<u8>>,
}

impl Default for Breaches {
    fn default() -> Self {
        Breaches::with_limits(BudgetLimits::default())
    }
}

impl Breaches {
    /// With other limits for the check of addresses: tests ask without waiting.
    pub fn with_limits(limits: BudgetLimits) -> Self {
        Breaches {
            xon: crate::hibp::Cache::default(),
            sites: SiteList::default(),
            budget: Budget { limits, state: tokio::sync::Mutex::new(BudgetState::default()) },
            xon_queue: XonQueue::new(XonLimits::default()),
            pages: Mutex::default(),
            salt: tokio::sync::OnceCell::new(),
        }
    }

    /// With other limits for the queue of XposedOrNot's passwords: tests wait milliseconds.
    pub fn with_xon_limits(mut self, limits: XonLimits) -> Self {
        self.xon_queue = XonQueue::new(limits);
        self
    }
}

/// Fetch `url` through the icons' checked client: never an address of the local network, at
/// most `limit` bytes, `seconds` in all. The status and the bytes.
async fn fetch(state: &AppState, url: &str, limit: usize, seconds: u64) -> Result<(u16, Vec<u8>), String> {
    fetch_answer(state, url, limit, seconds).await.map(|answer| (answer.status, answer.bytes))
}

/// What `fetch_answer` got back.
struct Answer {
    status: u16,
    /// `Retry-After` in seconds, when there was one.
    retry_after: Option<u64>,
    bytes: Vec<u8>,
}

/// Like `fetch`, with the `Retry-After` of the answer.
async fn fetch_answer(state: &AppState, url: &str, limit: usize, seconds: u64) -> Result<Answer, String> {
    let (client, upstream) = state.icons.fetcher().ok_or("no HTTP client")?;
    let url = url::Url::parse(url).map_err(|error| error.to_string())?;
    if !upstream.url_ok(&url) {
        return Err("refused".into());
    }
    let work = async {
        let mut response = client
            .get(url)
            .header(header::ACCEPT, "application/json")
            .timeout(Duration::from_secs(seconds))
            .send()
            .await
            .map_err(quiet)?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse().ok());
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(quiet)? {
            if bytes.len() + chunk.len() > limit {
                return Err("the answer is far larger than it should be".to_string());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(Answer { status, retry_after, bytes })
    };
    tokio::time::timeout(Duration::from_secs(seconds), work).await.map_err(|_| "it took too long".to_string())?
}

/// An error of a request without its address: the address carries a password's prefix or an
/// email address, and errors are logged.
pub(crate) fn quiet(error: reqwest::Error) -> String {
    crate::outbound::error_text(&error.without_url())
}

// ── XposedOrNot's passwords ───────────────────────────────

async fn xon_password(
    State(state): State<AppState>,
    session: Session,
    Path(prefix): Path<String>,
) -> ApiResult<Response> {
    if !state.settings().breaches.xon_passwords {
        return Err(off());
    }
    let prefix = prefix.to_ascii_lowercase();
    if prefix.len() != 10 || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::bad("A prefix is ten hex digits."));
    }
    let key = format!("{}:{prefix}", session.user.id);
    let count = match state.breaches.xon.get(&key) {
        Some(count) => count,
        None => {
            if !state.limits.hibp.take(session.user.id.clone()) {
                return Err(ApiError::too_many("Too many checks. Wait a minute and try again."));
            }
            let base = state.icons.fetcher().map(|(_, upstream)| upstream.xon_passwords.clone()).unwrap_or_default();
            let count: Arc<str> = match state.breaches.xon_queue.ask(&state, &session.user.id, &base, &prefix).await {
                Ok(count) => count.to_string().into(),
                Err(XonError::Busy(wait)) => {
                    // Nothing was asked: the try comes back (R1-15).
                    state.limits.hibp.give_back(&session.user.id);
                    // The queue is long: the client asks again later, nothing failed.
                    let seconds = wait.as_secs().max(1);
                    let mut response =
                        ApiError::too_many("XposedOrNot is busy. Ask again in a moment.").code("busy").into_response();
                    response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(seconds));
                    return Ok(response);
                }
                Err(XonError::Failed(error)) => {
                    tracing::warn!(%error, "XposedOrNot did not answer about a password");
                    return Err(ApiError::upstream("XposedOrNot did not answer. Try again later."));
                }
            };
            state.breaches.xon.put(key, count.clone());
            count
        }
    };
    let count: u64 = count.parse().unwrap_or(0);
    Ok(Json(json!({ "object": "xonPassword", "count": count })).into_response())
}

/// How XposedOrNot's passwords are asked: one question at a time for the whole server.
#[derive(Debug, Clone, Copy)]
pub struct XonLimits {
    /// Between two questions at least.
    pub spacing: Duration,
    /// How often one prefix is asked again after a 429 or a 5xx.
    pub retries: u32,
    /// The longest pause after a 429, whatever `Retry-After` says.
    pub longest_pause: Duration,
    /// How long one request may wait in the queue before its client is told to come back
    /// (429 `busy`).
    pub longest_wait: Duration,
    /// How many requests of one account may wait in the queue at once; one more is `busy` at
    /// once, so one account cannot fill the queue for everybody else (R1-15). The web vault asks
    /// four at a time.
    pub per_account: usize,
}

impl Default for XonLimits {
    fn default() -> Self {
        // XposedOrNot asks for one question a second; checks of a few hundred passwords answer
        // within minutes then, never "too many".
        XonLimits {
            spacing: Duration::from_secs(1),
            retries: 4,
            longest_pause: Duration::from_secs(120),
            longest_wait: Duration::from_secs(60),
            per_account: 4,
        }
    }
}

impl XonLimits {
    /// The pause before asking again after the `attempt`-th refusal (0 = the first): what
    /// `Retry-After` says, else twice as long each time; at least the spacing, at most
    /// `longest_pause`.
    fn pause(&self, retry_after: Option<u64>, attempt: u32) -> Duration {
        let pause = match retry_after {
            Some(seconds) => Duration::from_secs(seconds),
            None => self.spacing.max(Duration::from_secs(1)).saturating_mul(2u32.saturating_pow(attempt + 1)),
        };
        pause.max(self.spacing).min(self.longest_pause)
    }
}

/// Why a password's prefix got no count.
#[derive(Debug, PartialEq, Eq)]
enum XonError {
    /// The queue is too long right now: ask again after this.
    Busy(Duration),
    /// XposedOrNot did not answer, or kept refusing.
    Failed(String),
}

struct XonQueue {
    limits: XonLimits,
    /// Requests waiting (or being asked) per account.
    waiting: Arc<parking_lot::Mutex<HashMap<String, usize>>>,
    /// When the next question may go out. Held while a question is asked (and waited for), so
    /// the requests take turns in the order they came (tokio's mutex is fair).
    next: tokio::sync::Mutex<Instant>,
}

impl XonQueue {
    fn new(limits: XonLimits) -> Self {
        XonQueue { limits, waiting: Arc::default(), next: tokio::sync::Mutex::new(Instant::now()) }
    }

    /// A place in the queue for `account`, or none while it has `per_account` waiting already.
    fn enter(&self, account: &str) -> Option<QueuePlace> {
        let mut waiting = self.waiting.lock();
        let count = waiting.entry(account.to_string()).or_insert(0);
        if *count >= self.limits.per_account {
            return None;
        }
        *count += 1;
        Some(QueuePlace { waiting: self.waiting.clone(), account: account.to_string() })
    }

    /// How often XposedOrNot saw passwords whose hash starts with `prefix`: 0 when never.
    async fn ask(&self, state: &AppState, account: &str, base: &str, prefix: &str) -> Result<u64, XonError> {
        let limits = &self.limits;
        let Some(_place) = self.enter(account) else {
            return Err(XonError::Busy(limits.spacing.max(Duration::from_secs(1)).saturating_mul(2)));
        };
        let started = Instant::now();
        let mut next = match tokio::time::timeout(limits.longest_wait, self.next.lock()).await {
            Ok(next) => next,
            Err(_) => return Err(XonError::Busy(limits.spacing.max(Duration::from_secs(1)))),
        };
        let url = format!("{}/{prefix}", base.trim_end_matches('/'));
        let mut attempt = 0;
        loop {
            let now = Instant::now();
            if *next > now {
                if (*next - started) > limits.longest_wait {
                    return Err(XonError::Busy(*next - now));
                }
                tokio::time::sleep_until((*next).into()).await;
            }
            let answer = fetch_answer(state, &url, ANSWER_BYTES, 10).await;
            let now = Instant::now();
            *next = now + limits.spacing;
            let answer = answer.map_err(XonError::Failed)?;
            let again = answer.status == 429 || (500..600).contains(&answer.status);
            if !again {
                return xon_count(answer.status, &answer.bytes).map_err(XonError::Failed);
            }
            if attempt >= limits.retries {
                return Err(XonError::Failed(format!("XposedOrNot answered {} {} times", answer.status, attempt + 1)));
            }
            let pause = limits.pause(answer.retry_after, attempt);
            tracing::info!(
                status = answer.status,
                pause = pause.as_secs(),
                "XposedOrNot asks to wait; the queue waits"
            );
            *next = now + pause;
            attempt += 1;
        }
    }
}

/// An account's request in the XposedOrNot queue; leaving it makes room for the next.
struct QueuePlace {
    waiting: Arc<parking_lot::Mutex<HashMap<String, usize>>>,
    account: String,
}

impl Drop for QueuePlace {
    fn drop(&mut self) {
        let mut waiting = self.waiting.lock();
        if let Some(count) = waiting.get_mut(&self.account) {
            *count -= 1;
            if *count == 0 {
                waiting.remove(&self.account);
            }
        }
    }
}

/// XposedOrNot's answer about a password: `{"SearchPassAnon":{"count":"12", "char": …}}`, or 404
/// `{"Error":"Not found"}`. Only the count is kept; what it says about the characters is not.
fn xon_count(status: u16, bytes: &[u8]) -> Result<u64, String> {
    if status == 404 {
        return Ok(0);
    }
    if !(200..300).contains(&status) {
        return Err(format!("XposedOrNot answered {status}"));
    }
    let answer: Value = serde_json::from_slice(bytes).map_err(|_| "XposedOrNot's answer is not JSON".to_string())?;
    if answer.get("Error").is_some() {
        return Ok(0);
    }
    let count = &answer["SearchPassAnon"]["count"];
    count
        .as_u64()
        .or_else(|| count.as_str().and_then(|text| text.trim().parse().ok()))
        .ok_or_else(|| "XposedOrNot's answer has no count".into())
}

// ── Breached sites ────────────────────────────────────────

/// One breach of a site, as the merged list hands it out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Breach {
    /// The site's domain: lower case, ASCII, without `www.`.
    pub domain: String,
    pub title: String,
    /// When it happened (`YYYY-MM-DD`), as far as known.
    pub date: Option<String>,
    /// When the source learned of it (`YYYY-MM-DD`).
    pub added: Option<String>,
    /// Accounts in it, as the source counted.
    pub records: u64,
    /// Whether passwords (or their hashes) were taken.
    pub passwords: bool,
    /// What was taken, in the source's words.
    pub data_classes: Vec<String>,
    /// Each source that lists it, with the name it has there (XposedOrNot's names are what the
    /// check of addresses answers).
    pub sources: BTreeMap<String, String>,
}

/// The sources, by their id in `sources`.
const SOURCES: [(&str, &str, &str, Option<&str>); 2] = [
    ("hibp", "Have I Been Pwned", "https://haveibeenpwned.com/", Some("CC BY 4.0")),
    ("xon", "XposedOrNot", "https://xposedornot.com/", None),
];

struct Mirrored {
    body: String,
    etag: String,
}

/// After the lists could not be fetched for a request, the next request waits this long before
/// it asks again.
const SITES_RETRY: Duration = Duration::from_secs(5 * 60);

#[derive(Default)]
struct SiteList {
    mirrored: RwLock<Option<Arc<Mirrored>>>,
    refreshing: tokio::sync::Mutex<()>,
    /// When a request last failed to fetch the lists.
    failed: Mutex<Option<Instant>>,
}

fn sites_dir(state: &AppState) -> PathBuf {
    state.config.data.join("breaches")
}

fn source_file(state: &AppState, source: &str) -> PathBuf {
    sites_dir(state).join(format!("{source}.json"))
}

/// What one source's list was turned into, as kept on disk.
#[derive(Serialize, Deserialize)]
struct Stored {
    updated: String,
    breaches: Vec<Breach>,
}

fn text(value: &Value, most: usize) -> Option<String> {
    let text = value.as_str()?.trim();
    (!text.is_empty() && text.chars().count() <= most && !text.chars().any(char::is_control)).then(|| text.to_string())
}

/// A domain as the lists write it, made plain: lower case, ASCII, without a scheme, a path or
/// `www.`. None for anything that is not a public name.
pub fn plain_domain(raw: &str) -> Option<String> {
    let raw = raw.trim().to_ascii_lowercase();
    let raw = raw.split_once("://").map_or(raw.as_str(), |(_, rest)| rest);
    let raw = raw.split(['/', '?', '#']).next()?;
    let host = icon_fetch::normalize_host(raw)?;
    let host = host.strip_prefix("www.").map(str::to_string).unwrap_or(host);
    host.contains('.').then_some(host)
}

/// `2013-10-04`, `2013-10-04T00:00:00Z` or `2026-04-01T00:00:00+00:00` as `2013-10-04`.
fn day(value: &Value) -> Option<String> {
    let text = value.as_str()?.trim();
    let date = text.get(..10)?;
    time::Date::parse(date, time::macros::format_description!("[year]-[month]-[day]")).ok()?;
    Some(date.to_string())
}

fn classes(value: &Value) -> Vec<String> {
    value.as_array().map(|list| list.iter().filter_map(|class| text(class, 80)).take(60).collect()).unwrap_or_default()
}

fn has_passwords(classes: &[String]) -> bool {
    classes.iter().any(|class| class.eq_ignore_ascii_case("passwords"))
}

/// Have I Been Pwned's `/api/v3/breaches`: `[{Name, Title, Domain, BreachDate, AddedDate,
/// PwnCount, DataClasses, IsFabricated, IsSpamList, IsMalware, IsStealerLog, …}]`. Breaches
/// without a domain, made up, spam lists, malware and stealer logs are not about a site's own
/// accounts and are left out.
fn convert_hibp(bytes: &[u8]) -> Result<Vec<Breach>, String> {
    let list: Vec<Value> = serde_json::from_slice(bytes)
        .map_err(|error| format!("Have I Been Pwned's list could not be read: {error}"))?;
    let flag = |breach: &Value, name: &str| breach.get(name).and_then(Value::as_bool).unwrap_or(false);
    Ok(list
        .iter()
        .take(MOST_BREACHES)
        .filter(|breach| !["IsFabricated", "IsSpamList", "IsMalware", "IsStealerLog"].iter().any(|f| flag(breach, f)))
        .filter_map(|breach| {
            let name = text(breach.get("Name")?, 200)?;
            let data_classes = classes(&breach["DataClasses"]);
            Some(Breach {
                domain: plain_domain(breach.get("Domain")?.as_str()?)?,
                title: text(&breach["Title"], 200).unwrap_or_else(|| name.clone()),
                date: day(&breach["BreachDate"]),
                added: day(&breach["AddedDate"]),
                records: breach["PwnCount"].as_u64().unwrap_or(0),
                passwords: has_passwords(&data_classes),
                data_classes,
                sources: BTreeMap::from([("hibp".to_string(), name)]),
            })
        })
        .collect())
}

/// XposedOrNot's `/v1/breaches`: `{"exposedBreaches": [{breachID, breachedDate, addedDate,
/// domain, exposedData, exposedRecords, passwordRisk, breachType, …}]}`. Combo lists and stealer
/// logs are not a site's breach and are left out.
fn convert_xon(bytes: &[u8]) -> Result<Vec<Breach>, String> {
    let answer: Value =
        serde_json::from_slice(bytes).map_err(|error| format!("XposedOrNot's list could not be read: {error}"))?;
    let list = answer["exposedBreaches"].as_array().ok_or("XposedOrNot's list has no breaches")?;
    Ok(list
        .iter()
        .take(MOST_BREACHES)
        .filter(|breach| !matches!(breach["breachType"].as_str(), Some("ComboList" | "StealerLogs")))
        .filter_map(|breach| {
            let name = text(breach.get("breachID")?, 200)?;
            let data_classes = classes(&breach["exposedData"]);
            let risk = breach["passwordRisk"].as_str().unwrap_or("unknown");
            Some(Breach {
                domain: plain_domain(breach.get("domain")?.as_str()?)?,
                title: name.clone(),
                date: day(&breach["breachedDate"]),
                added: day(&breach["addedDate"]),
                records: breach["exposedRecords"].as_u64().unwrap_or(0),
                passwords: has_passwords(&data_classes)
                    || matches!(risk, "plaintext" | "plaintextpassword" | "easytocrack" | "hardtocrack"),
                data_classes,
                sources: BTreeMap::from([("xon".to_string(), name)]),
            })
        })
        .collect())
}

fn days_between(a: &str, b: &str) -> Option<i64> {
    let format = time::macros::format_description!("[year]-[month]-[day]");
    let a = time::Date::parse(a, format).ok()?;
    let b = time::Date::parse(b, format).ok()?;
    Some((a - b).whole_days().abs())
}

/// The lists of all sources as one: a breach two sources list for the same domain within
/// [`SAME_BREACH_DAYS`] is one, with both names, the earlier date and everything either says was
/// taken. Sorted by domain, then date.
pub fn merge(lists: Vec<Vec<Breach>>) -> Vec<Breach> {
    let mut by_domain: BTreeMap<String, Vec<Breach>> = BTreeMap::new();
    for list in lists {
        for breach in list {
            let same = by_domain.entry(breach.domain.clone()).or_default();
            let room = same.len() < MOST_PER_DOMAIN;
            let twin = same.iter_mut().find(|known| {
                breach.sources.keys().all(|source| !known.sources.contains_key(source))
                    && match (&known.date, &breach.date) {
                        (Some(a), Some(b)) => days_between(a, b).is_some_and(|days| days <= SAME_BREACH_DAYS),
                        _ => false,
                    }
            });
            match twin {
                Some(known) => {
                    known.sources.extend(breach.sources);
                    known.records = known.records.max(breach.records);
                    known.passwords |= breach.passwords;
                    for class in breach.data_classes {
                        if !known.data_classes.iter().any(|seen| seen.eq_ignore_ascii_case(&class)) {
                            known.data_classes.push(class);
                        }
                    }
                    if breach.date < known.date {
                        known.date = breach.date;
                    }
                    if known.added.is_none() || (breach.added.is_some() && breach.added < known.added) {
                        known.added = breach.added;
                    }
                }
                None if room => same.push(breach),
                None => {}
            }
        }
    }
    by_domain
        .into_values()
        .flat_map(|mut list| {
            list.sort_by(|a, b| a.date.cmp(&b.date).then_with(|| a.title.cmp(&b.title)));
            list
        })
        .collect()
}

impl SiteList {
    /// From memory, else from disk, else fetched now — by one request at a time, and not again
    /// for [`SITES_RETRY`] after that failed, so requests cannot pile up behind a source that is
    /// down.
    async fn get(&self, state: &AppState) -> Option<Arc<Mirrored>> {
        if let Some(list) = self.mirrored.read().clone() {
            return Some(list);
        }
        if let Some(list) = self.load(state).await {
            return Some(list);
        }
        let failed_lately = || self.failed.lock().is_some_and(|at| at.elapsed() < SITES_RETRY);
        if failed_lately() {
            return None;
        }
        let _one_at_a_time = self.refreshing.lock().await;
        // Another request may have fetched them, or failed, meanwhile.
        if let Some(list) = self.mirrored.read().clone() {
            return Some(list);
        }
        if failed_lately() {
            return None;
        }
        if let Err(error) = self.refresh_locked(state).await {
            *self.failed.lock() = Some(Instant::now());
            tracing::warn!(%error, "the lists of breached sites could not be fetched");
        }
        self.mirrored.read().clone()
    }

    /// Merge what is on disk into the list handed out; none when no source is there.
    async fn load(&self, state: &AppState) -> Option<Arc<Mirrored>> {
        let mut lists = Vec::new();
        let mut sources = Vec::new();
        for (id, name, url, license) in SOURCES {
            let Ok(body) = tokio::fs::read(source_file(state, id)).await else { continue };
            let Ok(stored) = serde_json::from_slice::<Stored>(&body) else { continue };
            sources.push(json!({ "id": id, "name": name, "url": url, "license": license, "updated": stored.updated }));
            lists.push(stored.breaches);
        }
        if lists.is_empty() {
            return None;
        }
        let breaches = merge(lists);
        let updated =
            sources.iter().filter_map(|source| source["updated"].as_str()).max().unwrap_or_default().to_string();
        let body = json!({ "object": "siteBreaches", "updated": updated, "sources": sources, "breaches": breaches })
            .to_string();
        let etag = format!(
            "\"{}\"",
            crate::auth::sha256(body.as_bytes())[..12].iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let list = Arc::new(Mirrored { body, etag });
        *self.mirrored.write() = Some(list.clone());
        Some(list)
    }

    /// Fetch every source again; one that fails keeps what it had.
    async fn refresh(&self, state: &AppState) -> Result<(), String> {
        let _one_at_a_time = self.refreshing.lock().await;
        self.refresh_locked(state).await
    }

    /// [`Self::refresh`], with `refreshing` held already.
    async fn refresh_locked(&self, state: &AppState) -> Result<(), String> {
        let Some((_, upstream)) = state.icons.fetcher() else { return Err("no HTTP client".into()) };
        let (hibp_url, xon_url) = (upstream.hibp_breaches.clone(), upstream.xon_breaches.clone());
        let mut errors = Vec::new();
        for (id, url, convert) in [
            ("hibp", hibp_url, convert_hibp as fn(&[u8]) -> Result<Vec<Breach>, String>),
            ("xon", xon_url, convert_xon),
        ] {
            let fetched = fetch(state, &url, LIST_BYTES, 60).await.and_then(|(status, bytes)| {
                if !(200..300).contains(&status) {
                    return Err(format!("{id} answered {status}"));
                }
                let breaches = convert(&bytes)?;
                if breaches.is_empty() {
                    return Err(format!("{id}'s list has no breaches"));
                }
                Ok(breaches)
            });
            match fetched {
                Ok(breaches) => {
                    let stored = Stored { updated: clock::now(), breaches };
                    if let Err(error) = write(state, id, &stored).await {
                        errors.push(format!("{id}: {error}"));
                    }
                }
                Err(error) => errors.push(format!("{id}: {error}")),
            }
        }
        let loaded = self.load(state).await;
        match (loaded, errors.is_empty()) {
            (_, true) => Ok(()),
            (Some(_), false) => {
                tracing::warn!(errors = %errors.join("; "), "a list of breached sites was not fetched; the last one is kept");
                Ok(())
            }
            (None, false) => Err(errors.join("; ")),
        }
    }

    async fn in_use(&self, state: &AppState) -> bool {
        self.mirrored.read().is_some() || tokio::fs::metadata(sites_dir(state)).await.is_ok()
    }
}

async fn write(state: &AppState, id: &str, stored: &Stored) -> Result<(), String> {
    tokio::fs::create_dir_all(sites_dir(state)).await.map_err(|error| error.to_string())?;
    let target = source_file(state, id);
    let temporary = target.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let body = serde_json::to_vec(stored).map_err(|error| error.to_string())?;
    tokio::fs::write(&temporary, body).await.map_err(|error| error.to_string())?;
    tokio::fs::rename(&temporary, target).await.map_err(|error| error.to_string())
}

async fn sites(State(state): State<AppState>, _session: Session, headers: HeaderMap) -> ApiResult<Response> {
    if !state.settings().breaches.site_breaches {
        return Err(off());
    }
    let list = state
        .breaches
        .sites
        .get(&state)
        .await
        .ok_or_else(|| ApiError::upstream("The lists of breached sites could not be fetched. Try again later."))?;
    let etag = HeaderValue::from_str(&list.etag).map_err(ApiError::internal)?;
    if headers.get(header::IF_NONE_MATCH).is_some_and(|given| given == etag) {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
    }
    Ok((
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8")),
            (header::ETAG, etag),
            (header::CACHE_CONTROL, HeaderValue::from_static("private, no-cache")),
        ],
        list.body.clone(),
    )
        .into_response())
}

/// Once a day: the lists again while somebody uses them, and old answers about addresses gone.
pub async fn daily(state: &AppState) {
    if state.settings().breaches.site_breaches
        && state.breaches.sites.in_use(state).await
        && let Err(error) = state.breaches.sites.refresh(state).await
    {
        tracing::warn!(%error, "the lists of breached sites could not be fetched");
    }
    let before = time::OffsetDateTime::now_utc().unix_timestamp() - EMAIL_KEEP;
    if let Err(error) = state.store.prune_breach_email_cache(before).await {
        tracing::warn!(%error, "old answers about addresses were not swept up");
    }
}

// ── Addresses ─────────────────────────────────────────────

/// XposedOrNot's limits for a whole server, and the share of one account.
#[derive(Debug, Clone, Copy)]
pub struct BudgetLimits {
    /// Between two questions at least.
    pub spacing: Duration,
    pub per_hour: usize,
    pub per_day: usize,
    /// New questions one account may cause a day.
    pub per_account_day: usize,
}

impl Default for BudgetLimits {
    fn default() -> Self {
        // XposedOrNot: 2 a second, 25 an hour, 100 a day for the free API. A little below.
        BudgetLimits { spacing: Duration::from_millis(600), per_hour: 24, per_day: 96, per_account_day: 24 }
    }
}

#[derive(Default)]
struct BudgetState {
    last: Option<Instant>,
    asked: VecDeque<Instant>,
    /// XposedOrNot said 429: nothing until then.
    blocked_until: Option<Instant>,
    accounts: HashMap<String, VecDeque<Instant>>,
}

struct Budget {
    limits: BudgetLimits,
    /// The queue: one question at a time, for the whole server.
    state: tokio::sync::Mutex<BudgetState>,
}

const HOUR: Duration = Duration::from_secs(60 * 60);
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

impl BudgetState {
    fn forget_old(&mut self, now: Instant) {
        while self.asked.front().is_some_and(|at| now.duration_since(*at) >= DAY) {
            self.asked.pop_front();
        }
        self.accounts.retain(|_, asked| {
            while asked.front().is_some_and(|at| now.duration_since(*at) >= DAY) {
                asked.pop_front();
            }
            !asked.is_empty()
        });
    }

    /// When the next question may be asked for `account`: now (`None`), or after this long.
    fn wait(&self, limits: &BudgetLimits, account: &str, now: Instant) -> Option<Duration> {
        let after = |at: Instant, window: Duration| (at + window).saturating_duration_since(now);
        let mut wait: Option<Duration> = None;
        let mut later = |duration: Duration| wait = Some(wait.map_or(duration, |known| known.max(duration)));
        if let Some(until) = self.blocked_until.filter(|until| *until > now) {
            later(until - now);
        }
        let in_hour: Vec<&Instant> = self.asked.iter().filter(|at| now.duration_since(**at) < HOUR).collect();
        if in_hour.len() >= limits.per_hour
            && let Some(first) = in_hour.first()
        {
            later(after(**first, HOUR));
        }
        if self.asked.len() >= limits.per_day
            && let Some(first) = self.asked.front()
        {
            later(after(*first, DAY));
        }
        if let Some(asked) = self.accounts.get(account)
            && asked.len() >= limits.per_account_day
            && let Some(first) = asked.front()
        {
            later(after(*first, DAY));
        }
        wait
    }

    fn record(&mut self, account: &str, now: Instant) {
        self.last = Some(now);
        self.asked.push_back(now);
        self.accounts.entry(account.to_string()).or_default().push_back(now);
    }
}

/// An address as it is checked: trimmed, lower case; none for what is not one.
pub fn plain_address(raw: &str) -> Option<String> {
    let address = raw.trim().to_ascii_lowercase();
    let (local, domain) = address.rsplit_once('@')?;
    let ok = address.len() <= 254
        && !local.is_empty()
        && local.len() <= 64
        && domain.contains('.')
        && !address.chars().any(|c| c.is_whitespace() || c.is_control() || "/?#%\\\"<>".contains(c))
        && domain
            .split('.')
            .all(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    ok.then_some(address)
}

/// The salt of the addresses' hashes: made once, kept sealed with the server secret, which is not
/// in the database.
async fn salt(state: &AppState) -> ApiResult<&[u8]> {
    state
        .breaches
        .salt
        .get_or_try_init(|| async {
            const PURPOSE: &str = "breaches.emailSalt";
            let fresh: String = crate::auth::random_bytes(32).iter().map(|b| format!("{b:02x}")).collect();
            let sealed = state.secret.seal(&fresh, PURPOSE).map_err(ApiError::internal)?;
            let stored = state.store.setting_or_insert("breach_email_salt", &sealed).await?;
            let opened = state.secret.open(&stored, PURPOSE).map_err(ApiError::internal)?;
            Ok::<_, ApiError>(opened.into_bytes())
        })
        .await
        .map(Vec::as_slice)
}

fn address_hash(salt: &[u8], address: &str) -> Vec<u8> {
    let mut input = salt.to_vec();
    input.push(0);
    input.extend_from_slice(address.as_bytes());
    crate::auth::sha256(&input)
}

/// XposedOrNot's answer about an address: `{"breaches": [["Adobe", "LinkedIn"]], …}`, or
/// `{"Error": "Not found"}` (with 200 or 404). The breaches' names, none for "not found".
fn xon_email_breaches(status: u16, bytes: &[u8]) -> Result<Vec<String>, String> {
    if status == 404 {
        return Ok(Vec::new());
    }
    if !(200..300).contains(&status) {
        return Err(format!("XposedOrNot answered {status}"));
    }
    let answer: Value = serde_json::from_slice(bytes).map_err(|_| "XposedOrNot's answer is not JSON".to_string())?;
    if answer.get("Error").is_some() {
        return Ok(Vec::new());
    }
    let lists = answer["breaches"].as_array().ok_or("XposedOrNot's answer has no breaches")?;
    let mut names: Vec<String> = lists
        .iter()
        .flat_map(|list| {
            list.as_array()
                .map(|names| names.iter().filter_map(|name| text(name, 200)).collect::<Vec<_>>())
                .unwrap_or_default()
        })
        .take(2000)
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

#[derive(Deserialize)]
struct EmailsBody {
    emails: Vec<String>,
}

async fn require_email_check(state: &AppState, session: &Session) -> ApiResult<()> {
    if !state.settings().breaches.email_check {
        return Err(off());
    }
    if state.store.breach_email_opt_in(&session.user.id).await?.is_none() {
        return Err(ApiError::forbidden("Agree to the check of your addresses first.").code("opt_in"));
    }
    Ok(())
}

async fn emails(
    State(state): State<AppState>,
    session: Session,
    Json(body): Json<EmailsBody>,
) -> ApiResult<Json<Value>> {
    require_email_check(&state, &session).await?;
    if body.emails.len() > MOST_EMAILS {
        return Err(ApiError::bad(format!("At most {MOST_EMAILS} addresses at once.")));
    }
    let mut addresses: Vec<String> = Vec::new();
    for raw in &body.emails {
        let address = plain_address(raw).ok_or_else(|| ApiError::bad("That is not an address."))?;
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    let salt = salt(&state).await?.to_vec();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut results: Vec<Value> = Vec::with_capacity(addresses.len());
    let mut missing: Vec<(usize, String, Vec<u8>)> = Vec::new();
    for address in addresses {
        let hash = address_hash(&salt, &address);
        match state.store.breach_email_cached(hash.clone(), now - EMAIL_KEEP).await? {
            Some(cached) => {
                let breaches: Vec<String> = serde_json::from_str(&cached).unwrap_or_default();
                results.push(email_result(&address, Some(&breaches)));
            }
            None => {
                missing.push((results.len(), address.clone(), hash));
                results.push(email_result(&address, None));
            }
        }
    }
    let mut retry_after: Option<u64> = None;
    if !missing.is_empty() {
        let started = Instant::now();
        let base = state.icons.fetcher().map(|(_, upstream)| upstream.xon_email.clone()).unwrap_or_default();
        let budget = &state.breaches.budget;
        match tokio::time::timeout(EMAIL_WAIT, budget.state.lock()).await {
            Err(_) => retry_after = Some(60),
            Ok(mut queue) => {
                for (done, (index, address, hash)) in missing.into_iter().enumerate() {
                    let now = Instant::now();
                    queue.forget_old(now);
                    if done >= FRESH_PER_REQUEST || started.elapsed() >= EMAIL_WAIT {
                        retry_after = Some(retry_after.map_or(1, |known| known.max(1)));
                        break;
                    }
                    if let Some(wait) = queue.wait(&budget.limits, &session.user.id, now) {
                        retry_after = Some(wait.as_secs().max(1));
                        break;
                    }
                    if let Some(last) = queue.last {
                        tokio::time::sleep_until((last + budget.limits.spacing).into()).await;
                    }
                    queue.record(&session.user.id, Instant::now());
                    let mut url = match url::Url::parse(&base) {
                        Ok(url) => url,
                        Err(_) => break,
                    };
                    if let Ok(mut segments) = url.path_segments_mut() {
                        segments.pop_if_empty().push(&address);
                    }
                    match fetch(&state, url.as_str(), ANSWER_BYTES, 10).await {
                        Ok((429, _)) => {
                            queue.blocked_until = Some(Instant::now() + HOUR);
                            retry_after = Some(HOUR.as_secs());
                            break;
                        }
                        Ok((status, bytes)) => match xon_email_breaches(status, &bytes) {
                            Ok(breaches) => {
                                let stored = serde_json::to_string(&breaches).unwrap_or_else(|_| "[]".into());
                                let checked = time::OffsetDateTime::now_utc().unix_timestamp();
                                state.store.set_breach_email_cached(hash, &stored, checked).await?;
                                results[index] = email_result(&address, Some(&breaches));
                            }
                            Err(_) => {
                                // Which address it was is never written down.
                                tracing::warn!(
                                    status,
                                    "XposedOrNot gave an answer about an address that could not be read"
                                );
                                results[index]["status"] = "failed".into();
                            }
                        },
                        Err(_) => {
                            tracing::warn!("XposedOrNot did not answer about an address");
                            results[index]["status"] = "failed".into();
                        }
                    }
                }
            }
        }
    }
    Ok(Json(json!({ "object": "emailBreaches", "results": results, "retryAfter": retry_after })))
}

fn email_result(address: &str, breaches: Option<&[String]>) -> Value {
    match breaches {
        Some(breaches) => json!({
            "email": address,
            "status": if breaches.is_empty() { "clean" } else { "found" },
            "breaches": breaches,
        }),
        None => json!({ "email": address, "status": "later", "breaches": [] }),
    }
}

async fn opt_in(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    if !state.settings().breaches.email_check {
        return Err(off());
    }
    let since = state.store.breach_email_opt_in(&session.user.id).await?;
    Ok(Json(json!({ "object": "emailBreachOptIn", "optedIn": since.is_some(), "since": since })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OptInBody {
    opted_in: bool,
}

async fn set_opt_in(
    State(state): State<AppState>,
    session: Session,
    Json(body): Json<OptInBody>,
) -> ApiResult<Json<Value>> {
    if !state.settings().breaches.email_check {
        return Err(off());
    }
    let since = state.store.set_breach_email_opt_in(&session.user.id, body.opted_in).await?;
    Ok(Json(json!({ "object": "emailBreachOptIn", "optedIn": since.is_some(), "since": since })))
}

/// For `/uwu/v1/account`: whether the account agreed, when the check is on.
pub async fn account_info(state: &AppState, user_id: &str) -> ApiResult<Value> {
    if !state.settings().breaches.email_check {
        return Ok(Value::Null);
    }
    let since = state.store.breach_email_opt_in(user_id).await?;
    Ok(json!({ "optedIn": since.is_some(), "since": since }))
}

// ── Change-password pages ─────────────────────────────────

/// Where a site's change-password page would be, by the scheme and ports `upstream` uses.
fn page_url(upstream: &icon_fetch::Upstream, host: &str, path: &str) -> String {
    let scheme = upstream.change_password_scheme;
    let (port, default) = if scheme == "https" { (upstream.https_port, 443) } else { (upstream.http_port, 80) };
    if port == default { format!("{scheme}://{host}{path}") } else { format!("{scheme}://{host}:{port}{path}") }
}

const WELL_KNOWN: &str = "/.well-known/change-password";
/// What a site must not answer with 200: if it does, it answers 200 for everything, and its
/// change-password answer says nothing (the check browsers make, from the W3C draft).
const NOT_THERE: &str = "/.well-known/resource-that-should-not-exist-whose-status-code-should-not-be-200";

async fn site_says_ok(state: &AppState, url: &str) -> Result<bool, String> {
    let (client, upstream) = state.icons.fetcher().ok_or("no HTTP client")?;
    let url = url::Url::parse(url).map_err(|error| error.to_string())?;
    let fetched = icon_fetch::get(client, upstream, url, 16 * 1024).await?;
    Ok((200..300).contains(&fetched.status))
}

/// Whether `host` has a change-password page: its address, or none.
async fn look_for_page(state: &AppState, host: &str) -> Option<String> {
    let (_, upstream) = state.icons.fetcher()?;
    let well_known = page_url(upstream, host, WELL_KNOWN);
    let not_there = page_url(upstream, host, NOT_THERE);
    let (page, everything) = tokio::join!(site_says_ok(state, &well_known), site_says_ok(state, &not_there));
    (page == Ok(true) && everything != Ok(true)).then_some(well_known)
}

async fn change_password(
    State(state): State<AppState>,
    session: Session,
    Path(host): Path<String>,
) -> ApiResult<Json<Value>> {
    if !state.settings().breaches.change_password {
        return Err(off());
    }
    if host.len() > 300 {
        return Err(ApiError::bad("That is not a host name."));
    }
    // Addresses, local names and whatever is not a host are never asked: no page.
    let Some(host) = icon_fetch::normalize_host(&host) else {
        return Ok(Json(json!({ "object": "changePassword", "host": host.to_ascii_lowercase(), "url": null })));
    };
    let key = format!("{}:{host}", session.user.id);
    let cached = {
        let pages = state.breaches.pages.lock();
        pages.get(&key).filter(|(_, at)| at.elapsed() < PAGE_KEEP).map(|(url, _)| url.clone())
    };
    let url = match cached {
        Some(url) => url,
        None => {
            if !state.limits.change_password.take(session.user.id.clone()) {
                return Err(ApiError::too_many("Too many checks. Wait a minute and try again."));
            }
            let url = look_for_page(&state, &host).await;
            let mut pages = state.breaches.pages.lock();
            if pages.len() >= MOST_PAGES {
                pages.retain(|_, (_, at)| at.elapsed() < PAGE_KEEP);
                if pages.len() >= MOST_PAGES {
                    pages.clear();
                }
            }
            pages.insert(key, (url.clone(), Instant::now()));
            url
        }
    };
    Ok(Json(json!({ "object": "changePassword", "host": host, "url": url })))
}

#[cfg(test)]
mod tests;
