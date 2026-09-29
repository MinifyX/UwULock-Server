//! Send domains (docs/uwu-api.md §14.1, §14.2): extra hosts, like `send.example.com` beside
//! `lock.example.com`, that serve only Sends and file requests.
//!
//! The admin adds them; each gets its certificate from Let's Encrypt through the server itself
//! (the same TLS-ALPN-01 as the main host, on port 443) or from a proxy in front. Every Send is
//! reachable on the main host and on every send domain; which one a Send "uses" only decides the
//! link UwULock's clients show and the look of the page. So deleting a domain loses nothing but
//! its links.
//!
//! What a request to a send domain may reach is [`crate::send_hosts::allowed`]; this module keeps
//! the domains in memory for that, so the check costs no database query.

use crate::auth::{Admin, Session};
use crate::errors::{ApiError, ApiResult};
use crate::{AppState, branding};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use parking_lot::{Mutex, RwLock};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use uwulock_notify::realtime::Live;
use uwulock_store::send_domains::SendDomain;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/admin/send-domains", get(list).post(add))
        .route("/uwu/v1/admin/send-domains/{id}", put(change).delete(remove))
        .route("/uwu/v1/admin/send-domains/{id}/check", post(check))
        .route("/uwu/v1/account/send-domain", put(set_account_default))
        .route("/uwu/v1/sends/domains", get(choices))
        .route("/uwu/v1/sends/{id}/domain", put(choose))
        .merge(branding::domain_routes())
}

// ── What the running server knows ─────────────────────────

/// How far a send domain's own certificate is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Certificate {
    /// `ok`, `pending` or `failed`; `proxy` is never kept here.
    pub status: &'static str,
    /// Seconds since 1970.
    pub expires: Option<i64>,
    pub error: Option<String>,
}

/// The send domains, in memory, and what the TLS side of the server says about their
/// certificates. The server's TLS listener watches [`Registry::acme_hosts`] and gets a
/// certificate for each name in it.
pub struct Registry {
    domains: RwLock<Arc<Vec<SendDomain>>>,
    certificates: RwLock<HashMap<String, Certificate>>,
    acme: tokio::sync::watch::Sender<Vec<String>>,
    /// Whether this server terminates TLS itself; without it, only a proxy can have certificates.
    own_tls: std::sync::atomic::AtomicBool,
    /// Tokens of checks under way: `/alive?probe=<token>` answers with a header when it is one,
    /// which tells the check that the request really reached this server.
    probes: Mutex<HashSet<String>>,
}

impl Default for Registry {
    fn default() -> Self {
        Registry {
            domains: RwLock::default(),
            certificates: RwLock::default(),
            acme: tokio::sync::watch::channel(Vec::new()).0,
            own_tls: std::sync::atomic::AtomicBool::new(false),
            probes: Mutex::default(),
        }
    }
}

impl Registry {
    /// The server does TLS itself: `acme` send domains get certificates from it.
    pub fn serving_tls(&self) {
        self.own_tls.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn own_tls(&self) -> bool {
        self.own_tls.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The names that want a certificate from the server's ACME CA, and every change of them.
    pub fn acme_hosts(&self) -> tokio::sync::watch::Receiver<Vec<String>> {
        self.acme.subscribe()
    }

    /// What the TLS side found out about `host`'s certificate.
    pub fn set_certificate(&self, host: &str, certificate: Certificate) {
        self.certificates.write().insert(host.to_string(), certificate);
    }

    pub fn all(&self) -> Arc<Vec<SendDomain>> {
        self.domains.read().clone()
    }

    /// The send domain of `host` (lower case, no port).
    pub fn by_host(&self, host: &str) -> Option<SendDomain> {
        self.domains.read().iter().find(|domain| domain.host == host).cloned()
    }

    pub fn by_id(&self, id: &str) -> Option<SendDomain> {
        self.domains.read().iter().find(|domain| domain.id == id).cloned()
    }

    fn replace(&self, domains: Vec<SendDomain>) {
        let acme: Vec<String> =
            domains.iter().filter(|domain| domain.tls == "acme").map(|domain| domain.host.clone()).collect();
        self.certificates.write().retain(|host, _| acme.contains(host));
        *self.domains.write() = Arc::new(domains);
        self.acme.send_if_modified(|hosts| {
            let changed = *hosts != acme;
            *hosts = acme;
            changed
        });
    }

    fn certificate(&self, domain: &SendDomain) -> Certificate {
        if domain.tls == "proxy" {
            return Certificate { status: "proxy", ..Certificate::default() };
        }
        if !self.own_tls() {
            return Certificate {
                status: "failed",
                expires: None,
                error: Some(
                    "This server runs behind a proxy (UWULOCK_TLS=off or proxy), so it cannot get certificates itself. \
                     Let the proxy get one and switch the domain to proxy."
                        .into(),
                ),
            };
        }
        self.certificates
            .read()
            .get(&domain.host)
            .cloned()
            .unwrap_or(Certificate { status: "pending", ..Certificate::default() })
    }

    /// When the certificates this server got for send domains expire: `(domain id, seconds since
    /// 1970)`, for the metrics.
    pub(crate) fn expiries(&self) -> Vec<(String, i64)> {
        let certificates = self.certificates.read();
        self.domains
            .read()
            .iter()
            .filter_map(|domain| Some((domain.id.clone(), certificates.get(&domain.host)?.expires?)))
            .collect()
    }

    /// A check's token is known: the request that carries it reached this server.
    pub(crate) fn probe_known(&self, token: &str) -> bool {
        self.probes.lock().contains(token)
    }
}

/// Read the send domains again, after a change, a restore or a switch: from the database, or
/// none while the feature is switched off. Then no domain answers, gets a certificate or shows
/// up in a link, and all come back when it is on.
pub async fn reload(state: &AppState) {
    if !state.feature(crate::Feature::SendDomains) {
        state.send_domains.replace(Vec::new());
        return;
    }
    match state.store.send_domains().await {
        Ok(domains) => state.send_domains.replace(domains),
        Err(error) => tracing::warn!(%error, "the send domains could not be read"),
    }
}

/// `https://send.example.com`, with the scheme of the main address (http only on a test server)
/// and its port, if it has one: the same listener serves both names. `host` may bring a port of
/// its own (a request's `Host`), which then stays.
pub(crate) fn url_of(state: &AppState, host: &str) -> String {
    let (scheme, rest) = state.config.public.split_once("://").unwrap_or(("https", ""));
    let main_port = rest.split('/').next().and_then(|authority| {
        let port = authority.rsplit_once(':')?.1;
        (!port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())).then_some(port)
    });
    let has_port = host.rsplit_once(':').is_some_and(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()));
    match main_port {
        Some(port) if !has_port => format!("{scheme}://{host}:{port}"),
        _ => format!("{scheme}://{host}"),
    }
}

/// The send domains for `/uwu/v1/info`: `[{ id, url }]`.
pub(crate) fn for_info(state: &AppState) -> Vec<Value> {
    state
        .send_domains
        .all()
        .iter()
        .map(|domain| json!({ "id": domain.id, "url": url_of(state, &domain.host) }))
        .collect()
}

// ── Admin ─────────────────────────────────────────────────

async fn render(state: &AppState, domain: &SendDomain) -> Value {
    let certificate = state.send_domains.certificate(domain);
    let loaded = branding::get_scope(state, &domain.id).await;
    json!({
        "object": "sendDomain",
        "id": domain.id,
        "host": domain.host,
        "url": url_of(state, &domain.host),
        "tls": domain.tls,
        "certificate": {
            "status": certificate.status,
            "expires": certificate.expires.map(date_of),
            "error": certificate.error,
        },
        "branding": loaded.custom().then(|| loaded.json(&url_of(state, &domain.host))),
        "creationDate": domain.created,
    })
}

fn date_of(seconds: i64) -> String {
    let when = time::OffsetDateTime::from_unix_timestamp(seconds).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    uwulock_store::clock::format(when)
}

async fn list(State(state): State<AppState>, _admin: Admin) -> Json<Value> {
    let mut data = Vec::new();
    for domain in state.send_domains.all().iter() {
        data.push(render(&state, domain).await);
    }
    Json(json!({ "object": "list", "data": data, "continuationToken": null }))
}

#[derive(Deserialize)]
struct NewDomain {
    #[serde(default)]
    host: String,
    #[serde(default)]
    tls: String,
}

fn checked_tls(tls: &str) -> ApiResult<&'static str> {
    match tls {
        "acme" => Ok("acme"),
        "proxy" => Ok("proxy"),
        _ => Err(ApiError::bad("TLS is acme (the server gets the certificate) or proxy (a proxy in front has it).")),
    }
}

/// A host name as it is kept: lower case, no scheme, port or path; a name with a dot, not an
/// address; not the main host.
pub(crate) fn checked_host(state: &AppState, typed: &str) -> ApiResult<String> {
    let host = typed.trim().trim_end_matches('.').to_ascii_lowercase();
    let bad = || ApiError::bad(format!("{typed} is not a host name like send.example.com (no https://, no port)."));
    if host.is_empty() || host.len() > 253 || !host.contains('.') {
        return Err(bad());
    }
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    };
    if !host.split('.').all(label_ok) {
        return Err(bad());
    }
    if host.parse::<std::net::IpAddr>().is_ok()
        || host.split('.').next_back().is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(ApiError::bad("A send domain is a name, not an IP address."));
    }
    let main = state.host().split(':').next().unwrap_or_default().to_ascii_lowercase();
    if host == main {
        return Err(ApiError::bad("That is the server's own address; a send domain is another name."));
    }
    Ok(host)
}

async fn add(State(state): State<AppState>, admin: Admin, Json(body): Json<NewDomain>) -> ApiResult<Json<Value>> {
    let host = checked_host(&state, &body.host)?;
    let tls = checked_tls(&body.tls)?;
    let domain = match state.store.add_send_domain(&host, tls).await {
        Ok(domain) => domain,
        Err(uwulock_store::StoreError::Exists) => {
            return Err(ApiError::new(StatusCode::CONFLICT, format!("{host} is a send domain already.")).code("exists"));
        }
        Err(error) => return Err(error.into()),
    };
    reload(&state).await;
    // `/uwu/v1/info` lists the send domains.
    state.realtime.broadcast(Live::Info);
    crate::admin::record(&state, &admin, format!("added the send domain {host} ({tls})")).await;
    Ok(Json(render(&state, &domain).await))
}

#[derive(Deserialize)]
struct Change {
    #[serde(default)]
    tls: String,
}

async fn change(
    State(state): State<AppState>,
    admin: Admin,
    Path(id): Path<String>,
    Json(body): Json<Change>,
) -> ApiResult<Json<Value>> {
    let tls = checked_tls(&body.tls)?;
    let domain =
        state.store.set_send_domain_tls(&id, tls).await?.ok_or_else(|| ApiError::not_found("No such send domain."))?;
    reload(&state).await;
    crate::admin::record(&state, &admin, format!("switched the send domain {} to {tls}", domain.host)).await;
    Ok(Json(render(&state, &domain).await))
}

async fn remove(State(state): State<AppState>, admin: Admin, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let host = state.send_domains.by_id(&id).map(|domain| domain.host);
    if !state.store.delete_send_domain(&id).await? {
        return Err(ApiError::not_found("No such send domain."));
    }
    reload(&state).await;
    branding::reload(&state).await;
    state.realtime.broadcast(Live::Info);
    crate::admin::record(&state, &admin, format!("removed the send domain {}", host.unwrap_or(id))).await;
    Ok(StatusCode::OK)
}

/// Whether the name points somewhere, whether https answers there, and whether what answers is
/// this server.
async fn check(State(state): State<AppState>, _admin: Admin, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let domain = state.send_domains.by_id(&id).ok_or_else(|| ApiError::not_found("No such send domain."))?;
    Ok(Json(check_domain(&state, &domain).await))
}

pub(crate) async fn check_domain(state: &AppState, domain: &SendDomain) -> Value {
    let resolved = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((domain.host.as_str(), 443)))
        .await
        .map_err(|_| "no answer within 5 seconds".to_string())
        .and_then(|found| found.map_err(|error| error.to_string()));
    let (dns, addresses) = match resolved {
        Ok(found) => {
            let mut addresses: Vec<String> = found.map(|address| address.ip().to_string()).collect();
            addresses.dedup();
            (json!({ "ok": !addresses.is_empty(), "addresses": addresses, "error": null }), addresses)
        }
        Err(error) => (json!({ "ok": false, "addresses": [], "error": error }), Vec::new()),
    };
    if addresses.is_empty() {
        return json!({
            "dns": dns,
            "https": { "ok": false, "error": "the name does not resolve" },
            "routing": { "ok": false },
        });
    }
    let token = crate::auth::random_token(16);
    state.send_domains.probes.lock().insert(token.clone());
    let answer = probe(&url_of(state, &domain.host), &token).await;
    state.send_domains.probes.lock().remove(&token);
    let (https, routing) = match answer {
        Ok(ours) => (json!({ "ok": true, "error": null }), json!({ "ok": ours })),
        Err(error) => (json!({ "ok": false, "error": error }), json!({ "ok": false })),
    };
    json!({ "dns": dns, "https": https, "routing": routing })
}

/// `GET <url>/alive?probe=<token>`: whether it answered, and whether it was this server.
async fn probe(url: &str, token: &str) -> Result<bool, String> {
    let client = crate::outbound::client()?;
    let response = client
        .get(format!("{url}/alive?probe={token}"))
        .send()
        .await
        .map_err(|error| crate::outbound::error_text(&error))?;
    if !response.status().is_success() {
        return Err(crate::outbound::refused(response).await);
    }
    Ok(response.headers().get(PROBE_HEADER).is_some())
}

/// The header `/alive` answers a check's token with.
pub(crate) const PROBE_HEADER: &str = "x-uwulock-probe";

// ── Accounts and Sends ────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DomainChoice {
    #[serde(default)]
    send_domain_id: Option<String>,
}

fn unknown_domain() -> ApiError {
    ApiError::bad("There is no such send domain (any more).").code("invalid")
}

async fn set_account_default(
    State(state): State<AppState>,
    session: Session,
    Json(body): Json<DomainChoice>,
) -> ApiResult<Json<Value>> {
    let id = body.send_domain_id.filter(|id| !id.is_empty());
    if !state.store.set_account_send_domain(&session.user.id, id.clone()).await? {
        return Err(unknown_domain());
    }
    Ok(Json(json!({ "object": "sendDomainDefault", "sendDomainId": id })))
}

async fn choices(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let choices = state.store.send_domain_choices(&session.user.id).await?;
    Ok(Json(json!(choices)))
}

async fn choose(
    State(state): State<AppState>,
    session: Session,
    Path(send_id): Path<String>,
    Json(body): Json<DomainChoice>,
) -> ApiResult<Json<Value>> {
    let id = body.send_domain_id.filter(|id| !id.is_empty());
    match state.store.set_send_domain(&session.user.id, &send_id, id.clone()).await? {
        None => Err(ApiError::not_found("No such Send.")),
        Some(false) => Err(unknown_domain()),
        Some(true) => {
            // The UwULock clients show the link with the chosen domain (§14.2).
            crate::notify::live(&state, &session.user.id, Some(&session), Live::changed("uwu"));
            Ok(Json(json!({ "object": "sendDomainChoice", "sendId": send_id, "sendDomainId": id })))
        }
    }
}

#[cfg(test)]
mod tests;
