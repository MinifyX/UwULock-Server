//! Have I Been Pwned, asked through this server for the web vault's password check.
//!
//! The browser hashes a password with SHA-1 and sends only the first five hex digits here; this
//! server asks HIBP for every hash that starts with them (with padding, so the size of the
//! answer tells nothing either) and hands the list back. The browser looks for the rest of its
//! hash in it. Neither this server nor HIBP learns the password, and the browser never talks to
//! anybody but its own server. This server does see the five digits for as long as it answers;
//! it writes them nowhere, not into a log nor next to the account.
//!
//! Answers are kept for a day, per account: breaches do not change by the minute, and a cache
//! shared by everybody would let one person see, by how fast it answers, which prefixes somebody
//! else checked.

use crate::AppState;
use crate::auth::Session;
use crate::errors::{ApiError, ApiResult};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

const KEEP: Duration = Duration::from_secs(24 * 60 * 60);
/// About 30 KB each: this many is a few hundred MB at the very most, and far more than one
/// person's vault asks for.
const MOST: usize = 4096;
/// What an answer from HIBP may be at the most.
const MAX_ANSWER: usize = 512 * 1024;

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/hibp/{prefix}", get(range))
}

/// Answers from HIBP by account and prefix, with when they came.
#[derive(Default)]
pub struct Cache {
    ranges: Mutex<HashMap<String, (Arc<str>, Instant)>>,
}

impl Cache {
    pub(crate) fn get(&self, prefix: &str) -> Option<Arc<str>> {
        let ranges = self.ranges.lock();
        ranges.get(prefix).filter(|(_, at)| at.elapsed() < KEEP).map(|(range, _)| range.clone())
    }

    pub(crate) fn put(&self, prefix: String, range: Arc<str>) {
        let mut ranges = self.ranges.lock();
        if ranges.len() >= MOST {
            ranges.retain(|_, (_, at)| at.elapsed() < KEEP);
            if ranges.len() >= MOST {
                ranges.clear();
            }
        }
        ranges.insert(prefix, (range, Instant::now()));
    }
}

fn client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|error| error.to_string())?
                .with_root_certificates(roots)
                .with_no_client_auth();
            reqwest::Client::builder()
                .tls_backend_preconfigured(tls)
                .user_agent("UwULock-Server")
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(Clone::clone)
}

async fn fetch(base: &str, prefix: &str) -> Result<String, String> {
    let mut response = client()?
        .get(format!("{}/range/{prefix}", base.trim_end_matches('/')))
        .header("add-padding", "true")
        .send()
        .await
        .map_err(crate::breaches::quiet)?;
    if !response.status().is_success() {
        return Err(format!("HIBP answered {}", response.status()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(crate::breaches::quiet)? {
        if body.len() + chunk.len() > MAX_ANSWER {
            return Err("HIBP answered with far more than a range".into());
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| "HIBP answered with something that is not text".into())
}

async fn range(State(state): State<AppState>, session: Session, Path(prefix): Path<String>) -> ApiResult<Response> {
    if !state.settings().hibp {
        return Err(ApiError::forbidden("The check against Have I Been Pwned is turned off on this server."));
    }
    let prefix = prefix.to_ascii_uppercase();
    if prefix.len() != 5 || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::bad("A prefix is five hex digits."));
    }
    let key = format!("{}:{prefix}", session.user.id);
    let range = match state.hibp.get(&key) {
        Some(range) => range,
        None => {
            if !state.limits.hibp.take(session.user.id.clone()) {
                return Err(ApiError::too_many("Too many checks. Wait a minute and try again."));
            }
            let range: Arc<str> = fetch(&state.config.hibp_url, &prefix)
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "Have I Been Pwned did not answer");
                    ApiError::new(
                        axum::http::StatusCode::BAD_GATEWAY,
                        "Have I Been Pwned did not answer. Try again later.",
                    )
                })?
                .into();
            state.hibp.put(key, range.clone());
            range
        }
    };
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], range.to_string()).into_response())
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::http::StatusCode;

    /// HIBP on this machine, which counts how often it is asked.
    async fn fake_hibp() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let asked = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = asked.clone();
        let app = axum::Router::new().route(
            "/range/{prefix}",
            axum::routing::get(
                move |axum::extract::Path(prefix): axum::extract::Path<String>, headers: axum::http::HeaderMap| {
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(headers.get("add-padding").unwrap(), "true");
                        assert_eq!(prefix.len(), 5);
                        "00000000000000000000000000000000000:3\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0"
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), asked)
    }

    #[tokio::test]
    async fn a_range_is_asked_once_and_kept() {
        let (url, asked) = fake_hibp().await;
        let server = TestServer::with_hibp(&url).await;
        let account = server.account("nyu@example.com").await;
        let response = server.get_as(&account.token, "/uwu/v1/hibp/21bd1").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(text(response).await.contains(":3"));
        server.get_as(&account.token, "/uwu/v1/hibp/21BD1").await;
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1, "the second came from memory");
        assert_eq!(server.get_as(&account.token, "/uwu/v1/hibp/xyz").await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(server.get("/uwu/v1/hibp/21BD1").await.status(), StatusCode::UNAUTHORIZED);
        // Somebody else's check of the same prefix is asked anew: nobody sees what others checked.
        let other = server.account("mio@example.com").await;
        server.get_as(&other.token, "/uwu/v1/hibp/21BD1").await;
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_admin_can_turn_it_off() {
        let server = TestServer::with_settings(crate::Settings { hibp: false, ..crate::Settings::default() }).await;
        let account = server.account("nyu@example.com").await;
        assert_eq!(server.get_as(&account.token, "/uwu/v1/hibp/21BD1").await.status(), StatusCode::FORBIDDEN);
    }
}
