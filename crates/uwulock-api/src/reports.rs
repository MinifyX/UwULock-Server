//! The password check's reports (docs/uwu-api.md §15): the last health report, kept as the
//! client encrypted it, and the list of [2FA Directory](https://2fa.directory/), mirrored for the
//! report "2FA possible, not set up".
//!
//! The web vault compares its items' websites with the list in the browser, so the server never
//! learns which sites are in a vault; and it gets the list from here, so the browser never talks
//! to anybody else. The server fetches it the first time somebody asks, then once a day, through
//! the same checked client as website icons.
//!
//! Source: `https://api.2fa.directory/v3/all.json` — 2FA Directory's public API, the data of
//! github.com/2factorauth/twofactorauth under the MIT licence, checked on 2026-09-29. Attribution
//! is required when the data is passed on; it travels in every answer as `source`.

use crate::auth::Session;
use crate::errors::{ApiError, ApiResult};
use crate::{AppState, icon_fetch, icons::Icons};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use parking_lot::RwLock;
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use uwulock_store::clock;

/// Where the list comes from.
pub const UPSTREAM: &str = "https://api.2fa.directory/v3/all.json";
/// The list is about half a megabyte; far more is not it.
const MOST_BYTES: usize = 8 * 1024 * 1024;
/// Sites past this many are not taken.
const MOST_ENTRIES: usize = 50_000;

/// The stored health report, at most (as the text of its EncString).
const REPORT_BYTES: usize = 1024 * 1024;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/twofa-directory", get(directory))
        .route("/uwu/v1/reports/health", get(health_report).put(set_health_report).delete(delete_health_report))
}

// ── The health report ─────────────────────────────────────

fn report_object(stored: Option<(String, String)>) -> Value {
    let (data, revision) = stored.map_or((None, None), |(data, revision)| (Some(data), Some(revision)));
    json!({ "object": "healthReport", "data": data, "revisionDate": revision })
}

async fn health_report(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    Ok(Json(report_object(state.store.health_report(&session.user.id).await?)))
}

#[derive(Deserialize)]
struct ReportBody {
    data: String,
}

async fn set_health_report(
    State(state): State<AppState>,
    session: Session,
    Json(body): Json<ReportBody>,
) -> ApiResult<Json<Value>> {
    if body.data.len() > REPORT_BYTES {
        return Err(ApiError::bad("The report is too large."));
    }
    // Only what the client encrypted: an EncString of type 2.
    if !body.data.starts_with("2.") || body.data.split('|').count() != 3 {
        return Err(ApiError::bad("The report has to be encrypted."));
    }
    let revision = state.store.set_health_report(&session.user.id, &body.data).await?;
    Ok(Json(report_object(Some((body.data, revision)))))
}

async fn delete_health_report(State(state): State<AppState>, session: Session) -> ApiResult<StatusCode> {
    state.store.delete_health_report(&session.user.id).await?;
    Ok(StatusCode::OK)
}

// ── 2FA Directory ─────────────────────────────────────────

/// The list as it is handed out.
struct Mirrored {
    body: String,
    etag: String,
}

/// The mirror: in memory, and on disk beside the icons.
#[derive(Default)]
pub struct Directory {
    mirrored: RwLock<Option<Arc<Mirrored>>>,
    refreshing: tokio::sync::Mutex<()>,
}

fn file(icons: &Icons) -> PathBuf {
    icons.dir().join("twofa-directory.json")
}

fn mirrored(body: String) -> Mirrored {
    let etag = format!(
        "\"{}\"",
        crate::auth::sha256(body.as_bytes())[..12].iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    Mirrored { body, etag }
}

impl Directory {
    /// From memory, else from disk, else fetched now.
    async fn get(&self, icons: &Icons) -> Option<Arc<Mirrored>> {
        if let Some(list) = self.mirrored.read().clone() {
            return Some(list);
        }
        if let Ok(body) = tokio::fs::read_to_string(file(icons)).await
            && serde_json::from_str::<Value>(&body).is_ok()
        {
            let list = Arc::new(mirrored(body));
            *self.mirrored.write() = Some(list.clone());
            return Some(list);
        }
        if let Err(error) = self.refresh(icons).await {
            tracing::warn!(%error, "2FA Directory's list could not be fetched");
        }
        self.mirrored.read().clone()
    }

    /// Fetch the list again and keep it.
    pub async fn refresh(&self, icons: &Icons) -> Result<(), String> {
        let _one_at_a_time = self.refreshing.lock().await;
        let (client, upstream) = icons.fetcher().ok_or("no HTTP client")?;
        let url = url::Url::parse(&upstream.twofa).map_err(|error| error.to_string())?;
        let fetched = tokio::time::timeout(Duration::from_secs(60), icon_fetch::get(client, upstream, url, MOST_BYTES))
            .await
            .map_err(|_| "it took too long".to_string())??;
        if !(200..300).contains(&fetched.status) || fetched.cut {
            return Err(format!("the list answered {}", fetched.status));
        }
        let body = convert(&fetched.bytes, &clock::now())?;
        tokio::fs::create_dir_all(icons.dir()).await.map_err(|error| error.to_string())?;
        let temporary = file(icons).with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&temporary, body.as_bytes()).await.map_err(|error| error.to_string())?;
        tokio::fs::rename(&temporary, file(icons)).await.map_err(|error| error.to_string())?;
        *self.mirrored.write() = Some(Arc::new(mirrored(body)));
        Ok(())
    }

    /// Whether anybody asked for the list yet: only then is it fetched every day.
    async fn in_use(&self, icons: &Icons) -> bool {
        self.mirrored.read().is_some() || tokio::fs::metadata(file(icons)).await.is_ok()
    }
}

/// 2FA Directory's `all.json` — `[["Name", {"domain", "additional-domains", "tfa", "documentation",
/// …}], …]` — as §15's object: only sites that offer a second factor, with only what the report
/// needs.
fn convert(bytes: &[u8], now: &str) -> Result<String, String> {
    let list: Vec<(String, Value)> =
        serde_json::from_slice(bytes).map_err(|error| format!("the list could not be read: {error}"))?;
    let text = |value: &Value| value.as_str().map(str::trim).filter(|text| !text.is_empty()).map(str::to_string);
    let domain = |value: &Value| {
        text(value).map(|domain| domain.to_ascii_lowercase()).filter(|domain| {
            domain.len() <= 253
                && domain.contains('.')
                && domain.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
        })
    };
    let entries: Vec<Value> = list
        .iter()
        .take(MOST_ENTRIES)
        .filter_map(|(name, site)| {
            let methods: Vec<String> =
                site.get("tfa")?.as_array()?.iter().filter_map(text).filter(|method| method.len() <= 40).collect();
            if methods.is_empty() {
                return None;
            }
            let additional: Vec<String> = site
                .get("additional-domains")
                .and_then(Value::as_array)
                .map(|list| list.iter().filter_map(domain).collect())
                .unwrap_or_default();
            // Only links a page may show: https, nothing else.
            let documentation = site
                .get("documentation")
                .and_then(text)
                .filter(|link| link.starts_with("https://") && link.len() <= 2048);
            Some(json!({
                "domain": domain(site.get("domain")?)?,
                "additionalDomains": additional,
                "name": name.chars().take(200).collect::<String>(),
                "methods": methods,
                "documentation": documentation,
            }))
        })
        .collect();
    if entries.is_empty() {
        return Err("the list has no sites".into());
    }
    Ok(json!({
        "object": "twofaDirectory",
        "updated": now,
        "source": {
            "name": "2FA Directory",
            "url": "https://2fa.directory/",
            "license": "MIT, © 2factorauth and contributors (github.com/2factorauth/twofactorauth)",
        },
        "entries": entries,
    })
    .to_string())
}

async fn directory(State(state): State<AppState>, _session: Session, headers: HeaderMap) -> ApiResult<Response> {
    let list = state
        .twofa
        .get(&state.icons)
        .await
        .ok_or_else(|| ApiError::upstream("2FA Directory's list could not be fetched. Try again later."))?;
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

/// Once a day: the list again, if anybody uses it.
pub async fn daily(state: &AppState) {
    if state.twofa.in_use(&state.icons).await
        && let Err(error) = state.twofa.refresh(&state.icons).await
    {
        tracing::warn!(%error, "2FA Directory's list could not be fetched");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestServer, json as body};

    #[tokio::test]
    async fn the_health_report_is_kept_encrypted_per_account() {
        let server = TestServer::new().await;
        let nyu = server.account("nyu@example.com").await;
        let other = server.account("other@example.com").await;
        let empty = body(server.get_as(&nyu.token, "/uwu/v1/reports/health").await).await;
        assert_eq!(empty, json!({ "object": "healthReport", "data": null, "revisionDate": null }));
        let plain =
            server.call("PUT", "/uwu/v1/reports/health", Some(&nyu.token), json!({ "data": "{\"weak\":3}" })).await;
        assert_eq!(plain.status(), StatusCode::BAD_REQUEST);
        let saved =
            server.call("PUT", "/uwu/v1/reports/health", Some(&nyu.token), json!({ "data": "2.iv|ct|mac" })).await;
        assert_eq!(body(saved).await["data"], "2.iv|ct|mac");
        assert_eq!(body(server.get_as(&nyu.token, "/uwu/v1/reports/health").await).await["data"], "2.iv|ct|mac");
        assert!(body(server.get_as(&other.token, "/uwu/v1/reports/health").await).await["data"].is_null());
        let deleted = server.call("DELETE", "/uwu/v1/reports/health", Some(&nyu.token), Value::Null).await;
        assert_eq!(deleted.status(), StatusCode::OK);
        assert!(body(server.get_as(&nyu.token, "/uwu/v1/reports/health").await).await["data"].is_null());
    }

    #[test]
    fn the_list_keeps_what_the_report_needs() {
        let upstream = json!([
            ["Example", {"domain": "Example.com", "additional-domains": ["example.net", "not a domain"],
                "tfa": ["sms", "totp", "u2f"], "documentation": "https://example.com/help/2fa", "keywords": ["x"]}],
            ["Mail only", {"domain": "mail.example.org", "tfa": ["email"], "documentation": "javascript:alert(1)"}],
            ["None", {"domain": "none.example.com", "contact": {"twitter": "x"}}],
            ["Broken", {"domain": "<script>", "tfa": ["totp"]}],
        ]);
        let converted: Value =
            serde_json::from_str(&convert(upstream.to_string().as_bytes(), "2026-09-29T00:00:00Z").unwrap()).unwrap();
        assert_eq!(converted["object"], "twofaDirectory");
        assert!(converted["source"]["license"].as_str().unwrap().starts_with("MIT"));
        let entries = converted["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entries[0]["domain"], "example.com");
        assert_eq!(entries[0]["additionalDomains"], json!(["example.net"]));
        assert_eq!(entries[0]["methods"], json!(["sms", "totp", "u2f"]));
        assert!(entries[0].get("keywords").is_none());
        assert!(entries[1]["documentation"].is_null(), "only https links");
        assert!(convert(b"{}", "now").is_err());
        assert!(convert(b"[]", "now").is_err());
    }
}
