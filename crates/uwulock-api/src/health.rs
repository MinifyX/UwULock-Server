//! Whether the server is alive.
//!
//! `/alive` and `/api/alive` answer with the time, the way Bitwarden's server and Vaultwarden do;
//! monitoring set up for either works here too. `/api/now` is the clock the clients compare
//! theirs against. `/healthz` is UwULock's own: it also asks the database, and it is what the
//! container's health check, `install.sh` and `update.sh` wait for.

use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/alive", get(alive))
        .route("/api/alive", get(now))
        .route("/api/now", get(now))
        .route("/healthz", get(healthz))
}

#[derive(serde::Deserialize)]
struct AliveQuery {
    probe: Option<String>,
}

/// The time; and for the check of a send domain (§14.1) a header saying the request reached this
/// server, when it carries the check's token.
async fn alive(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<AliveQuery>,
) -> axum::response::Response {
    let mut response = now().await.into_response();
    if query.probe.is_some_and(|token| state.send_domains.probe_known(&token)) {
        response.headers_mut().insert(crate::send_domains::PROBE_HEADER, axum::http::HeaderValue::from_static("ok"));
    }
    response
}

async fn now() -> Json<String> {
    Json(OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default())
}

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let database = state.store.ping().await;
    if let Err(error) = &database {
        tracing::warn!(%error, "health check: the database does not answer");
    }
    let ok = database.is_ok();
    let status = if ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (
        status,
        Json(json!({
            "ok": ok,
            "version": state.version,
            "database": if ok { "ok" } else { "unavailable" },
        })),
    )
}

#[cfg(test)]
mod tests {
    use crate::test_support::{TestServer, json};
    use axum::http::StatusCode;

    #[tokio::test]
    async fn alive_is_the_time_like_bitwarden_s() {
        let server = TestServer::new().await;
        for path in ["/alive", "/api/alive", "/api/now"] {
            let response = server.get(path).await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let body = json(response).await;
            let text = body.as_str().unwrap_or_default();
            assert!(
                time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).is_ok(),
                "{path}: {body}"
            );
        }
    }

    #[tokio::test]
    async fn healthz_asks_the_database() {
        let server = TestServer::new().await;
        let response = server.get("/healthz").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        let body = json(response).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["database"], "ok");
        assert_eq!(body["version"], "0.0.0-test");
    }
}
