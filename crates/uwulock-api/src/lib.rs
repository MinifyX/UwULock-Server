//! UwULock Server's HTTP side.
//!
//! Two APIs share one router:
//!
//! - **Bitwarden's**, under `/identity`, `/api`, `/notifications` and friends, spoken the way
//!   Bitwarden's own server speaks it, so the official browser extension, apps and CLI work
//!   unchanged. That is the contract; nothing UwULock adds may bend it.
//! - **UwULock's own**, under `/uwu/v1`, for what only UwULock's clients know how to use. The
//!   official clients never call it, so it cannot get in their way.
//!
//! Version 0.0 has neither yet: only the endpoints that say the server is alive. The rest comes
//! stage by stage, see `docs/plan.md`.

mod errors;
mod health;

pub use errors::ApiError;

use axum::Router;
use axum::http::{HeaderName, HeaderValue};
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use uwulock_store::Store;

/// What every request handler can reach.
#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub version: &'static str,
}

/// The largest request body anything takes for now. Attachments and sends get limits of their
/// own when they come.
const BODY_LIMIT: usize = 2 * 1024 * 1024;

/// A request that has not been answered after this long is answered with 408, rather than
/// holding its connection for ever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(health::routes())
        .fallback(errors::not_found)
        .with_state(state)
        .layer(TimeoutLayer::with_status_code(axum::http::StatusCode::REQUEST_TIMEOUT, REQUEST_TIMEOUT))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT))
        // A vault is JSON, and JSON shrinks to a fraction of itself. Clients ask for gzip; brotli
        // for whoever says they take it.
        .layer(CompressionLayer::new().gzip(true).br(true))
        .layer(header("x-content-type-options", "nosniff"))
        .layer(header("referrer-policy", "same-origin"))
        .layer(header("x-robots-tag", "noindex, nofollow"))
}

fn header(name: &'static str, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(HeaderName::from_static(name), HeaderValue::from_static(value))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, Response};
    use tower::ServiceExt;

    pub(crate) struct TestServer {
        pub router: Router,
        _dir: tempfile::TempDir,
    }

    impl TestServer {
        pub(crate) fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store =
                Store::open_sqlite(&dir.path().join("uwulock.db"), &uwulock_store::Options { readers: 2 }).unwrap();
            Self { router: router(AppState { store, version: "0.0.0-test" }), _dir: dir }
        }

        pub(crate) async fn get(&self, path: &str) -> Response<Body> {
            self.router.clone().oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap()
        }
    }

    pub(crate) async fn json(response: Response<Body>) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}
