//! The web vault and the admin portal: one app, built into the binary, at `/` and `/admin`.
//!
//! Its files come compressed already (brotli or gzip, whichever the browser takes), those with
//! a content hash in their name are cached for good, and the page itself says where scripts may
//! come from: only here. `'wasm-unsafe-eval'` is for the vault's crypto, which is WebAssembly.

use crate::AppState;
use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use uwulock_web::Asset;

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; \
     style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; \
     worker-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/", get(app)).route("/admin", get(app)).route("/admin/", get(app))
}

async fn app(headers: HeaderMap) -> Response {
    match uwulock_web::find("/index.html") {
        Some(index) => respond(index, &headers),
        None => Html(format!(
            "<!doctype html><meta charset=\"utf-8\"><title>UwULock Server</title>\
             <p style=\"font-family:sans-serif\">UwULock Server {} is running. This build has no web vault; \
             the Bitwarden apps and UwULock work all the same.</p>",
            env!("CARGO_PKG_VERSION")
        ))
        .into_response(),
    }
}

/// Everything no route took: a file of the app, or Bitwarden's 404.
pub(crate) async fn fallback(request: Request) -> Response {
    let path = request.uri().path();
    let api = ["/api/", "/identity/", "/uwu/", "/notifications/", "/icons/", "/events/"]
        .iter()
        .any(|prefix| path.starts_with(prefix));
    if !api && let Some(asset) = uwulock_web::find(path) {
        return respond(asset, request.headers());
    }
    crate::errors::not_found().await.into_response()
}

fn respond(asset: &'static Asset, request: &HeaderMap) -> Response {
    let accepts = request.get(header::ACCEPT_ENCODING).and_then(|value| value.to_str().ok()).unwrap_or_default();
    let takes =
        |coding: &str| accepts.split(',').any(|part| part.split(';').next().is_some_and(|name| name.trim() == coding));
    let (bytes, encoding) = match (asset.brotli, asset.gzip) {
        (Some(brotli), _) if takes("br") => (brotli, Some("br")),
        (_, Some(gzip)) if takes("gzip") => (gzip, Some("gzip")),
        _ => (asset.bytes, None),
    };
    let cache = if asset.path.starts_with("/assets/") {
        // Vite puts a hash of the content into these names: a new build means new names.
        "public, max-age=31536000, immutable"
    } else if asset.path.ends_with(".html") {
        "no-cache"
    } else {
        "public, max-age=3600"
    };
    let mut response = (StatusCode::OK, bytes).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(asset.content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    if asset.brotli.is_some() || asset.gzip.is_some() {
        headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
    if let Some(encoding) = encoding {
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
    }
    if asset.content_type.starts_with("text/html") {
        headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CONTENT_SECURITY_POLICY));
        headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    }
    response
}

/// For the admin portal's overview.
pub(crate) fn is_built() -> bool {
    uwulock_web::is_built()
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn the_root_answers_with_or_without_a_build() {
        let server = TestServer::new().await;
        let response = server.get("/").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers()["content-type"].to_str().unwrap().starts_with("text/html"));
        assert_eq!(server.get("/api/nope").await.status(), StatusCode::NOT_FOUND);
        assert_eq!(server.get("/no-such-file.js").await.status(), StatusCode::NOT_FOUND);
    }
}
