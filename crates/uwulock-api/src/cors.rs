//! CORS: which web pages may call this API from a browser.
//!
//! The browser extensions need none of it — their host permissions exempt them — and neither do
//! the apps and the CLI. What needs it is a page on another origin: the Bitwarden desktop app
//! (`bw-desktop-file://bundle`, and `file://` in older versions). The web vault is on this
//! server's own origin, which is allowed too, for a proxy that rewrites things. Nobody else.
//! A preflight is answered here, whatever the path.

use crate::AppState;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

fn allowed_origin(headers: &HeaderMap, public: &str) -> Option<HeaderValue> {
    let origin = headers.get(header::ORIGIN)?;
    let text = origin.to_str().ok()?;
    let ours = text.eq_ignore_ascii_case(public) || text == "bw-desktop-file://bundle" || text == "file://";
    ours.then(|| origin.clone())
}

pub(crate) async fn cors(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let origin = allowed_origin(request.headers(), &state.config.public);
    if request.method() == Method::OPTIONS {
        let mut response = StatusCode::OK.into_response();
        let headers = response.headers_mut();
        for (from, to) in [
            (header::ACCESS_CONTROL_REQUEST_METHOD, header::ACCESS_CONTROL_ALLOW_METHODS),
            (header::ACCESS_CONTROL_REQUEST_HEADERS, header::ACCESS_CONTROL_ALLOW_HEADERS),
        ] {
            if let Some(value) = request.headers().get(from) {
                headers.insert(to, value.clone());
            }
        }
        headers.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("3600"));
        allow(headers, origin);
        return response;
    }
    let mut response = next.run(request).await;
    allow(response.headers_mut(), origin);
    response
}

fn allow(headers: &mut HeaderMap, origin: Option<HeaderValue>) {
    headers.append(header::VARY, HeaderValue::from_static("Origin"));
    if let Some(origin) = origin {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::TestServer;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    #[tokio::test]
    async fn the_desktop_app_is_allowed_and_other_pages_are_not() {
        let server = TestServer::new().await;
        let preflight = |origin: &str| {
            Request::options("/api/sync")
                .header("origin", origin)
                .header("access-control-request-method", "GET")
                .header("access-control-request-headers", "authorization,bitwarden-client-version")
                .body(Body::empty())
                .unwrap()
        };
        let response = server.send(preflight("bw-desktop-file://bundle")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["access-control-allow-origin"], "bw-desktop-file://bundle");
        assert_eq!(response.headers()["access-control-allow-headers"], "authorization,bitwarden-client-version");

        let response = server.send(preflight("https://evil.example.net")).await;
        assert!(response.headers().get("access-control-allow-origin").is_none());

        let request =
            Request::get("/api/config").header("origin", "https://vault.example.com").body(Body::empty()).unwrap();
        let response = server.send(request).await;
        assert_eq!(response.headers()["access-control-allow-origin"], "https://vault.example.com");
    }
}
