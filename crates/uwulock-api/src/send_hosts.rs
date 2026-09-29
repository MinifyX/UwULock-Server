//! What a send domain answers (docs/uwu-api.md §14.1): the Send and file-request pages and the
//! few requests they make, nothing else — no web vault, no login, no admin portal.
//!
//! [`guard`] asks [`allowed`] for every request whose `Host` (or `X-Forwarded-Host` behind a
//! proxy the server trusts) is a send domain, and answers 404 for everything else there.

use crate::AppState;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Put on a request that came in on a send domain: the domain's id. Handlers that answer on send
/// domains differently (the token endpoint, `/uwu/v1/info`) look for it.
#[derive(Debug, Clone)]
pub struct SendHost(pub String);

/// On a send domain, only the paths of [`allowed`]; everywhere else, everything.
pub(crate) async fn guard(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    // HTTP/2 has no `Host` header but the `:authority`, which hyper puts into the URI: made a
    // `Host` here, so everything after this (the branding, the links) reads it the same way.
    if !request.headers().contains_key(header::HOST)
        && let Some(value) =
            request.uri().authority().and_then(|authority| HeaderValue::from_str(authority.as_str()).ok())
    {
        request.headers_mut().insert(header::HOST, value);
    }
    let host = crate::branding::request_host(&state, request.headers());
    if let Some(domain) = host.and_then(|host| state.send_domains.by_host(&host)) {
        if !allowed(request.method(), request.uri().path()) {
            return crate::errors::not_found().await.into_response();
        }
        request.extensions_mut().insert(SendHost(domain.id));
    }
    next.run(request).await
}

/// Whether a request for `path` may be answered on a send domain.
pub fn allowed(method: &Method, path: &str) -> bool {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let get = method == Method::GET || method == Method::HEAD;
    match segments.as_slice() {
        // The page's own files: the app and what it loads.
        ["assets", ..] | ["favicon.svg"] | ["favicon.ico"] | ["index.html"] | ["manifest.webmanifest"] => get,
        ["alive"] => get,
        // The file-request page (`/r/<accessId>#<secret>`) and the Send page (`/<accessId>#<key>`).
        ["r", access] | [access] => get && is_access_id(access),
        ["uwu", "v1", "info"] => get,
        ["uwu", "v1", branding, ..] if branding.starts_with("branding") => get,
        ["uwu", "v1", "public", "file-requests", ..] => true,
        ["api", "sends", "access", ..] => method == Method::POST,
        ["api", "sends", _, "access", "file", _] => method == Method::POST,
        ["api", "sends", _, _] => get,
        // Only the send access grant; the handler refuses every other grant type there.
        ["identity", "connect", "token"] => method == Method::POST,
        _ => false,
    }
}

/// An access id: 22 characters of base64url, the 16 bytes of an id.
pub(crate) fn is_access_id(text: &str) -> bool {
    text.len() == 22 && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_pages_of_sends_and_file_requests() {
        let id = "WwweLQAAQACAAAAAAACrzQ";
        for (method, path) in [
            (Method::GET, format!("/r/{id}")),
            (Method::GET, format!("/{id}")),
            (Method::GET, "/assets/index-abc.js".to_string()),
            (Method::GET, "/uwu/v1/info".to_string()),
            (Method::POST, format!("/uwu/v1/public/file-requests/{id}/open")),
            (Method::PUT, format!("/uwu/v1/public/file-requests/{id}/submissions/s/files/f")),
            (Method::POST, format!("/api/sends/access/{id}")),
            (Method::POST, "/identity/connect/token".to_string()),
        ] {
            assert!(allowed(&method, &path), "{method} {path}");
        }
        for (method, path) in [
            (Method::GET, "/".to_string()),
            (Method::GET, "/admin".to_string()),
            (Method::GET, "/api/sync".to_string()),
            (Method::GET, "/uwu/v1/file-requests".to_string()),
            (Method::POST, "/uwu/v1/keys".to_string()),
            (Method::GET, "/r/not-an-id".to_string()),
            (Method::DELETE, format!("/{id}")),
        ] {
            assert!(!allowed(&method, &path), "{method} {path}");
        }
    }
}
