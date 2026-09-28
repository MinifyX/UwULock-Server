//! What a send domain answers (docs/uwu-api.md §14.1): the Send and file-request pages and the
//! few requests they make, nothing else — no web vault, no login, no admin portal.
//!
//! Send domains themselves come with Stufe 6; this is the rule their middleware asks, by the
//! request's `Host`, so file requests (§11) work under them from the first day they exist.

use axum::http::Method;

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
fn is_access_id(text: &str) -> bool {
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
