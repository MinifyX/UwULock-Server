//! Requests this server makes to addresses an admin typed in: notification channels, Loki.
//!
//! Those may well be in the local network (an ntfy on the NAS), which is fine — only an admin
//! can set them. What is not fine is being sent on somewhere else: no redirects are followed,
//! only http and https are spoken, and nothing takes longer than ten seconds.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// How long any of these requests may take.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// The client for admin-configured addresses: no redirects, a short timeout, rustls with `ring`.
pub fn client() -> Result<&'static reqwest::Client, String> {
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
                .user_agent(concat!("UwULock-Server/", env!("CARGO_PKG_VERSION")))
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .timeout(TIMEOUT)
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// An address an admin typed: http or https, with a host, no user or password in it, no
/// fragment. Handed back without a trailing slash.
pub fn checked_url(typed: &str, what: &str) -> Result<String, String> {
    let typed = typed.trim();
    let url = reqwest::Url::parse(typed).map_err(|_| format!("{what}: {typed} is not an address."))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none_or(str::is_empty) {
        return Err(format!("{what}: the address has to start with http:// or https://."));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{what}: put credentials in their own fields, not into the address."));
    }
    if url.fragment().is_some() {
        return Err(format!("{what}: the address cannot have a #fragment."));
    }
    Ok(typed.trim_end_matches('/').to_string())
}

/// What went wrong with a request, with the interesting part (a refused connection, a
/// certificate) that reqwest keeps in its sources.
pub fn error_text(error: &reqwest::Error) -> String {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(inner) = source {
        let text = inner.to_string();
        if !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        source = inner.source();
    }
    message
}

/// What an error answer is read of, at most: enough for its message.
pub const ERROR_BYTES: usize = 4 * 1024;
/// A JSON answer of an OAuth or discovery endpoint, at most.
pub const JSON_BYTES: usize = 512 * 1024;

/// A response's body, at most `max` bytes: refused at once when its length says more, and
/// stopped while reading when it sends more. Every body this server reads from elsewhere goes
/// through here (or through a loop of its own with a ceiling): the only other bound is the
/// timeout, and ten seconds on a fast link are gigabytes.
pub async fn read_limited(mut response: reqwest::Response, max: usize) -> Result<Vec<u8>, String> {
    if response.content_length().is_some_and(|length| length > max as u64) {
        return Err("answered with far too much".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error_text(&error))? {
        if body.len() + chunk.len() > max {
            return Err("answered with far too much".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The start of a response's body, at most `max` bytes; the rest is not read.
pub async fn read_start(mut response: reqwest::Response, max: usize) -> Vec<u8> {
    let mut body = Vec::new();
    while body.len() < max {
        match response.chunk().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk[..chunk.len().min(max - body.len())]),
            _ => break,
        }
    }
    body
}

/// A response that is not a success, said in words: the status, and an OAuth-style `error`
/// code when the body is JSON with one. Nothing else of the body: the admin's test buttons reach
/// any address, and must not read what a service in the local network answers (SV-L19). The
/// start of the body goes to the debug log.
pub async fn refused(response: reqwest::Response) -> String {
    let status = response.status();
    if status.is_redirection() {
        return format!("answered {status} and wants to send the request elsewhere, which is not followed");
    }
    let body = read_start(response, ERROR_BYTES).await;
    let code = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| value.get("error").and_then(serde_json::Value::as_str).map(str::to_owned))
        .filter(|code| {
            (1..=40).contains(&code.len()) && code.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        });
    let start: String = String::from_utf8_lossy(&body).trim().chars().take(200).collect();
    tracing::debug!(%status, body = %start, "an error answer");
    match code {
        Some(code) => format!("answered {status} ({code})"),
        None => format!("answered {status}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review finding R3-6: a server that answers without end is not read without end.
    #[tokio::test]
    async fn answers_are_read_up_to_a_ceiling() {
        use axum::body::Body;
        let endless = || {
            let chunk = axum::body::Bytes::from(vec![b'x'; 64 * 1024]);
            Body::from_stream(tokio_stream::iter(std::iter::repeat_with(move || {
                Ok::<_, std::io::Error>(chunk.clone())
            })))
        };
        let app = axum::Router::new()
            .route(
                "/endless",
                axum::routing::get(move || async move { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, endless()) }),
            )
            .route("/long", axum::routing::get(|| async { vec![b'y'; 2 * 1024 * 1024] }))
            .route("/short", axum::routing::get(|| async { "fine" }))
            .route(
                "/oauth",
                axum::routing::get(|| async {
                    (axum::http::StatusCode::BAD_REQUEST, r#"{"error":"invalid_client","error_description":"inside"}"#)
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let get = |path: &str| client().unwrap().get(format!("{base}{path}")).send();

        let text = refused(get("/endless").await.unwrap()).await;
        assert_eq!(text, "answered 500 Internal Server Error", "only the status (SV-L19)");
        let text = refused(get("/oauth").await.unwrap()).await;
        assert_eq!(text, "answered 400 Bad Request (invalid_client)");
        assert!(read_limited(get("/endless").await.unwrap(), JSON_BYTES).await.is_err());
        assert!(read_limited(get("/long").await.unwrap(), JSON_BYTES).await.is_err(), "by its length");
        assert_eq!(read_limited(get("/short").await.unwrap(), JSON_BYTES).await.unwrap(), b"fine");
    }

    #[test]
    fn only_plain_web_addresses() {
        assert_eq!(checked_url("https://ntfy.example.com/", "ntfy").unwrap(), "https://ntfy.example.com");
        assert_eq!(checked_url("http://192.0.2.10:8080", "ntfy").unwrap(), "http://192.0.2.10:8080");
        for bad in ["ftp://ntfy.example.com", "ntfy.example.com", "https://user:pw@ntfy.example.com", "file:///etc"] {
            assert!(checked_url(bad, "ntfy").is_err(), "{bad}");
        }
    }
}
