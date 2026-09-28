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

/// A response that is not a success, said in words: the status and the start of the body.
pub async fn refused(response: reqwest::Response) -> String {
    let status = response.status();
    if status.is_redirection() {
        return format!("answered {status} and wants to send the request elsewhere, which is not followed");
    }
    let body = response.text().await.unwrap_or_default();
    let body: String = body.trim().chars().take(200).collect();
    if body.is_empty() { format!("answered {status}") } else { format!("answered {status}: {body}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_web_addresses() {
        assert_eq!(checked_url("https://ntfy.example.com/", "ntfy").unwrap(), "https://ntfy.example.com");
        assert_eq!(checked_url("http://192.0.2.10:8080", "ntfy").unwrap(), "http://192.0.2.10:8080");
        for bad in ["ftp://ntfy.example.com", "ntfy.example.com", "https://user:pw@ntfy.example.com", "file:///etc"] {
            assert!(checked_url(bad, "ntfy").is_err(), "{bad}");
        }
    }
}
