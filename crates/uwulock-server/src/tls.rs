//! Serving: plain HTTP behind a proxy, or TLS with certificate files or one from Let's Encrypt.
//!
//! The official Bitwarden apps and the browser extension only talk to a server whose certificate
//! the system trusts, so there is no self-made certificate here, unlike UwUSync: either the
//! server gets a real one, or something in front of it has one.

use crate::config::{Acme, Config, TlsMode};
use axum::Router;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use rustls::ServerConfig;
use rustls::crypto::ring;
use rustls_acme::AcmeConfig;
use rustls_acme::caches::DirCache;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_stream::StreamExt;

/// HTTP/2 first, like every browser and app wants it; 1.1 for everybody else.
fn alpn() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// Serve `app` on `listener` until `handle` says stop.
pub async fn serve(
    listener: std::net::TcpListener,
    app: Router,
    config: &Config,
    handle: Handle<SocketAddr>,
) -> Result<(), String> {
    let service = app.into_make_service_with_connect_info::<SocketAddr>();
    let mut server = axum_server::from_tcp(listener).map_err(|error| error.to_string())?.handle(handle);
    // A client gets 20 seconds to send the head of its request: a connection that trickles it
    // in byte by byte does not keep a slot for ever. An HTTP/2 connection is pinged when idle,
    // and closed when the other side stopped answering.
    let builder = server.http_builder();
    builder.http1().timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(Duration::from_secs(20));
    builder
        .http2()
        .timer(hyper_util::rt::TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(60)))
        .keep_alive_timeout(Duration::from_secs(20))
        .max_concurrent_streams(256);
    match &config.tls {
        TlsMode::Off => server.serve(service).await,
        TlsMode::Files { cert, key } => {
            let tls = RustlsConfig::from_config(from_files(cert, key)?);
            watch_files(tls.clone(), cert.clone(), key.clone());
            server.acceptor(axum_server::tls_rustls::RustlsAcceptor::new(tls)).serve(service).await
        }
        TlsMode::Acme(acme) => {
            let acceptor = acme_acceptor(acme, &config.acme_cache())?;
            server.acceptor(acceptor).serve(service).await
        }
    }
    .map_err(|error| error.to_string())
}

/// A TLS configuration from a certificate chain and a key in PEM files.
pub fn from_files(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, String> {
    let read = |path: &Path| std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()));
    let chain = rustls_pemfile::certs(&mut read(cert)?.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("{}: {error}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!("{} holds no certificate", cert.display()));
    }
    let key_der = rustls_pemfile::private_key(&mut read(key)?.as_slice())
        .map_err(|error| format!("{}: {error}", key.display()))?
        .ok_or_else(|| format!("{} holds no private key", key.display()))?;
    let mut tls = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key_der)
        .map_err(|error| format!("{} and {} do not go together: {error}", cert.display(), key.display()))?;
    tls.alpn_protocols = alpn();
    Ok(Arc::new(tls))
}

/// Read the files again whenever they change: certbot renews every two months, and the server
/// should not need a restart for it. A pair that does not load — the certificate written, the
/// key not yet — keeps the one that works, and is tried again next time.
fn watch_files(tls: RustlsConfig, cert: PathBuf, key: PathBuf) {
    let stamp = move |cert: &Path, key: &Path| -> Option<(SystemTime, SystemTime)> {
        Some((std::fs::metadata(cert).ok()?.modified().ok()?, std::fs::metadata(key).ok()?.modified().ok()?))
    };
    tokio::spawn(async move {
        let mut seen = stamp(&cert, &key);
        let mut every = tokio::time::interval(Duration::from_secs(60));
        every.tick().await;
        loop {
            every.tick().await;
            let now = stamp(&cert, &key);
            if now.is_none() || now == seen {
                continue;
            }
            match from_files(&cert, &key) {
                Ok(config) => {
                    tls.reload_from_config(config);
                    seen = now;
                    tracing::info!(cert = %cert.display(), "certificate changed on disk; using the new one");
                }
                Err(error) => tracing::warn!(%error, "the certificate changed on disk but does not load yet"),
            }
        }
    });
}

/// Let's Encrypt over TLS-ALPN-01: the CA connects to port 443 and asks for a special
/// certificate, which only whoever controls that port can show. No port 80, no web root.
fn acme_acceptor(acme: &Acme, cache: &Path) -> Result<rustls_acme::axum::AxumAcceptor, String> {
    let mut settings = AcmeConfig::new_with_provider([acme.domain.clone()], provider())
        .cache(DirCache::new(cache.to_path_buf()))
        .directory(&acme.directory);
    if let Some(email) = &acme.email {
        settings = settings.contact_push(format!("mailto:{email}"));
    }
    if let Some(ca) = &acme.directory_ca {
        settings = settings.client_tls_config(client_trusting(ca)?);
    }
    let mut state = settings.state();

    let mut tls = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(state.resolver());
    tls.alpn_protocols = alpn();
    let acceptor = state.axum_acceptor(Arc::new(tls));

    let domain = acme.domain.clone();
    tokio::spawn(async move {
        while let Some(event) = state.next().await {
            match event {
                Ok(event) => tracing::info!(%domain, ?event, "certificate"),
                Err(error) => tracing::warn!(
                    %domain,
                    %error,
                    "no certificate yet. Does {domain} point to this machine, and does port 443 reach this server?"
                ),
            }
        }
    });
    Ok(acceptor)
}

/// A client configuration that trusts the usual roots and one more CA from a PEM file.
fn client_trusting(ca: &Path) -> Result<Arc<rustls::ClientConfig>, String> {
    let pem = std::fs::read(ca).map_err(|error| format!("{}: {error}", ca.display()))?;
    let mut roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
        let cert = cert.map_err(|error| format!("{}: {error}", ca.display()))?;
        roots.add(cert).map_err(|error| format!("{}: {error}", ca.display()))?;
    }
    let client = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(client))
}
