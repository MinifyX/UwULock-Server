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
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
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
        TlsMode::Off => server.acceptor(Deadline(axum_server::accept::DefaultAcceptor)).serve(service).await,
        TlsMode::Files { cert, key } => {
            let tls = RustlsConfig::from_config(from_files(cert, key)?);
            watch_files(tls.clone(), cert.clone(), key.clone());
            server.acceptor(Deadline(axum_server::tls_rustls::RustlsAcceptor::new(tls))).serve(service).await
        }
        TlsMode::Acme(acme) => {
            let acceptor = acme_acceptor(acme, &config.acme_cache())?;
            server.acceptor(Deadline(acceptor)).serve(service).await
        }
    }
    .map_err(|error| error.to_string())
}

/// How long a connection gets for its TLS handshake.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// How long a connection may go without a byte either way before it is closed. Longer than the
/// HTTP/2 ping interval, so a client that answers pings stays.
const IDLE: Duration = Duration::from_secs(90);

/// Puts a deadline on every connection: the TLS handshake has to be done in [`HANDSHAKE`], and
/// after that a connection on which nothing moves for [`IDLE`] is closed. Without it, a
/// connection that sends nothing at all — not even the first byte hyper waits for to tell
/// HTTP/1 from HTTP/2 — would hold its socket for ever, and a few thousand of them would use up
/// every file descriptor the server has.
#[derive(Clone)]
struct Deadline<A>(A);

impl<I, S, A> axum_server::accept::Accept<I, S> for Deadline<A>
where
    A: axum_server::accept::Accept<I, S>,
    A::Future: Send + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = Idle<A::Stream>;
    type Service = A::Service;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let accepting = self.0.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = tokio::time::timeout(HANDSHAKE, accepting)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
            Ok((Idle::new(stream, IDLE), service))
        })
    }
}

/// A stream that fails once nothing has been read or written on it for a while.
pub struct Idle<S> {
    inner: S,
    after: Duration,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl<S> Idle<S> {
    fn new(inner: S, after: Duration) -> Self {
        Idle { inner, after, deadline: Box::pin(tokio::time::sleep(after)) }
    }

    fn moved(&mut self) {
        self.deadline.as_mut().reset(tokio::time::Instant::now() + self.after);
    }

    /// Pending while there is time left; an error once it ran out.
    fn check(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        self.deadline.as_mut().poll(cx).map(|()| io::Error::from(io::ErrorKind::TimedOut))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Idle<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                self.moved();
                Poll::Ready(result)
            }
            Poll::Pending => self.check(cx).map(Err),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Idle<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, data) {
            Poll::Ready(result) => {
                self.moved();
                Poll::Ready(result)
            }
            Poll::Pending => self.check(cx).map(Err),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write_vectored(cx, data) {
            Poll::Ready(result) => {
                self.moved();
                Poll::Ready(result)
            }
            Poll::Pending => self.check(cx).map(Err),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Pending => self.check(cx).map(Err),
            ready => ready,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn a_connection_on_which_nothing_moves_is_closed() {
        let (ours, mut theirs) = tokio::io::duplex(64);
        let mut idle = Idle::new(ours, Duration::from_millis(50));
        let mut buffer = [0u8; 8];
        theirs.write_all(b"hi").await.unwrap();
        assert_eq!(idle.read(&mut buffer).await.unwrap(), 2, "what arrives in time is read");
        let error = idle.read(&mut buffer).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
