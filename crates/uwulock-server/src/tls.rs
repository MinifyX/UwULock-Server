//! Serving: plain HTTP behind a proxy, or TLS with certificate files or one from Let's Encrypt.
//!
//! The official Bitwarden apps and the browser extension only talk to a server whose certificate
//! the system trusts, so there is no self-made certificate here, unlike UwUSync: either the
//! server gets a real one, or something in front of it has one.

use crate::config::{Acme, Config, TlsMode};
use axum::Router;
use axum_server::Handle;
use parking_lot::RwLock;
use rustls::ServerConfig;
use rustls::crypto::ring;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_acme::caches::DirCache;
use rustls_acme::{AcmeConfig, EventOk, ResolvesServerCertAcme};
use std::collections::HashMap;
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
use uwulock_api::send_domains::{Certificate, Registry};

/// HTTP/2 first, like every browser and app wants it; 1.1 for everybody else.
fn alpn() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// Serve `app` on `listener` until `handle` says stop. With TLS of its own, the send domains in
/// `send_domains` that want it get their certificates from the ACME CA too, each its own, chosen
/// by the name the client asks for (SNI).
pub async fn serve(
    listener: std::net::TcpListener,
    app: Router,
    config: &Config,
    handle: Handle<SocketAddr>,
    send_domains: Arc<Registry>,
) -> Result<(), String> {
    let local = listener.local_addr().map_err(|error| error.to_string())?;
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
    let main: Arc<dyn ResolvesServerCert> = match &config.tls {
        TlsMode::Off => {
            return server
                // Behind a proxy every connection comes from the proxy: only the total counts.
                .acceptor(Deadline(axum_server::accept::DefaultAcceptor, Connections::new(TOTAL, None)))
                .serve(service)
                .await
                .map_err(|error| error.to_string());
        }
        TlsMode::Files { cert, key } => {
            let certified = Arc::new(FileCert(RwLock::new(certified_from_files(cert, key)?)));
            watch_files(certified.clone(), cert.clone(), key.clone());
            certified
        }
        TlsMode::Acme(acme) => acme_resolver(acme, &config.acme_cache())?,
    };
    let sni = Arc::new(Sni { main, extra: RwLock::default() });
    send_domains.serving_tls();
    let own = SendDomainCertificates {
        acme: config.send_domain_acme.clone(),
        cache: config.acme_cache(),
        sni: sni.clone(),
        registry: send_domains,
        connect: if local.ip().is_unspecified() { format!("127.0.0.1:{}", local.port()) } else { local.to_string() },
    };
    tokio::spawn(own.run());
    server
        .acceptor(Deadline(SniAcceptor::new(sni)?, Connections::new(TOTAL, config.connections_per_network())))
        .serve(service)
        .await
        .map_err(|error| error.to_string())
}

// ── Certificates by name ──────────────────────────────────

/// The certificate for the name a client asks for: a send domain's own, else the main one.
#[derive(Debug)]
struct Sni {
    main: Arc<dyn ResolvesServerCert>,
    /// By host name, lower case.
    extra: RwLock<HashMap<String, Arc<ResolvesServerCertAcme>>>,
}

impl ResolvesServerCert for Sni {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let extra = hello.server_name().and_then(|name| self.extra.read().get(&name.to_ascii_lowercase()).cloned());
        match extra {
            Some(resolver) => resolver.resolve(hello),
            None => self.main.resolve(hello),
        }
    }
}

/// The certificate from files, replaced when they change.
#[derive(Debug)]
struct FileCert(RwLock<Arc<CertifiedKey>>);

impl ResolvesServerCert for FileCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.read().clone())
    }
}

/// Accepts TLS with the certificates of [`Sni`] — and answers the CA's TLS-ALPN-01 validation
/// for any of its names, which comes as a handshake with ALPN `acme-tls/1` and ends there.
#[derive(Clone)]
struct SniAcceptor {
    tls: Arc<ServerConfig>,
    challenge: Arc<ServerConfig>,
}

impl SniAcceptor {
    fn new(sni: Arc<Sni>) -> Result<Self, String> {
        let config = |alpn: Vec<Vec<u8>>| -> Result<Arc<ServerConfig>, String> {
            let mut tls = ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .map_err(|error| error.to_string())?
                .with_no_client_auth()
                .with_cert_resolver(sni.clone());
            tls.alpn_protocols = alpn;
            Ok(Arc::new(tls))
        };
        Ok(SniAcceptor { tls: config(alpn())?, challenge: config(vec![b"acme-tls/1".to_vec()])? })
    }
}

impl<I, S> axum_server::accept::Accept<I, S> for SniAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<I>;
    type Service = S;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let (tls, challenge) = (self.tls.clone(), self.challenge.clone());
        Box::pin(async move {
            let start = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream).await?;
            if rustls_acme::is_tls_alpn_challenge(&start.client_hello()) {
                start.into_stream(challenge).await?;
                return Err(io::Error::other("TLS-ALPN-01 validation request"));
            }
            Ok((start.into_stream(tls).await?, service))
        })
    }
}

/// Keeps a certificate for every send domain that wants one from the server: an ACME order of
/// its own per name, started when an admin adds it, stopped when it goes. What happens is told to
/// the [`Registry`] for the admin portal.
struct SendDomainCertificates {
    acme: Acme,
    cache: PathBuf,
    sni: Arc<Sni>,
    registry: Arc<Registry>,
    /// Where this server listens, to look at a certificate as a client sees it.
    connect: String,
}

impl SendDomainCertificates {
    async fn run(self) {
        let mut wanted = self.registry.acme_hosts();
        let mut running: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
        loop {
            let hosts: Vec<String> = wanted.borrow_and_update().clone();
            running.retain(|host, task| {
                let keep = hosts.contains(host);
                if !keep {
                    task.abort();
                    self.sni.extra.write().remove(host);
                    tracing::info!(%host, "a send domain no longer gets a certificate from the server");
                }
                keep
            });
            for host in hosts {
                if running.contains_key(&host) {
                    continue;
                }
                match self.start(&host) {
                    Ok(task) => {
                        running.insert(host, task);
                    }
                    Err(error) => self
                        .registry
                        .set_certificate(&host, Certificate { status: "failed", expires: None, error: Some(error) }),
                }
            }
            if wanted.changed().await.is_err() {
                return;
            }
        }
    }

    fn start(&self, host: &str) -> Result<tokio::task::JoinHandle<()>, String> {
        let mut settings = AcmeConfig::new_with_provider([host.to_string()], provider())
            .cache(DirCache::new(self.cache.clone()))
            .directory(&self.acme.directory);
        if let Some(email) = &self.acme.email {
            settings = settings.contact_push(format!("mailto:{email}"));
        }
        if let Some(ca) = &self.acme.directory_ca {
            settings = settings.client_tls_config(client_trusting(ca)?);
        }
        let mut state = settings.state();
        self.sni.extra.write().insert(host.to_string(), state.resolver());
        self.registry.set_certificate(host, Certificate { status: "pending", ..Certificate::default() });
        let (host, registry, connect) = (host.to_string(), self.registry.clone(), self.connect.clone());
        Ok(tokio::spawn(async move {
            while let Some(event) = state.next().await {
                match event {
                    Ok(event @ (EventOk::DeployedCachedCert | EventOk::DeployedNewCert)) => {
                        tracing::info!(%host, ?event, "send domain certificate");
                        // As a client sees it: for when it runs out.
                        let probe = uwulock_api::certificate::Probe { connect: connect.clone(), name: host.clone() };
                        let seen = uwulock_api::certificate::look(&probe).await;
                        registry
                            .set_certificate(&host, Certificate { status: "ok", expires: seen.expires, error: None });
                    }
                    Ok(event) => tracing::info!(%host, ?event, "send domain certificate"),
                    Err(error) => {
                        tracing::warn!(
                            %host,
                            %error,
                            "no certificate for the send domain yet. Does {host} point to this machine, and does port 443 reach this server?"
                        );
                        registry.set_certificate(
                            &host,
                            Certificate { status: "failed", expires: None, error: Some(error.to_string()) },
                        );
                    }
                }
            }
        }))
    }
}

/// How long a connection gets for its TLS handshake.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// How long a connection may go without a byte either way before it is closed. Longer than the
/// HTTP/2 ping interval, so a client that answers pings stays.
const IDLE: Duration = Duration::from_secs(90);

/// The most connections the server holds at once (R1-14)…
const TOTAL: usize = 8_192;
/// …and from one IPv4 address or IPv6 /64, with TLS of its own (no proxy in front), unless
/// `UWULOCK_CONNECTIONS_PER_NETWORK` says otherwise (`0`: no cap per network).
pub const PER_NETWORK: usize = 256;

/// Counts open connections, overall and per address (IPv6 by its /64), and refuses new ones past
/// the caps: a few clients that trickle bytes or answer pings must not take every file
/// descriptor (R1-14).
#[derive(Clone)]
struct Connections {
    inner: Arc<ConnectionCounts>,
}

struct ConnectionCounts {
    total: usize,
    per_network: Option<usize>,
    /// The most connections all private, loopback and link-local peers hold together, when there
    /// is a cap per network: [`shared_cap`] of the total, so that one client behind Docker's
    /// gateway can't take the slots public clients need (R8 S-1).
    shared: Option<usize>,
    open: parking_lot::Mutex<Open>,
}

#[derive(Default)]
struct Open {
    total: usize,
    shared: usize,
    per_network: HashMap<std::net::IpAddr, usize>,
}

/// Where a connection is counted besides the total.
#[derive(Clone, Copy)]
enum Slot {
    /// Only in the total (no cap per network: behind a proxy or `UWULOCK_CONNECTIONS_PER_NETWORK=0`).
    Total,
    /// Per client network.
    Network(std::net::IpAddr),
    /// Among the private, loopback and link-local peers.
    Shared,
}

/// One counted connection; the count goes down when it is dropped with its stream.
struct Counted {
    counts: Arc<ConnectionCounts>,
    slot: Slot,
}

impl Drop for Counted {
    fn drop(&mut self) {
        let mut open = self.counts.open.lock();
        open.total = open.total.saturating_sub(1);
        match self.slot {
            Slot::Total => {}
            Slot::Shared => open.shared = open.shared.saturating_sub(1),
            Slot::Network(network) => {
                if let Some(count) = open.per_network.get_mut(&network) {
                    *count -= 1;
                    if *count == 0 {
                        open.per_network.remove(&network);
                    }
                }
            }
        }
    }
}

/// The share of the total that private, loopback and link-local peers get together: all but an
/// eighth (1 024 of 8 192), which stays for clients with an address of their own.
fn shared_cap(total: usize) -> usize {
    total - total / 8
}

impl Connections {
    fn new(total: usize, per_network: Option<usize>) -> Self {
        Connections {
            inner: Arc::new(ConnectionCounts {
                total,
                per_network,
                shared: per_network.map(|_| shared_cap(total)),
                open: parking_lot::Mutex::new(Open::default()),
            }),
        }
    }

    /// A slot for a connection from `peer`, or none past a cap.
    fn take(&self, peer: Option<std::net::IpAddr>) -> Option<Counted> {
        let slot = match (self.inner.per_network, peer.map(network_of)) {
            (Some(_), Some(network)) if is_client(network) => Slot::Network(network),
            (Some(_), Some(_)) => Slot::Shared,
            _ => Slot::Total,
        };
        let mut open = self.inner.open.lock();
        if open.total >= self.inner.total {
            return None;
        }
        match slot {
            Slot::Total => {}
            Slot::Shared => {
                if self.inner.shared.is_some_and(|most| open.shared >= most) {
                    return None;
                }
                open.shared += 1;
            }
            Slot::Network(network) => {
                let most = self.inner.per_network.unwrap_or(usize::MAX);
                let count = open.per_network.entry(network).or_insert(0);
                if *count >= most {
                    return None;
                }
                *count += 1;
            }
        }
        open.total += 1;
        Some(Counted { counts: self.inner.clone(), slot })
    }
}

/// An IPv4 address as it is, an IPv6 address by its /64 (an IPv4-mapped one as IPv4).
fn network_of(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.into(),
            None => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                std::net::IpAddr::from(octets)
            }
        },
        v4 => v4,
    }
}

/// Whether `network` can be one client's own: not loopback, a private (RFC 1918, ULA) or
/// link-local address. Those are a proxy, Docker's gateway (its userland proxy hands every IPv6
/// client and, under rootless Docker, every client over with that address) or a NAT: counting
/// them per network would let one client fill the slots of everybody behind it (R5-5). They
/// count together, below the total ([`shared_cap`]), and in the total.
fn is_client(network: std::net::IpAddr) -> bool {
    match network {
        std::net::IpAddr::V4(v4) => !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()),
        std::net::IpAddr::V6(v6) => {
            !(v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local() || v6.is_unspecified())
        }
    }
}

/// Puts a deadline on every connection: the TLS handshake has to be done in [`HANDSHAKE`], and
/// after that a connection on which nothing moves for [`IDLE`] is closed. Without it, a
/// connection that sends nothing at all — not even the first byte hyper waits for to tell
/// HTTP/1 from HTTP/2 — would hold its socket for ever, and a few thousand of them would use up
/// every file descriptor the server has. It also caps how many connections are open
/// ([`Connections`]).
#[derive(Clone)]
struct Deadline<A>(A, Connections);

impl<S, A> axum_server::accept::Accept<tokio::net::TcpStream, S> for Deadline<A>
where
    A: axum_server::accept::Accept<tokio::net::TcpStream, S>,
    A::Future: Send + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = Idle<A::Stream>;
    type Service = A::Service;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let peer = stream.peer_addr().ok().map(|addr| addr.ip());
        let Some(counted) = self.1.take(peer) else {
            drop(stream);
            return Box::pin(async { Err(io::Error::other("too many connections")) });
        };
        let accepting = self.0.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = tokio::time::timeout(HANDSHAKE, accepting)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
            let mut idle = Idle::new(stream, IDLE);
            idle.counted = Some(counted);
            Ok((idle, service))
        })
    }
}

/// A stream that fails once nothing has been read or written on it for a while.
pub struct Idle<S> {
    inner: S,
    after: Duration,
    deadline: Pin<Box<tokio::time::Sleep>>,
    /// Its slot among the open connections, given back with the stream.
    counted: Option<Counted>,
}

impl<S> Idle<S> {
    fn new(inner: S, after: Duration) -> Self {
        Idle { inner, after, deadline: Box::pin(tokio::time::sleep(after)), counted: None }
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
    let certified = certified_from_files(cert, key)?;
    let mut tls = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FileCert(RwLock::new(certified))));
    tls.alpn_protocols = alpn();
    Ok(Arc::new(tls))
}

/// A certificate chain and its key from PEM files, checked to go together.
fn certified_from_files(cert: &Path, key: &Path) -> Result<Arc<CertifiedKey>, String> {
    let read = |path: &Path| std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()));
    let chain = CertificateDer::pem_slice_iter(&read(cert)?)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("{}: {error}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!("{} holds no certificate", cert.display()));
    }
    let key_der = PrivateKeyDer::from_pem_slice(&read(key)?).map_err(|error| match error {
        pem::Error::NoItemsFound => format!("{} holds no private key", key.display()),
        error => format!("{}: {error}", key.display()),
    })?;
    let certified = CertifiedKey::from_der(chain, key_der, &provider())
        .map_err(|error| format!("{} and {} do not go together: {error}", cert.display(), key.display()))?;
    Ok(Arc::new(certified))
}

/// Read the files again whenever they change: certbot renews every two months, and the server
/// should not need a restart for it. A pair that does not load — the certificate written, the
/// key not yet — keeps the one that works, and is tried again next time.
fn watch_files(current: Arc<FileCert>, cert: PathBuf, key: PathBuf) {
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
            match certified_from_files(&cert, &key) {
                Ok(certified) => {
                    *current.0.write() = certified;
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
fn acme_resolver(acme: &Acme, cache: &Path) -> Result<Arc<dyn ResolvesServerCert>, String> {
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
    let resolver = state.resolver();
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
    Ok(resolver)
}

/// A client configuration that trusts the usual roots and one more CA from a PEM file.
fn client_trusting(ca: &Path) -> Result<Arc<rustls::ClientConfig>, String> {
    let pem = std::fs::read(ca).map_err(|error| format!("{}: {error}", ca.display()))?;
    let mut roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    for cert in CertificateDer::pem_slice_iter(&pem) {
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

    #[test]
    fn connections_are_capped_overall_and_per_network() {
        let connections = Connections::new(3, Some(2));
        let a: std::net::IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: std::net::IpAddr = "2001:db8:1:2::ffff".parse().unwrap();
        let first = connections.take(Some(a)).unwrap();
        let _second = connections.take(Some(b)).unwrap();
        assert!(connections.take(Some(a)).is_none(), "the same /64 is full");
        let _third = connections.take(Some("192.0.2.1".parse().unwrap())).unwrap();
        assert!(connections.take(Some("192.0.2.2".parse().unwrap())).is_none(), "the total is full");
        drop(first);
        assert!(connections.take(Some(a)).is_some(), "a closed connection gives its slot back");
        let behind_proxy = Connections::new(2, None);
        let (_one, _two) = (behind_proxy.take(Some(a)).unwrap(), behind_proxy.take(Some(a)).unwrap());
        assert!(behind_proxy.take(Some(a)).is_none());
    }

    /// R5-5: Docker's gateway, a NAT or a proxy in front is everybody behind it, not one client.
    #[test]
    fn addresses_of_proxies_and_nat_count_only_in_the_total() {
        let connections = Connections::new(10, Some(1));
        for peer in
            ["172.18.0.1", "10.0.0.1", "192.168.1.1", "127.0.0.1", "::1", "fd00::1", "fe80::1", "::ffff:172.18.0.1"]
        {
            let peer: std::net::IpAddr = peer.parse().unwrap();
            let (_one, _two) = (connections.take(Some(peer)).unwrap(), connections.take(Some(peer)).unwrap());
        }
        let public: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        let _one = connections.take(Some(public)).unwrap();
        assert!(connections.take(Some(public)).is_none(), "a client's own address still counts");
    }

    /// R8 S-1: one client behind Docker's gateway can't take the slots public clients need.
    #[test]
    fn private_peers_share_a_cap_below_the_total() {
        let connections = Connections::new(16, Some(4));
        assert_eq!(shared_cap(16), 14);
        let gateway: std::net::IpAddr = "172.18.0.1".parse().unwrap();
        let mut held: Vec<_> = (0..14).map(|_| connections.take(Some(gateway)).unwrap()).collect();
        assert!(connections.take(Some(gateway)).is_none(), "the shared cap is full");
        assert!(connections.take(Some("::1".parse().unwrap())).is_none(), "for every private peer");
        let public: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        let _a = connections.take(Some(public)).unwrap();
        let _b = connections.take(Some("2001:db8::1".parse().unwrap())).unwrap();
        assert!(connections.take(Some(public)).is_none(), "the total is full");
        held.pop();
        held.pop();
        let _c = connections.take(Some(public)).expect("a closed private connection frees a slot");
        let _d = connections.take(Some(gateway)).unwrap();
        assert!(connections.take(Some(gateway)).is_none(), "the total is full again");
        assert_eq!(shared_cap(8_192), 7_168);
        let no_cap = Connections::new(2, None);
        let (_one, _two) = (no_cap.take(Some(gateway)).unwrap(), no_cap.take(Some(gateway)).unwrap());
    }

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
