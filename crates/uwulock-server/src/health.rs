//! `uwulock-server health`: the container's health check, asked from inside.
//!
//! The image has no shell and no curl, so the binary asks itself: `/healthz` where the server
//! listens, over whatever it serves — plain HTTP, or TLS under the name its certificate is for.
//! The certificate is not checked. This is the server asking itself on loopback whether it
//! answers; whether the world trusts its certificate is a different question, and Let's Encrypt
//! answers that one.
//!
//! With Let's Encrypt the server only counts as healthy once it has a certificate: without one,
//! no client could talk to it, and `install.sh` should say so rather than call it done.

use crate::config::{Config, TlsMode};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Ask the running server, and say what is wrong if it is not well.
pub fn probe(config: &Config) -> Result<(), String> {
    let runtime =
        tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|error| error.to_string())?;
    runtime.block_on(check(config))?;
    println!("ok");
    Ok(())
}

pub async fn check(config: &Config) -> Result<(), String> {
    let local = local(config.listen);
    let (scheme, host) = match &config.tls {
        TlsMode::Off => ("http", local.to_string()),
        TlsMode::Files { .. } => ("https", local.to_string()),
        // The certificate is looked up by the name the client asks for, so ask for that name,
        // and have it lead to loopback.
        TlsMode::Acme(acme) => ("https", format!("{}:{}", acme.domain, local.port())),
    };
    let mut client = reqwest::Client::builder()
        .tls_backend_preconfigured(any_certificate())
        .timeout(Duration::from_secs(5))
        .no_proxy();
    if let TlsMode::Acme(acme) = &config.tls {
        client = client.resolve(&acme.domain, local);
    }
    let client = client.build().map_err(|error| error.to_string())?;
    let url = format!("{scheme}://{host}/healthz");
    let response = client.get(&url).send().await.map_err(|error| format!("{url}: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("{url} answered {}", response.status()));
    }
    let health: serde_json::Value =
        response.json().await.map_err(|error| format!("{url} answered something else: {error}"))?;
    if health["ok"] != true {
        return Err(format!("{url} says it is not well: {health}"));
    }
    Ok(())
}

/// Where to knock: a server listening on every address is asked on loopback.
fn local(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, listen.port())
}

fn any_certificate() -> rustls::ClientConfig {
    let provider = Arc::new(ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring speaks the versions rustls asks for")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate { provider }))
        .with_no_client_auth()
}

/// Takes any certificate, but still checks that the handshake was signed by the key in it: the
/// connection is real TLS, only nobody vouches for the name.
#[derive(Debug)]
struct AnyCertificate {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_on_every_address_is_asked_on_loopback() {
        assert_eq!(local("0.0.0.0:8443".parse().unwrap()), "127.0.0.1:8443".parse().unwrap());
        assert_eq!(local("[::]:8443".parse().unwrap()), "[::1]:8443".parse().unwrap());
        assert_eq!(local("192.0.2.5:9000".parse().unwrap()), "192.0.2.5:9000".parse().unwrap());
    }
}
