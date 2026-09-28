//! The certificate clients see: fetched the way a client would, with a TLS handshake to the
//! server's own address, for the diagnosis, the metrics and the admin alerts.
//!
//! Behind a proxy that is the proxy's certificate — the one that matters to the clients. With
//! TLS of its own the server asks itself on the address it listens on, with the public name, so a
//! network that does not route back to its own public address does not get in the way.

use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::Arc;
use std::time::Duration;

/// Where to shake hands, and with which name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// `host:port` to connect to.
    pub connect: String,
    /// The name to ask for (SNI) and check the certificate against.
    pub name: String,
}

/// What a handshake showed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Seen {
    /// When the certificate expires, as seconds since 1970.
    pub expires: Option<i64>,
    /// Why a client would not trust it, if it would not.
    pub problem: Option<String>,
    /// When this was looked at, in the database's format.
    pub checked: String,
}

/// Records what the usual verification says, and lets the handshake finish either way: an
/// expired certificate should still say when it expired.
#[derive(Debug)]
struct Recorder {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    seen: parking_lot::Mutex<Option<(Vec<u8>, Option<String>)>>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verdict = self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now);
        *self.seen.lock() = Some((end_entity.as_ref().to_vec(), verdict.err().map(|error| error.to_string())));
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Shake hands with `probe` and say what the certificate is like.
pub async fn look(probe: &Probe) -> Seen {
    let checked = uwulock_store::clock::now();
    match tokio::time::timeout(Duration::from_secs(10), handshake(probe)).await {
        Ok(Ok((der, problem))) => Seen { expires: not_after(&der), problem, checked },
        Ok(Err(error)) => Seen { expires: None, problem: Some(error), checked },
        Err(_) => Seen { expires: None, problem: Some("no answer within 10 seconds".into()), checked },
    }
}

async fn handshake(probe: &Probe) -> Result<(Vec<u8>, Option<String>), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|error| error.to_string())?;
    let recorder = Arc::new(Recorder { inner, seen: parking_lot::Mutex::default() });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(probe.name.clone()).map_err(|error| error.to_string())?;
    let stream = tokio::net::TcpStream::connect(&probe.connect).await.map_err(|error| error.to_string())?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    connector.connect(name, stream).await.map_err(|error| error.to_string())?;
    recorder.seen.lock().take().ok_or_else(|| "the server showed no certificate".to_string())
}

/// One DER element: its tag, its contents, and what follows it.
fn element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let bytes = usize::from(first & 0x7f);
        if bytes == 0 || bytes > 4 || rest.len() < bytes {
            return None;
        }
        let length = rest[..bytes].iter().fold(0usize, |length, byte| (length << 8) | usize::from(*byte));
        (length, &rest[bytes..])
    };
    (rest.len() >= length).then(|| (tag, &rest[..length], &rest[length..]))
}

/// When an X.509 certificate stops being valid, as seconds since 1970.
pub fn not_after(der: &[u8]) -> Option<i64> {
    let (_, certificate, _) = element(der)?;
    let (_, tbs, _) = element(certificate)?;
    let mut rest = tbs;
    // [0] version, if it is there; then serial, signature algorithm, issuer, validity.
    let (tag, _, after) = element(rest)?;
    if tag == 0xa0 {
        rest = after;
    }
    for _ in 0..3 {
        rest = element(rest)?.2;
    }
    let (_, validity, _) = element(rest)?;
    let (_, _, after_not_before) = element(validity)?;
    let (tag, when, _) = element(after_not_before)?;
    let text = std::str::from_utf8(when).ok()?;
    // UTCTime YYMMDDHHMMSSZ, GeneralizedTime YYYYMMDDHHMMSSZ.
    let full = match tag {
        0x17 => {
            let year: i32 = text.get(..2)?.parse().ok()?;
            format!("{}{}", if year >= 50 { 1900 + year } else { 2000 + year }, text.get(2..)?)
        }
        0x18 => text.to_string(),
        _ => return None,
    };
    let number = |range: std::ops::Range<usize>| full.get(range)?.parse::<u32>().ok();
    let date = time::Date::from_calendar_date(
        number(0..4)? as i32,
        time::Month::try_from(number(4..6)? as u8).ok()?,
        number(6..8)? as u8,
    )
    .ok()?;
    let at = time::Time::from_hms(number(8..10)? as u8, number(10..12)? as u8, number(12..14)? as u8).ok()?;
    Some(time::PrimitiveDateTime::new(date, at).assume_utc().unix_timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_end_of_validity_is_read_from_the_certificate() {
        let mut params = rcgen::CertificateParams::new(vec!["vault.example.com".to_string()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2031, 3, 4);
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        let expected = time::macros::datetime!(2031-03-04 00:00 UTC).unix_timestamp();
        assert_eq!(not_after(certificate.der()), Some(expected));
        let mut params = rcgen::CertificateParams::new(vec!["vault.example.com".to_string()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2051, 1, 1);
        let later = params.self_signed(&key).unwrap();
        assert_eq!(not_after(later.der()), Some(time::macros::datetime!(2051-01-01 00:00 UTC).unix_timestamp()));
        assert_eq!(not_after(b"\x30\x03\x02\x01\x00"), None);
        assert_eq!(not_after(b""), None);
    }

    #[tokio::test]
    async fn a_handshake_says_when_and_whether_it_is_trusted() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["vault.example.com".to_string()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2031, 3, 4);
        let certificate = params.self_signed(&key).unwrap();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone()],
                rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        });
        let seen = look(&Probe { connect: address.to_string(), name: "vault.example.com".into() }).await;
        assert_eq!(seen.expires, Some(time::macros::datetime!(2031-03-04 00:00 UTC).unix_timestamp()));
        assert!(seen.problem.is_some(), "self-signed: no client trusts it");
    }
}
