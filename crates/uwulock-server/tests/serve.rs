//! The server, started for real on a free port: over plain HTTP, and with TLS from files.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::sync::oneshot;
use uwulock_server::Config;
use uwulock_server::config::TlsMode;

struct Running {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    done: tokio::task::JoinHandle<Result<(), String>>,
}

impl Running {
    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        let finished = tokio::time::timeout(Duration::from_secs(10), self.done).await;
        finished.expect("the server stops when told to").unwrap().unwrap();
    }
}

async fn start(mut config: Config) -> Running {
    let _ = rustls::crypto::ring::default_provider().install_default();
    config.listen = "127.0.0.1:0".parse().unwrap();
    config.update_check = false;
    let store = uwulock_server::open_store(&config).unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let (ready, listening) = oneshot::channel();
    let done = tokio::spawn(uwulock_server::run(
        config,
        store,
        async move {
            let _ = stopped.await;
        },
        Some(ready),
    ));
    let addr = listening.await.expect("the server says where it listens");
    Running { addr, stop: Some(stop), done }
}

fn config_in(dir: &Path) -> Config {
    Config { data_dir: dir.to_path_buf(), ..Config::default() }
}

#[tokio::test]
async fn plain_http_answers_and_is_healthy() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(config_in(dir.path())).await;

    let body: serde_json::Value = reqwest::Client::builder()
        .tls_backend_preconfigured(roots(&[]))
        .build()
        .unwrap()
        .get(format!("http://{}/healthz", server.addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));

    let mut asked = config_in(dir.path());
    asked.listen = server.addr;
    uwulock_server::health::check(&asked).await.unwrap();

    assert!(dir.path().join("uwulock.db").exists());
    server.stop().await;
}

#[tokio::test]
async fn tls_from_files_serves_that_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let issued = rcgen::generate_simple_self_signed(vec!["vault.test".to_string()]).unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, issued.cert.pem()).unwrap();
    std::fs::write(&key, issued.signing_key.serialize_pem()).unwrap();

    let mut config = config_in(dir.path());
    config.tls = TlsMode::Files { cert: cert.clone(), key: key.clone() };
    let server = start(config.clone()).await;

    // A client that trusts exactly this certificate, under its name.
    let client = reqwest::Client::builder()
        .tls_backend_preconfigured(roots(&[issued.cert.der().clone()]))
        .resolve("vault.test", server.addr)
        .build()
        .unwrap();
    let response = client.get(format!("https://vault.test:{}/alive", server.addr.port())).send().await.unwrap();
    assert!(response.status().is_success());
    assert_eq!(response.version(), reqwest::Version::HTTP_2, "h2 is offered first");

    config.listen = server.addr;
    uwulock_server::health::check(&config).await.unwrap();
    server.stop().await;
}

#[tokio::test]
async fn files_that_do_not_go_together_stop_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let one = rcgen::generate_simple_self_signed(vec!["one.test".to_string()]).unwrap();
    let other = rcgen::generate_simple_self_signed(vec!["other.test".to_string()]).unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, one.cert.pem()).unwrap();
    std::fs::write(&key, other.signing_key.serialize_pem()).unwrap();
    let error = uwulock_server::tls::from_files(&cert, &key).unwrap_err();
    assert!(error.contains("do not go together"), "{error}");
    let error = uwulock_server::tls::from_files(&dir.path().join("missing.pem"), &key).unwrap_err();
    assert!(error.contains("missing.pem"), "{error}");
}

fn roots(extra: &[rustls::pki_types::CertificateDer<'static>]) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in extra {
        roots.add(cert.clone()).unwrap();
    }
    let mut config =
        rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

/// A certificate from an ACME CA, end to end — against Pebble, Let's Encrypt's test CA, which
/// CI starts with `PEBBLE_VA_ALWAYS_VALID=1` (it does not come knocking on the challenge, which
/// needs port 443). Run by hand:
///
/// ```sh
/// docker run -d -p 14000:14000 -e PEBBLE_VA_ALWAYS_VALID=1 ghcr.io/letsencrypt/pebble
/// curl -fsSLo /tmp/pebble.minica.pem https://raw.githubusercontent.com/letsencrypt/pebble/main/test/certs/pebble.minica.pem
/// UWULOCK_TEST_PEBBLE=https://localhost:14000/dir UWULOCK_TEST_PEBBLE_CA=/tmp/pebble.minica.pem \
///   cargo test -p uwulock-server --test serve -- --ignored
/// ```
#[tokio::test]
#[ignore = "needs Pebble, see the comment"]
async fn a_certificate_from_an_acme_ca() {
    let directory = std::env::var("UWULOCK_TEST_PEBBLE").expect("UWULOCK_TEST_PEBBLE");
    let ca = std::env::var("UWULOCK_TEST_PEBBLE_CA").expect("UWULOCK_TEST_PEBBLE_CA");
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_in(dir.path());
    config.tls = TlsMode::Acme(uwulock_server::config::Acme {
        domain: "vault.uwulock.test".into(),
        email: Some("admin@example.com".into()),
        directory,
        directory_ca: Some(ca.into()),
    });
    let server = start(config.clone()).await;
    config.listen = server.addr;

    // Healthy means: a TLS handshake under that name worked, so the certificate is there.
    let mut last = String::new();
    for _ in 0..60 {
        match uwulock_server::health::check(&config).await {
            Ok(()) => {
                assert!(dir.path().join("acme").read_dir().unwrap().next().is_some(), "the certificate is kept");
                server.stop().await;
                return;
            }
            Err(error) => last = error,
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("no certificate after 30 seconds: {last}");
}
