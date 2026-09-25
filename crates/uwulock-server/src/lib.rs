//! UwULock Server: a Bitwarden-compatible password server, built for UwULock and fast.
//!
//! This crate is the program around the API: its settings, how it serves (plain HTTP behind a
//! proxy, or TLS of its own), the jobs it runs by itself, and the commands for a shell on the
//! box. The API is `uwulock-api`, the database `uwulock-store`.

pub mod backups;
pub mod config;
pub mod health;
pub mod tls;
pub mod updates;

pub use config::Config;

use axum_server::Handle;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use uwulock_store::{Options, Store};

/// How long open connections get to finish once the server is told to stop. Docker waits ten
/// seconds before it stops asking.
const GRACE: Duration = Duration::from_secs(5);

pub fn open_store(config: &Config) -> Result<Store, String> {
    Store::open_sqlite(&config.database(), &Options::default()).map_err(|error| error.to_string())
}

/// Serve until `stop` resolves. `ready` hears where the server listens once it does — for
/// tests that ask for port 0.
pub async fn run(
    config: Config,
    store: Store,
    stop: impl Future<Output = ()> + Send + 'static,
    ready: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .and_then(|listener| listener.into_std())
        .map_err(|error| format!("cannot listen on {}: {error}", config.listen))?;
    let local = listener.local_addr().map_err(|error| error.to_string())?;

    let app = uwulock_api::router(uwulock_api::AppState { store, version: updates::build().version });

    let handle = Handle::new();
    tokio::spawn({
        let handle = handle.clone();
        async move {
            stop.await;
            tracing::info!("stopping");
            handle.graceful_shutdown(Some(GRACE));
        }
    });

    let url = config.base_url();
    match &config.tls {
        config::TlsMode::Off => tracing::info!(
            listen = %local, %url,
            "serving plain HTTP — Bitwarden's apps need https, so a reverse proxy with a certificate belongs in front"
        ),
        config::TlsMode::Files { cert, .. } => {
            tracing::info!(listen = %local, %url, cert = %cert.display(), "serving TLS with the certificate from files")
        }
        config::TlsMode::Acme(acme) => tracing::info!(
            listen = %local, %url, domain = %acme.domain, directory = %acme.directory,
            "serving TLS with a certificate from Let's Encrypt"
        ),
    }
    if let Some(ready) = ready {
        let _ = ready.send(local);
    }
    tls::serve(listener, app, &config, handle).await
}

/// Ctrl-C at a terminal, SIGTERM from `docker stop`. The second matters more: a process that is
/// PID 1 in a container and has no handler for it does not stop at all, and gets killed ten
/// seconds later.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

/// Once a day: a backup, and the old ones swept away.
pub fn spawn_maintenance(config: Config, store: Store) {
    tokio::spawn(async move {
        // Not at once on start: a server that is restarted in a loop should not write a backup
        // every time.
        tokio::time::sleep(Duration::from_secs(10 * 60)).await;
        loop {
            match backups::write(&store, &config, None).await {
                Ok(path) => {
                    tracing::info!(path = %path.display(), "nightly backup written");
                    backups::keep_newest(&config.backups(), backups::KEPT);
                }
                Err(error) => tracing::warn!("no backup tonight: {error}"),
            }
            tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
        }
    });
}
