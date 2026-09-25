//! UwULock Server: a Bitwarden-compatible password server, built for UwULock and fast.
//!
//! This crate is the program around the API: its settings, how it serves (plain HTTP behind a
//! proxy, or TLS of its own), the jobs it runs by itself, and the commands for a shell on the
//! box. The API is `uwulock-api`, the database `uwulock-store`.

pub mod config;
pub mod health;
pub mod tls;
pub mod updates;

pub use config::Config;

use axum_server::Handle;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use uwulock_api::{ApiConfig, AppState, HashCost, LogBuffer};
use uwulock_store::{Options, Store, backups};

/// How long open connections get to finish once the server is told to stop. Docker waits ten
/// seconds before it stops asking.
const GRACE: Duration = Duration::from_secs(5);

pub fn open_store(config: &Config) -> Result<Store, String> {
    Store::open_sqlite(&config.database(), &Options::default()).map_err(|error| error.to_string())
}

/// What the API needs: the store, the settings from the database (or the start values), the
/// signing key, the mailer.
pub async fn app_state(config: &Config, store: Store, logs: Arc<LogBuffer>) -> Result<AppState, String> {
    let api = ApiConfig {
        public: config.base_url(),
        trust_forwarded: config.trust_forwarded,
        hash_cost: HashCost::default(),
        backups: config.backups(),
        start_settings: config.start_settings.clone(),
    };
    let state = AppState::new(store, api, updates::build().version, logs).await?;
    {
        let build = updates::build();
        let mut update = state.update.write();
        update.channel = config.channel.clone();
        update.commit = build.commit.map(str::to_string);
    }
    Ok(state)
}

/// Serve until `stop` resolves, and run the jobs the server does by itself. `ready` hears where
/// the server listens once it does — for tests that ask for port 0.
pub async fn run(
    config: Config,
    store: Store,
    logs: Arc<LogBuffer>,
    stop: impl Future<Output = ()> + Send + 'static,
    ready: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .and_then(|listener| listener.into_std())
        .map_err(|error| format!("cannot listen on {}: {error}", config.listen))?;
    let local = listener.local_addr().map_err(|error| error.to_string())?;

    let state = app_state(&config, store, logs).await?;
    spawn_maintenance(config.clone(), state.clone());
    updates::spawn(Arc::new(config.clone()), state.update.clone());
    if state.mailer.enabled() {
        tracing::info!("mail is set up");
    }
    let app = uwulock_api::router(state);

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

/// Once a day: a backup, and the old ones swept away — backups, events, codes, invitations and
/// sessions that ran out, items that were in the trash for 30 days.
pub fn spawn_maintenance(config: Config, state: AppState) {
    tokio::spawn(async move {
        // Not at once on start: a server that is restarted in a loop should not write a backup
        // every time.
        tokio::time::sleep(Duration::from_secs(10 * 60)).await;
        loop {
            if let Err(error) = state.store.sweep().await {
                tracing::warn!(%error, "sweeping up did not work");
            }
            match backups::write(&state.store, &config.backups(), None).await {
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
