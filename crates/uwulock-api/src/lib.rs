//! UwULock Server's HTTP side.
//!
//! Three things share one router:
//!
//! - **Bitwarden's API**, under `/identity`, `/api` and friends, spoken the way Bitwarden's own
//!   server speaks it, so the official browser extension, apps and CLI work unchanged. That is
//!   the contract; nothing UwULock adds may bend it.
//! - **UwULock's own API**, under `/uwu/v1`, for what only UwULock's clients use — the web
//!   vault's extras and the admin portal. The official clients never call it.
//! - **The web vault and the admin portal**, at `/` and `/admin`, from the files built into the
//!   binary.

mod accounts;
mod admin;
mod auth;
mod ciphers;
mod cors;
mod errors;
mod folders;
mod health;
mod identity;
mod json;
mod limits;
mod logs;
mod meta;
mod settings;
mod totp;
mod two_factor;
mod uwu;
mod web;

pub use admin::{Invited, invite};
pub use auth::{HashCost, Tokens};
pub use errors::{ApiError, ApiResult};
pub use limits::Limits;
pub use logs::{LogBuffer, LogLine};
pub use settings::Settings;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, HeaderValue};
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use uwulock_mail::Mailer;
use uwulock_store::Store;

/// What the server tells the API about itself when it starts.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// How the clients reach this server: `https://vault.example.com`. Links in mails, the
    /// tokens' issuer and the web vault's origin come from it.
    pub public: String,
    /// Believe `X-Forwarded-For` for the address a request comes from.
    pub trust_forwarded: bool,
    /// How hard the server's own hash of the master password hash works.
    pub hash_cost: HashCost,
    /// Where backups are kept, for the admin portal.
    pub backups: PathBuf,
    /// The settings a new server starts with, until an admin saves others.
    pub start_settings: Settings,
}

/// What the admin portal says about updates. The server's daily look at GitHub fills it in.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    /// When it last looked, in the database's time format.
    pub checked: Option<String>,
    /// A newer release, if there is one.
    pub newer: Option<String>,
    pub url: Option<String>,
    /// Commits on `main` since this build, for an `edge` build.
    pub commits: Option<u32>,
    pub error: Option<String>,
    /// What this machine follows: `latest`, `beta`, `edge` or a version.
    pub channel: Option<String>,
    pub commit: Option<String>,
}

/// What every request handler can reach. Cheap to clone.
#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub version: &'static str,
    pub config: Arc<ApiConfig>,
    pub tokens: Arc<Tokens>,
    pub mailer: Mailer,
    pub settings: Arc<RwLock<Settings>>,
    pub limits: Arc<Limits>,
    pub logs: Arc<LogBuffer>,
    pub update: Arc<RwLock<UpdateInfo>>,
    pub started: std::time::Instant,
}

impl AppState {
    /// Everything the API needs, with the settings and the signing key from the database.
    pub async fn new(
        store: Store,
        config: ApiConfig,
        version: &'static str,
        logs: Arc<LogBuffer>,
    ) -> Result<Self, String> {
        let settings = Settings::load(&store, &config.start_settings).await?;
        let mailer = Mailer::new(settings.smtp.as_ref()).map_err(|error| format!("mail: {error}"))?;
        let tokens = Tokens::load(&store, &config.public).await?;
        Ok(AppState {
            store,
            version,
            config: Arc::new(config),
            tokens: Arc::new(tokens),
            mailer,
            settings: Arc::new(RwLock::new(settings)),
            limits: Arc::new(Limits::default()),
            logs,
            update: Arc::default(),
            started: std::time::Instant::now(),
        })
    }

    pub fn settings(&self) -> Settings {
        self.settings.read().clone()
    }

    /// The host part of the public address, the way people know the server.
    pub fn host(&self) -> &str {
        self.config.public.split_once("://").map_or(self.config.public.as_str(), |(_, rest)| rest)
    }
}

/// The largest request body almost everything takes.
const BODY_LIMIT: usize = 2 * 1024 * 1024;

/// An import or a key rotation brings a whole vault at once.
const VAULT_BODY_LIMIT: usize = 64 * 1024 * 1024;

/// A request that has not been answered after this long is answered with 408, rather than
/// holding its connection for ever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub fn router(state: AppState) -> Router {
    // Served over https (by this server or a proxy in front), the browser is told to never try
    // plain http for it again: a first visit by http is where a network could slip in a vault
    // page of its own that reads the master password.
    let https = state.config.public.starts_with("https://");
    let whole_vault = Router::new()
        .merge(ciphers::vault_routes())
        .merge(accounts::vault_routes())
        .layer(DefaultBodyLimit::max(VAULT_BODY_LIMIT));
    let router = Router::new()
        .merge(health::routes())
        .merge(identity::routes())
        .merge(accounts::routes())
        .merge(ciphers::routes())
        .merge(folders::routes())
        .merge(two_factor::routes())
        .merge(meta::routes())
        .merge(uwu::routes())
        .merge(admin::routes())
        .merge(whole_vault)
        .merge(web::routes())
        .fallback(web::fallback)
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(axum::middleware::from_fn_with_state(state.clone(), cors::cors))
        .with_state(state)
        .layer(TimeoutLayer::with_status_code(axum::http::StatusCode::REQUEST_TIMEOUT, REQUEST_TIMEOUT))
        // A vault is JSON, and JSON shrinks to a fraction of itself. Clients ask for gzip; brotli
        // for whoever says they take it. The web vault's files come compressed already.
        .layer(CompressionLayer::new().gzip(true).br(true))
        .layer(header("x-content-type-options", "nosniff"))
        .layer(header("referrer-policy", "same-origin"))
        .layer(header("x-robots-tag", "noindex, nofollow"))
        .layer(header("x-frame-options", "SAMEORIGIN"))
        .layer(header("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()"))
        .layer(header("cache-control", "no-store"));
    if https { router.layer(header("strict-transport-security", "max-age=63072000")) } else { router }
}

fn header(name: &'static str, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(HeaderName::from_static(name), HeaderValue::from_static(value))
}

#[cfg(test)]
pub(crate) mod test_support;
