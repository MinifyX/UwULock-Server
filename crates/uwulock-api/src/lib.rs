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

// `json!` for an organisation in the profile has as many keys as Bitwarden's model.
#![recursion_limit = "256"]

mod accounts;
mod admin;
pub mod alerts;
mod attachments;
mod auth;
mod auth_requests;
pub mod branding;
pub mod certificate;
mod ciphers;
mod cors;
pub mod diagnosis;
pub mod emergency;
mod errors;
mod families;
pub mod features;
pub mod file_requests;
pub mod files;
mod folders;
mod health;
mod hibp;
pub mod icon_fetch;
pub mod icons;
mod identity;
mod invitations;
mod json;
mod keys;
mod limits;
mod logs;
pub mod loki;
mod masked;
mod meta;
pub mod metrics;
pub mod networks;
pub mod notices;
mod notifications;
pub(crate) mod notify;
pub mod offsite;
pub(crate) mod oidc;
mod org_collections;
mod org_members;
mod organizations;
pub mod outbound;
mod palette;
mod passkeys;
pub mod policies;
mod realtime;
pub mod reminders;
pub mod reports;
pub mod scim;
pub mod secret;
mod send_codes;
pub mod send_domains;
pub mod send_hosts;
mod sends;
mod settings;
pub mod sso;
mod suite;
mod sync;
mod totp;
mod travel;
mod two_factor;
mod uwu;
pub mod vaultwarden;
mod versions;
mod web;
mod webauthn;

pub use admin::{Invited, invite};
pub use auth::{HashCost, LEGACY_HASH, Tokens};
pub use errors::{ApiError, ApiResult};
pub use features::{Feature, Features};
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
use tower_http::compression::predicate::{NotForContentType, Predicate};
use tower_http::compression::{CompressionLayer, DefaultPredicate};
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
    /// The data directory: attachments and the files of Sends go below it.
    pub data: PathBuf,
    /// Have I Been Pwned's range API, which the password check asks through this server.
    pub hibp_url: String,
    /// How many logins one address may try at once.
    pub login_attempts: u32,
    /// The settings a new server starts with, until an admin saves others.
    pub start_settings: Settings,
    /// The feature switches a new server starts with (`UWULOCK_FEATURES`), until an admin
    /// switches one.
    pub start_features: Features,
    /// Where the diagnosis and the metrics look at the certificate clients get; none for a
    /// server at an http address.
    pub certificate_probe: Option<certificate::Probe>,
    /// Servers whose `Date` the diagnosis compares the clock with.
    pub time_sources: Vec<String>,
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
    /// Which extras are switched on (docs/features.md).
    pub features: Arc<RwLock<Features>>,
    pub limits: Arc<Limits>,
    pub logs: Arc<LogBuffer>,
    pub update: Arc<RwLock<UpdateInfo>>,
    pub started: std::time::Instant,
    /// Who WebAuthn is for: this server's host and origin.
    pub party: webauthn::Party,
    /// WebAuthn challenges that wait for their answer.
    pub challenges: Arc<webauthn::Challenges>,
    /// What Have I Been Pwned answered lately.
    pub hibp: Arc<hibp::Cache>,
    /// The most PBKDF2 rounds of the password hashes from Vaultwarden still waiting for a login,
    /// or 0: see [`auth::verify_login`].
    pub legacy_rounds: Arc<std::sync::atomic::AtomicU32>,
    /// Uploads running, per account.
    pub uploads: Arc<files::Uploads>,
    /// "Log in with a device" requests for addresses without an account.
    pub unanswerable: Arc<auth_requests::Unanswerable>,
    /// Who listens for live updates.
    pub hub: Arc<uwulock_notify::Hub>,
    /// Who listens on UwULock's own realtime channel.
    pub realtime: Arc<uwulock_notify::realtime::Realtime>,
    /// Bitwarden's push relay, for the phone apps.
    pub relay: uwulock_notify::relay::Relay,
    /// What `/metrics` counts.
    pub metrics: Arc<metrics::Metrics>,
    /// What the admins hear of: events going on, the channels' state.
    pub alerts: Arc<alerts::Alerts>,
    /// The certificate clients see, as last looked at.
    pub certificate: Arc<RwLock<Option<certificate::Seen>>>,
    /// Told whenever an admin saved the settings, for what runs beside the requests.
    pub settings_changed: Arc<tokio::sync::Notify>,
    /// When the admin networks were last read again from the database, as seconds since 1970.
    pub admin_reloaded: Arc<std::sync::atomic::AtomicI64>,
    /// One-time tickets for the admin portal's WebSocket check.
    pub socket_tickets: Arc<diagnosis::SocketTickets>,
    /// The backups to another system: SFTP, S3 or a mounted folder.
    pub offsite: uwulock_backup::Offsite,
    /// The key for secrets at rest, like the OpenID Connect client secret.
    pub secret: Arc<secret::ServerSecret>,
    /// What the OpenID Connect provider said about itself, and its keys.
    pub oidc: Arc<oidc::Cache>,
    /// Websites' icons and the icon library, fetched by the server.
    pub icons: Arc<icons::Icons>,
    /// The server's name, colour and pictures, as read from the database.
    pub branding: Arc<branding::Cache>,
    /// The codes mailed for Sends only given addresses may open.
    pub send_codes: Arc<send_codes::SendCodes>,
    /// 2FA Directory's list, mirrored for the password check.
    pub twofa: Arc<reports::Directory>,
    /// The send domains, and what the TLS side says about their certificates.
    pub send_domains: Arc<send_domains::Registry>,
    /// Masked addresses: connects waiting for UwUMail's answer, the refresh locks.
    pub masked: Arc<masked::Masked>,
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
        let features = Features::load(&store, &config.start_features).await?;
        let mailer = Mailer::new(settings.smtp.as_ref()).map_err(|error| format!("mail: {error}"))?;
        let tokens = Tokens::load(&store, &config.public).await?;
        let party = webauthn::Party::from_public(&config.public);
        let limits = Arc::new(Limits::with_login_attempts(config.login_attempts));
        let legacy_rounds = store.legacy_rounds().await.map_err(|error| error.to_string())?;
        logs.loki().configure(&settings.loki);
        let host = config.public.split_once("://").map_or(config.public.as_str(), |(_, rest)| rest).to_string();
        let offsite = uwulock_backup::Offsite::new(store.clone(), &config.data, &host, version);
        let alerts = Arc::new(alerts::Alerts::default());
        let config_data = config.data.clone();
        store.set_version_rule(settings.versions.rule(features.on(Feature::Versions)));
        let icons = Arc::new(icons::Icons::new(&config.data, icon_fetch::Upstream::default()));
        if let Some(success) = offsite.status().await.last_success {
            alerts.offsite_succeeded(success.max(0) as u64);
        }
        let state = AppState {
            store,
            version,
            config: Arc::new(config),
            tokens: Arc::new(tokens),
            mailer,
            settings: Arc::new(RwLock::new(settings)),
            features: Arc::new(RwLock::new(features)),
            limits,
            logs,
            update: Arc::default(),
            started: std::time::Instant::now(),
            party,
            challenges: Arc::default(),
            hibp: Arc::default(),
            unanswerable: Arc::default(),
            uploads: Arc::default(),
            legacy_rounds: Arc::new(std::sync::atomic::AtomicU32::new(legacy_rounds)),
            hub: Arc::default(),
            realtime: Arc::default(),
            relay: uwulock_notify::relay::Relay::default(),
            metrics: Arc::default(),
            alerts,
            certificate: Arc::default(),
            settings_changed: Arc::default(),
            admin_reloaded: Arc::default(),
            socket_tickets: Arc::default(),
            secret: Arc::new(secret::ServerSecret::new(&config_data)),
            offsite,
            oidc: Arc::default(),
            icons,
            branding: Arc::default(),
            send_codes: Arc::default(),
            twofa: Arc::default(),
            send_domains: Arc::default(),
            masked: Arc::default(),
        };
        send_domains::reload(&state).await;
        branding::reload(&state).await;
        Ok(state)
    }

    /// Settings an admin saved, or a restore brought, take effect everywhere.
    pub fn apply_settings(&self, settings: Settings) {
        self.logs.loki().configure(&settings.loki);
        self.store.set_version_rule(settings.versions.rule(self.feature(Feature::Versions)));
        *self.settings.write() = settings;
        self.settings_changed.notify_one();
        // `/uwu/v1/info` says something else now.
        self.realtime.broadcast(uwulock_notify::realtime::Live::Info);
    }

    /// Look again at how many hashes from Vaultwarden are left, after one was replaced or the
    /// database changed under the server.
    pub async fn count_legacy_hashes(&self) {
        match self.store.legacy_rounds().await {
            Ok(rounds) => self.legacy_rounds.store(rounds, std::sync::atomic::Ordering::Relaxed),
            Err(error) => tracing::warn!(%error, "the hashes from Vaultwarden could not be counted"),
        }
    }

    pub fn settings(&self) -> Settings {
        self.settings.read().clone()
    }

    /// Switches an admin changed, or a restore brought, take effect everywhere.
    pub fn apply_features(&self, features: Features) {
        let versions = features.on(Feature::Versions);
        *self.features.write() = features;
        self.store.set_version_rule(self.settings.read().versions.rule(versions));
        // What runs beside the requests looks again, and `/uwu/v1/info` says something else now.
        self.settings_changed.notify_one();
        self.realtime.broadcast(uwulock_notify::realtime::Live::Info);
    }

    pub fn features(&self) -> Features {
        self.features.read().clone()
    }

    /// Whether `feature` is switched on (and what it needs is too).
    pub fn feature(&self, feature: Feature) -> bool {
        self.features.read().on(feature)
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
    // The extras, each answered only while its switch is on (docs/features.md).
    let with = |routes: Router<AppState>, feature: Feature| features::only_with(routes, &state, feature);
    let whole_vault = Router::new()
        .merge(ciphers::vault_routes())
        .merge(accounts::vault_routes())
        .merge(with(suite::rekey_routes(), Feature::Suite))
        .layer(DefaultBodyLimit::max(VAULT_BODY_LIMIT));
    // A suite push brings up to 500 records with 8 MiB of sealed data, which is more in base64.
    let suite_push = with(suite::push_routes(), Feature::Suite).layer(DefaultBodyLimit::max(suite::MAX_PUSH_BODY));
    // Almost everything: small bodies, and an answer within a minute.
    let quick = Router::new()
        .merge(health::routes())
        .merge(identity::routes())
        .merge(accounts::routes())
        .merge(ciphers::routes())
        .merge(attachments::routes())
        .merge(sends::routes())
        .merge(emergency::routes())
        .merge(auth_requests::routes())
        .merge(passkeys::routes())
        .merge(hibp::routes())
        .merge(notifications::routes())
        .merge(organizations::routes())
        .merge(families::routes())
        .merge(with(families::family_routes(), Feature::Families))
        .merge(org_members::routes())
        .merge(org_collections::routes())
        .merge(folders::routes())
        .merge(two_factor::routes())
        .merge(meta::routes())
        .merge(uwu::routes())
        .merge(invitations::routes())
        .merge(notices::routes())
        .merge(admin::routes())
        .merge(features::routes())
        .merge(with(alerts::routes(), Feature::AdminNotifications))
        .merge(diagnosis::routes())
        .merge(with(offsite::routes(), Feature::OffsiteBackups))
        .merge(keys::routes())
        .merge(with(file_requests::routes(), Feature::FileRequests))
        .merge(sso::routes())
        .merge(with(sso::sso_routes(), Feature::Sso))
        .merge(with(sso::scim_routes(), Feature::Scim))
        .merge(with(scim::routes(), Feature::Scim))
        .merge(icons::routes())
        .merge(with(icons::own_routes(), Feature::OwnIcons))
        .merge(with(icons::library_routes(), Feature::IconLibrary))
        .merge(with(versions::routes(), Feature::Versions))
        .merge(with(travel::routes(), Feature::TravelMode))
        .merge(with(reminders::routes(), Feature::Reminders))
        .merge(branding::routes())
        .merge(reports::routes())
        .merge(with(reports::directory_routes(), Feature::TwofaDirectory))
        .merge(sync::routes())
        .merge(realtime::routes())
        .merge(with(suite::routes(), Feature::Suite))
        .merge(with(send_domains::routes(), Feature::SendDomains))
        .merge(with(masked::routes(), Feature::MaskedAddresses))
        .route("/metrics", axum::routing::get(metrics::public))
        .merge(whole_vault)
        .merge(suite_push)
        .merge(web::routes())
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(TimeoutLayer::with_status_code(axum::http::StatusCode::REQUEST_TIMEOUT, REQUEST_TIMEOUT));
    // Uploads of files: as large as the settings allow, which the handlers check as the bytes
    // come, and as long as they take — the connection's own deadline still ends one that stalls.
    let uploads = Router::new()
        .merge(attachments::upload_routes())
        .merge(sends::upload_routes())
        .merge(diagnosis::upload_routes())
        .merge(with(file_requests::upload_routes(), Feature::FileRequests))
        .layer(DefaultBodyLimit::disable());
    let router = Router::new()
        .merge(quick)
        .merge(uploads)
        .fallback(web::fallback)
        .layer(axum::middleware::from_fn_with_state(state.clone(), cors::cors))
        .layer(axum::middleware::from_fn_with_state(state.clone(), send_hosts::guard))
        .layer(axum::middleware::from_fn_with_state(state.clone(), networks::guard))
        .layer(axum::middleware::from_fn_with_state(state.clone(), metrics::track))
        .with_state(state)
        // A vault is JSON, and JSON shrinks to a fraction of itself. Clients ask for gzip; brotli
        // for whoever says they take it. The web vault's files come compressed already.
        .layer(CompressionLayer::new().gzip(true).br(true).compress_when(
            // Files are encrypted: nothing to shrink there.
            DefaultPredicate::new().and(NotForContentType::const_new("application/octet-stream")),
        ))
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
