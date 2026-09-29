//! Icons for items (docs/uwu-api.md §7).
//!
//! - **Automatic**: `/icons/<host>/icon.png`, where the official clients and UwULock's look. The
//!   server fetches the website's icon itself (see [`crate::icon_fetch`] for how it keeps away
//!   from the local network), makes a PNG of it and keeps it on disk. Browsers and apps only
//!   ever talk to this server.
//!   A site without an icon of its own gets one from the icon databases that come with the
//!   server ([`crate::icon_db`]): 2FA Directory's by its domain, else Simple Icons'. A device in
//!   the home network is never asked; it gets Dashboard Icons' by its name, if there is one.
//! - **The icon library**: the server mirrors the index of selfh.st Icons, the vault searches
//!   it, and an icon somebody picks is fetched by the server from its one upstream host.
//!   Dashboard Icons is part of it too, from the server's own copy.
//! - **Own icons**: a PNG the person chose, encrypted by their client and kept per item. The
//!   server cannot see it, nor which website or library icon it is.
//!
//! Hosts never appear in logs or metrics.

use crate::auth::{Admin, ClientIp, Session};
use crate::ciphers::{Found, visible};
use crate::errors::{ApiError, ApiResult};
use crate::icon_db;
use crate::icon_fetch::{self, Upstream};
use crate::{AppState, json as out};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path as FilePath, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uwulock_store::{OwnIcon, clock};

/// The icon libraries this server knows.
pub const LIBRARY_SOURCES: [&str; 1] = ["selfhst"];
/// An own icon, as the text of its EncString, at most.
pub const OWN_MAX_TEXT: usize = 96 * 1024;
/// Own icons are at most this many pixels wide and high (the client makes them so).
pub const OWN_PIXELS: u32 = 128;
/// Where the cache of website icons is, under `icons/`. A new name whenever what is kept changes
/// meaning: the older caches are deleted whole (once a day and when the admin empties the cache),
/// and every host is fetched again when it is next asked for. `auto` was 0.6.0-beta.1's, which
/// also kept icons of pages that had ended up on another site.
const CACHE_DIR: &str = "auto-2";
const OLD_CACHE_DIRS: [&str; 1] = ["auto"];
/// How long a fetched icon is kept, and how long "this site has none".
const ICON_DAYS: u64 = 30;
const NONE_DAYS: u64 = 3;
/// Fetches at once, server-wide.
const AT_ONCE: usize = 8;
/// The index of a library, at most.
const INDEX_BYTES: usize = 8 * 1024 * 1024;
/// Own icons asked for at once.
const MOST_AT_ONCE: usize = 500;
/// The cache of website icons, at most: anybody can have the server fetch any host, so without a
/// ceiling it grows until the disk (and the database on it) is full. Past it, the oldest go, down
/// to [`CACHE_AFTER_EVICTION`] percent. A typical icon is a few KiB.
pub const CACHE_MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const CACHE_MAX_FILES: u64 = 100_000;
const CACHE_AFTER_EVICTION: u64 = 80;

/// What the cache of website icons holds, counted as it changes: files ("none"s included) and
/// bytes. `None` until first counted on disk.
#[derive(Default)]
struct CacheBook {
    counted: Option<(u64, u64)>,
}

/// Automatic icons, with their own switch in the settings.
pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/icons/{host}/icon.png", get(automatic))
        .route("/uwu/v1/admin/icons", get(admin_status))
        .route("/uwu/v1/admin/icons/cache", delete(admin_clear))
}

/// Own icons: the `own-icons` switch.
pub(crate) fn own_routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/icons/own", get(own_list))
        .route("/uwu/v1/icons/own/get", post(own_many))
        .route("/uwu/v1/icons/own/{cipher}", get(own_one).put(own_put).delete(own_delete))
}

/// The icon library: the `icon-library` switch.
pub(crate) fn library_routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/icons/library", get(library))
        .route("/uwu/v1/icons/library/{source}/{file}", get(library_icon))
        .route("/uwu/v1/admin/icons/library/refresh", post(admin_refresh))
}

/// The mirrored index of a library, ready to hand out.
struct Library {
    body: String,
    etag: String,
    updated: String,
    /// Icon ids and the variants each has.
    icons: HashMap<String, Vec<String>>,
}

/// The icon fetcher's state: where its files are, who fetches what right now.
pub struct Icons {
    upstream: Arc<Upstream>,
    client: Result<reqwest::Client, String>,
    dir: PathBuf,
    slots: tokio::sync::Semaphore,
    hosts: parking_lot::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    library: parking_lot::RwLock<Option<Arc<Library>>>,
    refreshing: tokio::sync::Mutex<()>,
    book: parking_lot::Mutex<CacheBook>,
    /// Held while the oldest icons are removed: one eviction at a time.
    evicting: tokio::sync::Mutex<()>,
    /// The ceilings, lower in tests.
    limits: (u64, u64),
    /// The icon databases that come with the server.
    databases: Arc<icon_db::Databases>,
    /// The library with Dashboard Icons in it, and what it was made of.
    merged: parking_lot::Mutex<Option<(String, Arc<Library>)>>,
}

impl Icons {
    /// With its files under `data/icons`, fetching from `upstream` (the internet, but in tests).
    pub fn new(data: &FilePath, upstream: Upstream) -> Self {
        let upstream = Arc::new(upstream);
        Icons {
            client: icon_fetch::client(upstream.clone()),
            upstream,
            dir: data.join("icons"),
            slots: tokio::sync::Semaphore::new(AT_ONCE),
            hosts: parking_lot::Mutex::default(),
            library: parking_lot::RwLock::default(),
            refreshing: tokio::sync::Mutex::default(),
            book: parking_lot::Mutex::default(),
            evicting: tokio::sync::Mutex::default(),
            limits: (CACHE_MAX_FILES, CACHE_MAX_BYTES),
            databases: icon_db::bundled(),
            merged: parking_lot::Mutex::default(),
        }
    }

    /// The same, with other icon databases than the bundled ones: for tests.
    #[cfg(test)]
    pub(crate) fn with_databases(mut self, databases: icon_db::Databases) -> Self {
        self.databases = Arc::new(databases);
        self
    }

    /// The icon databases that come with the server.
    pub fn databases(&self) -> &icon_db::Databases {
        &self.databases
    }

    /// The same, with other ceilings for the cache (files, bytes): for tests.
    #[cfg(test)]
    pub(crate) fn with_limits(mut self, files: u64, bytes: u64) -> Self {
        self.limits = (files, bytes);
        self
    }

    /// The HTTP client with its checks, and where it may go: for other lists the server mirrors.
    pub(crate) fn fetcher(&self) -> Option<(&reqwest::Client, &Upstream)> {
        self.client().map(|client| (client, &*self.upstream))
    }

    /// The directory the icons are kept in, under the data directory.
    pub(crate) fn dir(&self) -> &FilePath {
        &self.dir
    }

    fn client(&self) -> Option<&reqwest::Client> {
        match &self.client {
            Ok(client) => Some(client),
            Err(error) => {
                tracing::warn!(%error, "no HTTP client for icons");
                None
            }
        }
    }

    fn auto_dir(&self) -> PathBuf {
        self.dir.join(CACHE_DIR)
    }

    /// The caches of older versions, gone: what they hold was made by other rules.
    async fn drop_old_caches(&self) {
        for old in OLD_CACHE_DIRS {
            let dir = self.dir.join(old);
            if tokio::fs::try_exists(&dir).await.unwrap_or(false) {
                match tokio::task::spawn_blocking(move || std::fs::remove_dir_all(dir)).await {
                    Ok(Ok(())) => tracing::info!("an older cache of website icons was deleted"),
                    Ok(Err(error)) => tracing::warn!(%error, "an older cache of website icons could not be deleted"),
                    Err(_) => {}
                }
            }
        }
    }

    fn cached(&self, host: &str) -> (PathBuf, PathBuf) {
        let name = hex(&crate::auth::sha256(host.as_bytes()));
        let dir = self.auto_dir();
        (dir.join(format!("{name}.png")), dir.join(format!("{name}.none")))
    }

    /// One lock per host: two requests for a new host fetch it once.
    fn host_lock(&self, host: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut hosts = self.hosts.lock();
        if hosts.len() > 1000 {
            hosts.retain(|_, lock| Arc::strong_count(lock) > 1);
        }
        hosts.entry(host.to_string()).or_default().clone()
    }

    /// What the cache says about `host`: an icon, "none", or nothing yet (or too old).
    async fn cached_icon(&self, host: &str) -> Option<Option<Vec<u8>>> {
        let (icon, none) = self.cached(host);
        if fresh(&icon, ICON_DAYS).await {
            return tokio::fs::read(&icon).await.ok().map(Some);
        }
        if fresh(&none, NONE_DAYS).await {
            return Some(None);
        }
        None
    }

    async fn keep(&self, host: &str, icon: Option<&[u8]>) {
        let (icon_path, none_path) = self.cached(host);
        let adding = icon.map_or(0, <[u8]>::len) as u64;
        // What fills the disk takes the database down with it: then the icon is shown, not kept.
        let dir = self.auto_dir();
        let _ = tokio::fs::create_dir_all(&dir).await;
        if !uwulock_store::backups::has_room(&dir, adding.max(4096)) {
            tracing::warn!("the disk is nearly full; website icons are not kept");
            return;
        }
        self.counted().await;
        let size = |path: PathBuf| async move { tokio::fs::metadata(&path).await.ok().map(|meta| meta.len()) };
        let before = [size(icon_path.clone()).await, size(none_path.clone()).await];
        let written = match icon {
            Some(bytes) => {
                let _ = tokio::fs::remove_file(&none_path).await;
                write_atomic(&icon_path, bytes).await
            }
            None => {
                let _ = tokio::fs::remove_file(&icon_path).await;
                write_atomic(&none_path, b"").await
            }
        };
        if let Err(error) = written {
            tracing::warn!(%error, "an icon could not be kept");
        }
        let over = {
            let mut book = self.book.lock();
            if let Some((files, bytes)) = book.counted.as_mut() {
                for gone in before.into_iter().flatten() {
                    *files = files.saturating_sub(1);
                    *bytes = bytes.saturating_sub(gone);
                }
                *files += 1;
                *bytes += adding;
            }
            book.counted.is_some_and(|(files, bytes)| files > self.limits.0 || bytes > self.limits.1)
        };
        if over {
            self.evict(false).await;
        }
    }

    /// The cache's files and bytes, counted on disk the first time.
    async fn counted(&self) -> (u64, u64) {
        if let Some(counted) = self.book.lock().counted {
            return counted;
        }
        let counted = self.cache_size().await;
        *self.book.lock().counted.get_or_insert(counted)
    }

    /// Makes room in the cache: with `expired`, what is too old to be used (icons after
    /// [`ICON_DAYS`], "none"s after [`NONE_DAYS`]); always, past the ceiling, the oldest until it
    /// is well below it. Counts the cache anew.
    async fn evict(&self, expired: bool) {
        let Ok(_one) = self.evicting.try_lock() else { return };
        let dir = self.auto_dir();
        let (max_files, max_bytes) = self.limits;
        let target = (max_files * CACHE_AFTER_EVICTION / 100, max_bytes * CACHE_AFTER_EVICTION / 100);
        let result = tokio::task::spawn_blocking(move || prune(&dir, expired, target)).await;
        if let Ok((files, bytes, removed)) = result {
            self.book.lock().counted = Some((files, bytes));
            if removed > 0 {
                tracing::info!(removed, files, bytes, "website icons removed from the cache");
            }
        }
    }

    /// The website's icon, fetched now: the page's `<link rel="icon">`s and `/favicon.ico`,
    /// the one nearest to 64 pixels that has at least 32, else the largest.
    ///
    /// With `own_site_only` (a host with a base domain to fall back to), a page that ends up on
    /// another site after its redirects has none: what it shows is that other site's — a login
    /// provider's, a hoster's, a parking page's — and not this host's. A base domain itself may
    /// redirect anywhere (`example.net` to `example.com` is one brand).
    async fn fetch_site(&self, host: &str, own_site_only: bool) -> Result<Option<Vec<u8>>, ()> {
        let client = self.client().ok_or(())?;
        let upstream = &self.upstream;
        let mut base = None;
        let mut candidates = Vec::new();
        for (scheme, port, default) in [("https", upstream.https_port, 443), ("http", upstream.http_port, 80)] {
            let address =
                if port == default { format!("{scheme}://{host}/") } else { format!("{scheme}://{host}:{port}/") };
            let Ok(url) = url::Url::parse(&address) else { return Err(()) };
            if let Ok(page) = icon_fetch::get(client, upstream, url, icon_fetch::PAGE_BYTES).await {
                let ended_on = page.url.host_str().map(icon_fetch::site);
                if own_site_only && ended_on != Some(icon_fetch::site(host)) {
                    return Ok(None);
                }
                if (200..300).contains(&page.status) {
                    candidates = icon_fetch::icon_links(&String::from_utf8_lossy(&page.bytes), &page.url);
                }
                base = Some(page.url);
                break;
            }
        }
        let Some(base) = base else { return Err(()) };
        candidates.sort_by_key(|candidate| match candidate.size {
            Some(size) if size >= 32 => (0, size.abs_diff(64)),
            None => (1, 0),
            Some(size) => (2, 64 - size),
        });
        if let Ok(favicon) = base.join("/favicon.ico") {
            candidates.push(icon_fetch::Candidate { url: favicon.to_string(), size: None });
        }
        let mut seen = HashSet::new();
        candidates.retain(|candidate| seen.insert(candidate.url.clone()));
        let mut best: Option<(Vec<u8>, u32)> = None;
        for candidate in candidates.into_iter().take(5) {
            let bytes = match icon_fetch::data_url(&candidate.url) {
                Some(bytes) => bytes,
                None => {
                    let Ok(url) = url::Url::parse(&candidate.url) else { continue };
                    match icon_fetch::get(client, upstream, url, icon_fetch::ICON_BYTES).await {
                        Ok(file) if (200..300).contains(&file.status) && !file.cut => file.bytes,
                        _ => continue,
                    }
                }
            };
            let Some((png, size)) = icon_fetch::decode(bytes, icon_fetch::AUTO_PIXELS).await else {
                continue;
            };
            let better = match &best {
                None => true,
                Some((_, known)) if *known >= 32 && size >= 32 => size.abs_diff(64) < known.abs_diff(64),
                Some((_, known)) => size > *known,
            };
            if better {
                best = Some((png, size));
            }
            if best.as_ref().is_some_and(|(_, size)| *size == 64) {
                break;
            }
        }
        Ok(best.map(|(png, _)| png))
    }

    /// The website's icon: the host's own, else its base domain's (`example.com` for
    /// `account.example.com`, by the Public Suffix List) — an address that answers 404 and names
    /// no icon still gets its site's. Each is cached under its own host, so the base domain is
    /// fetched once for all hosts below it, and a host's "none" does not keep its base domain's
    /// icon away. `Err` when this asker may not start another fetch right now.
    async fn site_icon(&self, state: &AppState, host: &str, ip: std::net::IpAddr) -> Result<Option<Vec<u8>>, ()> {
        // Out of tries, a cached host answers like one that is not: otherwise anybody could test
        // which sites this server's users have, without the side effect of a fetch. Cached
        // answers take no try.
        if !state.limits.icons.allows(&crate::limits::network_of(ip)) {
            return Err(());
        }
        let base = icon_fetch::base_domain(host);
        if let Some(icon) = self.host_icon(state, host, base.is_some(), ip).await? {
            return Ok(Some(icon));
        }
        match base {
            Some(base) => self.host_icon(state, &base, false, ip).await,
            None => Ok(None),
        }
    }

    /// One host's own icon: from the cache, or fetched now (and then kept, "none" too). Every
    /// fetch goes through the same checks, the same per-address tries and the same slots.
    async fn host_icon(
        &self,
        state: &AppState,
        host: &str,
        own_site_only: bool,
        ip: std::net::IpAddr,
    ) -> Result<Option<Vec<u8>>, ()> {
        if let Some(cached) = self.cached_icon(host).await {
            return Ok(cached);
        }
        if !state.limits.icons.check(ip) {
            return Err(());
        }
        let lock = self.host_lock(host);
        let _only_one = lock.lock().await;
        if let Some(cached) = self.cached_icon(host).await {
            return Ok(cached);
        }
        let _slot = self.slots.acquire().await.map_err(|_| ())?;
        let fetched = tokio::time::timeout(icon_fetch::WHOLE, self.fetch_site(host, own_site_only)).await;
        let (icon, result) = match fetched {
            Ok(Ok(Some(png))) => (Some(png), "found"),
            Ok(Ok(None)) => (None, "none"),
            Ok(Err(())) => (None, "error"),
            Err(_) => (None, "error"),
        };
        state.metrics.icon_fetch(result);
        self.keep(host, icon.as_deref()).await;
        Ok(icon)
    }

    /// An icon of a database as PNG of at most `pixels`: drawn once, then kept in the cache of
    /// website icons (under a name no host can have, which changes with the icon), so it counts
    /// toward the same ceiling.
    async fn database_png(&self, found: icon_db::Found<'_>, pixels: u32) -> Option<Vec<u8>> {
        let key = format!("database:{}:{}:{pixels}", found.database, found.hash);
        if let Some(Some(png)) = self.cached_icon(&key).await {
            return Some(png);
        }
        let (png, _) = icon_fetch::decode(found.bytes.to_vec(), pixels).await?;
        self.keep(&key, Some(&png)).await;
        Some(png)
    }

    /// A public host's icon from the databases switched on: 2FA Directory's, else Simple Icons'.
    async fn database_icon(&self, on: &[String], host: &str) -> Option<Vec<u8>> {
        let found = self.databases.for_host(on, host)?;
        self.database_png(found, icon_fetch::AUTO_PIXELS).await
    }

    /// A device in the home network: Dashboard Icons' by its name, if that database is on.
    async fn local_icon(&self, on: &[String], raw: &str) -> Option<Vec<u8>> {
        let found = self.databases.for_local(on, raw)?;
        self.database_png(found, icon_fetch::AUTO_PIXELS).await
    }

    /// Everything fetched so far, gone.
    pub async fn clear(&self) -> std::io::Result<()> {
        self.drop_old_caches().await;
        let result = match tokio::fs::remove_dir_all(self.auto_dir()).await {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        };
        self.book.lock().counted = None;
        result
    }

    /// How many icons (and "none"s) are kept, and their bytes.
    async fn cache_size(&self) -> (u64, u64) {
        let mut count = 0;
        let mut bytes = 0;
        if let Ok(mut entries) = tokio::fs::read_dir(self.auto_dir()).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(meta) = entry.metadata().await {
                    count += 1;
                    bytes += meta.len();
                }
            }
        }
        (count, bytes)
    }

    /// The bytes of every icon file the server keeps, for the metrics: the cache as counted,
    /// the library's files (a few thousand at most) walked.
    pub async fn bytes(&self) -> u64 {
        fn walk(dir: &FilePath) -> u64 {
            std::fs::read_dir(dir).map_or(0, |entries| {
                entries
                    .flatten()
                    .map(|entry| match entry.metadata() {
                        Ok(meta) if meta.is_dir() => walk(&entry.path()),
                        Ok(meta) => meta.len(),
                        Err(_) => 0,
                    })
                    .sum()
            })
        }
        let dir = self.library_dir();
        let library = tokio::task::spawn_blocking(move || walk(&dir)).await.unwrap_or(0);
        library + self.counted().await.1
    }

    // ── The library ────────────────────────────────────────

    fn library_dir(&self) -> PathBuf {
        self.dir.join("library")
    }

    /// The index as the vault gets it: from memory, else from disk, else fetched now.
    async fn library(&self) -> Option<Arc<Library>> {
        if let Some(library) = self.library.read().clone() {
            return Some(library);
        }
        if let Ok(body) = tokio::fs::read_to_string(self.library_dir().join("index.json")).await
            && let Some(library) = parse_ours(body)
        {
            let library = Arc::new(library);
            *self.library.write() = Some(library.clone());
            return Some(library);
        }
        if let Err(error) = self.refresh_library().await {
            tracing::warn!(%error, "the icon library's index could not be fetched");
        }
        self.library.read().clone()
    }

    /// The library as the vault gets it: selfh.st's mirrored index if it is on, and Dashboard
    /// Icons if that database is on — one index. None when neither is there.
    async fn library_for(&self, settings: &crate::settings::IconSettings) -> Option<Arc<Library>> {
        let selfhst =
            if settings.sources.iter().any(|source| source == "selfhst") { self.library().await } else { None };
        let dashboard = settings
            .databases
            .iter()
            .any(|id| id == icon_db::DASHBOARD)
            .then(|| self.databases.get(icon_db::DASHBOARD))
            .flatten();
        let Some(dashboard) = dashboard else { return selfhst };
        let made_of =
            format!("{}|{}", selfhst.as_ref().map_or("", |library| library.etag.as_str()), dashboard.about.commit);
        if let Some((known, library)) = self.merged.lock().as_ref()
            && *known == made_of
        {
            return Some(library.clone());
        }
        let mut index = match &selfhst {
            Some(library) => serde_json::from_str(&library.body).ok()?,
            None => json!({ "object": "iconLibrary", "updated": clock::now(), "sources": [], "icons": [] }),
        };
        let about = &dashboard.about;
        index["sources"].as_array_mut()?.push(json!({
            "id": icon_db::DASHBOARD,
            "name": about.name,
            "url": about.url,
            "license": about.license,
            "licenseUrl": about.license_url,
            "attribution": about.attribution,
        }));
        index["icons"].as_array_mut()?.extend(dashboard.library().iter().map(|entry| {
            json!({
                "source": icon_db::DASHBOARD,
                "id": entry.id,
                "name": entry.name,
                "variants": ["default"],
                "aliases": entry.aliases,
            })
        }));
        let body = index.to_string();
        let library = Arc::new(Library {
            etag: format!("\"{}\"", hex(&crate::auth::sha256(body.as_bytes())[..16])),
            updated: selfhst.as_ref().map_or_else(clock::now, |library| library.updated.clone()),
            icons: selfhst.as_ref().map(|library| library.icons.clone()).unwrap_or_default(),
            body,
        });
        *self.merged.lock() = Some((made_of, library.clone()));
        Some(library)
    }

    /// Fetch the libraries' indexes again, and keep them.
    pub async fn refresh_library(&self) -> Result<(), String> {
        let _one_at_a_time = self.refreshing.lock().await;
        let client = self.client().ok_or("no HTTP client")?;
        let url =
            url::Url::parse(&format!("{}/index.json", self.upstream.selfhst)).map_err(|error| error.to_string())?;
        let fetched =
            tokio::time::timeout(Duration::from_secs(60), icon_fetch::get(client, &self.upstream, url, INDEX_BYTES))
                .await
                .map_err(|_| "it took too long".to_string())??;
        if !(200..300).contains(&fetched.status) || fetched.cut {
            return Err(format!("the index answered {}", fetched.status));
        }
        let body = selfhst_index(&fetched.bytes)?;
        let library = parse_ours(body.clone()).ok_or("the index could not be read")?;
        tokio::fs::create_dir_all(self.library_dir()).await.map_err(|error| error.to_string())?;
        write_atomic(&self.library_dir().join("index.json"), body.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        *self.library.write() = Some(Arc::new(library));
        Ok(())
    }

    /// A library icon as PNG of at most 128 pixels: kept, or fetched now from the library's
    /// host.
    async fn library_icon(&self, id: &str, variant: &str) -> Result<Option<Vec<u8>>, ()> {
        let path = self.library_dir().join("selfhst").join(format!("{id}.{variant}.png"));
        if fresh(&path, ICON_DAYS).await
            && let Ok(bytes) = tokio::fs::read(&path).await
        {
            return Ok(Some(bytes));
        }
        let lock = self.host_lock(&format!("library:{id}:{variant}"));
        let _only_one = lock.lock().await;
        if let Ok(bytes) = tokio::fs::read(&path).await {
            return Ok(Some(bytes));
        }
        let _slot = self.slots.acquire().await.map_err(|_| ())?;
        let client = self.client().ok_or(())?;
        let suffix = match variant {
            "light" => "-light",
            "dark" => "-dark",
            _ => "",
        };
        let url = url::Url::parse(&format!("{}/png/{id}{suffix}.png", self.upstream.selfhst)).map_err(|_| ())?;
        let fetched = icon_fetch::get(client, &self.upstream, url, icon_fetch::ICON_BYTES).await.map_err(|_| ())?;
        if !(200..300).contains(&fetched.status) || fetched.cut {
            return Ok(None);
        }
        let bytes = fetched.bytes;
        let Some((png, _)) = icon_fetch::decode(bytes, icon_fetch::LIBRARY_PIXELS).await else {
            return Ok(None);
        };
        let _ = tokio::fs::create_dir_all(path.parent().unwrap_or(&self.dir)).await;
        if let Err(error) = write_atomic(&path, &png).await {
            tracing::warn!(%error, "a library icon could not be kept");
        }
        Ok(Some(png))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Removes from the cache of website icons what is too old to be used when `expired`, and the
/// oldest files while there are more than `target` (files, bytes). Answers what is left, and how
/// many went.
fn prune(dir: &FilePath, expired: bool, target: (u64, u64)) -> (u64, u64, usize) {
    let now = SystemTime::now();
    let age = |modified: SystemTime| now.duration_since(modified).unwrap_or_default();
    let mut kept = Vec::new();
    let mut removed = 0;
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let modified = meta.modified().unwrap_or(now);
        let path = entry.path();
        let days = if path.extension().is_some_and(|extension| extension == "none") { NONE_DAYS } else { ICON_DAYS };
        // Also what a write left behind: `.tmp-…` files older than a day.
        let stale = age(modified) > Duration::from_secs(days * 86_400)
            || (path.extension().is_some_and(|extension| extension.to_string_lossy().starts_with("tmp-"))
                && age(modified) > Duration::from_secs(86_400));
        if expired && stale {
            if std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
            continue;
        }
        kept.push((modified, meta.len(), path));
    }
    let (mut files, mut bytes) = (kept.len() as u64, kept.iter().map(|(_, len, _)| len).sum::<u64>());
    if files > target.0 || bytes > target.1 {
        kept.sort_by_key(|(modified, ..)| *modified);
        for (_, len, path) in kept {
            if files <= target.0 && bytes <= target.1 {
                break;
            }
            if std::fs::remove_file(&path).is_ok() {
                files -= 1;
                bytes -= len;
                removed += 1;
            }
        }
    }
    (files, bytes, removed)
}

async fn fresh(path: &FilePath, days: u64) -> bool {
    let Ok(meta) = tokio::fs::metadata(path).await else { return false };
    meta.modified()
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age < Duration::from_secs(days * 86_400))
}

async fn write_atomic(path: &FilePath, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&temporary, bytes).await?;
    tokio::fs::rename(&temporary, path).await
}

/// Whether a library icon id is one this server hands on: lower case, digits, `-`, `_`, `.`.
fn plain_id(id: &str) -> bool {
    (1..=100).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.'))
        && !id.starts_with('.')
}

/// selfh.st's `index.json` (`[{"Name", "Reference", "PNG", "Light", "Dark", …}]`) as UwULock's
/// library index (§7.2).
fn selfhst_index(bytes: &[u8]) -> Result<String, String> {
    let entries: Vec<Value> = serde_json::from_slice(bytes).map_err(|error| format!("the index: {error}"))?;
    let yes = |entry: &Value, key: &str| entry.get(key).and_then(Value::as_str) == Some("Yes");
    let icons: Vec<Value> = entries
        .iter()
        .filter_map(|entry| {
            let id = entry.get("Reference")?.as_str()?;
            let name = entry.get("Name")?.as_str()?;
            if !plain_id(id) || name.len() > 200 || !yes(entry, "PNG") {
                return None;
            }
            let mut variants = vec!["default"];
            if yes(entry, "Light") {
                variants.push("light");
            }
            if yes(entry, "Dark") {
                variants.push("dark");
            }
            Some(json!({ "source": "selfhst", "id": id, "name": name, "variants": variants, "aliases": [] }))
        })
        .collect();
    if icons.is_empty() {
        return Err("the index lists no icons".into());
    }
    Ok(json!({
        "object": "iconLibrary",
        "updated": clock::now(),
        "sources": [{
            "id": "selfhst",
            "name": "selfh.st Icons",
            "url": "https://selfh.st/icons/",
            "license": "CC BY 4.0",
            "licenseUrl": "https://creativecommons.org/licenses/by/4.0/",
            "attribution": "Icons by selfh.st",
        }],
        "icons": icons,
    })
    .to_string())
}

fn parse_ours(body: String) -> Option<Library> {
    let value: Value = serde_json::from_str(&body).ok()?;
    let icons = value
        .get("icons")?
        .as_array()?
        .iter()
        .filter_map(|icon| {
            let id = icon.get("id")?.as_str()?.to_string();
            let variants = icon
                .get("variants")?
                .as_array()?
                .iter()
                .filter_map(|variant| variant.as_str().map(str::to_string))
                .collect();
            Some((id, variants))
        })
        .collect();
    let updated = value.get("updated")?.as_str()?.to_string();
    let etag = format!("\"{}\"", hex(&crate::auth::sha256(body.as_bytes())[..16]));
    Some(Library { body, etag, updated, icons })
}

// ── Automatic icons ───────────────────────────────────────

fn png(bytes: Vec<u8>, cache: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("image/png")),
            (header::CACHE_CONTROL, HeaderValue::from_static(cache)),
        ],
        bytes,
    )
        .into_response()
}

/// No icon: the clients show their own symbol. Asked again in a day at the earliest.
fn none() -> Response {
    (StatusCode::NOT_FOUND, [(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=86400"))])
        .into_response()
}

async fn automatic(State(state): State<AppState>, ClientIp(ip): ClientIp, Path(host): Path<String>) -> Response {
    let settings = state.settings();
    if !settings.icons.automatic {
        return none();
    }
    let databases = &settings.icons.databases;
    let Some(host) = icon_fetch::normalize_host(&host) else {
        // The home network is never asked; an app there may have its icon in Dashboard Icons.
        return match state.icons.local_icon(databases, &host).await {
            Some(icon) => png(icon, "public, max-age=604800"),
            None => none(),
        };
    };
    match state.icons.site_icon(&state, &host, ip).await {
        Ok(Some(icon)) => png(icon, "public, max-age=604800"),
        // No icon of its own, nor its base domain: one of the databases', if they know it.
        Ok(None) => match state.icons.database_icon(databases, &host).await {
            Some(icon) => png(icon, "public, max-age=604800"),
            None => none(),
        },
        // Out of tries: not found, and not remembered as such by anyone.
        Err(()) => {
            (StatusCode::NOT_FOUND, [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))]).into_response()
        }
    }
}

// ── The library ───────────────────────────────────────────

/// Whether the vault has an icon library: it is on, and selfh.st or Dashboard Icons is in it.
pub(crate) fn library_available(state: &AppState) -> bool {
    let icons = state.settings().icons;
    icons.library
        && (!icons.sources.is_empty()
            || (icons.databases.iter().any(|id| id == icon_db::DASHBOARD)
                && state.icons.databases.get(icon_db::DASHBOARD).is_some()))
}

fn library_on(state: &AppState) -> ApiResult<()> {
    if !library_available(state) {
        return Err(ApiError::not_found("The icon library is switched off on this server.").code("feature_off"));
    }
    Ok(())
}

async fn library(State(state): State<AppState>, _session: Session, headers: HeaderMap) -> ApiResult<Response> {
    library_on(&state)?;
    let library = state
        .icons
        .library_for(&state.settings().icons)
        .await
        .ok_or_else(|| ApiError::upstream("The icon library could not be fetched. Try again later."))?;
    let etag = HeaderValue::from_str(&library.etag).map_err(ApiError::internal)?;
    if headers.get(header::IF_NONE_MATCH).is_some_and(|given| given == etag) {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
    }
    Ok((
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8")),
            (header::ETAG, etag),
            (header::CACHE_CONTROL, HeaderValue::from_static("private, no-cache")),
        ],
        library.body.clone(),
    )
        .into_response())
}

#[derive(Deserialize)]
struct VariantQuery {
    #[serde(default)]
    variant: Option<String>,
}

async fn library_icon(
    State(state): State<AppState>,
    _session: Session,
    ClientIp(ip): ClientIp,
    Path((source, file)): Path<(String, String)>,
    Query(query): Query<VariantQuery>,
) -> ApiResult<Response> {
    library_on(&state)?;
    let missing = || ApiError::not_found("There is no such icon in the library.").code("not_found");
    let settings = state.settings();
    let id = file.strip_suffix(".png").filter(|id| plain_id(id)).ok_or_else(missing)?;
    let variant = query.variant.unwrap_or_else(|| "default".into());
    if source == icon_db::DASHBOARD && settings.icons.databases.contains(&source) {
        let found = state.icons.databases.get(icon_db::DASHBOARD).and_then(|database| database.library_icon(id));
        let found = found.filter(|_| variant == "default").ok_or_else(missing)?;
        if !state.limits.icons.check(ip) {
            return Err(ApiError::too_many("Too many icons at once. Wait a moment.").code("rate_limited"));
        }
        let icon = state.icons.database_png(found, icon_fetch::LIBRARY_PIXELS).await.ok_or_else(missing)?;
        return Ok(png(icon, "private, max-age=604800"));
    }
    if !settings.icons.sources.contains(&source) || source != "selfhst" {
        return Err(missing());
    }
    let library = state.icons.library().await.ok_or_else(missing)?;
    if !library.icons.get(id).is_some_and(|variants| variants.contains(&variant)) {
        return Err(missing());
    }
    if !state.limits.icons.check(ip) {
        return Err(ApiError::too_many("Too many icons at once. Wait a moment.").code("rate_limited"));
    }
    match state.icons.library_icon(id, &variant).await {
        Ok(Some(icon)) => Ok(png(icon, "private, max-age=604800")),
        Ok(None) => Err(missing()),
        Err(()) => Err(ApiError::upstream("The icon library did not answer. Try again later.")),
    }
}

// ── Own icons ─────────────────────────────────────────────

fn own_json(icon: &OwnIcon) -> Value {
    let mut value = json!({
        "object": "ownIcon",
        "cipherId": icon.cipher_id,
        "keyType": icon.key_type,
        "revisionDate": icon.revision,
    });
    if let Some(data) = &icon.data {
        value["data"] = data.clone().into();
    }
    value
}

/// The ids of every item the account sees, travel mode's hidden ones left out.
async fn visible_ids(state: &AppState, user_id: &str) -> ApiResult<Vec<String>> {
    let (own, orgs) = tokio::try_join!(state.store.ciphers(user_id), state.store.org_vault(user_id))?;
    Ok(own.into_iter().map(|cipher| cipher.id).chain(orgs.ciphers.into_iter().map(|item| item.cipher.id)).collect())
}

async fn own_list(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let ids = visible_ids(&state, &session.user.id).await?;
    let icons = state.store.own_icons(ids, false).await?;
    Ok(Json(out::list(icons.iter().map(own_json).collect())))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Many {
    cipher_ids: Vec<String>,
}

async fn own_many(State(state): State<AppState>, session: Session, Json(body): Json<Many>) -> ApiResult<Json<Value>> {
    if body.cipher_ids.len() > MOST_AT_ONCE {
        return Err(ApiError::bad(format!("At most {MOST_AT_ONCE} icons at once.")).code("invalid"));
    }
    let seen: HashSet<String> = visible_ids(&state, &session.user.id).await?.into_iter().collect();
    let wanted: Vec<String> = body.cipher_ids.into_iter().filter(|id| seen.contains(id)).collect();
    let icons = state.store.own_icons(wanted, true).await?;
    Ok(Json(out::list(icons.iter().map(own_json).collect())))
}

fn no_icon() -> ApiError {
    ApiError::not_found("This item has no own icon.").code("not_found")
}

async fn own_one(
    State(state): State<AppState>,
    session: Session,
    Path(cipher): Path<String>,
) -> ApiResult<Json<Value>> {
    visible(&state, &session, &cipher).await?;
    let icon = state.store.own_icon(&cipher).await?.ok_or_else(no_icon)?;
    Ok(Json(own_json(&icon)))
}

/// The key an item's own icon is under: the extras key for a personal item, the organisation's
/// for an organisation's. Refused (404) unless the account may change the item.
/// Under which key an item's own icon is, and whose storage it counts against.
async fn writable_key_type(
    state: &AppState,
    session: &Session,
    cipher: &str,
) -> ApiResult<(&'static str, uwulock_store::Owner)> {
    match visible(state, session, cipher).await? {
        Found::Own(_) => Ok(("extras", uwulock_store::Owner::User(session.user.id.clone()))),
        Found::Org(item) if !item.access.read_only => match item.cipher.organization_id.clone() {
            Some(org) => Ok(("organization", uwulock_store::Owner::Org(org))),
            None => Err(crate::ciphers::not_visible()),
        },
        Found::Org(_) => Err(crate::ciphers::not_visible()),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OwnData {
    data: String,
    key_type: String,
}

async fn own_put(
    State(state): State<AppState>,
    session: Session,
    Path(cipher): Path<String>,
    Json(body): Json<OwnData>,
) -> ApiResult<Json<Value>> {
    let (key_type, owner) = writable_key_type(&state, &session, &cipher).await?;
    if body.data.len() > OWN_MAX_TEXT {
        return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "The icon is too large.").code("too_large"));
    }
    if !crate::keys::enc_string(&body.data, 2, OWN_MAX_TEXT) {
        return Err(ApiError::bad("The icon is not encrypted the way it should be.").code("invalid"));
    }
    if body.key_type != key_type {
        return Err(ApiError::bad(format!("This item's icon is under the {key_type} key.")).code("invalid"));
    }
    let previous = state.store.own_icon(&cipher).await?.and_then(|icon| icon.data).map_or(0, |data| data.len());
    crate::files::check_owner_storage(&state, &owner, body.data.len().saturating_sub(previous) as i64, None).await?;
    let icon = state.store.put_own_icon(&cipher, key_type, body.data).await?;
    icon_changed(&state, &session, &cipher).await;
    let mut answer = own_json(&icon);
    if let Some(object) = answer.as_object_mut() {
        object.remove("data");
    }
    Ok(Json(answer))
}

async fn own_delete(
    State(state): State<AppState>,
    session: Session,
    Path(cipher): Path<String>,
) -> ApiResult<StatusCode> {
    writable_key_type(&state, &session, &cipher).await?;
    state.store.delete_own_icon(&cipher).await?;
    icon_changed(&state, &session, &cipher).await;
    Ok(StatusCode::OK)
}

/// Everybody who sees the item hears that its icon changed (realtime area `uwu`): its owner, or
/// every member of its organisation.
async fn icon_changed(state: &AppState, session: &Session, cipher: &str) {
    let live = uwulock_notify::realtime::Live::changed("uwu");
    let organization = state.store.cipher_organization(cipher).await.ok().flatten();
    match organization {
        Some(org) => {
            for user in state.store.org_members_users(&org).await.unwrap_or_default() {
                crate::notify::live(state, &user, Some(session), live.clone());
            }
        }
        None => crate::notify::live(state, &session.user.id, Some(session), live),
    }
}

// ── Admin ─────────────────────────────────────────────────

async fn admin_status(State(state): State<AppState>, _admin: Admin) -> ApiResult<Json<Value>> {
    let (count, bytes) = state.icons.counted().await;
    let library = state.icons.library.read().clone();
    let own = state.store.own_icon_bytes().await?;
    let on = state.settings().icons.databases;
    let databases: Vec<Value> = state
        .icons
        .databases
        .all()
        .iter()
        .map(|database| {
            let (icons, domains, names, bytes) = database.counts();
            let mut about = serde_json::to_value(&database.about).unwrap_or_default();
            about["on"] = json!(on.contains(&database.about.id));
            about["icons"] = json!(icons);
            about["domains"] = json!(domains);
            about["names"] = json!(names);
            about["bytes"] = json!(bytes);
            about
        })
        .collect();
    Ok(Json(json!({
        "object": "iconStatus",
        "cached": count,
        "cacheBytes": bytes,
        "cacheMaxBytes": state.icons.limits.1,
        "cacheMaxFiles": state.icons.limits.0,
        "ownBytes": own,
        "libraryUpdated": library.as_ref().map(|library| library.updated.clone()),
        "libraryIcons": library.as_ref().map_or(0, |library| library.icons.len()),
        "databases": databases,
    })))
}

async fn admin_clear(State(state): State<AppState>, admin: Admin) -> ApiResult<StatusCode> {
    state.icons.clear().await.map_err(ApiError::internal)?;
    crate::admin::record(&state, &admin, "emptied the cache of website icons".into()).await;
    Ok(StatusCode::OK)
}

async fn admin_refresh(State(state): State<AppState>, admin: Admin) -> ApiResult<StatusCode> {
    crate::admin::record(&state, &admin, "fetches the icon library's index again".into()).await;
    let icons = state.icons.clone();
    tokio::spawn(async move {
        if let Err(error) = icons.refresh_library().await {
            tracing::warn!(%error, "the icon library's index could not be fetched");
        }
    });
    Ok(StatusCode::ACCEPTED)
}

/// Once a day: older versions' caches go, website icons too old to be used go (and the oldest,
/// past the ceiling), and the libraries' indexes are fetched again, if the library is on (its
/// switch and its setting).
pub async fn daily(state: &AppState) {
    state.icons.drop_old_caches().await;
    state.icons.evict(true).await;
    let settings = state.settings();
    if state.feature(crate::Feature::IconLibrary)
        && settings.icons.library
        && !settings.icons.sources.is_empty()
        && let Err(error) = state.icons.refresh_library().await
    {
        tracing::warn!(%error, "the icon library's index could not be fetched");
    }
}

#[cfg(test)]
mod tests;
