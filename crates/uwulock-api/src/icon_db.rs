//! Icon databases that come with the server (docs/icons.md): 2FA Directory, Simple Icons and
//! Dashboard Icons, each taken from one fixed upstream commit and made into a pack file by
//! `uwulock-server icon-databases build` (scripts/icons/update.mjs runs it). The packs are part of
//! the binary; nothing is fetched for them, and a lookup is a few map reads.
//!
//! - **2FA Directory** knows the domains of a few thousand sites and their logos.
//! - **Simple Icons** has brand glyphs and colours; the domains are worked out when the pack is
//!   built ([`build`] says how).
//! - **Dashboard Icons** has logos of self-hosted apps, found by name: a device in the home
//!   network like `jellyfin.local`, and the icon library of the vault.
//!
//! A pack is `UWUICONS1\n`, the length of its index (u32, little-endian), the index as JSON, and
//! then the icons one after the other — SVG or PNG, each once however many names point to it.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

pub mod build;

pub const TWOFA: &str = "2fa-directory";
pub const SIMPLE: &str = "simple-icons";
pub const DASHBOARD: &str = "dashboard-icons";
/// Every database, in the order a public host is looked up (Dashboard Icons is not: it is for
/// names in the home network).
pub const ALL: [&str; 3] = [TWOFA, SIMPLE, DASHBOARD];

const MAGIC: &[u8] = b"UWUICONS1\n";

/// Who made a database, under which licence, and from which commit it was taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct About {
    pub id: String,
    pub name: String,
    pub url: String,
    pub license: String,
    pub license_url: String,
    pub attribution: String,
    pub repository: String,
    pub commit: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Svg,
    Png,
}

/// One icon in the pack: where it is, what it is, and the start of its SHA-256 (for the cache).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    #[serde(rename = "o")]
    offset: u64,
    #[serde(rename = "l")]
    len: u32,
    #[serde(rename = "k")]
    kind: Kind,
    #[serde(rename = "h")]
    hash: String,
}

/// An icon the vault's library offers, by its id there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibraryEntry {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub icon: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct Index {
    about: About,
    icons: Vec<Entry>,
    /// Domains (lower case, ASCII) and the icon of each.
    domains: BTreeMap<String, u32>,
    /// Names — ids and aliases, lower case — and the icon of each.
    names: BTreeMap<String, u32>,
    library: Vec<LibraryEntry>,
}

/// An icon found: its bytes, and a name for the cache that changes with its content.
#[derive(Debug, Clone, Copy)]
pub struct Found<'a> {
    pub database: &'a str,
    pub hash: &'a str,
    pub kind: Kind,
    pub bytes: &'a [u8],
}

/// One database, read from its pack.
pub struct Database {
    pub about: About,
    data: Cow<'static, [u8]>,
    start: usize,
    icons: Vec<Entry>,
    domains: HashMap<String, u32>,
    names: HashMap<String, u32>,
    library: Vec<LibraryEntry>,
    library_ids: HashMap<String, usize>,
}

impl Database {
    /// A pack, checked: every icon inside it, every name pointing to an icon there.
    pub fn parse(data: Cow<'static, [u8]>) -> Result<Self, String> {
        let rest = data.strip_prefix(MAGIC).ok_or("not an icon database")?;
        let length: [u8; 4] = rest.get(..4).and_then(|bytes| bytes.try_into().ok()).ok_or("cut short")?;
        let length = u32::from_le_bytes(length) as usize;
        let index = rest.get(4..4 + length).ok_or("cut short")?;
        let index: Index = serde_json::from_slice(index).map_err(|error| format!("its index: {error}"))?;
        let start = MAGIC.len() + 4 + length;
        let room = (data.len() - start) as u64;
        if index.icons.iter().any(|icon| icon.offset.saturating_add(u64::from(icon.len)) > room) {
            return Err("an icon lies outside the pack".into());
        }
        let count = index.icons.len() as u32;
        let known = |icon: &u32| *icon < count;
        if !index.domains.values().all(known)
            || !index.names.values().all(known)
            || !index.library.iter().all(|entry| known(&entry.icon))
        {
            return Err("a name points to no icon".into());
        }
        let library_ids = index.library.iter().enumerate().map(|(at, entry)| (entry.id.clone(), at)).collect();
        Ok(Database {
            about: index.about,
            data,
            start,
            icons: index.icons,
            domains: index.domains.into_iter().collect(),
            names: index.names.into_iter().collect(),
            library: index.library,
            library_ids,
        })
    }

    fn icon(&self, at: u32) -> Option<Found<'_>> {
        let entry = self.icons.get(at as usize)?;
        let from = self.start + entry.offset as usize;
        Some(Found {
            database: &self.about.id,
            hash: &entry.hash,
            kind: entry.kind,
            bytes: self.data.get(from..from + entry.len as usize)?,
        })
    }

    /// The icon of `host` (made plain by [`crate::icon_fetch::normalize_host`]) or of a domain
    /// above it, down to its registrable domain: `console.aws.example.com`, then
    /// `aws.example.com`, then `example.com`.
    pub fn by_domain(&self, host: &str) -> Option<Found<'_>> {
        let base = crate::icon_fetch::base_domain(host);
        let mut name = host;
        loop {
            if let Some(&at) = self.domains.get(name) {
                return self.icon(at);
            }
            match (&base, name.split_once('.')) {
                (Some(base), Some((_, parent))) if parent.len() >= base.len() => name = parent,
                _ => return None,
            }
        }
    }

    /// The icon of an app by its name, as a device in the home network is called: `jellyfin`,
    /// `home-assistant` or `homeassistant`.
    pub fn by_name(&self, name: &str) -> Option<Found<'_>> {
        let plain: String = name.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        [name, plain.as_str()].iter().find_map(|name| self.names.get(*name)).and_then(|&at| self.icon(at))
    }

    pub fn library(&self) -> &[LibraryEntry] {
        &self.library
    }

    pub fn library_icon(&self, id: &str) -> Option<Found<'_>> {
        self.library_ids.get(id).and_then(|&at| self.icon(self.library[at].icon))
    }

    /// Icons, domains and names in the pack, and its bytes.
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        (self.icons.len(), self.domains.len(), self.names.len(), self.data.len())
    }
}

/// The databases this server has; none in most tests.
#[derive(Default)]
pub struct Databases {
    list: Vec<Database>,
}

impl Databases {
    /// The packs given, each checked; one that cannot be read is left out (and said so).
    pub fn parse(packs: Vec<Cow<'static, [u8]>>) -> Self {
        let mut list: Vec<Database> = Vec::new();
        for pack in packs {
            match Database::parse(pack) {
                Ok(database) if ALL.contains(&database.about.id.as_str()) => list.push(database),
                Ok(database) => tracing::warn!(id = %database.about.id, "an icon database this server does not know"),
                Err(error) => tracing::warn!(%error, "an icon database could not be read"),
            }
        }
        list.sort_by_key(|database| ALL.iter().position(|id| *id == database.about.id));
        list.dedup_by(|a, b| a.about.id == b.about.id);
        Databases { list }
    }

    pub fn all(&self) -> &[Database] {
        &self.list
    }

    pub fn get(&self, id: &str) -> Option<&Database> {
        self.list.iter().find(|database| database.about.id == id)
    }

    fn on<'a>(&'a self, on: &[String]) -> impl Iterator<Item = &'a Database> + 'a {
        let on: Vec<String> = on.to_vec();
        self.list.iter().filter(move |database| on.contains(&database.about.id))
    }

    /// A public host's icon: 2FA Directory's by domain, else Simple Icons' — those of `on` only.
    pub fn for_host(&self, on: &[String], host: &str) -> Option<Found<'_>> {
        self.on(on).filter(|database| database.about.id != DASHBOARD).find_map(|database| database.by_domain(host))
    }

    /// A device in the home network: Dashboard Icons by the first label of its name.
    pub fn for_local(&self, on: &[String], raw: &str) -> Option<Found<'_>> {
        let label = local_label(raw)?;
        self.on(on).filter(|database| database.about.id == DASHBOARD).find_map(|database| database.by_name(&label))
    }
}

/// The first label of a name in the home network — `nextcloud` of `nextcloud.home.arpa`,
/// `jellyfin` of `jellyfin.local` or of `jellyfin` alone. None for a public name (it has its own
/// icon), and for addresses: they name no app.
pub fn local_label(raw: &str) -> Option<String> {
    if crate::icon_fetch::normalize_host(raw).is_some() {
        return None;
    }
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') || host.contains(':') {
        return None;
    }
    if host.split('.').all(|label| label.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    let label = host.split('.').next()?;
    let fine = (1..=63).contains(&label.len())
        && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && label.bytes().any(|b| b.is_ascii_alphabetic());
    (fine && label != "localhost").then(|| label.to_string())
}

// ── The packs in the binary ────────────────────────────────

static BUNDLED: OnceLock<Vec<&'static [u8]>> = OnceLock::new();
static PARSED: OnceLock<std::sync::Arc<Databases>> = OnceLock::new();

/// The packs compiled into the server's binary, handed over by its `main` before it serves: only
/// the binary carries them, not every test.
pub fn bundle(packs: Vec<&'static [u8]>) {
    let _ = BUNDLED.set(packs);
}

/// The bundled databases, read once.
pub fn bundled() -> std::sync::Arc<Databases> {
    PARSED
        .get_or_init(|| {
            let packs = BUNDLED.get().map(|packs| packs.iter().map(|pack| Cow::Borrowed(*pack)).collect());
            std::sync::Arc::new(Databases::parse(packs.unwrap_or_default()))
        })
        .clone()
}

// ── Writing a pack ─────────────────────────────────────────

/// A pack, put together: icons once each (by content), in the order they came.
pub struct Writer {
    about: About,
    blobs: Vec<u8>,
    icons: Vec<Entry>,
    seen: HashMap<Vec<u8>, u32>,
    domains: BTreeMap<String, u32>,
    names: BTreeMap<String, u32>,
    library: Vec<LibraryEntry>,
}

impl Writer {
    pub fn new(about: About) -> Self {
        Writer {
            about,
            blobs: Vec::new(),
            icons: Vec::new(),
            seen: HashMap::new(),
            domains: BTreeMap::new(),
            names: BTreeMap::new(),
            library: Vec::new(),
        }
    }

    /// An icon, and its number; the same bytes a second time are the same icon.
    pub fn icon(&mut self, bytes: &[u8], kind: Kind) -> u32 {
        let digest = crate::auth::sha256(bytes);
        if let Some(&at) = self.seen.get(&digest) {
            return at;
        }
        let at = self.icons.len() as u32;
        let hash = digest[..8].iter().map(|byte| format!("{byte:02x}")).collect();
        self.icons.push(Entry { offset: self.blobs.len() as u64, len: bytes.len() as u32, kind, hash });
        self.blobs.extend_from_slice(bytes);
        self.seen.insert(digest, at);
        at
    }

    /// `domain` has `icon`; the first one given stays.
    pub fn domain(&mut self, domain: &str, icon: u32) {
        self.domains.entry(domain.to_string()).or_insert(icon);
    }

    /// `name` is `icon`'s; the first one given stays.
    pub fn name(&mut self, name: &str, icon: u32) {
        self.names.entry(name.to_string()).or_insert(icon);
    }

    pub fn library(&mut self, entry: LibraryEntry) {
        self.library.push(entry);
    }

    pub fn finish(self) -> Vec<u8> {
        let index = Index {
            about: self.about,
            icons: self.icons,
            domains: self.domains,
            names: self.names,
            library: self.library,
        };
        let index = serde_json::to_vec(&index).expect("an index is JSON");
        let mut pack = Vec::with_capacity(MAGIC.len() + 4 + index.len() + self.blobs.len());
        pack.extend_from_slice(MAGIC);
        pack.extend_from_slice(&(index.len() as u32).to_le_bytes());
        pack.extend_from_slice(&index);
        pack.extend_from_slice(&self.blobs);
        pack
    }
}

#[cfg(test)]
pub(crate) mod tests;
