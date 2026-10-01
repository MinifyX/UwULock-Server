//! Where an address is, from a database on this server: DB-IP's free "IP to City Lite" and "IP
//! to ASN Lite" (CC BY 4.0, <https://db-ip.com>), for the admin portal's failed logins
//! (docs/failed-logins.md).
//!
//! Nothing is asked of anybody per address: the server downloads both files once a month from
//! DB-IP (`geoipUrl`), keeps them in `<data>/geoip`, and looks addresses up in them. Switched off
//! (the setting `geoip`), nothing is downloaded, nothing is looked up, and the files are deleted
//! by the next daily run.

use crate::AppState;
use maxminddb::{PathElement, Reader};
use memmap2::Mmap;
use parking_lot::RwLock;
use serde::Serialize;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The two files, by DB-IP's names without the month.
const CITY: &str = "dbip-city-lite";
const ASN: &str = "dbip-asn-lite";
/// What a downloaded file may be at most, packed and unpacked. The city file is about 130 MB.
const MOST_PACKED: u64 = 300 << 20;
const MOST_UNPACKED: u64 = 800 << 20;

/// Where an address is, as far as the databases know.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Place {
    /// ISO 3166-1 alpha-2, like `DE`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    /// The autonomous system and who runs it: the network the address belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

impl Place {
    fn is_empty(&self) -> bool {
        *self == Place::default()
    }
}

struct Databases {
    city: Option<Reader<Mmap>>,
    asn: Option<Reader<Mmap>>,
}

/// What the admin portal shows about the databases.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// The month of the files there are, like `2026-10`.
    pub month: Option<String>,
    pub city_bytes: u64,
    pub asn_bytes: u64,
    /// When the server last tried to download them, and what went wrong then.
    pub attempted: Option<String>,
    pub error: Option<String>,
}

/// The databases, opened, and their downloads.
pub struct GeoIp {
    dir: PathBuf,
    databases: RwLock<Option<Arc<Databases>>>,
    updating: tokio::sync::Mutex<()>,
    last: RwLock<(Option<String>, Option<String>)>,
}

impl GeoIp {
    /// The databases under `<data>/geoip`, opened if they are there.
    pub fn new(data: &Path) -> Self {
        let geoip = GeoIp {
            dir: data.join("geoip"),
            databases: RwLock::new(None),
            updating: tokio::sync::Mutex::new(()),
            last: RwLock::new((None, None)),
        };
        geoip.open();
        geoip
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.mmdb"))
    }

    /// Open what is on disk again.
    fn open(&self) {
        let open = |name: &str| {
            let path = self.file(name);
            if !path.exists() {
                return None;
            }
            // SAFETY: the files are never written in place: a download goes to a temporary
            // file that is renamed over the old one, and deleting a file leaves a mapping of it
            // as it was.
            match unsafe { Reader::open_mmap(&path) } {
                Ok(reader) => Some(reader),
                Err(error) => {
                    tracing::warn!(%error, path = %path.display(), "a GeoIP database does not open");
                    None
                }
            }
        };
        let (city, asn) = (open(CITY), open(ASN));
        *self.databases.write() =
            if city.is_none() && asn.is_none() { None } else { Some(Arc::new(Databases { city, asn })) };
    }

    /// Whether a download runs right now.
    pub fn updating(&self) -> bool {
        self.updating.try_lock().is_err()
    }

    /// Whether there is anything to look up in.
    pub fn ready(&self) -> bool {
        self.databases.read().is_some()
    }

    /// Where `ip` is, with names in `language` where the database has them (else English).
    /// Nothing for addresses in no database, like those of the local network.
    pub fn lookup(&self, ip: IpAddr, language: &str) -> Option<Place> {
        let databases = self.databases.read().clone()?;
        // An IPv4 address in IPv6 clothes is looked up as the IPv4 address it is.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        let mut place = Place::default();
        let languages = [language, "en"];
        if let Some(city) = &databases.city
            && let Ok(found) = city.lookup(ip)
            && found.has_data()
        {
            let text = |path: &[PathElement<'_>]| found.decode_path::<String>(path).ok().flatten();
            let named = |head: &[PathElement<'_>]| {
                languages.iter().find_map(|language| {
                    let mut path = head.to_vec();
                    path.extend([PathElement::Key("names"), PathElement::Key(language)]);
                    text(&path)
                })
            };
            place.country = text(&[PathElement::Key("country"), PathElement::Key("iso_code")]);
            place.country_name = named(&[PathElement::Key("country")]);
            place.region = named(&[PathElement::Key("subdivisions"), PathElement::Index(0)]);
            place.city = named(&[PathElement::Key("city")]);
        }
        if let Some(asn) = &databases.asn
            && let Ok(found) = asn.lookup(ip)
            && found.has_data()
        {
            place.asn = found.decode_path::<u32>(&[PathElement::Key("autonomous_system_number")]).ok().flatten();
            place.network =
                found.decode_path::<String>(&[PathElement::Key("autonomous_system_organization")]).ok().flatten();
        }
        (!place.is_empty()).then_some(place)
    }

    pub fn status(&self) -> Status {
        let size = |name: &str| std::fs::metadata(self.file(name)).map_or(0, |meta| meta.len());
        let (attempted, error) = self.last.read().clone();
        Status {
            month: std::fs::read_to_string(self.dir.join("month")).ok().map(|text| text.trim().to_string()),
            city_bytes: size(CITY),
            asn_bytes: size(ASN),
            attempted,
            error,
        }
    }

    /// Download this month's files from `base` (last month's while this month's are not out
    /// yet), unless they are here already. Hands back the month there is now.
    pub async fn update(&self, base: &str, month: &str, previous: &str) -> Result<String, String> {
        let _one_at_a_time = self.updating.lock().await;
        let result = self.download(base, month, previous).await;
        *self.last.write() = (Some(uwulock_store::clock::now()), result.as_ref().err().cloned());
        if let Err(error) = &result {
            tracing::warn!(%error, "the GeoIP databases were not updated");
        }
        result
    }

    async fn download(&self, base: &str, month: &str, previous: &str) -> Result<String, String> {
        let have = self.status().month;
        if have.as_deref() == Some(month) && self.ready() {
            return Ok(month.to_string());
        }
        tokio::fs::create_dir_all(&self.dir).await.map_err(|error| error.to_string())?;
        let mut got = None;
        for candidate in [month, previous] {
            if have.as_deref() == Some(candidate) && self.ready() {
                return Ok(candidate.to_string());
            }
            match fetch(base, CITY, candidate, &self.dir).await? {
                Some(city) => {
                    got = Some((candidate, city));
                    break;
                }
                None => continue,
            }
        }
        let Some((month, city)) = got else {
            return Err(format!("DB-IP has no files for {month} or {previous}"));
        };
        let asn =
            fetch(base, ASN, month, &self.dir).await?.ok_or_else(|| format!("DB-IP has no ASN file for {month}"))?;
        for (temporary, name) in [(city, CITY), (asn, ASN)] {
            tokio::fs::rename(&temporary, self.file(name)).await.map_err(|error| error.to_string())?;
        }
        tokio::fs::write(self.dir.join("month"), month).await.map_err(|error| error.to_string())?;
        self.open();
        tracing::info!(month, "the GeoIP databases were updated");
        Ok(month.to_string())
    }

    /// The files gone, for a server that switched GeoIP off.
    pub async fn forget(&self) {
        *self.databases.write() = None;
        if self.dir.exists()
            && let Err(error) = tokio::fs::remove_dir_all(&self.dir).await
        {
            tracing::warn!(%error, "the GeoIP databases could not be deleted");
        }
    }

    /// For tests: these files, as if downloaded.
    #[cfg(test)]
    pub(crate) fn install(&self, city: &[u8], asn: &[u8]) {
        std::fs::create_dir_all(&self.dir).unwrap();
        std::fs::write(self.file(CITY), city).unwrap();
        std::fs::write(self.file(ASN), asn).unwrap();
        std::fs::write(self.dir.join("month"), "2026-10").unwrap();
        self.open();
    }
}

fn client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: std::sync::OnceLock<Result<reqwest::Client, String>> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|error| error.to_string())?
                .with_root_certificates(roots)
                .with_no_client_auth();
            reqwest::Client::builder()
                .tls_backend_preconfigured(tls)
                .user_agent(concat!("UwULock-Server/", env!("CARGO_PKG_VERSION")))
                .redirect(reqwest::redirect::Policy::custom(|attempt| {
                    if attempt.previous().len() >= 3 {
                        attempt.error("too many redirects")
                    } else if !redirect_ok(attempt.url()) {
                        attempt.error("a redirect to where the server does not go")
                    } else {
                        attempt.follow()
                    }
                }))
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(15 * 60))
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Where DB-IP may send a download on: https only, to a public name or address — never into the
/// local network, nor to plain http where anybody on the way could change the file.
fn redirect_ok(url: &url::Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && match url.host() {
            Some(url::Host::Domain(name)) => crate::icon_fetch::normalize_host(name).is_some(),
            Some(url::Host::Ipv4(ip)) => crate::icon_fetch::public(IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => crate::icon_fetch::public(IpAddr::V6(ip)),
            None => false,
        }
}

/// `<base>/<name>-<month>.mmdb.gz`, unpacked and checked, in a temporary file in `dir`. Nothing
/// when DB-IP has no such file (404).
async fn fetch(base: &str, name: &str, month: &str, dir: &Path) -> Result<Option<PathBuf>, String> {
    use tokio::io::AsyncWriteExt as _;
    let url = format!("{}/{name}-{month}.mmdb.gz", base.trim_end_matches('/'));
    let mut response =
        client()?.get(&url).send().await.map_err(|error| format!("{url}: {}", crate::outbound::error_text(&error)))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(format!("{url} answered {}", response.status()));
    }
    let tag = uuid::Uuid::new_v4();
    let packed = dir.join(format!("{name}.{tag}.gz.tmp"));
    let unpacked = dir.join(format!("{name}.{tag}.mmdb.tmp"));
    let result = async {
        let mut file = tokio::fs::File::create(&packed).await.map_err(|error| error.to_string())?;
        let mut written = 0u64;
        while let Some(chunk) = response.chunk().await.map_err(|error| crate::outbound::error_text(&error))? {
            written += chunk.len() as u64;
            if written > MOST_PACKED {
                return Err(format!("{url} is larger than it should be"));
            }
            file.write_all(&chunk).await.map_err(|error| error.to_string())?;
        }
        file.flush().await.map_err(|error| error.to_string())?;
        drop(file);
        let (from, to) = (packed.clone(), unpacked.clone());
        tokio::task::spawn_blocking(move || unpack(&from, &to)).await.map_err(|error| error.to_string())??;
        Ok(())
    }
    .await;
    let _ = tokio::fs::remove_file(&packed).await;
    match result {
        Ok(()) => Ok(Some(unpacked)),
        Err(error) => {
            let _ = tokio::fs::remove_file(&unpacked).await;
            Err(error)
        }
    }
}

/// Unpack the gzip file `from` into `to`, and check it is a database that opens.
fn unpack(from: &Path, to: &Path) -> Result<(), String> {
    use std::io::Read as _;
    let packed = std::fs::File::open(from).map_err(|error| error.to_string())?;
    let mut reader = flate2::read::GzDecoder::new(packed).take(MOST_UNPACKED + 1);
    let mut file = std::fs::File::create(to).map_err(|error| error.to_string())?;
    let copied = std::io::copy(&mut reader, &mut file).map_err(|error| format!("unpacking: {error}"))?;
    if copied > MOST_UNPACKED {
        return Err("the database is larger than it should be".into());
    }
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    // SAFETY: nothing else knows of this temporary file, and it is not changed while it is read.
    unsafe { Reader::open_mmap(to) }.map_err(|error| format!("not a GeoIP database: {error}"))?;
    Ok(())
}

/// `YYYY-MM` of now, and of the month before.
fn months() -> (String, String) {
    let today = time::OffsetDateTime::now_utc().date();
    let earlier = today.replace_day(1).ok().and_then(|first| first.previous_day()).unwrap_or(today);
    let format = |date: time::Date| format!("{:04}-{:02}", date.year(), u8::from(date.month()));
    (format(today), format(earlier))
}

/// Download the files now: the admin portal's button, and a switch turned on.
pub async fn update_now(state: &AppState) -> Result<String, String> {
    let (month, previous) = months();
    state.geoip.update(&state.config.geoip_url, &month, &previous).await
}

/// Once a day: a new month's files when they are out, or the files gone when GeoIP is off.
pub async fn daily(state: &AppState) {
    if state.settings().geoip {
        let _ = update_now(state).await;
    } else {
        state.geoip.forget().await;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn downloads_are_redirected_only_to_https_on_the_internet() {
        for good in ["https://download.db-ip.com/free/x.gz", "https://cdn.example.com/x.gz"] {
            assert!(redirect_ok(&url::Url::parse(good).unwrap()), "{good}");
        }
        for bad in [
            "http://download.db-ip.com/free/x.gz",
            "https://127.0.0.1/x.gz",
            "https://[::1]/x.gz",
            "https://192.168.1.1/x.gz",
            "https://intranet/x.gz",
            "https://router.local/x.gz",
            "https://user:pw@cdn.example.com/x.gz",
            "file:///etc/passwd",
        ] {
            assert!(!redirect_ok(&url::Url::parse(bad).unwrap()), "{bad}");
        }
    }

    /// A MaxMind DB with these networks and records, written the way the format is specified
    /// (<https://maxmind.github.io/MaxMind-DB/>): an IPv6 search tree with 24-bit records,
    /// IPv4 below `::/96`. Enough for tests; no real database is ever downloaded in them.
    pub(crate) fn mmdb(kind: &str, networks: &[(&str, Value)]) -> Vec<u8> {
        #[derive(Clone, Copy)]
        enum Record {
            Empty,
            Node(usize),
            Data(usize),
        }
        let mut nodes: Vec<[Record; 2]> = vec![[Record::Empty, Record::Empty]];
        let mut data = Vec::new();
        for (network, record) in networks {
            let (address, prefix) = network.split_once('/').unwrap_or((network, ""));
            let address: IpAddr = address.parse().unwrap();
            let (bits, prefix) = match address {
                IpAddr::V4(v4) => (u128::from(u32::from(v4)), 96 + prefix.parse::<u32>().unwrap_or(32)),
                IpAddr::V6(v6) => (u128::from(v6), prefix.parse::<u32>().unwrap_or(128)),
            };
            let offset = data.len();
            encode(record, &mut data);
            let mut node = 0;
            for depth in 0..prefix {
                let bit = ((bits >> (127 - depth)) & 1) as usize;
                if depth == prefix - 1 {
                    nodes[node][bit] = Record::Data(offset);
                } else {
                    node = match nodes[node][bit] {
                        Record::Node(next) => next,
                        _ => {
                            nodes.push([Record::Empty, Record::Empty]);
                            nodes[node][bit] = Record::Node(nodes.len() - 1);
                            nodes.len() - 1
                        }
                    };
                }
            }
        }
        let count = nodes.len();
        let mut out = Vec::new();
        for node in &nodes {
            for record in node {
                let value = match record {
                    Record::Empty => count,
                    Record::Node(next) => *next,
                    Record::Data(offset) => count + 16 + offset,
                } as u32;
                out.extend_from_slice(&value.to_be_bytes()[1..]);
            }
        }
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&data);
        out.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
        let metadata = json!({
            "binary_format_major_version": {"u16": 2},
            "binary_format_minor_version": {"u16": 0},
            "build_epoch": {"u64": 1_790_000_000u64},
            "database_type": kind,
            "description": {"en": "test"},
            "ip_version": {"u16": 6},
            "languages": ["en", "de"],
            "node_count": count,
            "record_size": {"u16": 24},
        });
        encode(&metadata, &mut out);
        out
    }

    fn head(kind: u8, size: usize, out: &mut Vec<u8>) {
        let (first, extra): (u8, Vec<u8>) = match size {
            0..29 => (size as u8, vec![]),
            29..285 => (29, vec![(size - 29) as u8]),
            _ => (30, ((size - 285) as u16).to_be_bytes().to_vec()),
        };
        if kind <= 7 {
            out.push((kind << 5) | first);
        } else {
            out.push(first);
            out.push(kind - 7);
        }
        out.extend(extra);
    }

    /// JSON as MaxMind DB data: strings, maps, arrays, numbers as uint32; `{"u16": n}` and
    /// `{"u64": n}` for the metadata's other widths.
    fn encode(value: &Value, out: &mut Vec<u8>) {
        let unsigned = |kind: u8, number: u64, out: &mut Vec<u8>| {
            let bytes: Vec<u8> = number.to_be_bytes().into_iter().skip_while(|byte| *byte == 0).collect();
            head(kind, bytes.len(), out);
            out.extend(bytes);
        };
        match value {
            Value::String(text) => {
                head(2, text.len(), out);
                out.extend_from_slice(text.as_bytes());
            }
            Value::Number(number) => unsigned(6, number.as_u64().unwrap(), out),
            Value::Array(items) => {
                head(11, items.len(), out);
                items.iter().for_each(|item| encode(item, out));
            }
            Value::Object(fields) if fields.len() == 1 && fields.contains_key("u16") => {
                unsigned(5, fields["u16"].as_u64().unwrap(), out);
            }
            Value::Object(fields) if fields.len() == 1 && fields.contains_key("u64") => {
                unsigned(9, fields["u64"].as_u64().unwrap(), out);
            }
            Value::Object(fields) => {
                head(7, fields.len(), out);
                for (key, item) in fields {
                    encode(&Value::String(key.clone()), out);
                    encode(item, out);
                }
            }
            other => panic!("not in the test format: {other}"),
        }
    }

    /// The city and ASN databases the tests use: 203.0.113.0/24 in Berlin, 2001:db8::/32 in
    /// Vienna, both in documentation networks.
    pub(crate) fn fixtures() -> (Vec<u8>, Vec<u8>) {
        let city = mmdb(
            "DBIP-City-Lite",
            &[
                (
                    "203.0.113.0/24",
                    json!({
                        "city": {"names": {"en": "Berlin"}},
                        "country": {"iso_code": "DE", "names": {"en": "Germany", "de": "Deutschland"}},
                        "subdivisions": [{"names": {"en": "Land Berlin"}}],
                    }),
                ),
                (
                    "2001:db8::/32",
                    json!({
                        "city": {"names": {"en": "Vienna", "de": "Wien"}},
                        "country": {"iso_code": "AT", "names": {"en": "Austria", "de": "Österreich"}},
                    }),
                ),
            ],
        );
        let asn = mmdb(
            "DBIP-ASN-Lite",
            &[(
                "203.0.113.0/24",
                json!({"autonomous_system_number": 64496, "autonomous_system_organization": "Example Net"}),
            )],
        );
        (city, asn)
    }

    #[test]
    fn addresses_are_found_in_the_databases() {
        let dir = tempfile::tempdir().unwrap();
        let geoip = GeoIp::new(dir.path());
        assert!(!geoip.ready() && geoip.lookup("203.0.113.9".parse().unwrap(), "de").is_none());
        let (city, asn) = fixtures();
        geoip.install(&city, &asn);
        let berlin = geoip.lookup("203.0.113.9".parse().unwrap(), "de").unwrap();
        assert_eq!(
            berlin,
            Place {
                country: Some("DE".into()),
                country_name: Some("Deutschland".into()),
                region: Some("Land Berlin".into()),
                city: Some("Berlin".into()),
                asn: Some(64496),
                network: Some("Example Net".into()),
            }
        );
        let vienna = geoip.lookup("2001:db8::7".parse().unwrap(), "en").unwrap();
        assert_eq!((vienna.city.as_deref(), vienna.asn), (Some("Vienna"), None));
        assert_eq!(geoip.lookup("::ffff:203.0.113.9".parse().unwrap(), "en").unwrap().country.as_deref(), Some("DE"));
        assert!(geoip.lookup("198.51.100.1".parse().unwrap(), "en").is_none(), "in no database");
        assert_eq!(geoip.status().month.as_deref(), Some("2026-10"));
    }

    /// DB-IP on this machine: the month's files, or only last month's.
    async fn fake_dbip(months: &'static [&'static str]) -> String {
        use axum::extract::Path as UrlPath;
        use std::io::Write as _;
        let (city, asn) = fixtures();
        let pack = |bytes: &[u8]| {
            let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(bytes).unwrap();
            encoder.finish().unwrap()
        };
        let (city, asn) = (Arc::new(pack(&city)), Arc::new(pack(&asn)));
        let app = axum::Router::new().route(
            "/{file}",
            axum::routing::get(move |UrlPath(file): UrlPath<String>| {
                let (city, asn) = (city.clone(), asn.clone());
                async move {
                    let month = months.iter().find(|month| file.ends_with(&format!("-{month}.mmdb.gz")));
                    match (month, file.starts_with(CITY), file.starts_with(ASN)) {
                        (Some(_), true, _) => Ok((*city).clone()),
                        (Some(_), _, true) => Ok((*asn).clone()),
                        _ => Err(axum::http::StatusCode::NOT_FOUND),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{address}")
    }

    #[tokio::test]
    async fn the_files_are_downloaded_once_a_month_and_last_months_until_then() {
        let base = fake_dbip(&["2026-09"]).await;
        let dir = tempfile::tempdir().unwrap();
        let geoip = GeoIp::new(dir.path());
        assert_eq!(geoip.update(&base, "2026-10", "2026-09").await.unwrap(), "2026-09");
        assert_eq!(geoip.lookup("203.0.113.1".parse().unwrap(), "en").unwrap().network.as_deref(), Some("Example Net"));
        let status = geoip.status();
        assert_eq!(status.month.as_deref(), Some("2026-09"));
        assert!(status.city_bytes > 0 && status.asn_bytes > 0 && status.error.is_none());
        let leftovers = std::fs::read_dir(dir.path().join("geoip")).unwrap().filter_map(Result::ok);
        assert!(leftovers.into_iter().all(|entry| !entry.file_name().to_string_lossy().ends_with(".tmp")));

        let nothing = fake_dbip(&[]).await;
        let error = geoip.update(&nothing, "2026-11", "2026-10").await.unwrap_err();
        assert!(error.contains("no files"), "{error}");
        assert_eq!(geoip.status().error.as_deref(), Some(error.as_str()));
        assert!(geoip.ready(), "the old files stay in use");
        assert_eq!(geoip.update(&nothing, "2026-10", "2026-09").await.unwrap(), "2026-09", "nothing to fetch");

        geoip.forget().await;
        assert!(!geoip.ready() && !dir.path().join("geoip").exists());
    }

    #[test]
    fn months_are_this_one_and_the_one_before() {
        let (now, before) = months();
        assert_eq!((now.len(), before.len()), (7, 7));
        assert!(before < now);
    }
}
