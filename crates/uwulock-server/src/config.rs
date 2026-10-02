//! Everything the server reads from its environment.
//!
//! No config file: a container gets its settings from environment variables, and a setting that
//! lives in two places is a setting that disagrees with itself. Settings a person changes while
//! the server runs — mail, invitations — live in the database and the admin portal; what is set
//! for them here is only where a new server starts.

use std::net::SocketAddr;
use std::path::PathBuf;
use uwulock_api::Settings;
use uwulock_mail::{Language, Security, SmtpSettings};

use crate::updates;

/// Where the certificate comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsMode {
    /// Plain HTTP, because a reverse proxy in front does TLS.
    Off,
    /// Certificate and key from two PEM files — from certbot, a company CA, whatever. They are
    /// read again when they change, so a renewed certificate needs no restart.
    Files { cert: PathBuf, key: PathBuf },
    /// A certificate from Let's Encrypt (or another ACME CA), for the name in `UWULOCK_PUBLIC`,
    /// renewed by the server itself. Needs that name to point here and port 443 to reach it.
    Acme(Acme),
}

impl TlsMode {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Files { .. } => "files",
            Self::Acme(_) => "acme",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acme {
    /// The name the certificate is for.
    pub domain: String,
    /// Where the CA writes about expiring certificates or problems. Optional.
    pub email: Option<String>,
    /// The CA's ACME directory.
    pub directory: String,
    /// A CA certificate to trust for talking to that directory, besides the usual ones. Only for
    /// a test CA like Pebble.
    pub directory_ca: Option<PathBuf>,
}

pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Debug, Clone)]
pub struct Config {
    /// The database, the backups, the ACME account and certificate. One volume.
    pub data_dir: PathBuf,
    pub listen: SocketAddr,
    /// How clients reach this server, as the address they type into their "server URL" field:
    /// `https://vault.example.com`. Also what mails and the web vault link to.
    pub public: Option<String>,
    pub tls: TlsMode,
    /// Trust `X-Forwarded-For` for the address a request comes from. Only ever on behind a proxy
    /// that sets it, or anyone can pretend to be someone else.
    pub trust_forwarded: bool,
    /// Ask GitHub once a day whether there is a newer release, and say so in the log. The only
    /// connection the server opens on its own.
    pub update_check: bool,
    /// The image tag this machine follows (`latest`, `beta`, `edge` or a version), which decides
    /// what counts as an update.
    pub channel: Option<String>,
    /// How many logins one address may try at once before it has to wait (one more a minute).
    /// More for many people behind one address.
    pub login_attempts: u32,
    /// Mail server and default language a new server starts with, until an admin saves others
    /// in the portal.
    pub start_settings: Settings,
    /// The extras a new server starts with switched on (`UWULOCK_FEATURES`: `all`, or names
    /// like `families,file-requests`); `None` when it is not set: then what the database kept
    /// from an earlier start with it, or none. A server that has its switches in the database
    /// keeps those (docs/features.md).
    pub start_features: Option<uwulock_api::Features>,
    /// Servers whose `Date` header the diagnosis compares the clock with. GitHub, which the
    /// update check asks anyway, unless the update check is off or `UWULOCK_TIME_SOURCE` says
    /// otherwise (`off` for none).
    pub time_sources: Vec<String>,
    /// The ACME CA and contact for send domains' certificates (docs/uwu-api.md §14.1), without a
    /// name: each domain brings its own.
    pub send_domain_acme: Acme,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            listen: "0.0.0.0:8443".parse().expect("a literal address"),
            public: None,
            tls: TlsMode::Off,
            trust_forwarded: false,
            update_check: true,
            login_attempts: 10,
            channel: None,
            start_settings: Settings::default(),
            start_features: None,
            time_sources: Vec::new(),
            send_domain_acme: Acme {
                domain: String::new(),
                email: None,
                directory: LETS_ENCRYPT.to_string(),
                directory_ca: None,
            },
        }
    }
}

impl Config {
    /// Read the environment. A variable that is set but unusable is an error rather than a
    /// default quietly taking over — a server that listens somewhere else than asked, or without
    /// the TLS it was told to use, is worse than one that refuses to start.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let var = |name: &str| lookup(name).map(|value| value.trim().to_string()).filter(|value| !value.is_empty());
        let mut config = Config::default();

        if let Some(dir) = var("UWULOCK_DATA") {
            config.data_dir = PathBuf::from(dir);
        }
        if let Some(listen) = var("UWULOCK_LISTEN") {
            config.listen = listen.parse().map_err(|_| format!("UWULOCK_LISTEN is not an address: {listen}"))?;
        }
        if let Some(public) = var("UWULOCK_PUBLIC") {
            config.public = Some(normalize_public(&public)?);
        }
        if let Some(trust) = var("UWULOCK_TRUST_FORWARDED") {
            config.trust_forwarded =
                switch(&trust).ok_or_else(|| format!("UWULOCK_TRUST_FORWARDED must be on or off: {trust}"))?;
        }
        if let Some(attempts) = var("UWULOCK_LOGIN_ATTEMPTS") {
            config.login_attempts = attempts
                .trim()
                .parse()
                .ok()
                .filter(|attempts| (1..=10_000).contains(attempts))
                .ok_or_else(|| format!("UWULOCK_LOGIN_ATTEMPTS must be a number from 1 to 10000: {attempts}"))?;
        }
        if let Some(check) = var("UWULOCK_UPDATE_CHECK") {
            config.update_check =
                switch(&check).ok_or_else(|| format!("UWULOCK_UPDATE_CHECK must be on or off: {check}"))?;
        }
        config.channel = var("UWULOCK_CHANNEL");
        config.time_sources = match var("UWULOCK_TIME_SOURCE") {
            Some(off) if switch(&off) == Some(false) => Vec::new(),
            Some(sources) => sources
                .split([',', ' '])
                .filter(|source| !source.is_empty())
                .map(|source| {
                    if source.starts_with("https://") || source.starts_with("http://") {
                        Ok(source.trim_end_matches('/').to_string())
                    } else {
                        Err(format!("UWULOCK_TIME_SOURCE must be http(s) addresses or off: {source}"))
                    }
                })
                .collect::<Result<_, _>>()?,
            None if config.update_check => vec![updates::TIME_SOURCE.to_string()],
            None => Vec::new(),
        };
        if let Some(features) = var("UWULOCK_FEATURES") {
            config.start_features = Some(
                uwulock_api::Features::parse_list(&features).map_err(|error| format!("UWULOCK_FEATURES: {error}"))?,
            );
        }
        if let Some(language) = var("UWULOCK_LANGUAGE") {
            config.start_settings.default_language = match language.to_ascii_lowercase().as_str() {
                "de" => Language::De,
                "en" => Language::En,
                _ => return Err(format!("UWULOCK_LANGUAGE must be de or en: {language}")),
            };
        }
        if let Some(host) = var("UWULOCK_SMTP_HOST") {
            let security = match var("UWULOCK_SMTP_SECURITY").as_deref().map(str::to_ascii_lowercase).as_deref() {
                None | Some("starttls") => Security::Starttls,
                Some("tls" | "ssl") => Security::Tls,
                Some("none" | "off") => Security::None,
                Some(other) => return Err(format!("UWULOCK_SMTP_SECURITY must be starttls, tls or none: {other}")),
            };
            let port = match var("UWULOCK_SMTP_PORT") {
                Some(port) => port.parse().map_err(|_| format!("UWULOCK_SMTP_PORT is not a port: {port}"))?,
                None => match security {
                    Security::Tls => 465,
                    Security::Starttls => 587,
                    Security::None => 25,
                },
            };
            let from =
                var("UWULOCK_SMTP_FROM").ok_or("UWULOCK_SMTP_HOST needs UWULOCK_SMTP_FROM: the sender address")?;
            config.start_settings.smtp = Some(SmtpSettings {
                host,
                port,
                security,
                username: var("UWULOCK_SMTP_USERNAME"),
                password: var("UWULOCK_SMTP_PASSWORD"),
                from,
                from_name: var("UWULOCK_SMTP_FROM_NAME"),
            });
        }

        // The CA for the main host with UWULOCK_TLS=acme, and for send domains that get their
        // certificate from the server whenever it does TLS itself (files or acme).
        let directory = match var("UWULOCK_ACME_DIRECTORY").as_deref() {
            None | Some("letsencrypt") => LETS_ENCRYPT.to_string(),
            Some("staging") => LETS_ENCRYPT_STAGING.to_string(),
            Some(url) if url.starts_with("https://") => url.to_string(),
            Some(other) => {
                return Err(format!(
                    "UWULOCK_ACME_DIRECTORY must be letsencrypt, staging or an https:// address: {other}"
                ));
            }
        };
        config.send_domain_acme = Acme {
            domain: String::new(),
            email: var("UWULOCK_ACME_EMAIL"),
            directory,
            directory_ca: var("UWULOCK_ACME_DIRECTORY_CA").map(PathBuf::from),
        };
        config.tls = match var("UWULOCK_TLS").as_deref().map(str::to_ascii_lowercase).as_deref() {
            None | Some("off" | "proxy") => TlsMode::Off,
            Some("files") => TlsMode::Files {
                cert: var("UWULOCK_TLS_CERT").map_or_else(|| config.data_dir.join("tls/cert.pem"), PathBuf::from),
                key: var("UWULOCK_TLS_KEY").map_or_else(|| config.data_dir.join("tls/key.pem"), PathBuf::from),
            },
            Some("acme") => {
                let public = config
                    .public
                    .as_deref()
                    .ok_or("UWULOCK_TLS=acme needs UWULOCK_PUBLIC: the name the certificate is for")?;
                TlsMode::Acme(Acme { domain: acme_domain(public)?, ..config.send_domain_acme.clone() })
            }
            Some(other) => return Err(format!("UWULOCK_TLS must be acme, files or off: {other}")),
        };
        Ok(config)
    }

    /// `uwulock.db` in the data directory.
    pub fn database(&self) -> PathBuf {
        self.data_dir.join("uwulock.db")
    }

    pub fn backups(&self) -> PathBuf {
        self.data_dir.join("backups")
    }

    /// Where Let's Encrypt's account key and the certificates are kept, so a restart does not
    /// ask for a new one — Let's Encrypt allows only a few per week.
    pub fn acme_cache(&self) -> PathBuf {
        self.data_dir.join("acme")
    }

    /// Where the diagnosis looks at the certificate clients get: this server's own listener with
    /// its public name when it does TLS itself, the public address when a proxy does. None for an
    /// http address.
    pub fn certificate_probe(&self) -> Option<uwulock_api::certificate::Probe> {
        let public = self.public.as_deref()?;
        let host_port = public.strip_prefix("https://")?;
        let (host, port) = match host_port.rsplit_once(':') {
            Some((host, port)) if !host.ends_with(':') && port.chars().all(|c| c.is_ascii_digit()) => (host, port),
            _ => (host_port, "443"),
        };
        let name = host.trim_start_matches('[').trim_end_matches(']').to_string();
        let connect = match self.tls {
            TlsMode::Off => format!("{host}:{port}"),
            _ if self.listen.ip().is_unspecified() => format!("127.0.0.1:{}", self.listen.port()),
            _ => self.listen.to_string(),
        };
        Some(uwulock_api::certificate::Probe { connect, name })
    }

    /// How a client writes this server down.
    pub fn base_url(&self) -> String {
        match &self.public {
            Some(public) => public.clone(),
            None => {
                let scheme = if self.tls == TlsMode::Off { "http" } else { "https" };
                format!("{scheme}://{}", self.listen)
            }
        }
    }
}

/// `vault.example.com` and `https://vault.example.com/` both become `https://vault.example.com`.
/// Only http and https; nothing after the host but a port. (A server under a path, like
/// `https://example.com/vault`, is something the official apps handle badly, so it is not
/// offered.)
fn normalize_public(value: &str) -> Result<String, String> {
    let value = value.trim_end_matches('/');
    let (scheme, rest) = match value.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => ("https".to_string(), value),
    };
    if scheme != "https" && scheme != "http" {
        return Err(format!("UWULOCK_PUBLIC must be an http(s) address: {value}"));
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(':') && (!host.starts_with('[') || host.ends_with(']')) => {
            (host, Some(port))
        }
        _ => (rest, None),
    };
    let host_ok = match host.strip_prefix('[').and_then(|inner| inner.strip_suffix(']')) {
        Some(ipv6) => ipv6.parse::<std::net::Ipv6Addr>().is_ok(),
        None => !host.is_empty() && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'),
    };
    let port_ok = port.is_none_or(|port| port.parse::<u16>().is_ok_and(|port| port > 0));
    if !host_ok || !port_ok {
        return Err(format!("UWULOCK_PUBLIC must be a name or address with an optional port, and no path: {value}"));
    }
    Ok(format!("{scheme}://{}", rest.to_ascii_lowercase()))
}

/// The host of `https://vault.example.com[:port]`, if a CA can issue a certificate for it.
fn acme_domain(public: &str) -> Result<String, String> {
    let host_port = public.split_once("://").map_or(public, |(_, rest)| rest);
    let host = match host_port.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => host_port,
    };
    let is_name = host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
        && !host.split('.').all(|label| label.chars().all(|c| c.is_ascii_digit()));
    if !is_name {
        return Err(format!(
            "UWULOCK_TLS=acme needs a public name like vault.example.com in UWULOCK_PUBLIC, not {host}"
        ));
    }
    Ok(host.to_string())
}

fn switch(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "1" | "true" | "yes" => Some(true),
        "off" | "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(pairs: &[(&str, &str)]) -> Result<Config, String> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Config::from_lookup(|name| map.get(name).cloned())
    }

    #[test]
    fn the_defaults_are_the_documented_ones() {
        let config = config(&[]).unwrap();
        assert_eq!(config.listen.port(), 8443);
        assert_eq!(config.tls, TlsMode::Off);
        assert!(!config.trust_forwarded, "off unless a proxy is in front");
        assert!(config.update_check);
        assert_eq!(config.database().file_name().unwrap(), "uwulock.db");
        assert_eq!(config.base_url(), "http://0.0.0.0:8443");
    }

    #[test]
    fn the_public_address_is_written_one_way() {
        for (given, expected) in [
            ("vault.example.com", "https://vault.example.com"),
            ("https://Vault.Example.com/", "https://vault.example.com"),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
            ("vault.example.com:8443", "https://vault.example.com:8443"),
            ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
        ] {
            let config = config(&[("UWULOCK_PUBLIC", given)]).unwrap();
            assert_eq!(config.base_url(), expected, "{given}");
        }
        for wrong in [
            "ftp://vault.example.com",
            "https://example.com/vault",
            "https://user@example.com",
            "https://",
            "vault.example.com:0",
            "vault.example.com:http",
            "https://[not-an-address]",
        ] {
            assert!(config(&[("UWULOCK_PUBLIC", wrong)]).is_err(), "{wrong}");
        }
    }

    #[test]
    fn acme_needs_a_name_it_can_certify() {
        let acme = config(&[("UWULOCK_TLS", "acme"), ("UWULOCK_PUBLIC", "https://vault.example.com")]).unwrap();
        match acme.tls {
            TlsMode::Acme(acme) => {
                assert_eq!(acme.domain, "vault.example.com");
                assert_eq!(acme.directory, LETS_ENCRYPT);
                assert_eq!(acme.email, None);
            }
            other => panic!("{other:?}"),
        }
        assert!(config(&[("UWULOCK_TLS", "acme")]).is_err(), "no name at all");
        assert!(config(&[("UWULOCK_TLS", "acme"), ("UWULOCK_PUBLIC", "192.0.2.10")]).is_err(), "an address");
        assert!(config(&[("UWULOCK_TLS", "acme"), ("UWULOCK_PUBLIC", "localhost")]).is_err(), "no dot");

        let staging = config(&[
            ("UWULOCK_TLS", "acme"),
            ("UWULOCK_PUBLIC", "vault.example.com"),
            ("UWULOCK_ACME_DIRECTORY", "staging"),
            ("UWULOCK_ACME_EMAIL", "admin@example.com"),
        ])
        .unwrap();
        match staging.tls {
            TlsMode::Acme(acme) => {
                assert_eq!(acme.directory, LETS_ENCRYPT_STAGING);
                assert_eq!(acme.email.as_deref(), Some("admin@example.com"));
            }
            other => panic!("{other:?}"),
        }
        assert!(
            config(&[
                ("UWULOCK_TLS", "acme"),
                ("UWULOCK_PUBLIC", "vault.example.com"),
                ("UWULOCK_ACME_DIRECTORY", "http://pebble.test/dir")
            ])
            .is_err(),
            "a directory over plain http"
        );
    }

    #[test]
    fn files_default_to_the_data_directory() {
        let config = config(&[("UWULOCK_TLS", "files"), ("UWULOCK_DATA", "/data")]).unwrap();
        assert_eq!(
            config.tls,
            TlsMode::Files { cert: PathBuf::from("/data/tls/cert.pem"), key: PathBuf::from("/data/tls/key.pem") }
        );
        assert_eq!(config.base_url(), "https://0.0.0.0:8443");
    }

    #[test]
    fn mail_from_the_environment_is_where_a_new_server_starts() {
        let started = config(&[
            ("UWULOCK_SMTP_HOST", "mail.example.com"),
            ("UWULOCK_SMTP_SECURITY", "tls"),
            ("UWULOCK_SMTP_FROM", "vault@example.com"),
            ("UWULOCK_LANGUAGE", "en"),
        ])
        .unwrap();
        let smtp = started.start_settings.smtp.unwrap();
        assert_eq!((smtp.port, smtp.security), (465, Security::Tls));
        assert_eq!(started.start_settings.default_language, Language::En);
        assert!(config(&[("UWULOCK_SMTP_HOST", "mail.example.com")]).is_err(), "no sender");
        assert!(config(&[("UWULOCK_LANGUAGE", "fr")]).is_err());
    }

    #[test]
    fn a_new_server_starts_with_the_features_it_is_told() {
        use uwulock_api::{Feature, Features};
        assert_eq!(config(&[]).unwrap().start_features, None, "what the database kept, or only the vault and icons");
        assert_eq!(config(&[("UWULOCK_FEATURES", "all")]).unwrap().start_features, Some(Features::all()));
        assert_eq!(config(&[("UWULOCK_FEATURES", "none")]).unwrap().start_features, Some(Features::none()));
        let some = config(&[("UWULOCK_FEATURES", "families, file-requests")]).unwrap().start_features.unwrap();
        assert_eq!(some.names(), [Feature::Families.id(), Feature::FileRequests.id()]);
        assert!(config(&[("UWULOCK_FEATURES", "families,teleport")]).is_err());
    }

    #[test]
    fn a_setting_that_is_set_wrong_stops_the_start() {
        assert!(config(&[("UWULOCK_TLS", "maybe")]).is_err());
        assert!(config(&[("UWULOCK_LISTEN", "everywhere")]).is_err());
        assert!(config(&[("UWULOCK_UPDATE_CHECK", "later")]).is_err());
        assert!(config(&[("UWULOCK_LOGIN_ATTEMPTS", "0")]).is_err());
        assert_eq!(config(&[("UWULOCK_LOGIN_ATTEMPTS", "50")]).unwrap().login_attempts, 50);
        assert!(config(&[("UWULOCK_TRUST_FORWARDED", "sometimes")]).is_err());
    }

    #[test]
    fn the_clock_is_compared_with_github_unless_told_otherwise() {
        assert_eq!(config(&[]).unwrap().time_sources, vec![updates::TIME_SOURCE.to_string()]);
        assert!(config(&[("UWULOCK_UPDATE_CHECK", "off")]).unwrap().time_sources.is_empty());
        assert!(config(&[("UWULOCK_TIME_SOURCE", "off")]).unwrap().time_sources.is_empty());
        let own = config(&[("UWULOCK_TIME_SOURCE", "https://time.example.com/, http://192.0.2.1")]).unwrap();
        assert_eq!(own.time_sources, vec!["https://time.example.com", "http://192.0.2.1"]);
        assert!(config(&[("UWULOCK_TIME_SOURCE", "ntp.example.com")]).is_err());
    }

    #[test]
    fn the_certificate_is_looked_at_where_clients_get_it() {
        let proxy = config(&[("UWULOCK_PUBLIC", "https://lock.example.com")]).unwrap().certificate_probe().unwrap();
        assert_eq!((proxy.connect.as_str(), proxy.name.as_str()), ("lock.example.com:443", "lock.example.com"));
        let own = config(&[
            ("UWULOCK_PUBLIC", "https://lock.example.com:8443"),
            ("UWULOCK_TLS", "files"),
            ("UWULOCK_LISTEN", "0.0.0.0:8443"),
        ])
        .unwrap()
        .certificate_probe()
        .unwrap();
        assert_eq!((own.connect.as_str(), own.name.as_str()), ("127.0.0.1:8443", "lock.example.com"));
        assert!(config(&[("UWULOCK_PUBLIC", "http://192.0.2.1:8080")]).unwrap().certificate_probe().is_none());
    }
}
