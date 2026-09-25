//! Everything the server reads from its environment.
//!
//! No config file: a container gets its settings from environment variables, and a setting that
//! lives in two places is a setting that disagrees with itself. Settings a person changes while
//! the server runs — mail, sign-ups — will live in the database and the admin portal instead.

use std::net::SocketAddr;
use std::path::PathBuf;

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
            channel: None,
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
        if let Some(check) = var("UWULOCK_UPDATE_CHECK") {
            config.update_check =
                switch(&check).ok_or_else(|| format!("UWULOCK_UPDATE_CHECK must be on or off: {check}"))?;
        }
        config.channel = var("UWULOCK_CHANNEL");

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
                let domain = acme_domain(public)?;
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
                TlsMode::Acme(Acme {
                    domain,
                    email: var("UWULOCK_ACME_EMAIL"),
                    directory,
                    directory_ca: var("UWULOCK_ACME_DIRECTORY_CA").map(PathBuf::from),
                })
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
        Some((host, port)) if !host.ends_with(':') && !(host.starts_with('[') && !host.ends_with(']')) => {
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
    fn a_setting_that_is_set_wrong_stops_the_start() {
        assert!(config(&[("UWULOCK_TLS", "maybe")]).is_err());
        assert!(config(&[("UWULOCK_LISTEN", "everywhere")]).is_err());
        assert!(config(&[("UWULOCK_UPDATE_CHECK", "later")]).is_err());
        assert!(config(&[("UWULOCK_TRUST_FORWARDED", "sometimes")]).is_err());
    }
}
