//! UwULock Server's mail: invitations, codes for two-step login, password hints, a note when a
//! new device logs in.
//!
//! Over SMTP, with TLS from the first byte (port 465), STARTTLS (587) or — only for a relay on
//! the same machine — none. The settings live in the database and change in the admin portal
//! while the server runs, so [`Mailer::configure`] swaps the connection without a restart.
//! Without settings the server works as before, only without what needs mail.
//!
//! Every mail is written in the language of whoever gets it, German or English, as plain text
//! and as simple HTML.

mod templates;

pub use templates::{Brand, Joining, Mail, NoticeLine, alert_text};

use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("no mail server is set up")]
    NotConfigured,
    #[error("{0}")]
    Settings(String),
    #[error("the mail server said: {0}")]
    Send(String),
}

/// How the connection to the mail server is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// TLS from the first byte, usually port 465.
    Tls,
    /// Plain first, then STARTTLS, usually port 587. Refused if the server does not offer it.
    #[default]
    Starttls,
    /// No TLS at all. Only for a relay on this machine or in the same private network.
    None,
}

/// What the admin portal asks for, stored as JSON in the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SmtpSettings {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub security: Security,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// The sender address, like `vault@example.com`.
    pub from: String,
    /// The sender name, like `UwULock`.
    #[serde(default)]
    pub from_name: Option<String>,
}

impl SmtpSettings {
    /// Whether there is enough to try: a host, a port and a sender.
    pub fn is_set(&self) -> bool {
        !self.host.trim().is_empty() && self.port != 0 && !self.from.trim().is_empty()
    }

    fn sender(&self) -> Result<Mailbox, MailError> {
        let name = self.from_name.clone().filter(|name| !name.trim().is_empty()).unwrap_or_else(|| "UwULock".into());
        let address =
            self.from.trim().parse().map_err(|_| MailError::Settings(format!("{} is not an address", self.from)))?;
        Ok(Mailbox::new(Some(name), address))
    }

    fn transport(&self) -> Result<AsyncSmtpTransport<Tokio1Executor>, MailError> {
        let host = self.host.trim();
        let builder = match self.security {
            Security::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(host),
            Security::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host),
            Security::None => Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)),
        }
        .map_err(|error| MailError::Settings(error.to_string()))?;
        let mut builder = builder.port(self.port).timeout(Some(Duration::from_secs(20)));
        if let Some(username) = self.username.as_ref().filter(|name| !name.is_empty()) {
            if self.security == Security::None && !nearby(host) {
                return Err(MailError::Settings(
                    "a password goes to a mail server only over TLS or STARTTLS, unless the server is on this machine or its network".into(),
                ));
            }
            builder =
                builder.credentials(Credentials::new(username.clone(), self.password.clone().unwrap_or_default()));
        }
        Ok(builder.build())
    }
}

/// A mail server that is on this machine or its own network, where a password without TLS
/// crosses nothing it should not: `localhost`, a name without a dot (a container next to this
/// one), or a loopback or private address.
fn nearby(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
        Err(_) => !host.contains('.'),
    }
}

/// German or English. What a user chose, or the server's default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    De,
    En,
}

impl Language {
    /// `de`, `de-DE`, `en-US` and friends; anything else is English.
    pub fn from_code(code: &str) -> Self {
        if code.trim().to_ascii_lowercase().starts_with("de") { Language::De } else { Language::En }
    }

    pub fn code(self) -> &'static str {
        match self {
            Language::De => "de",
            Language::En => "en",
        }
    }
}

/// A mail as it was sent, kept by [`Mailer::capturing`] for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    pub to: String,
    pub subject: String,
    pub text: String,
}

/// Sends mail, or says it cannot. Cheap to clone: every clone is the same.
#[derive(Clone)]
pub struct Mailer {
    inner: Arc<Inner>,
}

struct Inner {
    connection: RwLock<Option<Connection>>,
    /// In tests: what would have been sent, instead of sending it.
    captured: Option<Mutex<Vec<Sent>>>,
    health: Mutex<MailHealth>,
    /// The server's name and colour, for every mail.
    brand: RwLock<Brand>,
}

/// How sending goes, for the metrics, the admin alerts and the diagnosis.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailHealth {
    /// Mails that went out since the start.
    pub sent: u64,
    /// Mails the mail server did not take since the start.
    pub errors: u64,
    /// When the last one went out, as seconds since 1970.
    pub last_success: Option<u64>,
    /// When the last one did not, and why.
    pub last_error: Option<(u64, String)>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

#[derive(Clone)]
struct Connection {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    /// Whether the admin gave the sender a name of its own.
    named: bool,
}

impl Mailer {
    /// A mailer for these settings; none means mail is off.
    pub fn new(settings: Option<&SmtpSettings>) -> Result<Self, MailError> {
        let mailer = Mailer {
            inner: Arc::new(Inner {
                connection: RwLock::new(None),
                captured: None,
                health: Mutex::default(),
                brand: RwLock::default(),
            }),
        };
        mailer.configure(settings)?;
        Ok(mailer)
    }

    /// A mailer that keeps what it sends in memory, for tests.
    pub fn capturing() -> Self {
        Mailer {
            inner: Arc::new(Inner {
                connection: RwLock::new(None),
                captured: Some(Mutex::new(Vec::new())),
                health: Mutex::default(),
                brand: RwLock::default(),
            }),
        }
    }

    /// New settings, used from the next mail on. None, or settings that are not filled in, turn
    /// mail off. Needs a Tokio runtime: the connections are kept in a pool on it.
    pub fn configure(&self, settings: Option<&SmtpSettings>) -> Result<(), MailError> {
        let connection = match settings.filter(|settings| settings.is_set()) {
            Some(settings) => {
                let from = settings.sender()?;
                let named = settings.from_name.as_ref().is_some_and(|name| !name.trim().is_empty());
                Some(Connection { transport: settings.transport()?, from, named })
            }
            None => None,
        };
        *self.inner.connection.write() = connection;
        Ok(())
    }

    /// Whether mail goes out: a mail server is set up (or this mailer captures).
    pub fn enabled(&self) -> bool {
        self.inner.captured.is_some() || self.inner.connection.read().is_some()
    }

    /// The server's name and colour, from the next mail on.
    pub fn set_brand(&self, brand: Brand) {
        *self.inner.brand.write() = brand;
    }

    /// Write `mail` in `language` and send it to `to`.
    pub async fn send(&self, to: &str, mail: &Mail, language: Language) -> Result<(), MailError> {
        self.send_branded(to, mail, language, None).await
    }

    /// The same, in `brand`'s look instead of the server's: a send domain's own (Stufe 6).
    pub async fn send_branded(
        &self,
        to: &str,
        mail: &Mail,
        language: Language,
        brand: Option<&Brand>,
    ) -> Result<(), MailError> {
        let brand = brand.cloned().unwrap_or_else(|| self.inner.brand.read().clone());
        let (subject, text, html) = mail.render_branded(language, &brand);
        if let Some(captured) = &self.inner.captured {
            captured.lock().push(Sent { to: to.to_string(), subject, text });
            self.count(&Ok(()));
            return Ok(());
        }
        let Some(connection) = self.inner.connection.read().clone() else {
            return Err(MailError::NotConfigured);
        };
        let recipient: Mailbox = to.parse().map_err(|_| MailError::Send(format!("{to} is not an address")))?;
        // Without a sender name of its own, the mail comes from the server's name.
        let mut from = connection.from.clone();
        if brand.custom_name && !connection.named {
            from.name = Some(brand.name.clone());
        }
        let message = Message::builder()
            .from(from)
            .to(recipient)
            .subject(subject)
            .multipart(MultiPart::alternative_plain_html(text, html))
            .map_err(|error| MailError::Send(error.to_string()))?;
        let sent =
            connection.transport.send(message).await.map(drop).map_err(|error| MailError::Send(error.to_string()));
        self.count(&sent);
        sent?;
        tracing::debug!(to, "mail sent");
        Ok(())
    }

    fn count(&self, result: &Result<(), MailError>) {
        let mut health = self.inner.health.lock();
        match result {
            Ok(()) => {
                health.sent += 1;
                health.last_success = Some(unix_now());
            }
            Err(error) => {
                health.errors += 1;
                health.last_error = Some((unix_now(), error.to_string()));
            }
        }
    }

    /// How sending went since the start.
    pub fn health(&self) -> MailHealth {
        self.inner.health.lock().clone()
    }

    /// Whether the mail server takes a connection: connect, TLS, EHLO, login. Nothing is sent.
    pub async fn test_connection(&self) -> Result<(), MailError> {
        if self.inner.captured.is_some() {
            return Ok(());
        }
        let Some(connection) = self.inner.connection.read().clone() else {
            return Err(MailError::NotConfigured);
        };
        match connection.transport.test_connection().await {
            Ok(true) => Ok(()),
            Ok(false) => Err(MailError::Send("the mail server did not answer as expected".into())),
            Err(error) => Err(MailError::Send(error.to_string())),
        }
    }

    /// Everything a capturing mailer was asked to send so far.
    pub fn sent(&self) -> Vec<Sent> {
        self.inner.captured.as_ref().map(|captured| captured.lock().clone()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_language_from_what_clients_send() {
        assert_eq!(Language::from_code("de-DE"), Language::De);
        assert_eq!(Language::from_code("DE"), Language::De);
        assert_eq!(Language::from_code("en-GB"), Language::En);
        assert_eq!(Language::from_code("fr"), Language::En);
    }

    // The connection pool lives on the runtime, so this needs one.
    #[tokio::test]
    async fn settings_that_are_not_filled_in_turn_mail_off() {
        let mailer = Mailer::new(Some(&SmtpSettings::default())).unwrap();
        assert!(!mailer.enabled());
        let settings = SmtpSettings {
            host: "mail.example.com".into(),
            port: 587,
            from: "vault@example.com".into(),
            ..SmtpSettings::default()
        };
        mailer.configure(Some(&settings)).unwrap();
        assert!(mailer.enabled());
        mailer.configure(None).unwrap();
        assert!(!mailer.enabled());
    }

    #[tokio::test]
    async fn a_sender_that_is_no_address_is_refused() {
        let settings = SmtpSettings {
            host: "mail.example.com".into(),
            port: 587,
            from: "not an address".into(),
            ..SmtpSettings::default()
        };
        assert!(matches!(Mailer::new(Some(&settings)), Err(MailError::Settings(_))));
    }

    #[tokio::test]
    async fn without_a_server_nothing_is_sent() {
        let mailer = Mailer::new(None).unwrap();
        let result = mailer.send("nyu@example.com", &Mail::Test, Language::De).await;
        assert!(matches!(result, Err(MailError::NotConfigured)));
    }

    #[tokio::test]
    async fn a_capturing_mailer_keeps_what_it_sends() {
        let mailer = Mailer::capturing();
        mailer.send("nyu@example.com", &Mail::TwoFactorCode { code: "123456".into() }, Language::En).await.unwrap();
        let sent = mailer.sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].text.contains("123456"));
    }
}
