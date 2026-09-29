//! The settings an admin changes in the portal while the server runs: mail, invitations, a few
//! switches. Kept as JSON in the database; `.env` only gives the values a new server starts with.

use serde::{Deserialize, Serialize};
use uwulock_mail::{Language, SmtpSettings};
use uwulock_store::Store;

const KEY: &str = "settings";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// The mail server; none means the server sends no mail.
    pub smtp: Option<SmtpSettings>,
    /// For invitations, and for accounts until their owner picks a language.
    pub default_language: Language,
    /// How long an invitation link works.
    pub invitation_days: u32,
    /// A mail when a device logs in to an account for the first time.
    pub new_device_mail: bool,
    /// Whether a master password hint may be kept, and sent by mail when asked for.
    pub password_hints: bool,
    /// Whether "remember this device" may skip two-step login for 30 days.
    pub remember_two_factor: bool,
    /// The largest attachment or Send file, in MiB.
    pub max_file_mb: u32,
    /// Whether the web vault's password check may ask Have I Been Pwned, through this server,
    /// whether a password was in a breach.
    pub hibp: bool,
    /// Bitwarden's push relay, for waking the phone apps: installation id and key from
    /// bitwarden.com/host. None: the apps sync when they are opened.
    pub push: Option<uwulock_notify::relay::RelaySettings>,
    /// Whether every account may invite people, not only admins.
    pub users_may_invite: bool,
    /// How many accounts one user may bring in, counting invitations that still work.
    pub invitations_per_user: u32,
    /// Security notices: which kinds are not mailed (they are listed all the same).
    pub security_notices: SecurityNoticeSettings,
    /// Rules for every account: two-step login, the key derivation, the master password.
    pub policies: crate::policies::Policies,
    /// Networks the admin portal answers from, like `192.0.2.0/24`; none means everywhere.
    pub admin_networks: Vec<String>,
    /// `/metrics` for Prometheus.
    pub metrics: crate::metrics::MetricsSettings,
    /// The log to Grafana Loki.
    pub loki: crate::loki::LokiSettings,
    /// File requests: links people without an account upload files to.
    pub file_requests: FileRequestSettings,
    /// How much an account may keep in files (attachments, Send files, file requests), versions
    /// and own icons, in MiB; none for no limit.
    pub storage_per_user_mb: Option<u64>,
    /// Logging in through an OpenID Connect provider (docs/uwu-api.md §19.1). Changed through its
    /// own endpoints, `/uwu/v1/admin/sso`, never with the rest.
    pub sso: crate::sso::SsoSettings,
    /// SCIM from the provider: what a deleted person means, and the token's hash.
    pub scim: crate::scim::ScimSettings,
    /// Earlier states of items: how many, how long.
    pub versions: VersionSettings,
    /// Website icons: fetched by the server, and the icon library.
    pub icons: IconSettings,
    /// Families (Stufe 4d): who may make one, how many members one has at most, how many one
    /// account may own.
    pub families: OrgSettings,
    /// The suite vault of UwUSSH, UwURDP and the other UwU apps (docs/uwu-api.md §6).
    pub suite: SuiteSettings,
    /// Masked addresses: the UwUMail servers this server may talk to for them (§13, §21.8).
    pub masked: MaskedSettings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SuiteSettings {
    pub enabled: bool,
    /// Records one account may keep in all its spaces together.
    pub max_records: u32,
    /// And how many MiB they may take.
    pub max_mb: u32,
}

impl Default for SuiteSettings {
    fn default() -> Self {
        SuiteSettings { enabled: true, max_records: 50_000, max_mb: 256 }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MaskedSettings {
    /// The only servers the Lock server sends anything to for masked addresses.
    pub servers: Vec<MaskedServer>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MaskedServer {
    /// `https://mail.example.com`, without a trailing slash.
    pub url: String,
    /// What the web vault calls it.
    pub name: String,
}

impl MaskedSettings {
    /// The listed server `url` names, whatever slash it ends with.
    pub fn server(&self, url: &str) -> Option<&MaskedServer> {
        let url = url.trim().trim_end_matches('/');
        self.servers.iter().find(|server| server.url.eq_ignore_ascii_case(url))
    }

    /// Checked, and written the way it is kept: addresses without a trailing slash, a name for
    /// each.
    pub fn normalize(&mut self) -> Result<(), String> {
        if self.servers.len() > 20 {
            return Err("At most 20 UwUMail servers can be listed.".into());
        }
        let mut seen = std::collections::HashSet::new();
        for server in &mut self.servers {
            server.url = crate::outbound::checked_url(&server.url, "UwUMail server")?;
            let parsed = reqwest::Url::parse(&server.url).map_err(|error| error.to_string())?;
            if parsed.path() != "/" || parsed.query().is_some() {
                return Err(format!(
                    "UwUMail server: {} has to be the server's address alone, without a path.",
                    server.url
                ));
            }
            server.name = server.name.trim().to_string();
            if server.name.is_empty() {
                server.name = parsed.host_str().unwrap_or_default().to_string();
            }
            if server.name.chars().count() > 60 || server.name.chars().any(char::is_control) {
                return Err("UwUMail server: a name has at most 60 characters.".into());
            }
            if !seen.insert(server.url.to_ascii_lowercase()) {
                return Err(format!("UwUMail server: {} is listed twice.", server.url));
            }
        }
        Ok(())
    }
}

/// Who may make an organisation of one kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WhoMayCreate {
    Everyone,
    Admins,
    Nobody,
}

/// The rules for one kind of organisation: families today, Stufe 5's organisations with the
/// same keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OrgSettings {
    pub who_may_create: WhoMayCreate,
    /// Members one has at most, invited ones counting.
    pub max_members: u32,
    /// How many of them one account may own.
    pub per_user: u32,
}

impl Default for OrgSettings {
    fn default() -> Self {
        // Bitwarden's Families plan has six seats.
        OrgSettings { who_may_create: WhoMayCreate::Everyone, max_members: 6, per_user: 1 }
    }
}

impl OrgSettings {
    /// Whether `admin` (or not) may make one.
    pub fn may_create(&self, admin: bool) -> bool {
        match self.who_may_create {
            WhoMayCreate::Everyone => true,
            WhoMayCreate::Admins => admin,
            WhoMayCreate::Nobody => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VersionSettings {
    /// Versions kept per item; 0 keeps none.
    pub per_item: u32,
    /// Days a version is kept; 0 for no limit.
    pub days: u32,
}

impl Default for VersionSettings {
    fn default() -> Self {
        VersionSettings { per_item: 20, days: 365 }
    }
}

impl VersionSettings {
    pub fn rule(&self) -> uwulock_store::VersionRule {
        uwulock_store::VersionRule { per_item: self.per_item, days: self.days }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct IconSettings {
    /// The server fetches websites' icons for `/icons/<host>/icon.png`.
    pub automatic: bool,
    /// The icon library, searched in the vault, its icons fetched by the server.
    pub library: bool,
    /// The libraries mirrored: only `selfhst` today.
    pub sources: Vec<String>,
}

impl Default for IconSettings {
    fn default() -> Self {
        IconSettings { automatic: true, library: true, sources: vec!["selfhst".into()] }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FileRequestSettings {
    pub enabled: bool,
    /// Requests one account may have.
    pub per_user: u32,
    /// How far ahead a request may run out.
    pub max_days: u32,
    /// Files one submission may bring.
    pub max_files: u32,
}

impl Default for FileRequestSettings {
    fn default() -> Self {
        FileRequestSettings { enabled: true, per_user: 50, max_days: 90, max_files: 20 }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SecurityNoticeSettings {
    /// Kinds that are not mailed, like `newDevice`.
    pub mail_off: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            smtp: None,
            default_language: Language::De,
            invitation_days: 7,
            new_device_mail: true,
            password_hints: true,
            remember_two_factor: true,
            max_file_mb: 500,
            hibp: true,
            push: None,
            users_may_invite: false,
            invitations_per_user: 5,
            security_notices: SecurityNoticeSettings::default(),
            policies: crate::policies::Policies::default(),
            admin_networks: Vec::new(),
            metrics: crate::metrics::MetricsSettings::default(),
            loki: crate::loki::LokiSettings::default(),
            file_requests: FileRequestSettings::default(),
            suite: SuiteSettings::default(),
            storage_per_user_mb: None,
            sso: crate::sso::SsoSettings::default(),
            scim: crate::scim::ScimSettings::default(),
            versions: VersionSettings::default(),
            icons: IconSettings::default(),
            families: OrgSettings::default(),
            masked: MaskedSettings::default(),
        }
    }
}

impl Settings {
    /// The most an account may keep in files, in bytes; none for no limit.
    pub fn storage_limit(&self) -> Option<i64> {
        self.storage_per_user_mb.map(|mb| (mb.min(i64::MAX as u64 / (1024 * 1024)) * 1024 * 1024) as i64)
    }
}

impl Settings {
    /// What the database holds, or `start` for a server that never saved any.
    pub async fn load(store: &Store, start: &Settings) -> Result<Settings, String> {
        match store.setting(KEY).await.map_err(|error| error.to_string())? {
            Some(json) => serde_json::from_str(&json).map_err(|error| format!("the settings in the database: {error}")),
            None => Ok(start.clone()),
        }
    }

    pub async fn save(&self, store: &Store) -> Result<(), uwulock_store::StoreError> {
        store.set_setting(KEY, &serde_json::to_string(self).expect("settings serialize")).await
    }

    /// The settings as the portal (and `uwulock-server settings get`) shows them: passwords,
    /// keys and tokens never, only whether there is one.
    pub fn for_portal(&self) -> serde_json::Value {
        use serde_json::Value;
        let mut value = serde_json::to_value(self).expect("settings serialize");
        let mut hide = |section: &str, secret: &str, flag: &str| {
            if let Some(object) = value.get_mut(section).and_then(Value::as_object_mut) {
                let set =
                    object.remove(secret).is_some_and(|value| value.as_str().is_some_and(|text| !text.is_empty()));
                object.insert(flag.into(), set.into());
            }
        };
        hide("smtp", "password", "passwordSet");
        hide("push", "installationKey", "installationKeySet");
        hide("metrics", "tokenHash", "tokenSet");
        hide("loki", "password", "passwordSet");
        hide("sso", "clientSecret", "clientSecretSet");
        hide("scim", "tokenHash", "tokenSet");
        value["mailEnabled"] = self.smtp.as_ref().is_some_and(|smtp| smtp.is_set()).into();
        value
    }

    /// These settings with `value` at `path` (`adminNetworks`, `policies.requireTwoFactor.enabled`,
    /// camelCase like the admin portal's), checked: what `uwulock-server settings set` does.
    pub fn with(&self, path: &str, value: serde_json::Value) -> Result<Settings, String> {
        use serde_json::Value;
        let mut whole = serde_json::to_value(self).expect("settings serialize");
        let keys: Vec<&str> = path.split('.').filter(|key| !key.is_empty()).collect();
        let (last, parents) = keys.split_last().ok_or("Which setting? Like adminNetworks or metrics.enabled.")?;
        let mut place = &mut whole;
        for key in parents {
            let object = place.as_object_mut().ok_or_else(|| format!("{path}: {key} holds no settings of its own"))?;
            let next = object.entry(key.to_string()).or_insert_with(|| Value::Object(serde_json::Map::new()));
            if next.is_null() {
                *next = Value::Object(serde_json::Map::new());
            }
            place = next;
        }
        let object = place.as_object_mut().ok_or_else(|| format!("{path} is not a setting"))?;
        // The metrics token is only ever stored as its hash.
        let known = object.contains_key(*last) || (path == "metrics.token");
        if !known {
            return Err(format!("There is no setting {path}."));
        }
        object.insert(last.to_string(), value);
        let mut new: Settings = serde_json::from_value(whole).map_err(|error| format!("{path}: {error}"))?;
        new.metrics.take_token(&self.metrics)?;
        new.check()?;
        Ok(new)
    }

    /// Checked before saving: what would not work, said so a person can fix it.
    pub fn check(&self) -> Result<(), String> {
        if !(1..=90).contains(&self.invitation_days) {
            return Err("Invitations can last from 1 to 90 days.".into());
        }
        if !(1..=100).contains(&self.invitations_per_user) {
            return Err("A user may bring in from 1 to 100 people.".into());
        }
        if !(1..=4096).contains(&self.max_file_mb) {
            return Err("Files can be from 1 MB to 4096 MB.".into());
        }
        if let Some(push) = &self.push
            && (push.installation_id.trim().is_empty() || !matches!(push.region.as_str(), "us" | "eu"))
        {
            return Err("The push relay needs the installation id and the region it was made for (us or eu).".into());
        }
        if let Some(smtp) = &self.smtp
            && (smtp.host.trim().is_empty() || smtp.port == 0 || smtp.from.trim().is_empty())
        {
            return Err("The mail server needs a host, a port and a sender address.".into());
        }
        if let Some(kind) =
            self.security_notices.mail_off.iter().find(|kind| !crate::notices::KINDS.contains(&kind.as_str()))
        {
            return Err(format!("{kind} is no kind of security notice."));
        }
        self.policies.check()?;
        crate::networks::IpNetwork::parse_list(&self.admin_networks)
            .map_err(|error| format!("Admin networks: {error}"))?;
        self.metrics.check()?;
        self.loki.check()?;
        let requests = &self.file_requests;
        if !(1..=1000).contains(&requests.per_user) {
            return Err("An account may have from 1 to 1000 file requests.".into());
        }
        if !(1..=365).contains(&requests.max_days) {
            return Err("A file request may run from 1 to 365 days.".into());
        }
        if !(1..=100).contains(&requests.max_files) {
            return Err("A file request may take from 1 to 100 files at once.".into());
        }
        if self.versions.per_item > 100 {
            return Err("An item keeps at most 100 versions.".into());
        }
        if self.versions.days > 3650 {
            return Err("Versions are kept at most 3650 days (0 for no limit).".into());
        }
        if let Some(source) =
            self.icons.sources.iter().find(|source| !crate::icons::LIBRARY_SOURCES.contains(&source.as_str()))
        {
            return Err(format!("{source} is no icon library this server knows."));
        }
        if self.storage_per_user_mb == Some(0) {
            return Err("The storage per account is at least 1 MB, or no limit.".into());
        }
        if !(2..=50).contains(&self.families.max_members) {
            return Err("A family has from 2 to 50 members at most.".into());
        }
        if self.families.per_user > 10 {
            return Err("One account may own at most 10 families (0 for none).".into());
        }
        if !(1..=1_000_000).contains(&self.suite.max_records) {
            return Err("An account may keep from 1 to 1000000 suite records.".into());
        }
        if !(1..=65_536).contains(&self.suite.max_mb) {
            return Err("The suite vault of an account may take from 1 to 65536 MB.".into());
        }
        self.sso.check()?;
        self.masked.clone().normalize()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn start_values_until_something_is_saved() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_sqlite(&dir.path().join("db"), &uwulock_store::Options { readers: 1 }).unwrap();
        let start = Settings { invitation_days: 3, ..Settings::default() };
        assert_eq!(Settings::load(&store, &start).await.unwrap(), start);
        let saved = Settings { invitation_days: 14, default_language: Language::En, ..Settings::default() };
        saved.save(&store).await.unwrap();
        assert_eq!(Settings::load(&store, &start).await.unwrap(), saved, "the database wins");
    }

    #[test]
    fn what_would_not_work_is_refused() {
        assert!(Settings::default().check().is_ok());
        assert!(Settings { invitation_days: 0, ..Settings::default() }.check().is_err());
        let smtp = SmtpSettings { host: "mail.example.com".into(), port: 0, ..SmtpSettings::default() };
        assert!(Settings { smtp: Some(smtp), ..Settings::default() }.check().is_err());
    }

    #[test]
    fn one_setting_at_a_time_from_the_command_line() {
        let start = Settings { admin_networks: vec!["192.0.2.0/24".into()], ..Settings::default() };
        let open = start.with("adminNetworks", serde_json::json!([])).unwrap();
        assert!(open.admin_networks.is_empty());
        let on = start.with("policies.requireTwoFactor.enabled", serde_json::json!(true)).unwrap();
        assert!(on.policies.require_two_factor.enabled);
        assert!(start.with("adminNetworks", serde_json::json!(["nonsense"])).is_err(), "checked");
        assert!(start.with("noSuchThing", serde_json::json!(1)).is_err());
        let token = start.with("metrics.token", serde_json::json!("a-long-token-for-prometheus")).unwrap();
        assert!(token.metrics.token_hash.is_some() && token.metrics.token.is_none(), "only the hash");
    }

    #[test]
    fn older_settings_get_the_defaults_for_what_is_new() {
        let settings: Settings = serde_json::from_str(r#"{"invitationDays": 5}"#).unwrap();
        assert_eq!(settings.invitation_days, 5);
        assert!(settings.remember_two_factor);
    }
}
