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
        }
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

    /// Checked before saving: what would not work, said so a person can fix it.
    pub fn check(&self) -> Result<(), String> {
        if !(1..=90).contains(&self.invitation_days) {
            return Err("Invitations can last from 1 to 90 days.".into());
        }
        if let Some(smtp) = &self.smtp
            && (smtp.host.trim().is_empty() || smtp.port == 0 || smtp.from.trim().is_empty())
        {
            return Err("The mail server needs a host, a port and a sender address.".into());
        }
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
    fn older_settings_get_the_defaults_for_what_is_new() {
        let settings: Settings = serde_json::from_str(r#"{"invitationDays": 5}"#).unwrap();
        assert_eq!(settings.invitation_days, 5);
        assert!(settings.remember_two_factor);
    }
}
