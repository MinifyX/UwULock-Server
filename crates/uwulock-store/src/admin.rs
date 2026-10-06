//! What the admin portal reads and writes: settings, the event log, the numbers.

use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, params};

/// Events are kept this long.
pub const EVENT_DAYS: i64 = 90;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Event {
    pub id: i64,
    pub time: String,
    /// `login`, `login-failed`, `two-factor-failed`, `admin`, …
    pub kind: String,
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub ip: Option<String>,
    pub device_type: Option<i64>,
    pub detail: Option<String>,
    /// What the client said about itself at a login: its `User-Agent`, its name and version
    /// (Bitwarden's `Bitwarden-Client-Name`/`-Version`), the device's name.
    pub user_agent: Option<String>,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub device_name: Option<String>,
    /// Why a login was refused: `password`, `unknown-account`, `disabled`, `api-key`,
    /// `two-factor`.
    pub reason: Option<String>,
}

/// The columns of an event, in the order [`event_row`] reads them.
pub(crate) const EVENT_COLUMNS: &str = "id, time, kind, user_id, email, ip, device_type, detail, user_agent, \
     client_name, client_version, device_name, reason";

pub(crate) fn event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Event> {
    Ok(Event {
        id: row.get(0)?,
        time: row.get(1)?,
        kind: row.get(2)?,
        user_id: row.get(3)?,
        email: row.get(4)?,
        ip: row.get(5)?,
        device_type: row.get(6)?,
        detail: row.get(7)?,
        user_agent: row.get(8)?,
        client_name: row.get(9)?,
        client_version: row.get(10)?,
        device_name: row.get(11)?,
        reason: row.get(12)?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    pub users: i64,
    pub admins: i64,
    pub disabled: i64,
    pub invitations: i64,
    pub devices: i64,
    pub ciphers: i64,
    pub trashed: i64,
    pub folders: i64,
    pub two_factor: i64,
    pub failed_logins_day: i64,
}

/// One day of the numbers over time.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Day {
    /// YYYY-MM-DD, UTC.
    pub day: String,
    pub users: i64,
    pub devices: i64,
    pub ciphers: i64,
    pub sends: i64,
    pub file_bytes: i64,
    pub logins: i64,
    pub failed_logins: i64,
}

/// What a file Send's file weighs, from its data (Bitwarden writes the size as text).
const SEND_FILE_BYTES: &str = "CAST(coalesce(json_extract(data, '$.size'), 0) AS INTEGER)";

impl Store {
    /// Write down today's numbers, and yesterday's logins once more: the day's last hours
    /// happened after its last count. Called by the maintenance job every hour.
    pub async fn record_day(&self) -> Result<()> {
        self.sqlite_write(|tx| {
            let today = clock::now()[..10].to_string();
            let yesterday = clock::in_seconds(-86_400)[..10].to_string();
            let logins = |kinds: &str| {
                format!("(SELECT count(*) FROM events WHERE kind IN ({kinds}) AND substr(time, 1, 10) = ?1)")
            };
            tx.execute(
                &format!(
                    "INSERT INTO daily_stats (day, users, devices, ciphers, sends, file_bytes, logins, failed_logins) \
                     VALUES (?1, (SELECT count(*) FROM users), \
                     (SELECT count(*) FROM devices WHERE refresh_hash IS NOT NULL), \
                     (SELECT count(*) FROM ciphers WHERE deleted IS NULL), (SELECT count(*) FROM sends), \
                     (SELECT coalesce(sum(size), 0) FROM attachments WHERE uploaded) + \
                     (SELECT coalesce(sum({SEND_FILE_BYTES}), 0) FROM sends WHERE type = 1 AND uploaded), \
                     {}, {}) \
                     ON CONFLICT (day) DO UPDATE SET users = excluded.users, devices = excluded.devices, \
                     ciphers = excluded.ciphers, sends = excluded.sends, file_bytes = excluded.file_bytes, \
                     logins = excluded.logins, failed_logins = excluded.failed_logins",
                    logins("'login'"),
                    logins("'login-failed', 'two-factor-failed'")
                ),
                [&today],
            )?;
            tx.execute(
                &format!(
                    "UPDATE daily_stats SET logins = {}, failed_logins = {} WHERE day = ?1",
                    logins("'login'"),
                    logins("'login-failed', 'two-factor-failed'")
                ),
                [&yesterday],
            )?;
            Ok(())
        })
        .await
    }

    /// The last `days` days of numbers there are, the oldest first.
    pub async fn daily_stats(&self, days: i64) -> Result<Vec<Day>> {
        self.sqlite_read(move |conn| {
            let since = clock::in_seconds(-days * 86_400)[..10].to_string();
            conn.prepare_cached(
                "SELECT day, users, devices, ciphers, sends, file_bytes, logins, failed_logins FROM daily_stats \
                 WHERE day > ?1 ORDER BY day",
            )?
            .query_map([since], |row| {
                Ok(Day {
                    day: row.get(0)?,
                    users: row.get(1)?,
                    devices: row.get(2)?,
                    ciphers: row.get(3)?,
                    sends: row.get(4)?,
                    file_bytes: row.get(5)?,
                    logins: row.get(6)?,
                    failed_logins: row.get(7)?,
                })
            })?
            .collect()
        })
        .await
    }

    /// What each account keeps in files: its attachments and the files of its Sends, in bytes.
    /// An organisation's attachments count for nobody.
    pub async fn storage_by_user(&self) -> Result<std::collections::HashMap<String, i64>> {
        self.sqlite_read(|conn| {
            conn.prepare(&format!(
                "SELECT user_id, sum(bytes) FROM ( \
                 SELECT c.user_id AS user_id, a.size AS bytes FROM attachments a JOIN ciphers c ON c.id = a.cipher_id \
                 WHERE a.uploaded AND c.user_id IS NOT NULL \
                 UNION ALL SELECT user_id, {SEND_FILE_BYTES} FROM sends WHERE type = 1 AND uploaded \
                 UNION ALL SELECT user_id, size FROM cipher_versions WHERE user_id IS NOT NULL \
                 UNION ALL SELECT c.user_id, length(i.data) FROM own_icons i JOIN ciphers c ON c.id = i.cipher_id \
                 WHERE c.user_id IS NOT NULL) GROUP BY user_id"
            ))?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect()
        })
        .await
    }

    /// What all attachments and all files of Sends weigh, in bytes.
    pub async fn file_bytes(&self) -> Result<(i64, i64)> {
        self.sqlite_read(|conn| {
            conn.query_row(
                &format!(
                    "SELECT (SELECT coalesce(sum(size), 0) FROM attachments WHERE uploaded), \
                     (SELECT coalesce(sum({SEND_FILE_BYTES}), 0) FROM sends WHERE type = 1 AND uploaded)"
                ),
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .await
    }

    /// How many values in the database are sealed with the server secret (`secret.key`): the
    /// settings' passwords, the channels' tokens, the tokens of masked addresses.
    pub async fn sealed_values(&self) -> Result<u64> {
        self.sqlite_read(|conn| {
            conn.query_row(
                "SELECT (SELECT count(*) FROM server WHERE value LIKE '%\"v1.%')
                      + (SELECT count(*) FROM notification_channels WHERE config LIKE '%\"v1.%')
                      + (SELECT count(*) FROM masked_connections
                         WHERE refresh_token LIKE 'v1.%' OR access_token LIKE 'v1.%')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count.max(0) as u64)
        })
        .await
    }

    /// Empties every sealed value: for a server whose `secret.key` is lost for good. The admin
    /// enters them again; masked addresses connect again.
    pub async fn forget_sealed_values(&self) -> Result<()> {
        self.sqlite_write(|tx| empty_sealed(tx)).await
    }

    /// A setting the server keeps for itself, like the mail server or a signing key.
    pub async fn setting(&self, key: &str) -> Result<Option<String>> {
        let key = key.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached("SELECT value FROM server WHERE key = ?1")?
                .query_row([key], |row| row.get(0))
                .optional()
        })
        .await
    }

    pub async fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let (key, value) = (key.to_string(), value.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO server (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                [key, value],
            )
            .map(drop)
        })
        .await
    }

    /// Write `value` under `key` unless something is there already; hands back what is there
    /// afterwards. For values made once, like a signing key, that two starts must not both make.
    pub async fn setting_or_insert(&self, key: &str, value: &str) -> Result<String> {
        let (key, value) = (key.to_string(), value.to_string());
        self.sqlite_write(move |tx| {
            tx.execute("INSERT INTO server (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO NOTHING", [&key, &value])?;
            tx.query_row("SELECT value FROM server WHERE key = ?1", [&key], |row| row.get(0))
        })
        .await
    }

    /// The feature switches (docs/features.md) something is kept for in the database: accounts'
    /// data, not the admin's settings. By their names on the wire, like `file-requests`.
    pub async fn features_with_data(&self) -> Result<Vec<&'static str>> {
        const CHECKS: [(&str, &str); 13] = [
            ("families", "SELECT 1 FROM organizations"),
            ("file-requests", "SELECT 1 FROM file_requests"),
            ("send-domains", "SELECT 1 FROM send_domains"),
            (
                "masked-addresses",
                "SELECT 1 FROM masked_connections UNION ALL SELECT 1 FROM masked_links \
                 UNION ALL SELECT 1 FROM masked_api_keys",
            ),
            ("versions", "SELECT 1 FROM cipher_versions"),
            ("reminders", "SELECT 1 FROM reminders"),
            ("travel-mode", "SELECT 1 FROM travel UNION ALL SELECT 1 FROM folders WHERE travel"),
            ("own-icons", "SELECT 1 FROM own_icons"),
            ("twofa-directory", "SELECT 1 FROM health_reports"),
            ("sso", "SELECT 1 FROM sso_identities"),
            ("scim", "SELECT 1 FROM scim_provisioned UNION ALL SELECT 1 FROM scim_groups"),
            ("admin-notifications", "SELECT 1 FROM notification_channels WHERE kind <> 'mail'"),
            ("suite", "SELECT 1 FROM suite_spaces"),
        ];
        self.sqlite_read(|conn| {
            let mut found = Vec::new();
            for (name, query) in CHECKS {
                let used: bool = conn.query_row(&format!("SELECT EXISTS ({query})"), [], |row| row.get(0))?;
                if used {
                    found.push(name);
                }
            }
            Ok(found)
        })
        .await
    }

    /// How many accounts are travelling right now (travel mode on).
    pub async fn travelling_count(&self) -> Result<i64> {
        self.sqlite_read(|conn| conn.query_row("SELECT count(*) FROM travel", [], |row| row.get(0))).await
    }

    pub async fn log_event(&self, event: Event) -> Result<()> {
        self.sqlite_write(move |tx| {
            tx.prepare_cached(
                "INSERT INTO events (time, kind, user_id, email, ip, device_type, detail, user_agent, client_name, \
                 client_version, device_name, reason) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )?
            .execute(params![
                if event.time.is_empty() { clock::now() } else { event.time },
                event.kind,
                event.user_id,
                event.email,
                event.ip,
                event.device_type,
                event.detail,
                event.user_agent,
                event.client_name,
                event.client_version,
                event.device_name,
                event.reason
            ])
            .map(drop)
        })
        .await
    }

    /// The newest events first, of one kind or all, before the event `before` (for paging).
    pub async fn events(&self, kind: Option<String>, before: Option<i64>, limit: i64) -> Result<Vec<Event>> {
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {EVENT_COLUMNS} FROM events \
                 WHERE (?1 IS NULL OR kind = ?1) AND (?2 IS NULL OR id < ?2) ORDER BY id DESC LIMIT ?3"
            ))?
            .query_map(params![kind, before, limit], event_row)?
            .collect()
        })
        .await
    }

    /// Sweep away what has run out: old events, codes and invitations nobody used, and devices
    /// remembered longer than `remember_days` ago (0: they stay).
    pub async fn sweep(&self, remember_days: u32) -> Result<()> {
        self.sqlite_write(move |tx| {
            let now = clock::now();
            // No time sorts before the empty text: "remembered without end" sweeps nothing.
            let remembered_since = match remember_days {
                0 => String::new(),
                days => clock::in_seconds(-i64::from(days) * 86_400),
            };
            tx.execute("DELETE FROM events WHERE time < ?1", [clock::in_seconds(-EVENT_DAYS * 86_400)])?;
            tx.execute("DELETE FROM ip_blocks WHERE expires < ?1", [&now])?;
            tx.execute(
                "DELETE FROM security_notices WHERE time < ?1",
                [clock::in_seconds(-crate::NOTICE_DAYS * 86_400)],
            )?;
            tx.execute("DELETE FROM codes WHERE expires < ?1", [&now])?;
            crate::sso::sweep(tx, &now)?;
            tx.execute(
                "UPDATE devices SET refresh_hash = NULL, refresh_expires = NULL WHERE refresh_expires < ?1",
                [&now],
            )?;
            tx.execute(
                "UPDATE devices SET remember_hash = NULL, remember_renewed = NULL WHERE remember_renewed < ?1",
                [&remembered_since],
            )?;
            // Invitations stay a while after they ran out, so the portal can still show them.
            tx.execute("DELETE FROM invitations WHERE expires < ?1", [clock::in_seconds(-30 * 86_400)])?;
            // A Send is gone on its deletion date; its owner's clients hear of it.
            let senders: Vec<String> = tx
                .prepare("SELECT DISTINCT user_id FROM sends WHERE deletion < ?1")?
                .query_map([&now], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            tx.execute("DELETE FROM sends WHERE deletion < ?1", [&now])?;
            for owner in senders {
                crate::accounts::bump_revision(tx, &owner)?;
            }
            tx.execute("DELETE FROM auth_requests WHERE created < ?1", [clock::in_seconds(-86_400)])?;
            // Announced attachments whose file never came.
            tx.execute("DELETE FROM attachments WHERE NOT uploaded AND created < ?1", [clock::in_seconds(-86_400)])?;
            // Items in the trash for more than 30 days are gone, like at Bitwarden.
            let old = clock::in_seconds(-30 * 86_400);
            // An organisation's item has no owner of its own: its members hear of it.
            let mut owners: Vec<String> = tx
                .prepare("SELECT DISTINCT user_id FROM ciphers WHERE deleted < ?1 AND user_id IS NOT NULL")?
                .query_map([&old], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let orgs: Vec<String> = tx
                .prepare(
                    "SELECT DISTINCT organization_id FROM ciphers WHERE deleted < ?1 AND organization_id IS NOT NULL",
                )?
                .query_map([&old], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            for org in orgs {
                owners.extend(crate::organizations::member_users(tx, &org)?);
            }
            tx.execute("DELETE FROM ciphers WHERE deleted < ?1", [&old])?;
            owners.sort();
            owners.dedup();
            for owner in owners {
                crate::accounts::bump_revision(tx, &owner)?;
            }
            Ok(())
        })
        .await?;
        // Revisions and logged-in devices may have changed for anyone.
        let mut sessions = self.sessions.write();
        sessions.by_user.clear();
        sessions.forgotten += 1;
        Ok(())
    }

    pub async fn stats(&self) -> Result<Stats> {
        self.sqlite_read(|conn| {
            conn.query_row(
                "SELECT (SELECT count(*) FROM users), (SELECT count(*) FROM users WHERE admin), \
                 (SELECT count(*) FROM users WHERE disabled), (SELECT count(*) FROM invitations WHERE expires > ?1), \
                 (SELECT count(*) FROM devices WHERE refresh_hash IS NOT NULL), (SELECT count(*) FROM ciphers), \
                 (SELECT count(*) FROM ciphers WHERE deleted IS NOT NULL), (SELECT count(*) FROM folders), \
                 (SELECT count(DISTINCT user_id) FROM two_factor WHERE enabled), \
                 (SELECT count(*) FROM events WHERE kind IN ('login-failed', 'two-factor-failed') AND time > ?2)",
                [clock::now(), clock::in_seconds(-86_400)],
                |row| {
                    Ok(Stats {
                        users: row.get(0)?,
                        admins: row.get(1)?,
                        disabled: row.get(2)?,
                        invitations: row.get(3)?,
                        devices: row.get(4)?,
                        ciphers: row.get(5)?,
                        trashed: row.get(6)?,
                        folders: row.get(7)?,
                        two_factor: row.get(8)?,
                        failed_logins_day: row.get(9)?,
                    })
                },
            )
        })
        .await
    }
}

/// Empties every value sealed with `secret.key`: the strings in the settings and the channels'
/// configs, and the connections of masked addresses. For a lost key, and for an unencrypted
/// backup, which leaves the key out.
pub(crate) fn empty_sealed(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    fn empty(value: &mut serde_json::Value) -> bool {
        match value {
            serde_json::Value::String(text) if crate::secret::is_sealed(text) => {
                text.clear();
                true
            }
            serde_json::Value::Array(items) => items.iter_mut().fold(false, |any, item| empty(item) | any),
            serde_json::Value::Object(fields) => fields.values_mut().fold(false, |any, item| empty(item) | any),
            _ => false,
        }
    }
    for (table, key, column) in [("server", "key", "value"), ("notification_channels", "id", "config")] {
        let rows: Vec<(String, String)> = conn
            .prepare(&format!("SELECT {key}, {column} FROM {table} WHERE {column} LIKE '%\"v1.%'"))?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, text) in rows {
            let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
            if empty(&mut value) {
                conn.execute(&format!("UPDATE {table} SET {column} = ?2 WHERE {key} = ?1"), [id, value.to_string()])?;
            }
        }
    }
    conn.execute("DELETE FROM masked_connections WHERE refresh_token LIKE 'v1.%' OR access_token LIKE 'v1.%'", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::store;

    #[tokio::test]
    async fn a_value_made_once_stays() {
        let (store, _dir) = store();
        assert_eq!(store.setting_or_insert("key", "first").await.unwrap(), "first");
        assert_eq!(store.setting_or_insert("key", "second").await.unwrap(), "first");
        store.set_setting("key", "third").await.unwrap();
        assert_eq!(store.setting("key").await.unwrap().as_deref(), Some("third"));
    }

    #[tokio::test]
    async fn events_page_backwards_and_old_ones_go() {
        let (store, _dir) = store();
        for n in 0..5 {
            store
                .log_event(Event { kind: "login-failed".into(), detail: Some(n.to_string()), ..Event::default() })
                .await
                .unwrap();
        }
        store
            .log_event(Event {
                kind: "login".into(),
                time: clock::in_seconds(-(EVENT_DAYS + 1) * 86_400),
                ..Event::default()
            })
            .await
            .unwrap();
        let first = store.events(Some("login-failed".into()), None, 3).await.unwrap();
        assert_eq!(first.iter().map(|e| e.detail.clone().unwrap()).collect::<Vec<_>>(), ["4", "3", "2"]);
        let rest = store.events(Some("login-failed".into()), Some(first[2].id), 3).await.unwrap();
        assert_eq!(rest.len(), 2);
        assert_eq!(store.stats().await.unwrap().failed_logins_day, 5);
        store.sweep(90).await.unwrap();
        assert_eq!(store.events(None, None, 100).await.unwrap().len(), 5, "the old login is gone");
    }

    #[tokio::test]
    async fn the_numbers_of_each_day_are_kept() {
        let (store, _dir) = store();
        let nyu = store.create_user(crate::accounts::tests::new_user("nyu@example.com")).await.unwrap();
        store.save_cipher(crate::vault::tests::cipher(&nyu.id, "c1", None)).await.unwrap();
        let mut send = crate::sends::tests::text_send(&nyu.id, "s1");
        send.kind = crate::sends::FILE;
        send.uploaded = true;
        send.data = r#"{"id":"f","fileName":"2.f|f|f","size":"1500","sizeName":"1.46 KB"}"#.into();
        store.save_send(send).await.unwrap().unwrap();
        for kind in ["login", "login", "login-failed"] {
            store.log_event(Event { kind: kind.into(), ..Event::default() }).await.unwrap();
        }
        store.record_day().await.unwrap();
        store.record_day().await.unwrap();
        let days = store.daily_stats(30).await.unwrap();
        assert_eq!(days.len(), 1, "one row a day, however often it is written");
        let today = &days[0];
        assert_eq!((today.users, today.ciphers, today.sends, today.file_bytes), (1, 1, 1, 1500));
        assert_eq!((today.logins, today.failed_logins), (2, 1));
        assert_eq!(store.storage_by_user().await.unwrap().get(&nyu.id), Some(&1500));
    }
}
