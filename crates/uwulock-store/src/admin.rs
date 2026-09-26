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

impl Store {
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

    pub async fn log_event(&self, event: Event) -> Result<()> {
        self.sqlite_write(move |tx| {
            tx.prepare_cached(
                "INSERT INTO events (time, kind, user_id, email, ip, device_type, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?
            .execute(params![
                if event.time.is_empty() { clock::now() } else { event.time },
                event.kind,
                event.user_id,
                event.email,
                event.ip,
                event.device_type,
                event.detail
            ])
            .map(drop)
        })
        .await
    }

    /// The newest events first, of one kind or all, before the event `before` (for paging).
    pub async fn events(&self, kind: Option<String>, before: Option<i64>, limit: i64) -> Result<Vec<Event>> {
        self.sqlite_read(move |conn| {
            conn.prepare_cached(
                "SELECT id, time, kind, user_id, email, ip, device_type, detail FROM events \
                 WHERE (?1 IS NULL OR kind = ?1) AND (?2 IS NULL OR id < ?2) ORDER BY id DESC LIMIT ?3",
            )?
            .query_map(params![kind, before, limit], |row| {
                Ok(Event {
                    id: row.get(0)?,
                    time: row.get(1)?,
                    kind: row.get(2)?,
                    user_id: row.get(3)?,
                    email: row.get(4)?,
                    ip: row.get(5)?,
                    device_type: row.get(6)?,
                    detail: row.get(7)?,
                })
            })?
            .collect()
        })
        .await
    }

    /// Sweep away what has run out: old events, codes and invitations nobody used.
    pub async fn sweep(&self) -> Result<()> {
        self.sqlite_write(|tx| {
            let now = clock::now();
            tx.execute("DELETE FROM events WHERE time < ?1", [clock::in_seconds(-EVENT_DAYS * 86_400)])?;
            tx.execute("DELETE FROM codes WHERE expires < ?1", [&now])?;
            tx.execute(
                "UPDATE devices SET refresh_hash = NULL, refresh_expires = NULL WHERE refresh_expires < ?1",
                [&now],
            )?;
            tx.execute(
                "UPDATE devices SET remember_hash = NULL, remember_expires = NULL WHERE remember_expires < ?1",
                [&now],
            )?;
            // Invitations stay a while after they ran out, so the portal can still show them.
            tx.execute("DELETE FROM invitations WHERE expires < ?1", [clock::in_seconds(-30 * 86_400)])?;
            // Items in the trash for more than 30 days are gone, like at Bitwarden.
            let old = clock::in_seconds(-30 * 86_400);
            let owners: Vec<String> = tx
                .prepare("SELECT DISTINCT user_id FROM ciphers WHERE deleted < ?1")?
                .query_map([&old], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            tx.execute("DELETE FROM ciphers WHERE deleted < ?1", [&old])?;
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
        store.sweep().await.unwrap();
        assert_eq!(store.events(None, None, 100).await.unwrap().len(), 5, "the old login is gone");
    }
}
