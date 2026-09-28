//! Security notices: what happened on an account, for its owner. And the channels admins hear
//! of trouble on.
//!
//! A notice is written when it happens and waits for the next bundled mail (or for none); the
//! web vault lists them. Failed logins are one notice per burst, counted up while the burst
//! lasts, so an attack is one line and not thousands.

use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, Row, params};

/// Notices are kept this long.
pub const NOTICE_DAYS: i64 = 180;

/// No mail for the notice.
pub const MAIL_NONE: i64 = 0;
/// Waits for the next bundle.
pub const MAIL_WAITING: i64 = 1;
/// Went out.
pub const MAIL_SENT: i64 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Notice {
    pub id: i64,
    pub user_id: String,
    pub kind: String,
    pub time: String,
    pub ip: Option<String>,
    pub device_type: Option<i64>,
    pub device_name: Option<String>,
    pub app: Option<String>,
    /// A JSON object.
    pub detail: String,
    /// [`MAIL_NONE`], [`MAIL_WAITING`] or [`MAIL_SENT`].
    pub mail: i64,
    pub mailed: Option<String>,
    pub seen: bool,
}

const COLUMNS: &str = "id, user_id, kind, time, ip, device_type, device_name, app, detail, mail, mailed, seen";

fn notice_from(row: &Row<'_>) -> rusqlite::Result<Notice> {
    Ok(Notice {
        id: row.get(0)?,
        user_id: row.get(1)?,
        kind: row.get(2)?,
        time: row.get(3)?,
        ip: row.get(4)?,
        device_type: row.get(5)?,
        device_name: row.get(6)?,
        app: row.get(7)?,
        detail: row.get(8)?,
        mail: row.get(9)?,
        mailed: row.get(10)?,
        seen: row.get(11)?,
    })
}

/// A channel admins hear of trouble on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Channel {
    pub id: String,
    /// `mail`, `ntfy`, `gotify` or `matrix`.
    pub kind: String,
    pub name: String,
    pub enabled: bool,
    /// A JSON list of event names.
    pub events: String,
    /// A JSON object, secrets included.
    pub config: String,
    pub created: String,
}

fn channel_from(row: &Row<'_>) -> rusqlite::Result<Channel> {
    Ok(Channel {
        id: row.get(0)?,
        kind: row.get(1)?,
        name: row.get(2)?,
        enabled: row.get(3)?,
        events: row.get(4)?,
        config: row.get(5)?,
        created: row.get(6)?,
    })
}

impl Store {
    /// Write a notice down; its id. `time` empty means now.
    pub async fn add_notice(&self, notice: Notice) -> Result<i64> {
        self.sqlite_write(move |tx| {
            tx.prepare_cached(
                "INSERT INTO security_notices (user_id, kind, time, ip, device_type, device_name, app, detail, mail) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?
            .execute(params![
                notice.user_id,
                notice.kind,
                if notice.time.is_empty() { clock::now() } else { notice.time },
                notice.ip,
                notice.device_type,
                notice.device_name,
                notice.app,
                notice.detail,
                notice.mail,
            ])?;
            Ok(tx.last_insert_rowid())
        })
        .await
    }

    /// A burst of failed attempts of `kind` (`failedLogins`, `failedTwoFactor`): the notice of
    /// the burst that is still going on (one within `window` seconds) gets the new `detail`,
    /// otherwise there is a new one. Unseen again, either way. Whether it was new.
    pub async fn burst_notice(&self, notice: Notice, window: i64) -> Result<bool> {
        self.sqlite_write(move |tx| {
            let since = clock::in_seconds(-window);
            let going_on: Option<i64> = tx
                .prepare_cached(
                    "SELECT id FROM security_notices WHERE user_id = ?1 AND kind = ?2 AND time > ?3 \
                     ORDER BY id DESC LIMIT 1",
                )?
                .query_row(params![notice.user_id, notice.kind, since], |row| row.get(0))
                .optional()?;
            if let Some(id) = going_on {
                // Mailed already: what came since goes into the next bundle.
                tx.execute(
                    "UPDATE security_notices SET detail = ?2, time = ?3, ip = ?4, device_type = ?5, seen = 0, \
                     mail = CASE WHEN mail = 2 AND ?6 = 1 THEN 1 ELSE mail END WHERE id = ?1",
                    params![id, notice.detail, clock::now(), notice.ip, notice.device_type, notice.mail],
                )?;
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO security_notices (user_id, kind, time, ip, device_type, device_name, app, detail, mail) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    notice.user_id,
                    notice.kind,
                    clock::now(),
                    notice.ip,
                    notice.device_type,
                    notice.device_name,
                    notice.app,
                    notice.detail,
                    notice.mail
                ],
            )?;
            Ok(true)
        })
        .await
    }

    /// How many events of `kind` an account had in the last `seconds`: failed logins.
    pub async fn recent_events(&self, user_id: &str, kind: &str, seconds: i64) -> Result<i64> {
        let (user_id, kind) = (user_id.to_string(), kind.to_string());
        self.sqlite_read(move |conn| {
            conn.prepare_cached("SELECT count(*) FROM events WHERE time > ?1 AND user_id = ?2 AND kind = ?3")?
                .query_row(params![clock::in_seconds(-seconds), user_id, kind], |row| row.get(0))
        })
        .await
    }

    /// How many events of these kinds there were in the last `seconds`, for all accounts.
    pub async fn recent_events_of(&self, kinds: &[&str], seconds: i64) -> Result<i64> {
        let kinds: Vec<String> = kinds.iter().map(|kind| (*kind).to_string()).collect();
        self.sqlite_read(move |conn| {
            let mut total = 0;
            for kind in kinds {
                total += conn
                    .prepare_cached("SELECT count(*) FROM events WHERE time > ?1 AND kind = ?2")?
                    .query_row(params![clock::in_seconds(-seconds), kind], |row| row.get::<_, i64>(0))?;
            }
            Ok(total)
        })
        .await
    }

    /// Whether the account has a notice of `kind` newer than its newest of `unless`: for a note
    /// that is written once, until what it is about changes.
    pub async fn has_notice_since(&self, user_id: &str, kind: &str, unless: &str) -> Result<bool> {
        let (user_id, kind, unless) = (user_id.to_string(), kind.to_string(), unless.to_string());
        self.sqlite_read(move |conn| {
            conn.prepare_cached(
                "SELECT EXISTS (SELECT 1 FROM security_notices WHERE user_id = ?1 AND kind = ?2 AND time > \
                 coalesce((SELECT max(time) FROM security_notices WHERE user_id = ?1 AND kind = ?3), ''))",
            )?
            .query_row(params![user_id, kind, unless], |row| row.get(0))
        })
        .await
    }

    /// An account's notices, the newest first, older than `before` (for paging).
    pub async fn notices(&self, user_id: &str, before: Option<i64>, limit: i64) -> Result<Vec<Notice>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM security_notices WHERE user_id = ?1 AND (?2 IS NULL OR id < ?2) \
                 ORDER BY id DESC LIMIT ?3"
            ))?
            .query_map(params![user_id, before, limit], notice_from)?
            .collect()
        })
        .await
    }

    pub async fn unseen_notices(&self, user_id: &str) -> Result<i64> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached("SELECT count(*) FROM security_notices WHERE user_id = ?1 AND NOT seen")?
                .query_row([user_id], |row| row.get(0))
        })
        .await
    }

    /// `up_to` and every older notice of the account are seen.
    pub async fn see_notices(&self, user_id: &str, up_to: i64) -> Result<()> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute(
                "UPDATE security_notices SET seen = 1 WHERE user_id = ?1 AND id <= ?2 AND NOT seen",
                params![user_id, up_to],
            )
            .map(drop)
        })
        .await
    }

    /// Accounts whose waiting notices are due for their bundle at `now`: the first of them is
    /// older than `gather` seconds, and the last bundle went out more than `spacing` seconds ago.
    pub async fn notices_due(&self, now: &str, gather: i64, spacing: i64) -> Result<Vec<String>> {
        let Some(now) = clock::parse(now) else { return Ok(Vec::new()) };
        let gathered = clock::format(now - time::Duration::seconds(gather));
        let spaced = clock::format(now - time::Duration::seconds(spacing));
        self.sqlite_read(move |conn| {
            conn.prepare_cached(
                "SELECT w.user_id FROM (SELECT user_id, min(time) AS first FROM security_notices WHERE mail = 1 \
                 GROUP BY user_id) w WHERE w.first <= ?1 AND coalesce((SELECT max(mailed) FROM security_notices \
                 s WHERE s.user_id = w.user_id), '') <= ?2",
            )?
            .query_map(params![gathered, spaced], |row| row.get(0))?
            .collect()
        })
        .await
    }

    /// The notices of an account that wait for a bundle, the oldest first.
    pub async fn waiting_notices(&self, user_id: &str) -> Result<Vec<Notice>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM security_notices WHERE user_id = ?1 AND mail = 1 ORDER BY id"
            ))?
            .query_map([user_id], notice_from)?
            .collect()
        })
        .await
    }

    /// These notices went out in a bundle at `now`, or (with `sent` false) never will.
    pub async fn notices_mailed(&self, ids: Vec<i64>, now: &str, sent: bool) -> Result<()> {
        let now = now.to_string();
        self.sqlite_write(move |tx| {
            let mut update = tx.prepare_cached(
                "UPDATE security_notices SET mail = ?2, mailed = CASE WHEN ?2 = 2 THEN ?3 ELSE mailed END \
                 WHERE id = ?1",
            )?;
            for id in ids {
                update.execute(params![id, if sent { MAIL_SENT } else { MAIL_NONE }, now])?;
            }
            Ok(())
        })
        .await
    }

    // ── Channels ──────────────────────────────────────────

    pub async fn channels(&self) -> Result<Vec<Channel>> {
        self.sqlite_read(|conn| {
            conn.prepare_cached(
                "SELECT id, kind, name, enabled, events, config, created FROM notification_channels ORDER BY created, id",
            )?
            .query_map([], channel_from)?
            .collect()
        })
        .await
    }

    pub async fn channel(&self, id: &str) -> Result<Option<Channel>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(
                "SELECT id, kind, name, enabled, events, config, created FROM notification_channels WHERE id = ?1",
            )?
            .query_row([id], channel_from)
            .optional()
        })
        .await
    }

    /// Add a channel, or change the one with its id.
    pub async fn put_channel(&self, channel: Channel) -> Result<()> {
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO notification_channels (id, kind, name, enabled, events, config, created) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT (id) DO UPDATE SET kind = excluded.kind, \
                 name = excluded.name, enabled = excluded.enabled, events = excluded.events, config = excluded.config",
                params![
                    channel.id,
                    channel.kind,
                    channel.name,
                    channel.enabled,
                    channel.events,
                    channel.config,
                    if channel.created.is_empty() { clock::now() } else { channel.created }
                ],
            )
            .map(drop)
        })
        .await
    }

    pub async fn delete_channel(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM notification_channels WHERE id = ?1", [id]).map(|changed| changed > 0)
        })
        .await
    }

    /// The addresses of every admin whose account is not disabled, with their language.
    pub async fn admin_addresses(&self) -> Result<Vec<(String, String)>> {
        self.sqlite_read(|conn| {
            conn.prepare_cached("SELECT email, language FROM users WHERE admin AND NOT disabled ORDER BY email")?
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Options;

    async fn store_with_user(dir: &tempfile::TempDir) -> (Store, String) {
        let store = Store::open_sqlite(&dir.path().join("uwulock.db"), &Options { readers: 1 }).unwrap();
        let id: String = store
            .sqlite_write(|tx| {
                tx.execute(
                    "INSERT INTO users (id, email, password_hash, user_key, kdf_type, kdf_iterations, security_stamp, \
                     language, created, updated, revision) VALUES ('u1', 'nyu@example.com', 'x', 'k', 0, 600000, \
                     's', 'de', '2026-01-01T00:00:00.000000Z', '2026-01-01T00:00:00.000000Z', \
                     '2026-01-01T00:00:00.000000Z')",
                    [],
                )?;
                Ok("u1".to_string())
            })
            .await
            .unwrap();
        (store, id)
    }

    #[tokio::test]
    async fn a_burst_is_one_notice_and_bundles_wait_their_turn() {
        let dir = tempfile::tempdir().unwrap();
        let (store, user) = store_with_user(&dir).await;
        let failed = |count: i64| Notice {
            user_id: user.clone(),
            kind: "failedLogins".into(),
            detail: format!("{{\"count\":{count}}}"),
            mail: MAIL_WAITING,
            ..Notice::default()
        };
        assert!(store.burst_notice(failed(3), 900).await.unwrap());
        assert!(!store.burst_notice(failed(4), 900).await.unwrap(), "the same burst");
        let listed = store.notices(&user, None, 50).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].detail, "{\"count\":4}");
        assert_eq!(store.unseen_notices(&user).await.unwrap(), 1);

        // Not due right away; due once the gathering time is over.
        assert!(store.notices_due(&clock::now(), 300, 900).await.unwrap().is_empty());
        let later = clock::in_seconds(301);
        assert_eq!(store.notices_due(&later, 300, 900).await.unwrap(), vec![user.clone()]);
        let waiting = store.waiting_notices(&user).await.unwrap();
        store.notices_mailed(waiting.iter().map(|n| n.id).collect(), &later, true).await.unwrap();
        assert!(store.notices_due(&later, 300, 900).await.unwrap().is_empty());

        // More of the burst after the mail: waits again, but not before the spacing is over.
        store.burst_notice(failed(9), 900).await.unwrap();
        let soon = clock::in_seconds(600);
        assert!(store.notices_due(&soon, 300, 900).await.unwrap().is_empty(), "the last mail was too recent");
        assert_eq!(store.notices_due(&clock::in_seconds(1300), 300, 900).await.unwrap(), vec![user.clone()]);

        store.see_notices(&user, listed[0].id).await.unwrap();
        assert_eq!(store.unseen_notices(&user).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_note_once_until_what_it_is_about_changes() {
        let dir = tempfile::tempdir().unwrap();
        let (store, user) = store_with_user(&dir).await;
        let note = |kind: &str| Notice { user_id: user.clone(), kind: kind.into(), ..Notice::default() };
        assert!(!store.has_notice_since(&user, "kdfBelowMinimum", "kdfChanged").await.unwrap());
        store.add_notice(note("kdfBelowMinimum")).await.unwrap();
        assert!(store.has_notice_since(&user, "kdfBelowMinimum", "kdfChanged").await.unwrap());
        store.add_notice(Notice { time: clock::in_seconds(1), ..note("kdfChanged") }).await.unwrap();
        assert!(!store.has_notice_since(&user, "kdfBelowMinimum", "kdfChanged").await.unwrap());
    }

    #[tokio::test]
    async fn channels_are_kept_and_the_first_one_is_mail() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = store_with_user(&dir).await;
        let channels = store.channels().await.unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].kind, "mail");
        assert_eq!(channels[0].id.len(), 36, "{}", channels[0].id);
        let ntfy = Channel {
            id: "c2".into(),
            kind: "ntfy".into(),
            name: "Phone".into(),
            enabled: true,
            events: "[]".into(),
            config: "{}".into(),
            created: String::new(),
        };
        store.put_channel(ntfy.clone()).await.unwrap();
        store.put_channel(Channel { name: "Mine".into(), ..ntfy }).await.unwrap();
        assert_eq!(store.channel("c2").await.unwrap().unwrap().name, "Mine");
        assert!(store.delete_channel("c2").await.unwrap());
        assert!(!store.delete_channel("c2").await.unwrap());
    }
}
