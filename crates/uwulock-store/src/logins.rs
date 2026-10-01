//! Failed logins for the admin portal (docs/failed-logins.md): the attempts with filters, the
//! same grouped by address, and the addresses that may not log in for a while.

use crate::admin::{EVENT_COLUMNS, Event, event_row};
use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, params};

/// The kinds of event that are a refused login.
const FAILED: &str = "'login-failed', 'two-factor-failed'";

/// Which login events to list. Everything is optional; `all` adds the logins that worked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoginFilter {
    /// Only events after this time (the database's time format).
    pub since: Option<String>,
    /// An account's id, or a part of the address that was typed.
    pub user: Option<String>,
    /// One address; ending in `*`, every address that starts like this.
    pub ip: Option<String>,
    /// `password`, `unknown-account`, `disabled`, `api-key`, `two-factor`.
    pub reason: Option<String>,
    /// The logins that worked too, for the history of an address.
    pub all: bool,
}

impl LoginFilter {
    /// The `WHERE` of the filter, with its values as `?1` to `?5`.
    fn condition(&self) -> String {
        let kinds = if self.all { format!("{FAILED}, 'login'") } else { FAILED.to_string() };
        format!(
            "kind IN ({kinds}) AND (?1 IS NULL OR time > ?1) \
             AND (?2 IS NULL OR user_id = ?2 OR instr(lower(email), lower(?2)) > 0) \
             AND (?3 IS NULL OR ip = ?3 OR (substr(?3, -1) = '*' AND substr(ip, 1, length(?3) - 1) = substr(?3, 1, length(?3) - 1))) \
             AND (?4 IS NULL OR reason = ?4)"
        )
    }

    fn values(&self) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
        let clean =
            |value: &Option<String>| value.as_ref().map(|text| text.trim().to_string()).filter(|text| !text.is_empty());
        (clean(&self.since), clean(&self.user), clean(&self.ip), clean(&self.reason))
    }
}

/// The refused logins from one address, within a filter.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IpGroup {
    pub ip: String,
    pub attempts: i64,
    pub first: String,
    pub last: String,
    /// How many different accounts (or typed addresses) were tried.
    pub targets: i64,
    /// Attempts at addresses without an account.
    pub unknown: i64,
    /// Up to five of the addresses tried, the most tried first.
    pub emails: Vec<String>,
    /// Logins that worked from this address in the same time.
    pub logins: i64,
}

/// An address, or a network, that may not log in.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IpBlock {
    pub id: i64,
    /// `203.0.113.7` or `2001:db8::/64`.
    pub network: String,
    pub reason: String,
    pub created: String,
    /// None: until an admin lifts it.
    pub expires: Option<String>,
    pub created_by: Option<String>,
}

fn block_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<IpBlock> {
    Ok(IpBlock {
        id: row.get(0)?,
        network: row.get(1)?,
        reason: row.get(2)?,
        created: row.get(3)?,
        expires: row.get(4)?,
        created_by: row.get(5)?,
    })
}

impl Store {
    /// Login events by the filter, the newest first, before the event `before` (for paging).
    pub async fn login_events(&self, filter: LoginFilter, before: Option<i64>, limit: i64) -> Result<Vec<Event>> {
        self.sqlite_read(move |conn| {
            let (since, user, ip, reason) = filter.values();
            conn.prepare(&format!(
                "SELECT {EVENT_COLUMNS} FROM events WHERE {} AND (?5 IS NULL OR id < ?5) ORDER BY id DESC LIMIT ?6",
                filter.condition()
            ))?
            .query_map(params![since, user, ip, reason, before, limit], event_row)?
            .collect()
        })
        .await
    }

    /// The refused logins by the filter, by address: the most attempts first, at most `limit`
    /// addresses. `filter.all` is ignored; each group counts the logins that worked beside.
    pub async fn failed_by_ip(&self, filter: LoginFilter, limit: i64) -> Result<Vec<IpGroup>> {
        self.sqlite_read(move |conn| {
            let filter = LoginFilter { all: false, ..filter };
            let (since, user, ip, reason) = filter.values();
            let condition = filter.condition();
            let mut groups: Vec<IpGroup> = conn
                .prepare(&format!(
                    "SELECT ip, count(*), min(time), max(time), count(DISTINCT coalesce(user_id, email)), \
                     sum(user_id IS NULL AND reason = 'unknown-account') \
                     FROM events WHERE {condition} AND ip IS NOT NULL \
                     GROUP BY ip ORDER BY count(*) DESC, max(time) DESC LIMIT ?5"
                ))?
                .query_map(params![since, user, ip, reason, limit], |row| {
                    Ok(IpGroup {
                        ip: row.get(0)?,
                        attempts: row.get(1)?,
                        first: row.get(2)?,
                        last: row.get(3)?,
                        targets: row.get(4)?,
                        unknown: row.get::<_, Option<i64>>(5)?.unwrap_or(0),
                        ..IpGroup::default()
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            let mut emails = conn.prepare(&format!(
                "SELECT email FROM events WHERE {condition} AND ip = ?5 AND email IS NOT NULL \
                 GROUP BY email ORDER BY count(*) DESC, email LIMIT 5"
            ))?;
            let mut logins = conn.prepare_cached(
                "SELECT count(*) FROM events WHERE kind = 'login' AND ip = ?1 AND (?2 IS NULL OR time > ?2)",
            )?;
            for group in &mut groups {
                group.emails = emails
                    .query_map(params![since, user, ip, reason, group.ip], |row| row.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                group.logins = logins.query_row(params![group.ip, since], |row| row.get(0))?;
            }
            Ok(groups)
        })
        .await
    }

    /// The blocks that still hold, the newest first.
    pub async fn ip_blocks(&self) -> Result<Vec<IpBlock>> {
        self.sqlite_read(|conn| {
            conn.prepare_cached(
                "SELECT id, network, reason, created, expires, created_by FROM ip_blocks \
                 WHERE expires IS NULL OR expires > ?1 ORDER BY id DESC",
            )?
            .query_map([clock::now()], block_row)?
            .collect()
        })
        .await
    }

    /// Block `network` (as the server writes it) until `expires`; a block of the same network
    /// is replaced.
    pub async fn block_ip(
        &self,
        network: &str,
        reason: &str,
        expires: Option<String>,
        created_by: Option<String>,
    ) -> Result<IpBlock> {
        let (network, reason) = (network.to_string(), reason.to_string());
        self.sqlite_write(move |tx| {
            tx.query_row(
                "INSERT INTO ip_blocks (network, reason, created, expires, created_by) VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT (network) DO UPDATE SET reason = excluded.reason, created = excluded.created, \
                 expires = excluded.expires, created_by = excluded.created_by \
                 RETURNING id, network, reason, created, expires, created_by",
                params![network, reason, clock::now(), expires, created_by],
                block_row,
            )
        })
        .await
    }

    /// Lift the block `id`; whether there was one.
    pub async fn unblock_ip(&self, id: i64) -> Result<Option<IpBlock>> {
        self.sqlite_write(move |tx| {
            tx.query_row(
                "DELETE FROM ip_blocks WHERE id = ?1 RETURNING id, network, reason, created, expires, created_by",
                [id],
                block_row,
            )
            .optional()
        })
        .await
    }

    /// Lift the block of `network`, as the command line names it; whether there was one.
    pub async fn unblock_network(&self, network: &str) -> Result<bool> {
        let network = network.to_string();
        self.sqlite_write(move |tx| tx.execute("DELETE FROM ip_blocks WHERE network = ?1", [network]).map(|n| n > 0))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::store;

    fn failed(ip: &str, email: &str, user: Option<&str>, reason: &str) -> Event {
        Event {
            kind: if reason == "two-factor" { "two-factor-failed" } else { "login-failed" }.into(),
            ip: Some(ip.into()),
            email: Some(email.into()),
            user_id: user.map(Into::into),
            reason: Some(reason.into()),
            user_agent: Some("Mozilla/5.0".into()),
            client_name: Some("web".into()),
            client_version: Some("2026.9.0".into()),
            device_name: Some("firefox".into()),
            ..Event::default()
        }
    }

    #[tokio::test]
    async fn failed_logins_filter_and_group_by_address() {
        let (store, _dir) = store();
        for event in [
            failed("203.0.113.5", "nyu@example.com", Some("u1"), "password"),
            failed("203.0.113.5", "nyu@example.com", Some("u1"), "password"),
            failed("203.0.113.5", "ghost@example.com", None, "unknown-account"),
            failed("203.0.113.50", "nyu@example.com", Some("u1"), "two-factor"),
            failed("2001:db8::1", "other@example.org", Some("u2"), "password"),
            Event {
                kind: "login".into(),
                ip: Some("203.0.113.5".into()),
                email: Some("nyu@example.com".into()),
                ..Event::default()
            },
            Event { kind: "admin".into(), ip: Some("203.0.113.5".into()), ..Event::default() },
        ] {
            store.log_event(event).await.unwrap();
        }
        let old = Event {
            time: clock::in_seconds(-3 * 86_400),
            ..failed("198.51.100.1", "nyu@example.com", None, "unknown-account")
        };
        store.log_event(old).await.unwrap();

        let all = store.login_events(LoginFilter::default(), None, 100).await.unwrap();
        assert_eq!(all.len(), 6, "refused logins only");
        assert_eq!(all[0].device_name.as_deref(), Some("firefox"));
        let recent = LoginFilter { since: Some(clock::in_seconds(-86_400)), ..LoginFilter::default() };
        assert_eq!(store.login_events(recent.clone(), None, 100).await.unwrap().len(), 5);
        let by_user = LoginFilter { user: Some("NYU@".into()), ..recent.clone() };
        assert_eq!(store.login_events(by_user, None, 100).await.unwrap().len(), 3);
        let by_id = LoginFilter { user: Some("u2".into()), ..LoginFilter::default() };
        assert_eq!(store.login_events(by_id, None, 100).await.unwrap().len(), 1);
        let one_ip = LoginFilter { ip: Some("203.0.113.5".into()), ..LoginFilter::default() };
        assert_eq!(store.login_events(one_ip.clone(), None, 100).await.unwrap().len(), 3, "not .50");
        let prefix = LoginFilter { ip: Some("203.0.113.*".into()), ..LoginFilter::default() };
        assert_eq!(store.login_events(prefix, None, 100).await.unwrap().len(), 4);
        let reason = LoginFilter { reason: Some("two-factor".into()), ..LoginFilter::default() };
        assert_eq!(store.login_events(reason, None, 100).await.unwrap().len(), 1);
        let history = LoginFilter { all: true, ..one_ip };
        assert_eq!(store.login_events(history, None, 100).await.unwrap().len(), 4, "with the login, not the admin");
        let page = store.login_events(LoginFilter::default(), None, 2).await.unwrap();
        let rest = store.login_events(LoginFilter::default(), Some(page[1].id), 100).await.unwrap();
        assert_eq!(rest.len(), 4);

        let groups = store.failed_by_ip(recent, 10).await.unwrap();
        assert_eq!(groups.len(), 3);
        let first = &groups[0];
        assert_eq!((first.ip.as_str(), first.attempts, first.targets, first.unknown), ("203.0.113.5", 3, 2, 1));
        assert_eq!(first.emails, ["nyu@example.com", "ghost@example.com"]);
        assert_eq!(first.logins, 1);
    }

    #[tokio::test]
    async fn blocks_hold_until_they_run_out_or_are_lifted() {
        let (store, _dir) = store();
        let forever =
            store.block_ip("203.0.113.5", "tries passwords", None, Some("admin@example.com".into())).await.unwrap();
        store.block_ip("2001:db8::/64", "", Some(clock::in_seconds(3600)), None).await.unwrap();
        store.block_ip("198.51.100.7", "", Some(clock::in_seconds(-1)), None).await.unwrap();
        let blocks = store.ip_blocks().await.unwrap();
        assert_eq!(
            blocks.iter().map(|block| block.network.as_str()).collect::<Vec<_>>(),
            ["2001:db8::/64", "203.0.113.5"]
        );
        let again = store.block_ip("203.0.113.5", "again", Some(clock::in_seconds(60)), None).await.unwrap();
        assert_eq!(again.id, forever.id, "the same network is one block");
        assert_eq!(store.ip_blocks().await.unwrap().len(), 2);
        store.sweep().await.unwrap();
        assert!(store.unblock_ip(forever.id).await.unwrap().is_some());
        assert!(store.unblock_ip(forever.id).await.unwrap().is_none());
        assert!(store.unblock_network("2001:db8::/64").await.unwrap());
        assert!(store.ip_blocks().await.unwrap().is_empty());
        let left: i64 = store
            .sqlite_read(|conn| conn.query_row("SELECT count(*) FROM ip_blocks", [], |row| row.get(0)))
            .await
            .unwrap();
        assert_eq!(left, 0, "the run-out one was swept away");
    }
}
