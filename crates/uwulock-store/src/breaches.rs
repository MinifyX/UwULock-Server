//! What the password check's breach sources keep (docs/uwu-api.md §15): the ignore list an
//! account's clients encrypted, who agreed to the check of addresses, and XposedOrNot's answers
//! for addresses, by a salted hash only.

use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, params};

impl Store {
    /// The ignore list and when it was stored.
    pub async fn health_ignores(&self, user_id: &str) -> Result<Option<(String, String)>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row("SELECT data, revision FROM health_ignores WHERE user_id = ?1", [user_id], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()
        })
        .await
    }

    /// Keep `data` as the account's ignore list; its revision date. With `expected` (the
    /// revision the client read, `Some(None)` when it read none), only if that is still what is
    /// stored: `None` when it is not, and nothing is written.
    pub async fn set_health_ignores(
        &self,
        user_id: &str,
        data: &str,
        expected: Option<Option<String>>,
    ) -> Result<Option<String>> {
        let (user_id, data, now) = (user_id.to_string(), data.to_string(), clock::now());
        self.sqlite_write(move |tx| {
            if let Some(expected) = expected {
                let stored: Option<String> = tx
                    .query_row("SELECT revision FROM health_ignores WHERE user_id = ?1", [&user_id], |row| row.get(0))
                    .optional()?;
                if stored != expected {
                    return Ok(None);
                }
            }
            tx.execute(
                "INSERT INTO health_ignores (user_id, data, revision) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (user_id) DO UPDATE SET data = excluded.data, revision = excluded.revision",
                params![user_id, data, now],
            )?;
            Ok(Some(now))
        })
        .await
    }

    pub async fn delete_health_ignores(&self, user_id: &str) -> Result<()> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| tx.execute("DELETE FROM health_ignores WHERE user_id = ?1", [user_id]).map(drop))
            .await
    }

    /// Since when the account agreed to the check of its addresses, if it did.
    pub async fn breach_email_opt_in(&self, user_id: &str) -> Result<Option<String>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row("SELECT since FROM breach_email_opt_ins WHERE user_id = ?1", [user_id], |row| row.get(0))
                .optional()
        })
        .await
    }

    /// Agree (keeping the first date) or take it back; since when it holds.
    pub async fn set_breach_email_opt_in(&self, user_id: &str, on: bool) -> Result<Option<String>> {
        let (user_id, now) = (user_id.to_string(), clock::now());
        self.sqlite_write(move |tx| {
            if !on {
                tx.execute("DELETE FROM breach_email_opt_ins WHERE user_id = ?1", [&user_id])?;
                return Ok(None);
            }
            tx.execute(
                "INSERT INTO breach_email_opt_ins (user_id, since) VALUES (?1, ?2) ON CONFLICT (user_id) DO NOTHING",
                params![user_id, now],
            )?;
            tx.query_row("SELECT since FROM breach_email_opt_ins WHERE user_id = ?1", [&user_id], |row| row.get(0))
                .optional()
        })
        .await
    }

    /// XposedOrNot's answer for the address behind `hash` (its breaches as a JSON list), if it
    /// was asked at or after `since` (Unix seconds).
    pub async fn breach_email_cached(&self, hash: Vec<u8>, since: i64) -> Result<Option<String>> {
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT breaches FROM breach_email_cache WHERE address_hash = ?1 AND checked >= ?2",
                params![hash, since],
                |row| row.get(0),
            )
            .optional()
        })
        .await
    }

    pub async fn set_breach_email_cached(&self, hash: Vec<u8>, breaches: &str, checked: i64) -> Result<()> {
        let breaches = breaches.to_string();
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO breach_email_cache (address_hash, breaches, checked) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (address_hash) DO UPDATE SET breaches = excluded.breaches, checked = excluded.checked",
                params![hash, breaches, checked],
            )
            .map(drop)
        })
        .await
    }

    /// Forget answers asked before `before` (Unix seconds).
    pub async fn prune_breach_email_cache(&self, before: i64) -> Result<()> {
        self.sqlite_write(move |tx| tx.execute("DELETE FROM breach_email_cache WHERE checked < ?1", [before]).map(drop))
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::Store;

    async fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_sqlite(&dir.path().join("db"), &crate::Options { readers: 1 }).unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn the_email_cache_is_kept_by_hash_and_pruned() {
        let (_dir, store) = store().await;
        store.set_breach_email_cached(vec![1, 2], "[\"Adobe\"]", 100).await.unwrap();
        assert_eq!(store.breach_email_cached(vec![1, 2], 50).await.unwrap().as_deref(), Some("[\"Adobe\"]"));
        assert!(store.breach_email_cached(vec![1, 2], 101).await.unwrap().is_none(), "too old");
        store.prune_breach_email_cache(101).await.unwrap();
        assert!(store.breach_email_cached(vec![1, 2], 0).await.unwrap().is_none());
    }
}
