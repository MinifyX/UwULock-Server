//! The last password-health report of an account, as its client encrypted it (docs/uwu-api.md
//! §15): kept so another device can show it without checking every password again.

use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, params};

impl Store {
    /// The report and when it was stored.
    pub async fn health_report(&self, user_id: &str) -> Result<Option<(String, String)>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row("SELECT data, revision FROM health_reports WHERE user_id = ?1", [user_id], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()
        })
        .await
    }

    /// Keep `data` as the account's report; its revision date.
    pub async fn set_health_report(&self, user_id: &str, data: &str) -> Result<String> {
        let (user_id, data, now) = (user_id.to_string(), data.to_string(), clock::now());
        let revision = now.clone();
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO health_reports (user_id, data, revision) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (user_id) DO UPDATE SET data = excluded.data, revision = excluded.revision",
                params![user_id, data, now],
            )
            .map(drop)
        })
        .await?;
        Ok(revision)
    }

    pub async fn delete_health_report(&self, user_id: &str) -> Result<()> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| tx.execute("DELETE FROM health_reports WHERE user_id = ?1", [user_id]).map(drop))
            .await
    }
}
