//! The schema, one numbered step at a time.
//!
//! Each step is a file under `migrations/sqlite`, applied once, in order, inside a transaction.
//! How far a database has come is its `user_version`. A step is never changed once it is
//! released: a database that went through it already would not go through it again.

use crate::{Result, StoreError};
use rusqlite::Connection;

const STEPS: &[&str] = &[
    include_str!("../migrations/sqlite/0001_server.sql"),
    include_str!("../migrations/sqlite/0002_accounts.sql"),
    include_str!("../migrations/sqlite/0003_features.sql"),
    include_str!("../migrations/sqlite/0004_organizations.sql"),
];

/// The schema this build writes.
pub const SCHEMA_VERSION: i64 = STEPS.len() as i64;

pub(crate) fn run(conn: &mut Connection) -> Result<()> {
    let found: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::TooNew { found, known: SCHEMA_VERSION });
    }
    if found == SCHEMA_VERSION {
        return Ok(());
    }
    // A step may build a table again (SQLite changes no column in place), which with foreign
    // keys on would take everything that points at the old table with it. So they are off while
    // the steps run — outside the transactions, the only place SQLite lets that change — and
    // checked before they are on again.
    conn.pragma_update(None, "foreign_keys", "OFF")?;
    let result = (|| -> Result<()> {
        for (index, step) in STEPS.iter().enumerate().skip(found as usize) {
            let version = index as i64 + 1;
            let tx = conn.transaction()?;
            tx.execute_batch(step)?;
            let broken: i64 = tx.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| row.get(0))?;
            if broken > 0 {
                return Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY),
                    Some(format!("schema step {version} left {broken} broken references")),
                )));
            }
            tx.pragma_update(None, "user_version", version)?;
            tx.commit()?;
            tracing::info!(version, "database schema updated");
        }
        Ok(())
    })();
    conn.pragma_update(None, "foreign_keys", "ON")?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database from 0.1 with an item and an attachment on it goes through the step that builds
    /// `ciphers` again — and keeps both, the attachment still pointing at its item.
    #[test]
    fn an_older_database_keeps_its_items_and_their_attachments() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        for step in &STEPS[..3] {
            conn.execute_batch(step).unwrap();
        }
        conn.execute_batch(
            "INSERT INTO users (id, email, password_hash, user_key, kdf_type, kdf_iterations, security_stamp, language, \
             created, updated, revision) VALUES ('u', 'nyu@example.com', 'h', 'k', 0, 600000, 's', 'de', 't', 't', 't');
             INSERT INTO ciphers (id, user_id, type, name, data, created, revision) VALUES ('c', 'u', 1, 'n', '{}', 't', 't');
             INSERT INTO attachments (id, cipher_id, file_name, size, uploaded, created) VALUES ('a', 'c', 'f', 1, 1, 't');",
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 3).unwrap();
        run(&mut conn).unwrap();
        let (user, org): (Option<String>, Option<String>) = conn
            .query_row("SELECT user_id, organization_id FROM ciphers WHERE id = 'c'", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!((user.as_deref(), org), (Some("u"), None));
        let attachments: i64 = conn.query_row("SELECT count(*) FROM attachments", [], |row| row.get(0)).unwrap();
        assert_eq!(attachments, 1);
        let on: i64 = conn.pragma_query_value(None, "foreign_keys", |row| row.get(0)).unwrap();
        assert_eq!(on, 1, "foreign keys are on again");
        conn.execute("DELETE FROM ciphers WHERE id = 'c'", []).unwrap();
        let left: i64 = conn.query_row("SELECT count(*) FROM attachments", [], |row| row.get(0)).unwrap();
        assert_eq!(left, 0, "and the attachment still goes with its item");
    }
}
