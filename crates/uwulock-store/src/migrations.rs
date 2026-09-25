//! The schema, one numbered step at a time.
//!
//! Each step is a file under `migrations/sqlite`, applied once, in order, inside a transaction.
//! How far a database has come is its `user_version`. A step is never changed once it is
//! released: a database that went through it already would not go through it again.

use crate::{Result, StoreError};
use rusqlite::Connection;

const STEPS: &[&str] = &[include_str!("../migrations/sqlite/0001_server.sql")];

/// The schema this build writes.
pub const SCHEMA_VERSION: i64 = STEPS.len() as i64;

pub(crate) fn run(conn: &mut Connection) -> Result<()> {
    let found: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::TooNew { found, known: SCHEMA_VERSION });
    }
    for (index, step) in STEPS.iter().enumerate().skip(found as usize) {
        let version = index as i64 + 1;
        let tx = conn.transaction()?;
        tx.execute_batch(step)?;
        tx.pragma_update(None, "user_version", version)?;
        tx.commit()?;
        tracing::info!(version, "database schema updated");
    }
    Ok(())
}
