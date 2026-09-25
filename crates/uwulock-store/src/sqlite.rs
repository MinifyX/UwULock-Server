//! The SQLite backend: one connection that writes, a few that read.
//!
//! In WAL mode readers see a consistent state and never wait for the writer, and the writer
//! never waits for them. So a sync — the one request every client sends all the time — takes a
//! read connection of its own and runs beside everything else, while writes, which are rare and
//! small, queue up for the one write connection.

use crate::migrations;
use crate::{Options, Result, StoreError};
use parking_lot::Mutex;
use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub(crate) struct Sqlite {
    path: PathBuf,
    writer: Mutex<Connection>,
    readers: Vec<Mutex<Connection>>,
    /// Where the next reader search starts, so the load spreads.
    next: AtomicUsize,
}

impl Sqlite {
    pub(crate) fn open(path: &Path, options: &Options) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut writer = Connection::open(path)?;
        let mode: String = writer.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            tracing::warn!(mode, "the database is not in WAL mode; reads will wait for writes");
        }
        tune(&writer)?;
        // FULL, not NORMAL: a saved password must survive a power cut. Writes are rare enough
        // that the extra sync costs nothing anybody notices.
        writer.pragma_update(None, "synchronous", "FULL")?;
        // What is deleted is gone: an item's ciphertext must not stay readable in a free page.
        writer.pragma_update(None, "secure_delete", "ON")?;
        migrations::run(&mut writer)?;

        let readers = (0..options.readers.max(1))
            .map(|_| {
                let conn = Connection::open_with_flags(
                    path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_URI,
                )?;
                tune(&conn)?;
                conn.pragma_update(None, "query_only", "ON")?;
                Ok(Mutex::new(conn))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;

        Ok(Self { path: path.to_path_buf(), writer: Mutex::new(writer), readers, next: AtomicUsize::new(0) })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// A free reader if there is one, otherwise the next one in turn.
    pub(crate) fn read<T>(&self, query: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> rusqlite::Result<T> {
        let count = self.readers.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed) % count;
        for offset in 0..count {
            if let Some(conn) = self.readers[(start + offset) % count].try_lock() {
                return query(&conn);
            }
        }
        query(&self.readers[start].lock())
    }

    pub(crate) fn write<T>(
        &self,
        change: impl FnOnce(&rusqlite::Transaction<'_>) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        let mut conn = self.writer.lock();
        // IMMEDIATE takes the write lock at once, so a transaction never finds out halfway that
        // it cannot write after all.
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let value = change(&tx)?;
        tx.commit()?;
        Ok(value)
    }

    /// `VACUUM INTO` through a connection of its own: a reader in WAL mode holds nobody up, so a
    /// large database is copied while requests go on being answered.
    pub(crate) fn backup_to(&self, target: &Path) -> Result<()> {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open_with_flags(&self.path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute("VACUUM INTO ?1", [target.to_string_lossy().as_ref()])?;
        Ok(())
    }
}

/// What every connection gets.
fn tune(conn: &Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    // 8 MiB of page cache per connection, temporary tables in memory, and the file mapped rather
    // than read page by page — the address space is reserved, not the memory.
    conn.pragma_update(None, "cache_size", -8192)?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "mmap_size", 256 * 1024 * 1024)?;
    conn.set_prepared_statement_cache_capacity(64);
    Ok(())
}
