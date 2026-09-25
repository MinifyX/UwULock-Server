//! UwULock Server's database.
//!
//! One SQLite file today. Everything above this crate talks to [`Store`] and never to SQLite
//! itself, so PostgreSQL can come later as a second backend behind the same methods — for a
//! company that wants its database where its other databases are.
//!
//! The server never sees a password or an item in the clear: what it stores for a vault is what
//! the clients encrypted. So this is mostly bookkeeping, and it has to be fast at one thing above
//! all: handing a whole vault to a client that syncs.

mod accounts;
mod admin;
mod backup;
pub mod backups;
pub mod clock;
mod migrations;
mod sqlite;
mod vault;

pub use accounts::{
    CODE_ATTEMPTS, CodeRefusal, Device, DeviceLogin, Invitation, Kdf, NewUser, SessionUser, TwoFactor, User,
    UserOverview, normalize_email,
};
pub use admin::{EVENT_DAYS, Event, Stats};
pub use backup::restore;
pub use migrations::SCHEMA_VERSION;
pub use vault::{Bulk, Cipher, Folder, VaultContents};

use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// What can go wrong down here.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// Something with that name is there already, like an account for an address.
    #[error("it exists already")]
    Exists,
    /// The file was last opened by a newer UwULock Server, which changed it in ways this one
    /// does not know. Going on would mean guessing.
    #[error("the database comes from a newer UwULock Server (schema {found}, this one knows up to {known})")]
    TooNew { found: i64, known: i64 },
    /// A query's thread went away before it answered, which only happens while shutting down.
    #[error("the database task did not finish")]
    Gone,
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// Tuning that differs between a server and a test.
#[derive(Debug, Clone)]
pub struct Options {
    /// Connections that only read, each used by one query at a time. Reads never wait for a
    /// write in WAL mode, so this is how many syncs can be answered at once.
    pub readers: usize,
}

impl Default for Options {
    fn default() -> Self {
        let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
        Self { readers: cores.clamp(2, 8) }
    }
}

/// The database. Cheap to clone: every clone is the same connections.
#[derive(Clone)]
pub struct Store {
    backend: Arc<Backend>,
    /// Who the requests are from, by user id, and since when that is known: see
    /// [`Store::session_user`].
    sessions: Arc<RwLock<HashMap<String, (SessionUser, std::time::Instant)>>>,
}

enum Backend {
    Sqlite(sqlite::Sqlite),
}

impl Store {
    /// Open (or make) the SQLite database at `path` and bring its schema up to date.
    pub fn open_sqlite(path: &Path, options: &Options) -> Result<Self> {
        let sqlite = sqlite::Sqlite::open(path, options)?;
        Ok(Self { backend: Arc::new(Backend::Sqlite(sqlite)), sessions: Arc::default() })
    }

    /// Whether the database answers. What `/healthz` asks.
    pub async fn ping(&self) -> Result<()> {
        match &*self.backend {
            Backend::Sqlite(_) => self.sqlite_read(|conn| conn.query_row("SELECT 1", [], |_| Ok(()))).await,
        }
    }

    /// The schema the database is at.
    pub async fn schema_version(&self) -> Result<i64> {
        match &*self.backend {
            Backend::Sqlite(_) => {
                self.sqlite_read(|conn| conn.pragma_query_value(None, "user_version", |row| row.get(0))).await
            }
        }
    }

    /// When this database was made, as the server wrote it down (RFC 3339, UTC).
    pub async fn created(&self) -> Result<String> {
        self.sqlite_read(|conn| conn.query_row("SELECT value FROM server WHERE key = 'created'", [], |row| row.get(0)))
            .await
    }

    /// A consistent copy of the running database at `path`, which copying the file is not: the
    /// write-ahead log would be missing. The server goes on answering while it is written.
    pub async fn backup_to(&self, path: &Path) -> Result<()> {
        let path = path.to_path_buf();
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || match &*backend {
            Backend::Sqlite(sqlite) => sqlite.backup_to(&path),
        })
        .await
        .map_err(|_| StoreError::Gone)?
    }

    /// The file behind this store, for the size of a backup.
    pub fn path(&self) -> &Path {
        match &*self.backend {
            Backend::Sqlite(sqlite) => sqlite.path(),
        }
    }

    /// Run `query` on a read connection, on a blocking thread.
    pub(crate) async fn sqlite_read<T, F>(&self, query: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&rusqlite::Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || match &*backend {
            Backend::Sqlite(sqlite) => sqlite.read(query),
        })
        .await
        .map_err(|_| StoreError::Gone)?
        .map_err(StoreError::from)
    }

    /// Run `change` in a transaction on the write connection, on a blocking thread. It commits
    /// when `change` returns `Ok`, and rolls back otherwise.
    pub(crate) async fn sqlite_write<T, F>(&self, change: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&rusqlite::Transaction<'_>) -> rusqlite::Result<T> + Send + 'static,
    {
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || match &*backend {
            Backend::Sqlite(sqlite) => sqlite.write(change),
        })
        .await
        .map_err(|_| StoreError::Gone)?
        .map_err(StoreError::from)
    }
}

/// `name` with `suffix` added to its file name: `uwulock.db` and `-wal` make `uwulock.db-wal`.
pub fn with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(dir: &tempfile::TempDir) -> Store {
        Store::open_sqlite(&dir.path().join("uwulock.db"), &Options { readers: 2 }).unwrap()
    }

    #[tokio::test]
    async fn a_new_database_is_at_the_newest_schema() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        store.ping().await.unwrap();
        assert_eq!(store.schema_version().await.unwrap(), SCHEMA_VERSION);
        let created = store.created().await.unwrap();
        assert!(created.ends_with('Z') && created.len() == 20, "{created}");
    }

    #[tokio::test]
    async fn opening_again_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let first = open(&dir).created().await.unwrap();
        let second = open(&dir).created().await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn a_write_that_fails_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        let failed = store
            .sqlite_write(|tx| {
                tx.execute("INSERT INTO server (key, value) VALUES ('half', 'done')", [])?;
                tx.execute("INSERT INTO nowhere VALUES (1)", [])
            })
            .await;
        assert!(failed.is_err());
        let left: i64 = store
            .sqlite_read(|conn| conn.query_row("SELECT count(*) FROM server WHERE key = 'half'", [], |row| row.get(0)))
            .await
            .unwrap();
        assert_eq!(left, 0);
    }

    #[tokio::test]
    async fn readers_see_what_was_written() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        store
            .sqlite_write(|tx| tx.execute("INSERT INTO server (key, value) VALUES ('seen', 'yes')", []))
            .await
            .unwrap();
        // Every reader, not only the one that happens to be free first.
        for _ in 0..4 {
            let value: String = store
                .sqlite_read(|conn| conn.query_row("SELECT value FROM server WHERE key = 'seen'", [], |row| row.get(0)))
                .await
                .unwrap();
            assert_eq!(value, "yes");
        }
    }

    #[tokio::test]
    async fn a_database_from_a_newer_server_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("uwulock.db");
        drop(open(&dir));
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1).unwrap();
        drop(conn);
        match Store::open_sqlite(&path, &Options::default()) {
            Err(StoreError::TooNew { found, known }) => {
                assert_eq!(found, SCHEMA_VERSION + 1);
                assert_eq!(known, SCHEMA_VERSION);
            }
            Err(other) => panic!("{other}"),
            Ok(_) => panic!("a newer schema was opened"),
        }
    }
}
