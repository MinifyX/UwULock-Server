//! Putting a backup back.

use crate::migrations::SCHEMA_VERSION;
use crate::with_suffix;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use std::time::Duration;

/// Put `backup` in place of the database at `database`, keeping what was there at `aside`.
///
/// The backup is checked first: an intact SQLite file, with this server's tables, at a schema
/// this build can read. And the database must not be in use — a server still writing to it would
/// lose everything after the backup, or worse, write its log into the file that replaced it.
/// Leaving WAL mode needs the only connection there is, which makes it the test, and it folds the
/// log into the file on the way, so nothing of it is left lying next to the backup either.
pub fn restore(backup: &Path, database: &Path, aside: &Path) -> Result<(), String> {
    let found = |error: rusqlite::Error| format!("{}: {error}", backup.display());
    {
        let conn = Connection::open_with_flags(backup, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(found)?;
        let check: String = conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|_| format!("{} is not a database", backup.display()))?;
        if check != "ok" {
            return Err(format!("{} is damaged: {check}", backup.display()));
        }
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0)).map_err(found)?;
        let ours: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'server'", [], |row| {
                row.get(0)
            })
            .map_err(found)?;
        if version < 1 || ours != 1 {
            return Err(format!("{} is not a UwULock Server database", backup.display()));
        }
        if version > SCHEMA_VERSION {
            return Err(format!(
                "{} comes from a newer UwULock Server (schema {version}); restore it with that one",
                backup.display()
            ));
        }
    }

    if let (Ok(backup), Ok(database)) = (backup.canonicalize(), database.canonicalize())
        && backup == database
    {
        return Err("that is the database itself, not a backup of it".into());
    }

    let failed = |error: rusqlite::Error| error.to_string();
    let replaced = database.exists();
    if replaced {
        let conn = Connection::open(database).map_err(failed)?;
        conn.busy_timeout(Duration::ZERO).map_err(failed)?;
        let mode: Option<String> = conn.pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0)).ok();
        if mode.as_deref() != Some("delete") {
            return Err("the database is in use. Stop the server first: docker compose stop".into());
        }
    }

    // The backup is made ready beside the database — copied through SQLite, so it is one
    // consistent file — and only then swapped in. Until the last step the database is where it
    // was; a copy that fails halfway, on a full disk say, leaves it alone.
    let incoming = with_suffix(database, "-restoring");
    let _ = std::fs::remove_file(&incoming);
    let prepared = Connection::open_with_flags(backup, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .and_then(|conn| conn.execute("VACUUM INTO ?1", [incoming.to_string_lossy().as_ref()]).map(drop));
    if let Err(error) = prepared {
        let _ = std::fs::remove_file(&incoming);
        return Err(format!("the backup could not be made ready: {error}"));
    }

    if replaced {
        std::fs::rename(database, aside).map_err(|error| error.to_string())?;
    }
    if let Err(error) = std::fs::rename(&incoming, database) {
        if replaced {
            let _ = std::fs::rename(aside, database);
        }
        return Err(format!("the backup could not be put in place: {error}"));
    }
    // A log beside the database belongs to the one that was there; the backup must never have
    // it played over it.
    for leftover in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(with_suffix(database, leftover));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Options, Store};

    async fn store_with(dir: &Path, marker: &'static str) -> Store {
        let store = Store::open_sqlite(&dir.join("uwulock.db"), &Options { readers: 1 }).unwrap();
        store
            .sqlite_write(move |tx| {
                tx.execute("INSERT OR REPLACE INTO server (key, value) VALUES ('marker', ?1)", [marker])
            })
            .await
            .unwrap();
        store
    }

    async fn marker(store: &Store) -> String {
        store
            .sqlite_read(|conn| conn.query_row("SELECT value FROM server WHERE key = 'marker'", [], |row| row.get(0)))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_backup_goes_back_and_what_was_there_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(dir.path(), "before").await;
        let backup = dir.path().join("backups/uwulock-1.db");
        store.backup_to(&backup).await.unwrap();
        store
            .sqlite_write(|tx| tx.execute("UPDATE server SET value = 'after' WHERE key = 'marker'", []))
            .await
            .unwrap();
        drop(store);

        let database = dir.path().join("uwulock.db");
        let aside = dir.path().join("uwulock.db.before-restore");
        restore(&backup, &database, &aside).unwrap();

        let store = Store::open_sqlite(&database, &Options { readers: 1 }).unwrap();
        assert_eq!(marker(&store).await, "before");
        let kept = Store::open_sqlite(&aside, &Options { readers: 1 }).unwrap();
        assert_eq!(marker(&kept).await, "after");
    }

    #[tokio::test]
    async fn not_under_a_running_server() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(dir.path(), "x").await;
        let backup = dir.path().join("backup.db");
        store.backup_to(&backup).await.unwrap();
        let error = restore(&backup, &dir.path().join("uwulock.db"), &dir.path().join("aside.db")).unwrap_err();
        assert!(error.contains("in use"), "{error}");
        assert_eq!(marker(&store).await, "x");
    }

    #[test]
    fn only_a_database_of_ours() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("other.db");
        Connection::open(&other).unwrap().execute_batch("CREATE TABLE t (x); PRAGMA user_version = 1;").unwrap();
        let error = restore(&other, &dir.path().join("uwulock.db"), &dir.path().join("aside.db")).unwrap_err();
        assert!(error.contains("not a UwULock Server database"), "{error}");

        let text = dir.path().join("notes.txt");
        std::fs::write(&text, "hello").unwrap();
        assert!(restore(&text, &dir.path().join("uwulock.db"), &dir.path().join("aside.db")).is_err());
    }
}
