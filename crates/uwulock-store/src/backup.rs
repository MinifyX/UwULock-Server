//! Putting a backup back.

use crate::migrations::SCHEMA_VERSION;
use crate::with_suffix;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::path::Path;
use std::time::Duration;

/// Whether `backup` is one this build can put back: an intact SQLite file, with this server's
/// tables, at a schema it can read.
pub(crate) fn check(backup: &Path) -> Result<(), String> {
    let found = |error: rusqlite::Error| format!("{}: {error}", backup.display());
    let conn = Connection::open_with_flags(backup, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(found)?;
    let check: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| format!("{} is not a database", backup.display()))?;
    if check != "ok" {
        return Err(format!("{} is damaged: {check}", backup.display()));
    }
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0)).map_err(found)?;
    let ours: i64 = conn
        .query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'server'", [], |row| row.get(0))
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
    Ok(())
}

/// A value of the `server` table in `backup`, such as the key that signs access tokens: to tell
/// whether a backup is of this server.
pub fn setting_in(backup: &Path, key: &str) -> Result<Option<String>, String> {
    let conn = Connection::open_with_flags(backup, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| format!("{}: {error}", backup.display()))?;
    conn.query_row("SELECT value FROM server WHERE key = ?1", [key], |row| row.get(0))
        .optional()
        .map_err(|error| format!("{}: {error}", backup.display()))
}

/// Rows of the `server` table that are the server's own keys: the one that signs access tokens.
/// An unencrypted off-site backup leaves them out, so whoever reads the backup cannot forge a
/// login with them; a server restored from one makes a new key, and everybody logs in again.
pub const SERVER_SECRETS: &[&str] = &["token_key"];

/// Removes the server's own keys ([`SERVER_SECRETS`]) from the database copy at `path`, the
/// accounts' API keys (stored as they are, since they are shown again: with one and the account
/// id, the command line logs in without a second step — R1-4), and
/// empties what is sealed with `secret.key` (which stays home too), with the deleted bytes
/// overwritten and the file compacted, so nothing of them stays in free pages.
pub fn forget_secrets_in(path: &Path) -> Result<(), String> {
    let failed = |error: rusqlite::Error| format!("{}: {error}", path.display());
    let conn = Connection::open(path).map_err(failed)?;
    conn.pragma_update(None, "secure_delete", "ON").map_err(failed)?;
    for key in SERVER_SECRETS {
        conn.execute("DELETE FROM server WHERE key = ?1", [key]).map_err(failed)?;
    }
    conn.execute("DELETE FROM api_keys", []).map_err(failed)?;
    crate::admin::empty_sealed(&conn).map_err(failed)?;
    conn.execute_batch("VACUUM").map_err(failed)?;
    Ok(())
}

/// The schema version of the database file at `path`, for an off-site backup's manifest.
pub fn schema_of(path: &Path) -> Result<i64, String> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// End every session in a database that was just put back: a backup carries the tokens and
/// security stamps of its day, and among them ones that were taken back since — a device logged
/// out, a password changed after a theft. Everybody logs in again instead.
pub(crate) fn end_sessions(conn: &Connection) -> rusqlite::Result<()> {
    let has_accounts: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'devices')",
        [],
        |row| row.get(0),
    )?;
    if has_accounts {
        conn.execute_batch(
            "UPDATE users SET security_stamp = lower(hex(randomblob(16))); \
             UPDATE devices SET refresh_hash = NULL, refresh_expires = NULL, remember_hash = NULL;",
            // Only the hash: a backup from before 0027 calls the time beside it differently, and
            // without the hash no device is remembered.
        )?;
    }
    // Every delta-sync cursor from before starts over (docs/uwu-api.md §4.3). A backup from
    // before 0012 gets its epoch from that step.
    conn.execute("UPDATE server SET value = lower(hex(randomblob(8))) WHERE key = 'sync_epoch'", [])?;
    Ok(())
}

/// Put `backup` in place of the database at `database`, keeping what was there at `aside`.
///
/// The backup is checked first: an intact SQLite file, with this server's tables, at a schema
/// this build can read. And the database must not be in use — a server still writing to it would
/// lose everything after the backup, or worse, write its log into the file that replaced it.
/// Leaving WAL mode needs the only connection there is, which makes it the test, and it folds the
/// log into the file on the way, so nothing of it is left lying next to the backup either.
pub fn restore(backup: &Path, database: &Path, aside: &Path) -> Result<(), String> {
    check(backup)?;

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
        .and_then(|conn| conn.execute("VACUUM INTO ?1", [incoming.to_string_lossy().as_ref()]).map(drop))
        .and_then(|()| end_sessions(&Connection::open(&incoming)?));
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

    /// A user logged in on one device: their security stamp, and whether the device still has
    /// a refresh token.
    async fn session(store: &Store) -> (String, bool) {
        store
            .sqlite_read(|conn| {
                conn.query_row(
                    "SELECT u.security_stamp, d.refresh_hash IS NOT NULL FROM users u JOIN devices d ON d.user_id = u.id",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
            })
            .await
            .unwrap()
    }

    async fn log_in(store: &Store) {
        let user = store.create_user(crate::accounts::tests::new_user("nyu@example.com")).await.unwrap();
        store
            .log_in_device(crate::DeviceLogin {
                user_id: user.id,
                id: "d".into(),
                name: "d".into(),
                kind: 9,
                ip: None,
                refresh_hash: vec![1; 32],
                refresh_expires: "2999-01-01T00:00:00.000000Z".into(),
                remember: None,
                sso: false,
                client_id: None,
            })
            .await
            .unwrap();
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
        log_in(&store).await;
        let (stamp, _) = session(&store).await;
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
        let (after, logged_in) = session(&store).await;
        assert!(after != stamp && !logged_in, "everybody logs in again");
        let kept = Store::open_sqlite(&aside, &Options { readers: 1 }).unwrap();
        assert_eq!(marker(&kept).await, "after");
    }

    #[tokio::test]
    async fn a_copy_without_secrets_has_no_api_keys() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(dir.path(), "x").await;
        let user = store.create_user(crate::accounts::tests::new_user("nyu@example.com")).await.unwrap();
        store.api_key(&user.id, "the api key".into()).await.unwrap();
        let copy = dir.path().join("copy.db");
        store.backup_to(&copy).await.unwrap();
        forget_secrets_in(&copy).unwrap();
        let bytes = std::fs::read(&copy).unwrap();
        assert!(!bytes.windows(11).any(|window| window == b"the api key"), "R1-4");
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

    #[tokio::test]
    async fn a_backup_goes_back_under_a_running_server() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(dir.path(), "before").await;
        log_in(&store).await;
        let (stamp, _) = session(&store).await;
        let backup = dir.path().join("backups/uwulock-1.db");
        store.backup_to(&backup).await.unwrap();
        store
            .sqlite_write(|tx| tx.execute("UPDATE server SET value = 'after' WHERE key = 'marker'", []))
            .await
            .unwrap();
        assert_eq!(marker(&store).await, "after");
        store.restore_online(&backup).await.unwrap();
        assert_eq!(marker(&store).await, "before", "the readers see it at once");
        let (after, logged_in) = session(&store).await;
        assert!(after != stamp && !logged_in, "everybody logs in again");
        store
            .sqlite_write(|tx| tx.execute("UPDATE server SET value = 'later' WHERE key = 'marker'", []))
            .await
            .unwrap();
        assert_eq!(marker(&store).await, "later", "and it goes on writing");

        std::fs::write(dir.path().join("not-a-backup.db"), b"nonsense").unwrap();
        assert!(store.restore_online(&dir.path().join("not-a-backup.db")).await.is_err());
        assert_eq!(marker(&store).await, "later");
    }
}
