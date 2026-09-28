use std::path::{Path, PathBuf};

use uwulock_backup::{Repository, Retention, Source};
use uwulock_store::{Options, Store};

/// A server's data directory: a database with something in it, an attachment, a Send's file and
/// a key file.
pub struct Server {
    pub dir: tempfile::TempDir,
    pub store: Store,
}

impl Server {
    pub async fn new() -> Server {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_sqlite(&dir.path().join("uwulock.db"), &Options { readers: 1 }).unwrap();
        store.set_setting("marker", "first").await.unwrap();
        let data = dir.path();
        write(data, "attachments/c1/a1", &[7u8; 300_000]);
        write(data, "sends/s1/f1", b"a send's file");
        write(data, "acme/account.key", b"-----BEGIN PRIVATE KEY-----");
        // Neither the local backups nor scratch space go off-site.
        write(data, "backups/uwulock-2026-01-01-000000.db", b"a local backup");
        Server { dir, store }
    }

    pub fn data(&self) -> &Path {
        self.dir.path()
    }

    pub async fn backup(&self, repo: &Repository, now: i64) -> uwulock_backup::BackupReport {
        let source =
            Source { store: &self.store, data_dir: self.data(), hostname: "lock.example.com", version: "0.6.0" };
        uwulock_backup::backup(&source, repo, Retention::default(), now).await.unwrap()
    }
}

pub fn write(data: &Path, path: &str, content: &[u8]) -> PathBuf {
    let path = data.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, content).unwrap();
    path
}

/// What a restore brought back: the marker in the database, and the files.
pub async fn check_restored(dir: &Path) {
    let store = Store::open_sqlite(&dir.join("uwulock.db"), &Options { readers: 1 }).unwrap();
    assert_eq!(store.setting("marker").await.unwrap().as_deref(), Some("first"));
    assert_eq!(std::fs::read(dir.join("attachments/c1/a1")).unwrap(), vec![7u8; 300_000]);
    assert_eq!(std::fs::read(dir.join("sends/s1/f1")).unwrap(), b"a send's file");
    assert!(dir.join("acme/account.key").exists());
    assert!(!dir.join("backups").exists(), "local backups stay local");
}
