use uwulock_backup::{Error, FolderTarget, RepoKey, Repository, Retention, Storage, Target};

use crate::support::*;

async fn open(dir: &std::path::Path, key: Option<RepoKey>) -> Repository {
    let storage = Storage::open(&Target::Folder(FolderTarget { path: dir.display().to_string() })).await.unwrap();
    Repository::open(storage, key, 1).await.unwrap()
}

#[tokio::test]
async fn a_backup_goes_to_a_folder_and_comes_back() {
    let server = Server::new().await;
    let target = tempfile::tempdir().unwrap();
    let key = RepoKey::generate();
    let repo = open(target.path(), Some(key.clone())).await;
    let first = server.backup(&repo, 1_000).await;
    assert!(first.uploaded > 0);
    assert!(uwulock_backup::check(&repo, &first.snapshot).await.unwrap().is_empty());

    // Nothing changed: nothing but the manifest goes up, and the files are not read again.
    let second = server.backup(&repo, 90_000).await;
    assert!(second.uploaded < first.uploaded / 4, "{} after {}", second.uploaded, first.uploaded);
    let manifest = repo.manifest(&second.snapshot).await.unwrap();
    assert_eq!(manifest.hostname, "lock.example.com");
    assert!(manifest.files.iter().all(|file| !file.path.starts_with("backups")), "{:?}", manifest.files);
    assert_eq!(repo.snapshots().await.unwrap().len(), 2);

    // Nothing in the folder gives away what it holds.
    for entry in walk(target.path()) {
        let bytes = std::fs::read(&entry).unwrap();
        assert!(!bytes.windows(13).any(|window| window == b"a send's file"), "{}", entry.display());
    }

    // A new machine: an empty data directory.
    let new = tempfile::tempdir().unwrap();
    let again = open(target.path(), Some(key)).await;
    uwulock_backup::restore_into(&again, &first.snapshot, new.path()).await.unwrap();
    check_restored(new.path()).await;
    let error = uwulock_backup::restore_into(&again, &first.snapshot, new.path()).await.unwrap_err();
    assert!(error.to_string().contains("already holds a server"), "{error}");

    // The wrong key, or none, opens nothing.
    let storage =
        Storage::open(&Target::Folder(FolderTarget { path: target.path().display().to_string() })).await.unwrap();
    assert_eq!(Repository::is_encrypted(&storage).await.unwrap(), Some(true));
    assert!(matches!(Repository::open_existing(storage, Some(RepoKey::generate())).await, Err(Error::WrongKey)));
}

/// An unencrypted backup leaves out the server's own keys: whoever reads the folder must not be
/// able to forge a login, or open the secrets the server keeps for talking to others.
#[tokio::test]
async fn an_unencrypted_backup_leaves_the_server_keys_out() {
    let server = Server::new().await;
    server.store.set_setting("token_key", "the signing key").await.unwrap();
    write(server.data(), "secret.key", b"thirty-two bytes of server key..");
    let target = tempfile::tempdir().unwrap();
    let repo = open(target.path(), None).await;
    let done = server.backup(&repo, 1_000).await;
    let manifest = repo.manifest(&done.snapshot).await.unwrap();
    let paths: Vec<&str> = manifest.files.iter().map(|file| file.path.as_str()).collect();
    assert!(paths.contains(&"attachments/c1/a1"), "{paths:?}");
    assert!(!paths.iter().any(|path| *path == "secret.key" || path.starts_with("acme/")), "{paths:?}");
    for entry in walk(target.path()) {
        let bytes = std::fs::read(&entry).unwrap();
        assert!(!bytes.windows(15).any(|window| window == b"the signing key"), "{}", entry.display());
    }
    let new = tempfile::tempdir().unwrap();
    uwulock_backup::restore_into(&repo, &done.snapshot, new.path()).await.unwrap();
    let store =
        uwulock_store::Store::open_sqlite(&new.path().join("uwulock.db"), &uwulock_store::Options { readers: 1 })
            .unwrap();
    assert_eq!(store.setting("marker").await.unwrap().as_deref(), Some("first"));
    assert_eq!(store.setting("token_key").await.unwrap(), None);

    // Encrypted, they go along.
    let sealed = tempfile::tempdir().unwrap();
    let repo = open(sealed.path(), Some(RepoKey::generate())).await;
    let done = server.backup(&repo, 1_000).await;
    let manifest = repo.manifest(&done.snapshot).await.unwrap();
    assert!(manifest.files.iter().any(|file| file.path == "secret.key"));
}

#[tokio::test]
async fn old_snapshots_go_and_take_what_only_they_needed() {
    let server = Server::new().await;
    let target = tempfile::tempdir().unwrap();
    let repo = open(target.path(), None).await;
    let day = 86_400;
    let first = server.backup(&repo, 20_000 * day).await;
    write(server.data(), "attachments/c1/a1", &[9u8; 300_000]);
    for n in 1..10 {
        server.backup(&repo, (20_000 + n) * day).await;
    }
    let names = repo.snapshots().await.unwrap();
    assert!(!names.contains(&first.snapshot), "a week of days, and the first was not the newest of its week");
    let (_, removed) = uwulock_backup::prune(&repo, Retention::default()).await.unwrap();
    assert_eq!(removed, 0, "the backups pruned already");
    let newest = repo.manifest(names.last().unwrap()).await.unwrap();
    assert!(uwulock_backup::check(&repo, &newest.name).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_damaged_or_foreign_snapshot_is_refused() {
    let server = Server::new().await;
    let target = tempfile::tempdir().unwrap();
    let repo = open(target.path(), Some(RepoKey::generate())).await;
    let report = server.backup(&repo, 1_000).await;
    // A manifest put under another snapshot's name.
    let other = "000000009999-abcdef";
    std::fs::copy(target.path().join("snapshots").join(&report.snapshot), target.path().join("snapshots").join(other))
        .unwrap();
    assert!(matches!(repo.manifest(other).await, Err(Error::Damaged(_))));
    // An object swapped for another.
    let manifest = repo.manifest(&report.snapshot).await.unwrap();
    let (a, b) = (&manifest.database[0], &manifest.files[0].chunks[0]);
    let path = |id: &String| target.path().join("data").join(&id[..2]).join(id);
    std::fs::copy(path(b), path(a)).unwrap();
    let new = tempfile::tempdir().unwrap();
    let error = uwulock_backup::restore_into(&repo, &report.snapshot, new.path()).await.unwrap_err();
    assert!(matches!(error, Error::Damaged(_)), "{error}");
    assert!(!new.path().join("uwulock.db").exists());
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        if entry.file_type().unwrap().is_dir() {
            found.extend(walk(&entry.path()));
        } else {
            found.push(entry.path());
        }
    }
    found
}

/// A run that goes on and on is stopped at its deadline, and lets go of the lock that restores
/// and the next nightly run need (review finding M2).
#[tokio::test]
async fn a_run_past_its_deadline_is_stopped() {
    let server = Server::new().await;
    let target = tempfile::tempdir().unwrap();
    let offsite =
        uwulock_backup::Offsite::with_deadline(server.store.clone(), server.data(), std::time::Duration::ZERO);
    let settings = uwulock_backup::OffsiteSettings {
        enabled: true,
        target: Some(Target::Folder(FolderTarget { path: target.path().display().to_string() })),
        key: Some(RepoKey::generate().recovery_text()),
        ..Default::default()
    };
    offsite.save_settings(&settings).await.unwrap();
    let error = offsite.run_now().await.unwrap_err();
    assert!(error.to_string().contains("was stopped"), "{error}");
    assert!(!offsite.is_running());
    assert!(offsite.status().await.last_error.unwrap().contains("was stopped"));
    let again = offsite.run_now().await.unwrap_err();
    assert!(!matches!(again, Error::Busy(_)), "the lock is free again: {again}");
}
