//! The command line of the off-site backups: putting a snapshot back on a new machine, where
//! there is no server yet and so no settings, only what the admin types and the environment.

use std::path::Path;

use uwulock_backup::{FolderTarget, Login, Manifest, RepoKey, Repository, S3Target, SftpTarget, Storage, Target};

/// `user@host:path` with the key or the password to log in with.
pub fn sftp_target(
    spec: &str,
    port: u16,
    private_key: Option<String>,
    password: Option<String>,
    host_key: Option<String>,
) -> Result<Target, String> {
    let (user, rest) = spec.split_once('@').ok_or("--sftp is user@host:path")?;
    let (host, path) = rest.split_once(':').unwrap_or((rest, ""));
    let login = match (private_key, password) {
        (Some(private_key), _) => Login::Key { private_key },
        (None, Some(password)) => Login::Password { password },
        (None, None) => return Err("--sftp needs --ssh-key or UWULOCK_BACKUP_SFTP_PASSWORD".into()),
    };
    Ok(Target::Sftp(SftpTarget { host: host.into(), port, user: user.into(), path: path.into(), login, host_key }))
}

/// `s3://bucket/folder` at an endpoint.
pub fn s3_target(
    spec: &str,
    endpoint: &str,
    region: &str,
    access_key: String,
    secret_key: String,
    path_style: bool,
) -> Result<Target, String> {
    let rest = spec.strip_prefix("s3://").ok_or("--s3 is s3://bucket/folder")?;
    let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
    Ok(Target::S3(S3Target {
        endpoint: endpoint.into(),
        region: region.into(),
        bucket: bucket.into(),
        prefix: prefix.into(),
        access_key,
        secret_key,
        path_style,
    }))
}

pub fn folder_target(folder: &Path) -> Target {
    Target::Folder(FolderTarget { path: folder.display().to_string() })
}

/// A line from the terminal, with nothing echoed back (SV-L30); `None` for an empty one. Not
/// from a terminal (a pipe), the line as it comes.
pub fn ask(prompt: &str) -> Result<Option<String>, String> {
    use std::io::{BufRead, IsTerminal, Write};
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        let mut line = String::new();
        stdin.lock().read_line(&mut line).map_err(|error| error.to_string())?;
        return Ok(Some(line.trim().to_string()).filter(|line| !line.is_empty()));
    }
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let _quiet = Quiet::new();
    let mut line = String::new();
    let read = stdin.lock().read_line(&mut line).map_err(|error| error.to_string());
    eprintln!();
    read?;
    Ok(Some(line.trim().to_string()).filter(|line| !line.is_empty()))
}

/// Yes or no from the terminal; no when stdin is not one.
pub fn confirm(prompt: &str) -> Result<bool, String> {
    use std::io::{BufRead, IsTerminal, Write};
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Ok(false);
    }
    eprint!("{prompt} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    stdin.lock().read_line(&mut line).map_err(|error| error.to_string())?;
    Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes" | "j" | "ja"))
}

/// The terminal's echo off while this lives.
struct Quiet {
    #[cfg(unix)]
    before: Option<libc::termios>,
}

impl Quiet {
    fn new() -> Self {
        #[cfg(unix)]
        {
            // SAFETY: tcgetattr and tcsetattr on stdin with a termios this function owns.
            unsafe {
                let mut now: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(libc::STDIN_FILENO, &mut now) != 0 {
                    return Quiet { before: None };
                }
                let before = now;
                now.c_lflag &= !libc::ECHO;
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &now);
                Quiet { before: Some(before) }
            }
        }
        #[cfg(not(unix))]
        Quiet {}
    }
}

impl Drop for Quiet {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(before) = self.before {
            // SAFETY: puts back what `new` read.
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &before);
            }
        }
    }
}

async fn open(target: &Target, key: Option<&str>) -> Result<Repository, String> {
    let given = key.is_some();
    let key = key.map(RepoKey::from_recovery_text).transpose().map_err(|error| error.to_string())?;
    // An SFTP server is asked only for its host key until `--host-key` confirms it (SV-L27).
    let storage = Storage::open(target).await.map_err(opening)?;
    Repository::open_existing(storage, key).await.map_err(|error| match error {
        uwulock_backup::Error::WrongKey if !given => no_key().into(),
        other => other.to_string(),
    })
}

/// What went wrong reaching the backup server, said for the command line.
fn opening(error: uwulock_backup::Error) -> String {
    match error {
        uwulock_backup::Error::HostKeyUnconfirmed { seen } => format!(
            "The backup server shows the host key {seen}. Check it (on the server: \
             ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub) and run again with --host-key {seen}"
        ),
        // Unlike the portal, the command line remembers no key to forget: it trusts the one
        // given with --host-key, so the advice is to give the other one.
        uwulock_backup::Error::HostKeyChanged { expected, seen } => format!(
            "The backup server shows the host key {seen}, not {expected} as given with --host-key; \
             nothing was sent to it. Check it (on the server: ssh-keygen -lf \
             /etc/ssh/ssh_host_ed25519_key.pub); if {seen} is right, run again with --host-key {seen}"
        ),
        other => other.to_string(),
    }
}

/// An encrypted backup, and no recovery key: not a wrong one, none at all.
fn no_key() -> &'static str {
    "This backup is encrypted, and no recovery key was given. Set UWULOCK_BACKUP_KEY \
     (docker compose run --rm -e UWULOCK_BACKUP_KEY uwulock backup restore …, with the key in \
     UWULOCK_BACKUP_KEY of the shell), or run the command in a terminal to be asked for it."
}

/// The snapshots there, newest first.
pub async fn list(target: &Target, key: Option<&str>) -> Result<Vec<Manifest>, String> {
    let repo = open(target, key).await?;
    let listing = repo.listing().await.map_err(|error| error.to_string());
    repo.storage.close().await;
    listing
}

/// Puts a snapshot (the newest without one) into `into`, which holds no server yet, and
/// switches the off-site backups off there: the snapshot carries the old machine's target, and
/// the new one should not write over its history until the admin says so.
pub async fn restore(
    target: &Target,
    key: Option<&str>,
    snapshot: Option<&str>,
    into: &Path,
) -> Result<Manifest, String> {
    let repo = open(target, key).await?;
    let restored = async {
        let name = match snapshot {
            Some(name) => name.to_string(),
            None => repo
                .snapshots()
                .await
                .map_err(|error| error.to_string())?
                .pop()
                .ok_or("There are no snapshots there.")?,
        };
        uwulock_backup::restore_into(&repo, &name, into).await.map_err(|error| error.to_string())
    }
    .await;
    repo.storage.close().await;
    let manifest = restored?;
    switch_off_offsite(into, &manifest).await?;
    Ok(manifest)
}

/// The database is closed again when this returns.
async fn switch_off_offsite(into: &Path, manifest: &Manifest) -> Result<(), String> {
    let store = uwulock_store::Store::open_sqlite(&into.join("uwulock.db"), &uwulock_store::Options { readers: 1 })
        .map_err(|error| error.to_string())?;
    let offsite = uwulock_backup::Offsite::new(store, into, &manifest.hostname, &manifest.version);
    let mut settings = offsite.settings().await.map_err(|error| error.to_string())?;
    settings.enabled = false;
    settings.enabled_since = None;
    offsite.save_settings(&settings).await.map_err(|error| error.to_string())
}

/// `1.4 MB`.
pub fn size(bytes: u64) -> String {
    match bytes {
        0..1_000 => format!("{bytes} B"),
        1_000..1_000_000 => format!("{:.1} kB", bytes as f64 / 1e3),
        1_000_000..1_000_000_000 => format!("{:.1} MB", bytes as f64 / 1e6),
        _ => format!("{:.1} GB", bytes as f64 / 1e9),
    }
}

pub fn print_snapshots(snapshots: &[Manifest]) {
    if snapshots.is_empty() {
        println!("No snapshots there yet.");
    }
    for manifest in snapshots {
        let when = time::OffsetDateTime::from_unix_timestamp(manifest.created_at)
            .map(uwulock_store::clock::format)
            .unwrap_or_default();
        println!(
            "{}  {}  {:>9}  UwULock Server {}  {}",
            manifest.name,
            &when[..when.len().min(19)],
            size(manifest.database_size + manifest.files_size),
            manifest.version,
            manifest.hostname
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uwulock_backup::{Offsite, OffsiteSettings};
    use uwulock_store::{Options, Store};

    #[tokio::test]
    async fn a_new_machine_gets_the_newest_snapshot_with_its_backups_switched_off() {
        let old = tempfile::tempdir().unwrap();
        let store = Store::open_sqlite(&old.path().join("uwulock.db"), &Options { readers: 1 }).unwrap();
        std::fs::create_dir_all(old.path().join("sends/s1")).unwrap();
        std::fs::write(old.path().join("sends/s1/f1"), b"a send's file").unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = folder_target(outside.path());
        let offsite = Offsite::new(store.clone(), old.path(), "lock.example.com", "0.6.0");
        let key = RepoKey::generate().recovery_text();
        let settings = OffsiteSettings {
            enabled: true,
            target: Some(target.clone()),
            key: Some(key.clone()),
            ..Default::default()
        };
        offsite.save_settings(&settings).await.unwrap();
        // Switched on by `UWULOCK_FEATURES` only: not in the environment of the new machine.
        uwulock_api::Features::remember_start(&store, Some(&uwulock_api::Features::all())).await.unwrap();
        let report = offsite.run_now().await.unwrap();

        let error = restore(&target, None, None, &tempfile::tempdir().unwrap().path().join("x")).await.unwrap_err();
        assert!(error.contains("no recovery key was given") && error.contains("UWULOCK_BACKUP_KEY"), "{error}");
        let listed = list(&target, Some(&key)).await.unwrap();
        assert_eq!(listed[0].name, report.snapshot);
        let new = tempfile::tempdir().unwrap();
        let manifest = restore(&target, Some(&key.to_lowercase()), None, new.path()).await.unwrap();
        assert_eq!(manifest.name, report.snapshot);
        assert_eq!(std::fs::read(new.path().join("sends/s1/f1")).unwrap(), b"a send's file");
        let mut left: Vec<String> = std::fs::read_dir(new.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["secret.key", "sends", "uwulock.db"], "no backup-tmp, no -wal or -shm");
        let restored = Store::open_sqlite(&new.path().join("uwulock.db"), &Options { readers: 1 }).unwrap();
        let features = uwulock_api::Features::load(&restored, None).await.unwrap();
        assert_eq!(features, uwulock_api::Features::all(), "the switches came along");
        let settings = Offsite::new(restored, new.path(), "", "").settings().await.unwrap();
        assert!(!settings.enabled && settings.key.as_deref() == Some(key.as_str()), "{settings:?}");
    }

    #[test]
    fn targets_from_the_command_line() {
        let sftp =
            sftp_target("backup@nas.example.com:/volume1/lock", 2222, None, Some("geheim".into()), None).unwrap();
        assert_eq!(sftp.shown(), "sftp://backup@nas.example.com:2222//volume1/lock");
        assert!(sftp_target("nas.example.com", 22, None, Some("x".into()), None).is_err());
        assert!(sftp_target("backup@nas.example.com:x", 22, None, None, None).is_err(), "no way to log in");
        let s3 = s3_target("s3://bucket/lock", "https://s3.example.com", "eu-central-1", "a".into(), "s".into(), true)
            .unwrap();
        assert_eq!(s3.shown(), "s3://bucket/lock at https://s3.example.com");
        assert_eq!(size(1_500_000), "1.5 MB");
    }

    #[test]
    fn a_changed_host_key_is_answered_with_the_new_one_to_pass() {
        let changed =
            uwulock_backup::Error::HostKeyChanged { expected: "SHA256:old".into(), seen: "SHA256:new".into() };
        let text = opening(changed);
        assert!(text.contains("run again with --host-key SHA256:new") && !text.contains("forget"), "{text}");
        let unconfirmed = opening(uwulock_backup::Error::HostKeyUnconfirmed { seen: "SHA256:new".into() });
        assert!(unconfirmed.contains("--host-key SHA256:new"), "{unconfirmed}");
    }
}
