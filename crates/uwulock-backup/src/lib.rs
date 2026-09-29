//! Off-site backups of a UwULock server: the database and the files of the data directory
//! (attachments, Send files, file-request uploads, certificates and keys), deduplicated
//! and (by default) encrypted, on an SFTP server, in an S3 bucket or in a folder of this machine.
//!
//! The design and the repository format are UwUMail Server's (`docs/backups.md` there). The
//! first backup uploads everything; later ones only what is new. The database copy and every
//! file are cut into content-defined chunks, so a day of changes touches only a few of them, and
//! a file that did not change (same size, same time) is not even read again. Old snapshots go by
//! the retention rules, and objects no snapshot needs any more go with them.

mod folder;
pub mod format;
pub mod retention;
pub mod s3;
pub mod service;
pub mod sftp;
pub mod storage;
pub mod target;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Serialize;
use uwulock_store::Store;

pub use format::{Codec, FileEntry, Manifest, RepoConfig, RepoKey};
pub use retention::Retention;
pub use service::{Offsite, OffsiteSettings, OffsiteStatus};
pub use sftp::{Login, SftpTarget};
pub use storage::Storage;
pub use target::{FolderTarget, S3Target, Target};

use crate::format::{CONFIG_PATH, checked_id, is_snapshot_name, object_path};

const CHUNK_MIN: usize = 16 * 1024;
const CHUNK_AVG: usize = 64 * 1024;
const CHUNK_MAX: usize = 256 * 1024;
/// Where a backup makes its copy of the database, and a restore fetches one, in the data directory.
pub const TEMP_DIR: &str = "backup-tmp";

// What this server reads from a backup server at most. The backup server decides how big its
// files are, and one that is not ours must not be able to have this server read, or inflate,
// all the memory there is.
/// `uwulock-backup.json` is a few lines.
const CONFIG_MAX: u64 = 64 * 1024;
/// A manifest names every chunk, about 67 bytes each: this is room for terabytes.
const MANIFEST_MAX: u64 = 256 * 1024 * 1024;
/// What an object adds to its content: the header, the nonce and the tag.
const OBJECT_OVERHEAD: u64 = 64;
/// Names one listing may bring, and their bytes together: a server that says "there is more"
/// for ever could otherwise fill the memory at every backup. A repository of a terabyte in
/// 64 KiB chunks has about 16 million objects over 256 folders, some 65,000 each.
pub(crate) const MAX_LISTED_NAMES: usize = 2_000_000;
pub(crate) const MAX_LISTED_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the recovery key does not fit this backup")]
    WrongKey,
    #[error("the backup is damaged: {0}")]
    Damaged(String),
    #[error("encryption failed")]
    Crypto,
    #[error("{0}")]
    Storage(String),
    #[error("the backup server refused the login for {0}")]
    LoginRefused(String),
    #[error("the backup server's host key changed from {expected} to {seen}; if that is expected, forget the old key")]
    HostKeyChanged { expected: String, seen: String },
    #[error("{0}")]
    Config(String),
    /// Something else has the backup server right now: a backup, a restore. Try again later.
    #[error("{0}")]
    Busy(String),
    #[error("file error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Store(#[from] uwulock_store::StoreError),
}

impl Error {
    /// A short text of our own for the alerts: what kind of thing went wrong, with the storage
    /// server's status or S3 error code, but none of its words (a hostile storage server would
    /// otherwise write to the admins). The whole error goes to the log and the portal.
    pub fn summary(&self) -> String {
        match self {
            Error::Storage(text) => match answered(text) {
                Some(code) => format!("the backup server answered {code}"),
                None => "the backup server could not be reached or did not work".into(),
            },
            Error::Damaged(_) => "the backup is damaged".into(),
            Error::Io(_) => "a file error on this server".into(),
            Error::Store(_) => "a database error on this server".into(),
            Error::LoginRefused(_) => "the backup server refused the login".into(),
            Error::HostKeyChanged { .. } => "the backup server's host key changed".into(),
            // Our own words, without anything from the storage server.
            Error::WrongKey | Error::Crypto | Error::Config(_) | Error::Busy(_) => self.to_string(),
        }
    }
}

/// The status or S3 error code after "answered " in a storage error, when it looks like one.
fn answered(text: &str) -> Option<&str> {
    let (_, rest) = text.split_once(" answered ")?;
    let word = rest.split([' ', ':']).next()?;
    let status = word.len() == 3 && word.bytes().all(|byte| byte.is_ascii_digit());
    let code = (1..=40).contains(&word.len()) && word.bytes().all(|byte| byte.is_ascii_alphabetic());
    (status || code).then_some(word)
}

/// An opened repository.
pub struct Repository {
    pub storage: Storage,
    pub codec: Codec,
    pub config: RepoConfig,
}

impl Repository {
    /// Opens the repository at the storage, creating it when there is none yet. `key` is needed
    /// for encrypted ones; a new repository is encrypted exactly when a key is given.
    pub async fn open(storage: Storage, key: Option<RepoKey>, now: i64) -> Result<Repository, Error> {
        Self::open_with(storage, key, Some(now)).await
    }

    /// Opens a repository that must exist already, e.g. for a restore.
    pub async fn open_existing(storage: Storage, key: Option<RepoKey>) -> Result<Repository, Error> {
        Self::open_with(storage, key, None).await
    }

    /// Whether the repository at the storage is encrypted, without needing the key. `None` when
    /// there is none.
    pub async fn is_encrypted(storage: &Storage) -> Result<Option<bool>, Error> {
        let Some(bytes) = storage.read(CONFIG_PATH, CONFIG_MAX).await? else { return Ok(None) };
        let config: RepoConfig = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Damaged(format!("{CONFIG_PATH} is not a UwULock backup")))?;
        Ok(Some(config.encrypted))
    }

    async fn open_with(storage: Storage, key: Option<RepoKey>, create_at: Option<i64>) -> Result<Repository, Error> {
        let config = match storage.read(CONFIG_PATH, CONFIG_MAX).await? {
            Some(bytes) => serde_json::from_slice::<RepoConfig>(&bytes)
                .map_err(|_| Error::Damaged(format!("{CONFIG_PATH} is not a UwULock backup")))?,
            None => {
                let Some(now) = create_at else {
                    return Err(Error::Config("there is no UwULock backup there".into()));
                };
                let config = Codec::config_for(key.as_ref(), now);
                storage.write(CONFIG_PATH, &serde_json::to_vec_pretty(&config).expect("config serializes")).await?;
                config
            }
        };
        if config.format > format::FORMAT {
            return Err(Error::Config("this backup was written by a newer UwULock Server".into()));
        }
        let codec = Codec::new(&config, key)?;
        Ok(Repository { storage, codec, config })
    }

    /// Ids of every object in the repository. A name that is not one is left alone with a
    /// warning: the listing comes from the backup server, and nothing it says reaches a path
    /// unchecked.
    async fn object_ids(&self) -> Result<HashSet<String>, Error> {
        let mut ids = HashSet::new();
        for prefix in self.storage.list("data").await? {
            if prefix.len() != 2 || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                tracing::warn!(name = %prefix.escape_debug(), "the backup server lists something in data/ that is not ours");
                continue;
            }
            for id in self.storage.list(&format!("data/{prefix}")).await? {
                if checked_id(&id).is_err() || !id.starts_with(&prefix) {
                    tracing::warn!(name = %id.escape_debug(), "the backup server lists something in data/ that is not an object");
                    continue;
                }
                ids.insert(id);
            }
        }
        Ok(ids)
    }

    /// Stores content unless the repository has it already; returns its id and the bytes uploaded.
    async fn put(&self, content: &[u8], known: &mut HashSet<String>) -> Result<(String, u64), Error> {
        let id = self.codec.id_for(content);
        if known.contains(&id) {
            return Ok((id, 0));
        }
        let object = self.codec.encode(content)?;
        self.storage.write(&object_path(&id)?, &object).await?;
        known.insert(id.clone());
        Ok((id, object.len() as u64))
    }

    /// An object's content, which may be at most `limit` bytes long.
    async fn get(&self, id: &str, limit: u64) -> Result<Vec<u8>, Error> {
        let object = self
            .storage
            .read(&object_path(id)?, limit.saturating_add(OBJECT_OVERHEAD))
            .await?
            .ok_or_else(|| Error::Damaged(format!("the object {id} is missing")))?;
        let content = self.codec.decode(&object, limit)?;
        // The id comes from the content, keyed in an encrypted repository. Recomputing it is what
        // ties an object to its name: the authentication tag alone proves only that this server
        // wrote it, and an authentic object moved to another id's path would pass that.
        if self.codec.id_for(&content) != id {
            return Err(Error::Damaged(format!("the object {id} does not match its content")));
        }
        Ok(content)
    }

    /// Snapshot names, oldest first. Only names this server gives count.
    pub async fn snapshots(&self) -> Result<Vec<String>, Error> {
        let mut names = self.storage.list("snapshots").await?;
        names.retain(|name| is_snapshot_name(name));
        names.sort();
        Ok(names)
    }

    pub async fn manifest(&self, name: &str) -> Result<Manifest, Error> {
        let missing = || Error::Config(format!("there is no snapshot {}", name.escape_debug()));
        if !is_snapshot_name(name) {
            return Err(missing());
        }
        let object = self.storage.read(&format!("snapshots/{name}"), MANIFEST_MAX).await?.ok_or_else(missing)?;
        let manifest: Manifest = serde_json::from_slice(&self.codec.decode(&object, MANIFEST_MAX)?)
            .map_err(|_| Error::Damaged(format!("the snapshot {name} cannot be read")))?;
        // A manifest names itself inside what the key seals, so an authentic one cannot stand in
        // for another.
        if manifest.name != name {
            return Err(Error::Damaged(format!("the snapshot {name} holds another snapshot")));
        }
        Ok(manifest)
    }

    /// The snapshots with what they hold, newest first.
    pub async fn listing(&self) -> Result<Vec<Manifest>, Error> {
        let mut found = Vec::new();
        for name in self.snapshots().await?.into_iter().rev() {
            found.push(self.manifest(&name).await?);
        }
        Ok(found)
    }
}

/// What a backup did.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackupReport {
    pub snapshot: String,
    pub uploaded: u64,
    pub total: u64,
    pub removed_snapshots: usize,
    pub removed_objects: usize,
}

fn random_suffix() -> String {
    format::hex(&format::random::<3>().expect("the system random generator works"))
}

/// Whether a name at the top of the data directory is the server's own business rather than
/// part of a backup: the database and its journal, the local backups, scratch space, and the
/// icons fetched from websites and the icon library, which are fetched again (own icons are in
/// the database).
fn left_out(name: &str) -> bool {
    name.starts_with("uwulock.db") || name == "backups" || name == "icons" || name == TEMP_DIR
}

/// What an unencrypted backup leaves out besides: the server's own keys, which whoever reads the
/// backup must not get. `secret.key` opens the secrets the server keeps for talking to others
/// (an OpenID Connect client secret, UwUMail tokens); `acme` holds the Let's Encrypt account and
/// certificate keys, which a restored server fetches anew.
fn secret(name: &str) -> bool {
    name == "secret.key" || name == "acme"
}

/// The files of the data directory a backup carries, with their sizes and times. Symbolic links
/// and anything else that is not a plain file are left out, and for an unencrypted backup the
/// server's own keys.
fn data_files(data_dir: &Path, plain: bool) -> Vec<(String, PathBuf, u64, i64)> {
    let mut found = Vec::new();
    let mut pending = vec![(String::new(), data_dir.to_path_buf())];
    while let Some((prefix, dir)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if prefix.is_empty() && (left_out(&name) || (plain && secret(&name))) {
                continue;
            }
            let relative = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else { continue };
            if meta.is_dir() {
                pending.push((relative, entry.path()));
            } else if meta.is_file() {
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |since| since.as_nanos() as i64);
                found.push((relative, entry.path(), meta.len(), modified));
            }
        }
    }
    found.sort();
    found
}

/// Reads a file in content-defined chunks, on a thread of its own, and stores each one. Returns
/// the chunk ids, the file's size and the bytes uploaded.
async fn put_chunked(
    repo: &Repository,
    path: PathBuf,
    known: &mut HashSet<String>,
) -> Result<(Vec<String>, u64, u64), Error> {
    let (sender, mut chunks) = tokio::sync::mpsc::channel::<Result<Vec<u8>, Error>>(2);
    let shown = path.display().to_string();
    let chunker = tokio::task::spawn_blocking(move || {
        let file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(error) => {
                let _ = sender.blocking_send(Err(error.into()));
                return;
            }
        };
        for chunk in fastcdc::v2020::StreamCDC::new(file, CHUNK_MIN, CHUNK_AVG, CHUNK_MAX) {
            let item =
                chunk.map(|chunk| chunk.data).map_err(|error| Error::Storage(format!("reading {shown}: {error}")));
            if sender.blocking_send(item).is_err() {
                return;
            }
        }
    });
    let (mut ids, mut size, mut uploaded) = (Vec::new(), 0, 0);
    while let Some(chunk) = chunks.recv().await {
        let chunk = chunk?;
        size += chunk.len() as u64;
        let (id, bytes) = repo.put(&chunk, known).await?;
        uploaded += bytes;
        ids.push(id);
    }
    chunker.await.map_err(|error| Error::Storage(error.to_string()))?;
    Ok((ids, size, uploaded))
}

/// What a backup is told about the server it backs up.
pub struct Source<'a> {
    pub store: &'a Store,
    pub data_dir: &'a Path,
    /// The server's public host.
    pub hostname: &'a str,
    pub version: &'a str,
}

/// Backs up the server into the repository and applies the retention rules.
pub async fn backup(
    source: &Source<'_>,
    repo: &Repository,
    retention: Retention,
    now: i64,
) -> Result<BackupReport, Error> {
    let mut known = repo.object_ids().await?;
    let mut uploaded = 0;
    // The newest snapshot says which files it had, and how they looked: those that still look
    // the same are not read again.
    let previous: HashMap<String, FileEntry> = match repo.snapshots().await?.last() {
        Some(name) => repo.manifest(name).await?.files.into_iter().map(|file| (file.path.clone(), file)).collect(),
        None => HashMap::new(),
    };

    // The database: a consistent copy, cut into chunks.
    let temp = source.data_dir.join(TEMP_DIR);
    tokio::fs::create_dir_all(&temp).await?;
    let copy = temp.join(format!("backup-{}.db", random_suffix()));
    let _ = tokio::fs::remove_file(&copy).await;
    source.store.backup_to(&copy).await?;
    let plain = !repo.config.encrypted;
    if plain {
        let scrubbed = copy.clone();
        tokio::task::spawn_blocking(move || uwulock_store::forget_secrets_in(&scrubbed))
            .await
            .map_err(|error| Error::Storage(error.to_string()))?
            .map_err(Error::Config)?;
    }
    let schema = uwulock_store::schema_of(&copy).map_err(Error::Config)?;
    let chunked = put_chunked(repo, copy.clone(), &mut known).await;
    let _ = tokio::fs::remove_file(&copy).await;
    let (database, database_size, bytes) = chunked?;
    uploaded += bytes;

    // The files: attachments, Sends, file requests, certificates and keys.
    let mut files = Vec::new();
    let mut files_size = 0;
    for (path, full, size, modified) in data_files(source.data_dir, plain) {
        if let Some(before) = previous.get(&path)
            && before.size == size
            && before.modified == modified
            && modified != 0
            && before.chunks.iter().all(|id| known.contains(id))
        {
            files_size += size;
            files.push(before.clone());
            continue;
        }
        let (chunks, size, bytes) = match put_chunked(repo, full, &mut known).await {
            Ok(done) => done,
            // Removed while the backup ran, like a Send that ran out: not a failure.
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        uploaded += bytes;
        files_size += size;
        files.push(FileEntry { path, chunks, size, modified });
    }

    let name = format!("{now:012}-{}", random_suffix());
    let manifest = Manifest {
        format: format::FORMAT,
        created_at: now,
        hostname: source.hostname.to_owned(),
        version: source.version.to_owned(),
        schema,
        database,
        database_size,
        files,
        files_size,
        uploaded,
        name: name.clone(),
    };
    let encoded = repo.codec.encode(&serde_json::to_vec(&manifest).expect("manifests serialize"))?;
    repo.storage.write(&format!("snapshots/{name}"), &encoded).await?;

    let (removed_snapshots, removed_objects) = prune(repo, retention).await?;
    Ok(BackupReport { snapshot: name, uploaded, total: database_size + files_size, removed_snapshots, removed_objects })
}

/// Removes snapshots the retention rules let go, then objects no snapshot needs.
pub async fn prune(repo: &Repository, retention: Retention) -> Result<(usize, usize), Error> {
    let names = repo.snapshots().await?;
    let mut manifests = Vec::new();
    for name in &names {
        manifests.push((name.clone(), repo.manifest(name).await?));
    }
    let times: Vec<i64> = manifests.iter().map(|(_, manifest)| manifest.created_at).collect();
    let kept = retention::keep(&times, retention);
    let mut removed_snapshots = 0;
    let mut needed = HashSet::new();
    for (index, (name, manifest)) in manifests.iter().enumerate() {
        if kept.contains(&index) {
            needed.extend(manifest.objects().cloned());
        } else {
            repo.storage.remove(&format!("snapshots/{name}")).await?;
            removed_snapshots += 1;
        }
    }
    let mut removed_objects = 0;
    if !manifests.is_empty() {
        for id in repo.object_ids().await? {
            if !needed.contains(&id) {
                repo.storage.remove(&object_path(&id)?).await?;
                removed_objects += 1;
            }
        }
    }
    Ok((removed_snapshots, removed_objects))
}

/// Whether this build can put a snapshot back: migrations only ever run forwards.
pub fn fits_this_server(manifest: &Manifest) -> Result<(), Error> {
    if manifest.format > format::FORMAT {
        return Err(Error::Config(format!(
            "this snapshot is written in backup format {}, and this server knows {}",
            manifest.format,
            format::FORMAT
        )));
    }
    if manifest.schema > uwulock_store::SCHEMA_VERSION {
        return Err(Error::Config(format!(
            "this snapshot comes from UwULock Server {}, which is newer than this one; restore it with {} or newer",
            manifest.version, manifest.version
        )));
    }
    Ok(())
}

/// Puts a snapshot's database together from its chunks at `path`.
pub async fn fetch_database(repo: &Repository, manifest: &Manifest, path: &Path) -> Result<(), Error> {
    write_chunks(repo, &manifest.database, path).await
}

async fn write_chunks(repo: &Repository, chunks: &[String], path: &Path) -> Result<(), Error> {
    let mut file = tokio::fs::File::create(path).await?;
    for id in chunks {
        let chunk = repo.get(checked_id(id)?, CHUNK_MAX as u64).await?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await?;
    }
    tokio::io::AsyncWriteExt::flush(&mut file).await?;
    file.sync_all().await?;
    Ok(())
}

/// Puts a snapshot's files into a data directory: those that are missing, or not the size they
/// were. A file this server has already, the same size, stays: attachments and Send files never
/// change under their names. Returns how many were written.
///
/// A second attempt after a broken connection picks up where the first one stopped.
pub async fn restore_files(repo: &Repository, manifest: &Manifest, data_dir: &Path) -> Result<usize, Error> {
    let mut written = 0;
    for file in &manifest.files {
        // Rules out `..`, an absolute path and a Windows drive letter in one go: the snapshot may
        // come from a backup server that is not ours, and this writes wherever it says. Nor does
        // it write over the database or into the local backups.
        let relative = Path::new(&file.path);
        let top = file.path.split('/').next().unwrap_or_default();
        if relative.components().any(|part| !matches!(part, std::path::Component::Normal(_))) || left_out(top) {
            return Err(Error::Damaged(format!("the file name {} leaves its place", file.path.escape_debug())));
        }
        let path = data_dir.join(relative);
        if tokio::fs::symlink_metadata(&path).await.is_ok_and(|meta| meta.is_file() && meta.len() == file.size) {
            continue;
        }
        tokio::fs::create_dir_all(path.parent().unwrap_or(data_dir)).await?;
        let partial = uwulock_store::with_suffix(&path, ".restoring");
        write_chunks(repo, &file.chunks, &partial).await?;
        if tokio::fs::metadata(&partial).await?.len() != file.size {
            let _ = tokio::fs::remove_file(&partial).await;
            return Err(Error::Damaged(format!("{} is not the size it was", file.path.escape_debug())));
        }
        tokio::fs::rename(&partial, &path).await?;
        written += 1;
    }
    Ok(written)
}

/// Writes a snapshot into a data directory without a server in it, for a new machine: the files,
/// then the database, checked and with every session ended, as `uwulock-server restore` does.
pub async fn restore_into(repo: &Repository, snapshot: &str, data_dir: &Path) -> Result<Manifest, Error> {
    let database = data_dir.join("uwulock.db");
    if tokio::fs::try_exists(&database).await? {
        return Err(Error::Config(format!(
            "{} already holds a server; restore into an empty directory",
            data_dir.display()
        )));
    }
    let manifest = repo.manifest(snapshot).await?;
    fits_this_server(&manifest)?;
    tokio::fs::create_dir_all(data_dir.join(TEMP_DIR)).await?;
    restore_files(repo, &manifest, data_dir).await?;
    let fetched = data_dir.join(TEMP_DIR).join("restore.db");
    fetch_database(repo, &manifest, &fetched).await?;
    let aside = uwulock_store::with_suffix(&database, ".before-restore");
    let placed = uwulock_store::restore(&fetched, &database, &aside).map_err(Error::Config);
    let _ = tokio::fs::remove_file(&fetched).await;
    placed?;
    Ok(manifest)
}

/// Checks that every object a snapshot needs is there. Returns the missing ids.
pub async fn check(repo: &Repository, snapshot: &str) -> Result<Vec<String>, Error> {
    let manifest = repo.manifest(snapshot).await?;
    let present = repo.object_ids().await?;
    Ok(manifest.objects().filter(|id| !present.contains(*id)).cloned().collect())
}
