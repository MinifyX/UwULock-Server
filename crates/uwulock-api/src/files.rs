//! Files on disk: attachments and the files of Sends, encrypted by the clients before they
//! come here.
//!
//! They live next to the database, `attachments/<item>/<id>` and `sends/<send>/<id>`. An upload
//! is written to a hidden file first and renamed when it is complete, so a file that is there is
//! a whole one. Deleting an attachment or a Send leaves its file to the nightly sweep, which
//! takes what nothing claims any more after a week — long enough for a backup from before the
//! delete to be put back and find its files.
//!
//! Downloads go by a link with a token in it, the way Bitwarden's clients expect: they fetch it
//! without their access token, so the token says which file for how long.

use crate::AppState;
use crate::errors::{ApiError, ApiResult};
use axum::body::Body;
use axum::extract::Multipart;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

/// How long a download link works when a client asks for it.
pub const LINK_SECONDS: i64 = 5 * 60;
/// How long the links in a sync work: a client may show the item a while later.
pub const SYNC_LINK_SECONDS: i64 = 60 * 60;

/// Files nothing claims are kept this long before the sweep takes them.
pub const ORPHAN_DAYS: u64 = 7;

/// Ids that name files: made here or by a client, but never more than letters, digits and `-`,
/// so no id reaches outside its folder.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// A new id for an attachment or a Send's file: 20 lower-case hex digits, like Bitwarden's.
pub fn new_file_id() -> String {
    crate::auth::random_bytes(10).iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn attachment_path(state: &AppState, cipher_id: &str, id: &str) -> ApiResult<PathBuf> {
    if !valid_id(cipher_id) || !valid_id(id) {
        return Err(ApiError::bad("Attachment doesn't exist"));
    }
    Ok(state.config.data.join("attachments").join(cipher_id).join(id))
}

pub fn send_path(state: &AppState, send_id: &str, id: &str) -> ApiResult<PathBuf> {
    if !valid_id(send_id) || !valid_id(id) {
        return Err(ApiError::bad("Send doesn't exist"));
    }
    Ok(state.config.data.join("sends").join(send_id).join(id))
}

/// What an upload brought: how many bytes, and the file name the client gave the part.
pub struct Uploaded {
    pub size: i64,
    pub file_name: Option<String>,
    /// Text fields that came along, like the key of a legacy attachment upload.
    pub fields: Vec<(String, String)>,
    /// Where it waits until it is kept: a name of its own, so two uploads for the same file at
    /// once never write into each other.
    partial: PathBuf,
}

/// How long an upload may go without a byte before it is given up.
const STALLED: std::time::Duration = std::time::Duration::from_secs(60);
/// How many uploads one account may have running at once.
const UPLOADS_PER_USER: usize = 4;

/// Uploads running, per account: a few at once, so nobody holds the server's files open by the
/// hundred. Uploads to a file request also count per file (one at a time) and per request, and
/// reserve the bytes they announced: the free-space check counts every upload still on its way.
#[derive(Default)]
pub struct Uploads {
    running: parking_lot::Mutex<Running>,
}

#[derive(Default)]
struct Running {
    counts: std::collections::HashMap<String, usize>,
    /// Bytes announced by uploads running now, which the disk needs room for together.
    reserved: u64,
}

/// One running upload; it ends when this is dropped.
pub struct Uploading {
    uploads: std::sync::Arc<Uploads>,
    keys: Vec<String>,
    reserved: u64,
}

impl Uploads {
    pub fn start(self: &std::sync::Arc<Self>, user_id: &str) -> ApiResult<Uploading> {
        let mut running = self.running.lock();
        let count = running.counts.entry(user_id.to_string()).or_default();
        if *count >= UPLOADS_PER_USER {
            return Err(ApiError::too_many("Too many uploads at once. Wait for the others to finish."));
        }
        *count += 1;
        Ok(Uploading { uploads: self.clone(), keys: vec![user_id.to_string()], reserved: 0 })
    }

    /// An upload of `size` bytes to file `file_id` of file request `request_id`, into `dir`: one
    /// at a time per file, a few per request, and only while the disk has room for it besides
    /// every other upload on its way — checked and reserved in one step.
    pub fn start_file(
        self: &std::sync::Arc<Self>,
        request_id: &str,
        file_id: &str,
        size: u64,
        dir: &Path,
    ) -> ApiResult<Uploading> {
        let (request, file) = (format!("request:{request_id}"), format!("file:{file_id}"));
        let mut running = self.running.lock();
        if running.counts.get(&file).is_some_and(|count| *count > 0) {
            return Err(ApiError::new(axum::http::StatusCode::CONFLICT, "This file is being uploaded already.")
                .code("conflict"));
        }
        if running.counts.get(&request).is_some_and(|count| *count >= UPLOADS_PER_USER) {
            return Err(ApiError::too_many("Too many uploads at once. Wait for the others to finish."));
        }
        if !uwulock_store::backups::has_room(dir, running.reserved.saturating_add(size)) {
            return Err(ApiError::bad("There is not enough room on the server for this file."));
        }
        running.reserved += size;
        for key in [&request, &file] {
            *running.counts.entry(key.clone()).or_default() += 1;
        }
        Ok(Uploading { uploads: self.clone(), keys: vec![request, file], reserved: size })
    }
}

impl Drop for Uploading {
    fn drop(&mut self) {
        let mut running = self.uploads.running.lock();
        running.reserved = running.reserved.saturating_sub(self.reserved);
        for key in &self.keys {
            if let Some(count) = running.counts.get_mut(key) {
                *count -= 1;
                if *count == 0 {
                    running.counts.remove(key);
                }
            }
        }
    }
}

/// The next piece of an upload, or an error when none comes in time.
async fn in_time<T, E>(next: impl std::future::Future<Output = Result<T, E>>) -> ApiResult<T> {
    match tokio::time::timeout(STALLED, next).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) | Err(_) => Err(ApiError::bad("The upload is not complete.")),
    }
}

/// The most parts an upload may have, and the most a part that is not the file may hold: the
/// clients send a key and a name next to the file, nothing more.
const MOST_PARTS: usize = 8;
const MOST_FIELD: usize = 10_000;

/// Write the part called `data` of a multipart upload to `path`, at most `limit` bytes. Other
/// small parts are handed back as text.
pub async fn receive(mut form: Multipart, path: &Path, limit: u64) -> ApiResult<Uploaded> {
    let folder = path.parent().ok_or_else(|| ApiError::internal("a file path without a folder"))?;
    tokio::fs::create_dir_all(folder).await.map_err(ApiError::internal)?;
    // A file that would leave the disk too full for the database is not taken in the first place.
    if !uwulock_store::backups::has_room(folder, limit) {
        return Err(ApiError::bad("There is not enough room on the server for this file."));
    }
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("upload");
    let partial = folder.join(format!(".{name}.{}.part", new_file_id()));
    let mut fields = Vec::new();
    let mut received: Option<(i64, Option<String>)> = None;
    let mut parts = 0;
    let result: ApiResult<()> = async {
        while let Some(mut field) = in_time(form.next_field()).await? {
            parts += 1;
            if parts > MOST_PARTS {
                return Err(ApiError::bad("The upload has too many parts."));
            }
            let name = field.name().unwrap_or_default().to_string();
            if name != "data" {
                // Read a piece at a time and stop at the limit: the body has no limit of its own
                // here, so reading a whole part first would take whatever somebody sends.
                let mut text = Vec::new();
                while let Some(chunk) = in_time(field.chunk()).await? {
                    if text.len() + chunk.len() > MOST_FIELD {
                        return Err(ApiError::bad("A part of the upload is too large."));
                    }
                    text.extend_from_slice(&chunk);
                }
                let text = String::from_utf8(text).map_err(|_| ApiError::bad("The upload is not complete."))?;
                fields.push((name, text));
                continue;
            }
            if received.is_some() {
                return Err(ApiError::bad("One file at a time."));
            }
            let file_name = field.file_name().map(str::to_string);
            let mut file = tokio::fs::File::create(&partial).await.map_err(ApiError::internal)?;
            let mut size: u64 = 0;
            while let Some(chunk) = in_time(field.chunk()).await? {
                size += chunk.len() as u64;
                if size > limit {
                    return Err(too_large(limit));
                }
                file.write_all(&chunk).await.map_err(ApiError::internal)?;
            }
            file.sync_all().await.map_err(ApiError::internal)?;
            received = Some((size as i64, file_name));
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        let _ = tokio::fs::remove_file(&partial).await;
        return Err(error);
    }
    let Some((size, file_name)) = received else {
        let _ = tokio::fs::remove_file(&partial).await;
        return Err(ApiError::bad("No file was uploaded."));
    };
    Ok(Uploaded { size, file_name, fields, partial })
}

/// Put a received upload in its place — unless another one got there first: a file that is
/// there stays as it is.
pub async fn keep(uploaded: &Uploaded, path: &Path) -> ApiResult<()> {
    let linked = tokio::fs::hard_link(&uploaded.partial, path).await;
    let _ = tokio::fs::remove_file(&uploaded.partial).await;
    match linked {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(ApiError::bad("The file is uploaded already."))
        }
        Err(error) => Err(ApiError::internal(error)),
    }
}

/// Throw a received upload away, when what it was for said no.
pub async fn discard(uploaded: &Uploaded) {
    let _ = tokio::fs::remove_file(&uploaded.partial).await;
}

pub fn too_large(limit: u64) -> ApiError {
    ApiError::bad(format!("The file is larger than this server takes ({}).", size_name(limit as i64)))
}

/// The most a file may have, from the settings.
pub fn limit(state: &AppState) -> u64 {
    u64::from(state.settings().max_file_mb) * 1024 * 1024
}

/// Whether `adding` more bytes fit into the account's storage (`storagePerUserMb`: its
/// attachments, Send files and file requests together). 422 `quota` when not.
pub async fn check_storage(state: &AppState, user_id: &str, adding: i64) -> ApiResult<()> {
    let Some(limit) = state.settings().storage_limit() else { return Ok(()) };
    let used = state.store.storage_used(user_id).await?;
    if used.saturating_add(adding) > limit {
        return Err(ApiError::new(
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            format!("Your storage on this server is full ({} of {}).", size_name(used), size_name(limit)),
        )
        .code("quota"));
    }
    Ok(())
}

/// Whether `adding` more bytes fit where an item's files count: the account's own storage for a
/// personal item, every confirmed owner's for a family's (a family counts against its owners).
/// `already_counted` is an account the bytes count for already (moving an own item into a
/// family it owns). A family without an owner stores nothing more while there is a limit.
pub async fn check_owner_storage(
    state: &AppState,
    owner: &uwulock_store::Owner,
    adding: i64,
    already_counted: Option<&str>,
) -> ApiResult<()> {
    let org_id = match owner {
        uwulock_store::Owner::User(user_id) => {
            let adding = if already_counted == Some(user_id.as_str()) { 0 } else { adding };
            return check_storage(state, user_id, adding).await;
        }
        uwulock_store::Owner::Org(org_id) => org_id,
    };
    let Some(limit) = state.settings().storage_limit() else { return Ok(()) };
    let owners = state.store.org_owners(org_id).await?;
    let full = || {
        ApiError::new(
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            format!("The family's storage on this server is full (its owners have {} each).", size_name(limit)),
        )
        .code("quota")
    };
    if owners.is_empty() {
        return Err(full());
    }
    for user_id in owners {
        let adding = if already_counted == Some(user_id.as_str()) { 0 } else { adding };
        if state.store.storage_used(&user_id).await?.saturating_add(adding) > limit {
            return Err(full());
        }
    }
    Ok(())
}

/// The file at `path`, streamed.
pub async fn serve(path: &Path) -> ApiResult<Response> {
    let file = tokio::fs::File::open(path).await.map_err(|_| ApiError::not_found("The file is not there."))?;
    let length = file.metadata().await.map_err(ApiError::internal)?.len();
    let body = Body::from_stream(tokio_util::io::ReaderStream::with_capacity(file, 64 * 1024));
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, length.to_string()),
            (header::CONTENT_DISPOSITION, "attachment".to_string()),
        ],
        body,
    )
        .into_response())
}

/// `1.2 MB`, the way Bitwarden writes sizes.
pub fn size_name(bytes: i64) -> String {
    let units = ["Bytes", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < units.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} Bytes") } else { format!("{:.2} {}", size, units[unit]).replace(".00 ", " ") }
}

/// Take the files nothing claims any more and that are older than [`ORPHAN_DAYS`]; also
/// uploads that never finished. `claimed(folder, id)` says whether one still belongs to
/// something.
pub async fn sweep<F, Fut>(root: &Path, claimed: F) -> std::io::Result<usize>
where
    F: Fn(String, String) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(ORPHAN_DAYS * 86_400);
    let mut removed = 0;
    let Ok(mut folders) = tokio::fs::read_dir(root).await else { return Ok(0) };
    while let Some(folder) = folders.next_entry().await? {
        if !folder.file_type().await?.is_dir() {
            continue;
        }
        let owner = folder.file_name().to_string_lossy().into_owned();
        let mut files = tokio::fs::read_dir(folder.path()).await?;
        let mut left = 0;
        while let Some(file) = files.next_entry().await? {
            let name = file.file_name().to_string_lossy().into_owned();
            let old = file.metadata().await?.modified().is_ok_and(|modified| modified < cutoff);
            let partial = name.starts_with('.') && name.ends_with(".part");
            if old && (partial || !claimed(owner.clone(), name).await) {
                tokio::fs::remove_file(file.path()).await?;
                removed += 1;
            } else {
                left += 1;
            }
        }
        if left == 0 {
            let _ = tokio::fs::remove_dir(folder.path()).await;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_stay_in_their_folder() {
        assert!(valid_id("5f7c2a1e-0000-4000-8000-000000000000"));
        assert!(valid_id(&new_file_id()));
        for bad in ["", "..", "../x", "a/b", "a\\b", "a.b", &"x".repeat(65)] {
            assert!(!valid_id(bad), "{bad}");
        }
    }

    #[test]
    fn sizes_read_like_bitwarden_s() {
        assert_eq!(size_name(12), "12 Bytes");
        assert_eq!(size_name(2048), "2 KB");
        assert_eq!(size_name(1_572_864), "1.50 MB");
        assert_eq!(size_name(500 * 1024 * 1024), "500 MB");
    }

    #[tokio::test]
    async fn a_kept_upload_never_writes_over_one_that_is_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        let upload = |bytes: &'static [u8], name: &str| {
            let partial = dir.path().join(name);
            std::fs::write(&partial, bytes).unwrap();
            Uploaded { size: bytes.len() as i64, file_name: None, fields: Vec::new(), partial }
        };
        keep(&upload(b"first", ".file.a.part"), &path).await.unwrap();
        assert!(keep(&upload(b"second", ".file.b.part"), &path).await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "no partial file left behind");
    }

    #[test]
    fn an_account_runs_a_few_uploads_at_once() {
        let uploads = std::sync::Arc::new(Uploads::default());
        let running: Vec<_> = (0..UPLOADS_PER_USER).map(|_| uploads.start("nyu").unwrap()).collect();
        assert!(uploads.start("nyu").is_err());
        assert!(uploads.start("mio").is_ok(), "somebody else still can");
        drop(running);
        assert!(uploads.start("nyu").is_ok());
    }

    #[tokio::test]
    async fn the_sweep_takes_old_files_nothing_claims() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("c1");
        std::fs::create_dir_all(&folder).unwrap();
        for name in ["kept", "orphan", "new-orphan", ".half.part"] {
            std::fs::write(folder.join(name), b"x").unwrap();
        }
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs((ORPHAN_DAYS + 1) * 86_400);
        for name in ["kept", "orphan", ".half.part"] {
            std::fs::File::options().write(true).open(folder.join(name)).unwrap().set_modified(old).unwrap();
        }
        let removed = sweep(dir.path(), |_, name| async move { name == "kept" }).await.unwrap();
        assert_eq!(removed, 2);
        assert!(folder.join("kept").exists() && folder.join("new-orphan").exists());
        assert!(!folder.join("orphan").exists() && !folder.join(".half.part").exists());
    }
}
