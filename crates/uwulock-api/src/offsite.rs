//! Off-site backups in the admin portal (docs/uwu-api.md §21.2): where they go, when, how long
//! they are kept, a test of the target, a run by hand, the snapshots, putting one back, and the
//! recovery key. The backups themselves are `uwulock-backup`'s.
//!
//! Secrets never come back: the SFTP password and the S3 secret key are `…Set: true`, the SSH
//! key only as its public half for `authorized_keys`, and the recovery key once when it is made,
//! later only after the master password.

use crate::alerts::Detail;
use crate::auth::Admin;
use crate::{ApiError, ApiResult, AppState};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_backup::sftp::{generate_key, public_key_line};
use uwulock_backup::{
    Error as BackupError, FolderTarget, Login, Offsite, OffsiteSettings, OffsiteStatus, RepoKey, Retention, S3Target,
    SftpTarget, Target,
};
use uwulock_store::clock;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/admin/backups/offsite", get(view).put(save))
        .route("/uwu/v1/admin/backups/offsite/test", post(test))
        .route("/uwu/v1/admin/backups/offsite/forget-host-key", post(forget_host_key))
        .route("/uwu/v1/admin/backups/offsite/run", post(run))
        .route("/uwu/v1/admin/backups/offsite/snapshots", get(snapshots))
        .route("/uwu/v1/admin/backups/offsite/restore", post(restore))
        .route("/uwu/v1/admin/backups/offsite/recovery-key", post(recovery_key))
}

/// What went wrong, as the answer says it: the backup server's failures are 502 `upstream`,
/// settings that do not work 400, a run already going 409.
fn failed(error: BackupError) -> ApiError {
    match error {
        BackupError::Config(message) => ApiError::bad(message),
        BackupError::Busy(message) => ApiError::new(StatusCode::CONFLICT, message).code("conflict"),
        BackupError::WrongKey => ApiError::bad("The recovery key does not fit this backup."),
        BackupError::Io(error) => ApiError::internal(error),
        BackupError::Store(error) => ApiError::internal(error),
        other => ApiError::upstream(other.to_string()),
    }
}

fn time_of(seconds: Option<i64>) -> Value {
    seconds
        .and_then(|seconds| time::OffsetDateTime::from_unix_timestamp(seconds).ok())
        .map_or(Value::Null, |when| Value::String(clock::format(when)))
}

fn target_view(target: &Target) -> Value {
    match target {
        Target::Sftp(sftp) => {
            let (method, public_key, password_set) = match &sftp.login {
                Login::Key { private_key } => ("key", public_key_line(private_key).ok(), false),
                Login::Password { password } => ("password", None, !password.is_empty()),
            };
            json!({
                "kind": "sftp",
                "host": sftp.host,
                "port": sftp.port,
                "user": sftp.user,
                "path": sftp.path,
                "method": method,
                "publicKey": public_key,
                "passwordSet": password_set,
                "hostKey": sftp.host_key,
            })
        }
        Target::S3(s3) => json!({
            "kind": "s3",
            "endpoint": s3.endpoint,
            "region": s3.region,
            "bucket": s3.bucket,
            "prefix": s3.prefix,
            "accessKey": s3.access_key,
            "secretKeySet": !s3.secret_key.is_empty(),
            "pathStyle": s3.path_style,
        }),
        Target::Folder(folder) => json!({ "kind": "folder", "path": folder.path }),
    }
}

fn view_of(offsite: &Offsite, settings: &OffsiteSettings, status: &OffsiteStatus) -> Value {
    let report = status.last_report.as_ref();
    json!({
        "object": "offsiteBackups",
        "enabled": settings.enabled,
        "hour": settings.hour,
        "minute": settings.minute,
        "retention": settings.retention,
        "encrypted": settings.key.is_some(),
        "warnAfterHours": settings.warn_after_hours,
        "target": settings.target.as_ref().map(target_view),
        "status": {
            "lastSuccess": time_of(status.last_success),
            "lastAttempt": time_of(status.last_attempt),
            "lastError": status.last_error,
            "lastDuration": status.last_duration,
            "bytes": report.map(|report| report.total),
            "uploaded": report.map(|report| report.uploaded),
            "snapshot": report.map(|report| report.snapshot.clone()),
        },
        // Settings from before that send backups unencrypted to SFTP or S3: they do not run
        // until they are saved again with encryption.
        "encryptionRequired": settings.plain_elsewhere(),
        "running": offsite.is_running(),
        "stale": Offsite::stale_hours(settings, status, crate::auth::now_seconds()).is_some(),
    })
}

async fn view(State(state): State<AppState>, _admin: Admin) -> ApiResult<Json<Value>> {
    let settings = state.offsite.settings().await.map_err(failed)?;
    let status = state.offsite.status().await;
    Ok(Json(view_of(&state.offsite, &settings, &status)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TargetBody {
    kind: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    user: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    bucket: String,
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    access_key: String,
    #[serde(default)]
    secret_key: Option<String>,
    #[serde(default)]
    path_style: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveBody {
    enabled: bool,
    #[serde(default)]
    hour: Option<u8>,
    #[serde(default)]
    minute: Option<u8>,
    #[serde(default)]
    retention: Option<Retention>,
    #[serde(default = "yes")]
    encrypted: bool,
    #[serde(default)]
    warn_after_hours: Option<u32>,
    #[serde(default)]
    target: Option<TargetBody>,
    /// Every change asks for the admin's master password: the settings decide where the whole
    /// database goes, so a session token that got away is not enough to send it elsewhere.
    #[serde(default)]
    master_password_hash: Option<String>,
    /// Said out loud when encryption goes off and the recovery key with it.
    #[serde(default)]
    forget_key: bool,
}

fn yes() -> bool {
    true
}

/// Whether two targets are the same place, where the same backups lie.
fn same_place(a: &Target, b: &Target) -> bool {
    match (a, b) {
        (Target::Sftp(a), Target::Sftp(b)) => {
            (&a.host, a.port, &a.user, &a.path) == (&b.host, b.port, &b.user, &b.path)
        }
        (Target::S3(a), Target::S3(b)) => {
            (&a.endpoint, &a.bucket, a.prefix.trim_matches('/')) == (&b.endpoint, &b.bucket, b.prefix.trim_matches('/'))
        }
        (Target::Folder(a), Target::Folder(b)) => a.path.trim_end_matches('/') == b.path.trim_end_matches('/'),
        _ => false,
    }
}

/// The target as the admin sent it, with the secrets that were left out taken from the one
/// before — only for the same server and account, like the SMTP password.
fn target_from(body: TargetBody, before: Option<&Target>, data: &std::path::Path) -> ApiResult<Target> {
    let text = |value: &str| value.trim().to_string();
    match body.kind.as_str() {
        "sftp" => {
            let host = text(&body.host);
            let user = text(&body.user);
            if host.is_empty() || user.is_empty() || host.contains(char::is_whitespace) {
                return Err(ApiError::bad("SFTP needs a host and a user."));
            }
            let port = body.port.unwrap_or(22);
            let previous = before.and_then(Target::as_sftp);
            let same_account = previous.is_some_and(|sftp| sftp.host == host && sftp.user == user);
            let login = match body.method.as_deref().unwrap_or("key") {
                "password" => {
                    let typed = body.password.filter(|password| !password.is_empty());
                    let kept = previous.filter(|_| same_account).and_then(|sftp| match &sftp.login {
                        Login::Password { password } => Some(password.clone()),
                        Login::Key { .. } => None,
                    });
                    let password = typed.or(kept).ok_or_else(|| ApiError::bad("Enter the SFTP password."))?;
                    Login::Password { password }
                }
                "key" => {
                    // The server's own key stays the same whatever the target: it is what the
                    // admin put into authorized_keys.
                    let kept = previous.and_then(|sftp| match &sftp.login {
                        Login::Key { private_key } => Some(private_key.clone()),
                        Login::Password { .. } => None,
                    });
                    let private_key = match kept {
                        Some(key) => key,
                        None => generate_key("uwulock-backup").map_err(ApiError::internal)?.0,
                    };
                    Login::Key { private_key }
                }
                _ => return Err(ApiError::bad("The SFTP login is a key or a password.")),
            };
            let host_key =
                previous.filter(|sftp| sftp.host == host && sftp.port == port).and_then(|sftp| sftp.host_key.clone());
            Ok(Target::Sftp(SftpTarget { host, port, user, path: text(&body.path), login, host_key }))
        }
        "s3" => {
            let previous = before.and_then(|target| match target {
                Target::S3(s3) => Some(s3),
                _ => None,
            });
            let endpoint = text(&body.endpoint).trim_end_matches('/').to_string();
            let bucket = text(&body.bucket);
            let access_key = text(&body.access_key);
            let kept = previous
                .filter(|s3| s3.endpoint == endpoint && s3.bucket == bucket && s3.access_key == access_key)
                .map(|s3| s3.secret_key.clone());
            let secret_key = body.secret_key.filter(|key| !key.is_empty()).or(kept).unwrap_or_default();
            let target = S3Target {
                endpoint,
                region: text(&body.region),
                bucket,
                prefix: text(&body.prefix),
                access_key,
                secret_key,
                path_style: body.path_style,
            };
            // The settings are checked here, before anything is sent anywhere.
            uwulock_backup::s3::S3::new(&target).map_err(|error| ApiError::bad(error.to_string()))?;
            Ok(Target::S3(target))
        }
        "folder" => {
            let path = text(&body.path);
            let dir = std::path::Path::new(&path);
            if !dir.is_absolute() {
                return Err(ApiError::bad("The folder is a full path, like /backup."));
            }
            // A backup inside the data directory would be lost together with the server.
            let inside = |folder: &std::path::Path| {
                let data = data.canonicalize().unwrap_or_else(|_| data.to_path_buf());
                folder.canonicalize().unwrap_or_else(|_| folder.to_path_buf()).starts_with(data)
            };
            if inside(dir) {
                return Err(ApiError::bad("The folder has to be outside the data directory."));
            }
            Ok(Target::Folder(FolderTarget { path }))
        }
        _ => Err(ApiError::bad("The target is sftp, s3 or folder.")),
    }
}

async fn save(State(state): State<AppState>, admin: Admin, Json(body): Json<SaveBody>) -> ApiResult<Json<Value>> {
    crate::accounts::check_password(&state, &admin.0.user, body.master_password_hash.as_deref()).await?;
    let before = state.offsite.settings().await.map_err(failed)?;
    let status = state.offsite.status().await;
    let target =
        body.target.map(|target| target_from(target, before.target.as_ref(), &state.config.data)).transpose()?;
    // Whether there are backups where they go: then encrypting them or not is fixed.
    let same = matches!((&target, &before.target), (Some(new), Some(old)) if same_place(new, old));
    let has_backups = same && status.last_success.is_some();
    // Unencrypted, a backup is the whole database in the open: only into a folder of this
    // machine, and never with the server's own keys (uwulock-backup leaves them out).
    if !body.encrypted && target.as_ref().is_some_and(|target| !matches!(target, Target::Folder(_))) {
        return Err(ApiError::bad("Backups to SFTP or S3 are always encrypted.").code("encryption_required"));
    }
    if !body.encrypted && before.key.is_some() && !body.forget_key {
        return Err(ApiError::bad(
            "Without encryption the recovery key is forgotten, and the encrypted backups need it. Keep it first, then confirm.",
        )
        .code("key_would_be_forgotten"));
    }
    let mut recovery_key = None;
    let key = match (body.encrypted, before.key.clone()) {
        (true, Some(key)) => Some(key),
        (false, None) => None,
        (_, _) if has_backups => {
            return Err(ApiError::bad(
                "There are backups there already, so whether they are encrypted is fixed. Choose another place for a change.",
            ));
        }
        (true, None) => {
            let text = RepoKey::generate().recovery_text();
            recovery_key = Some(text.clone());
            Some(text)
        }
        (false, Some(_)) => None,
    };
    let enabled = body.enabled && target.is_some();
    let settings = OffsiteSettings {
        enabled,
        target,
        key,
        retention: body.retention.unwrap_or(before.retention),
        hour: body.hour.unwrap_or(before.hour),
        minute: body.minute.unwrap_or(before.minute),
        warn_after_hours: body.warn_after_hours.unwrap_or(before.warn_after_hours),
        enabled_since: match (enabled, before.enabled) {
            (true, true) => before.enabled_since,
            (true, false) => Some(crate::auth::now_seconds()),
            (false, _) => None,
        },
    };
    state.offsite.save_settings(&settings).await.map_err(failed)?;
    let shown = settings.target.as_ref().map_or_else(|| "nowhere".to_string(), Target::shown);
    crate::admin::record(
        &state,
        &admin,
        format!(
            "changed the off-site backups: {} to {shown}, {}",
            if settings.enabled { "on" } else { "off" },
            if settings.key.is_some() { "encrypted" } else { "not encrypted" }
        ),
    )
    .await;
    let mut view = view_of(&state.offsite, &settings, &status);
    view["recoveryKey"] = json!(recovery_key);
    Ok(Json(view))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct TestBody {
    /// The SFTP server's host key the admin confirmed, from the answer before.
    #[serde(default)]
    host_key: Option<String>,
}

/// Tests the target. An SFTP server without a confirmed host key is only asked for its key:
/// the answer has `confirmed: false` and the key, and the admin tests again with `hostKey`
/// (SV-L27).
async fn test(State(state): State<AppState>, admin: Admin, body: Option<Json<TestBody>>) -> ApiResult<Json<Value>> {
    let settings = state.offsite.settings().await.map_err(failed)?;
    let kind =
        settings.target.as_ref().map(Target::kind).ok_or_else(|| ApiError::bad("Say where the backups go first."))?;
    let confirm = body.and_then(|Json(body)| body.host_key).filter(|key| !key.trim().is_empty());
    let (host_key, known, confirmed) = match state.offsite.test(confirm.as_deref().map(str::trim)).await {
        Ok((host_key, known)) => (host_key, known, true),
        Err(uwulock_backup::Error::HostKeyUnconfirmed { seen }) => (Some(seen), false, false),
        Err(error) => return Err(failed(error)),
    };
    crate::admin::record(&state, &admin, "tested the off-site backup target".into()).await;
    Ok(Json(json!({
        "object": "offsiteTest", "kind": kind, "hostKey": host_key, "known": known, "confirmed": confirmed,
    })))
}

/// Trusting whatever host key the backup server shows next: the master password first, as for
/// the settings themselves.
async fn forget_host_key(
    State(state): State<AppState>,
    admin: Admin,
    Json(secret): Json<crate::two_factor::Secret>,
) -> ApiResult<Json<Value>> {
    crate::accounts::check_password(&state, &admin.0.user, secret.master_password_hash.as_deref()).await?;
    let mut settings = state.offsite.settings().await.map_err(failed)?;
    if let Some(sftp) = settings.target.as_mut().and_then(Target::as_sftp_mut) {
        sftp.host_key = None;
    }
    state.offsite.save_settings(&settings).await.map_err(failed)?;
    crate::admin::record(&state, &admin, "forgot the host key of the off-site backup server".into()).await;
    let status = state.offsite.status().await;
    Ok(Json(view_of(&state.offsite, &settings, &status)))
}

/// Runs an off-site backup and tells the metrics and alerts how it went.
pub async fn run_now(state: &AppState) -> Result<uwulock_backup::BackupReport, BackupError> {
    let result = state.offsite.run_now().await;
    if result.is_ok() {
        state.alerts.offsite_succeeded(crate::auth::now_seconds().max(0) as u64);
    }
    result
}

async fn run(State(state): State<AppState>, admin: Admin) -> ApiResult<(StatusCode, Json<Value>)> {
    let settings = state.offsite.settings().await.map_err(failed)?;
    if settings.target.is_none() {
        return Err(ApiError::bad("Say where the backups go first."));
    }
    if state.offsite.is_running() {
        return Err(ApiError::new(StatusCode::CONFLICT, "An off-site backup is running already.").code("conflict"));
    }
    crate::admin::record(&state, &admin, "started an off-site backup".into()).await;
    let running = state.clone();
    tokio::spawn(async move {
        let _ = run_now(&running).await;
    });
    // A moment for the run to say it has begun, so the answer and the next look agree.
    for _ in 0..50 {
        if state.offsite.is_running() {
            break;
        }
        tokio::task::yield_now().await;
    }
    Ok((StatusCode::ACCEPTED, Json(json!({ "object": "offsiteRun", "started": true }))))
}

async fn snapshots(State(state): State<AppState>, _admin: Admin) -> ApiResult<Json<Value>> {
    let list = state.offsite.snapshots().await.map_err(failed)?;
    // The last snapshot this server wrote is never pruned: when the storage does not list it,
    // whoever keeps the storage hides it, and the portal says so (SV-L31).
    let written = state.offsite.status().await.last_report.map(|report| report.snapshot);
    let newest_missing = written.as_ref().is_some_and(|written| !list.iter().any(|manifest| &manifest.name == written));
    let data: Vec<Value> = list
        .iter()
        .map(|manifest| {
            json!({
                "object": "offsiteSnapshot",
                "id": manifest.name,
                "date": time_of(Some(manifest.created_at)),
                "bytes": manifest.database_size + manifest.files_size,
                "version": manifest.version,
                "hostname": manifest.hostname,
                "uploaded": manifest.uploaded,
            })
        })
        .collect();
    Ok(Json(json!({
        "object": "list", "data": data, "continuationToken": null,
        "lastWritten": written, "lastWrittenMissing": newest_missing,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RestoreBody {
    snapshot: String,
    #[serde(default)]
    master_password_hash: Option<String>,
}

/// Puts a snapshot back into the running server, like a local backup: only one of this server
/// (the same signing key), a local backup of how it is now first, and everybody logs in again.
/// The off-site settings stay those of now: the snapshot's may be older than the key that
/// opened it.
async fn restore(State(state): State<AppState>, admin: Admin, Json(body): Json<RestoreBody>) -> ApiResult<Json<Value>> {
    crate::accounts::check_password(&state, &admin.0.user, body.master_password_hash.as_deref()).await?;
    let fetched = state.offsite.fetch(&body.snapshot).await.map_err(failed)?;
    let result = async {
        let theirs = uwulock_store::setting_in(&fetched.database, crate::auth::TOKEN_KEY).map_err(ApiError::bad)?;
        if theirs.is_none() || theirs != state.store.setting(crate::auth::TOKEN_KEY).await? {
            return Err(ApiError::bad(
                "This snapshot is of another server; it can only go back with the command line on a new server.",
            ));
        }
        let settings = state.offsite.settings().await.map_err(failed)?;
        let status = state.offsite.status().await;
        let before = crate::admin::backup_before_restore(&state).await?;
        state.store.restore_online(&fetched.database).await.map_err(ApiError::bad)?;
        // The database is the snapshot's now: whatever happens with the files, the steps after a
        // restore run and the audit log says so (SV-L28).
        let files = fetched.put_files(&state.config.data).await;
        // The snapshot's `secret.key` may have come with the files.
        state.secret.forget();
        let finished = async {
            state.offsite.save_settings(&settings).await.map_err(failed)?;
            state.offsite.save_status(&status).await;
            crate::admin::after_restore(&state).await
        }
        .await;
        Ok((before, files, finished))
    }
    .await;
    let manifest = fetched.manifest.clone();
    fetched.close().await;
    let (before, files, finished) = result?;
    let outcome = match (&files, &finished) {
        (Ok(_), Ok(())) => String::new(),
        (Err(error), _) => format!("; putting back the files failed: {}", error.summary()),
        (_, Err(error)) => format!("; the steps after it failed ({})", error.status),
    };
    crate::admin::record(
        &state,
        &admin,
        format!("restored the off-site snapshot {} (what was there before: {before}){outcome}", manifest.name),
    )
    .await;
    let files = files.map_err(failed)?;
    finished?;
    Ok(Json(json!({ "restored": manifest.name, "before": before, "files": files })))
}

async fn recovery_key(
    State(state): State<AppState>,
    admin: Admin,
    Json(secret): Json<crate::two_factor::Secret>,
) -> ApiResult<Json<Value>> {
    crate::accounts::check_password(&state, &admin.0.user, secret.master_password_hash.as_deref()).await?;
    let settings = state.offsite.settings().await.map_err(failed)?;
    let key = settings.key.ok_or_else(|| ApiError::not_found("The off-site backups are not encrypted."))?;
    crate::admin::record(&state, &admin, "looked at the recovery key of the off-site backups".into()).await;
    Ok(Json(json!({ "object": "offsiteRecoveryKey", "recoveryKey": key })))
}

/// What is wrong with the off-site backups right now, for the alerts: the last one failed, or
/// the last good one is too old.
pub async fn problems(state: &AppState) -> Vec<(&'static str, &'static str, Detail)> {
    if !state.feature(crate::Feature::OffsiteBackups) {
        return Vec::new();
    }
    let Ok(settings) = state.offsite.settings().await else { return Vec::new() };
    if !settings.enabled {
        return Vec::new();
    }
    let status = state.offsite.status().await;
    let mut found = Vec::new();
    // Our own words with the status (SV-L29); the storage server's text is in the log and the
    // portal's status.
    if status.last_error.is_some() {
        let failure = status.last_failure.as_deref().unwrap_or("see the admin portal");
        found.push((
            "backupFailed",
            "error",
            Detail::new(
                format!("Das Backup außer Haus ging nicht ({failure})."),
                format!("The off-site backup did not work ({failure})."),
            ),
        ));
    }
    if let Some(hours) = Offsite::stale_hours(&settings, &status, crate::auth::now_seconds()) {
        let detail = match status.last_success {
            Some(when) => {
                let when = crate::identity::format_time(&clock::format(
                    time::OffsetDateTime::from_unix_timestamp(when).unwrap_or(time::OffsetDateTime::UNIX_EPOCH),
                ));
                Detail::new(
                    format!("Das letzte Backup außer Haus ist vom {when} ({hours} Stunden alt)."),
                    format!("The last off-site backup is from {when} ({hours} hours old)."),
                )
            }
            None => Detail::new(
                "Es gibt noch kein gelungenes Backup außer Haus.",
                "There is no successful off-site backup yet.",
            ),
        };
        found.push(("backupStale", "warning", detail));
    }
    found
}

/// Once a minute: the nightly off-site backup when it is due, or one asked for. Nothing while
/// the feature is switched off.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        loop {
            let asked = state.offsite.asked(std::time::Duration::from_secs(60)).await;
            if !state.feature(crate::Feature::OffsiteBackups) {
                continue;
            }
            let due = match state.offsite.settings().await {
                Ok(settings) => Offsite::due(&settings, &state.offsite.status().await, crate::auth::now_seconds()),
                Err(error) => {
                    tracing::warn!(%error, "reading the off-site backup settings failed");
                    false
                }
            };
            if asked || due {
                let _ = run_now(&state).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    async fn admin(server: &TestServer) -> Account {
        let token = server.invite("admin@example.com", true).await;
        let response = server
            .call("POST", "/identity/accounts/register/finish", None, register_body("admin@example.com", &token))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        server.login("admin@example.com", "admin-device").await
    }

    fn folder_body(path: &std::path::Path, encrypted: bool) -> Value {
        json!({
            "enabled": true,
            "hour": 3,
            "minute": 0,
            "encrypted": encrypted,
            "retention": { "days": 7, "weeks": 4, "months": 6 },
            "warnAfterHours": 48,
            "target": { "kind": "folder", "path": path.display().to_string() },
            "masterPasswordHash": password_hash("admin@example.com"),
        })
    }

    #[tokio::test]
    async fn a_folder_gets_encrypted_backups_that_go_back_into_the_running_server() {
        let server = TestServer::new().await;
        let admin = admin(&server).await;
        let path = "/uwu/v1/admin/backups/offsite";
        let target = tempfile::tempdir().unwrap();

        // Inside the data directory, a backup would go down with the server.
        let inside = server.call("PUT", path, Some(&admin.token), folder_body(&server.state.config.data, true)).await;
        assert_eq!(inside.status(), StatusCode::BAD_REQUEST);

        let saved = json(server.call("PUT", path, Some(&admin.token), folder_body(target.path(), true)).await).await;
        let recovery = saved["recoveryKey"].as_str().expect("the recovery key, once").to_string();
        assert!(saved["encrypted"].as_bool().unwrap());
        let shown = json(server.get_as(&admin.token, path).await).await;
        assert!(shown.get("recoveryKey").is_none(), "{shown}");
        assert_eq!(shown["target"]["kind"], "folder");
        let again = json(server.call("PUT", path, Some(&admin.token), folder_body(target.path(), true)).await).await;
        assert!(again["recoveryKey"].is_null(), "the key stays, and is not shown again");

        let tested = json(server.call("POST", &format!("{path}/test"), Some(&admin.token), json!({})).await).await;
        assert_eq!(tested["kind"], "folder");

        // A run by hand answers at once, and the backup comes after.
        let run = server.call("POST", &format!("{path}/run"), Some(&admin.token), json!({})).await;
        assert_eq!(run.status(), StatusCode::ACCEPTED);
        let mut status = json(server.get_as(&admin.token, path).await).await;
        for _ in 0..500 {
            if status["status"]["lastSuccess"].is_string() || status["status"]["lastError"].is_string() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            status = json(server.get_as(&admin.token, path).await).await;
        }
        assert!(status["status"]["lastSuccess"].is_string(), "{status}");
        assert!(server.state.alerts.offsite_success().is_some(), "for the metric");

        // Now whether they are encrypted is fixed.
        let plain = server.call("PUT", path, Some(&admin.token), folder_body(target.path(), false)).await;
        assert_eq!(plain.status(), StatusCode::BAD_REQUEST);

        let secret = json!({ "masterPasswordHash": password_hash("admin@example.com") });
        let key =
            json(server.call("POST", &format!("{path}/recovery-key"), Some(&admin.token), secret.clone()).await).await;
        assert_eq!(key["recoveryKey"], recovery.as_str());
        let wrong = json!({ "masterPasswordHash": "wrong" });
        let refused = server.call("POST", &format!("{path}/recovery-key"), Some(&admin.token), wrong.clone()).await;
        assert!(refused.status().is_client_error());

        let list = json(server.get_as(&admin.token, &format!("{path}/snapshots")).await).await;
        let snapshot = list["data"][0]["id"].as_str().unwrap().to_string();
        assert_eq!(list["data"][0]["version"], "0.0.0-test");
        assert_eq!(
            (list["lastWritten"].as_str(), list["lastWrittenMissing"].as_bool()),
            (Some(&*snapshot), Some(false))
        );
        // SV-L31: the storage hides the newest snapshot; the portal hears of it.
        let stored = target.path().join("snapshots").join(&snapshot);
        let aside = target.path().join("aside");
        std::fs::rename(&stored, &aside).unwrap();
        let hidden = json(server.get_as(&admin.token, &format!("{path}/snapshots")).await).await;
        assert_eq!(hidden["lastWrittenMissing"], true, "{hidden}");
        std::fs::rename(&aside, &stored).unwrap();

        // Something changes after the backup, and a file goes missing; the restore brings both back.
        server.state.store.set_setting("marker", "after").await.unwrap();
        let attachment = server.state.config.data.join("attachments/c1/a1");
        std::fs::create_dir_all(attachment.parent().unwrap()).unwrap();
        std::fs::write(&attachment, b"late").unwrap();
        let body = json!({ "snapshot": snapshot, "masterPasswordHash": "wrong" });
        let refused = server.call("POST", &format!("{path}/restore"), Some(&admin.token), body).await;
        assert!(refused.status().is_client_error());
        let body = json!({ "snapshot": snapshot, "masterPasswordHash": password_hash("admin@example.com") });
        let restored = json(server.call("POST", &format!("{path}/restore"), Some(&admin.token), body).await).await;
        assert_eq!(restored["restored"], snapshot.as_str(), "{restored}");
        assert!(restored["before"].as_str().unwrap().ends_with("-before-restore.db"));
        assert_eq!(server.state.store.setting("marker").await.unwrap(), None);
        // Everybody logs in again, and the off-site settings are those of now.
        assert_eq!(server.get_as(&admin.token, path).await.status(), StatusCode::UNAUTHORIZED);
        let admin = server.login("admin@example.com", "admin-device").await;
        let shown = json(server.get_as(&admin.token, path).await).await;
        assert!(shown["enabled"].as_bool().unwrap() && shown["status"]["lastSuccess"].is_string(), "{shown}");
    }

    #[tokio::test]
    async fn too_old_or_failed_off_site_backups_are_an_alert() {
        let server = TestServer::new().await;
        let target = tempfile::tempdir().unwrap();
        let hours = 3600;
        let settings = OffsiteSettings {
            enabled: true,
            target: Some(Target::Folder(FolderTarget { path: target.path().display().to_string() })),
            enabled_since: Some(crate::auth::now_seconds() - 50 * hours),
            ..OffsiteSettings::default()
        };
        server.state.offsite.save_settings(&settings).await.unwrap();
        let found = problems(&server.state).await;
        assert_eq!(found.iter().map(|(event, ..)| *event).collect::<Vec<_>>(), ["backupStale"]);

        // The storage server's words stay out of the alert, its status goes in.
        let error = uwulock_backup::Error::Storage(
            "s3.example.com answered 503 Service Unavailable: <b>Hi admins, mail me at evil@example.com</b>".into(),
        );
        let status = OffsiteStatus {
            last_error: Some(error.to_string()),
            last_failure: Some(error.summary()),
            ..OffsiteStatus::default()
        };
        server.state.offsite.save_status(&status).await;
        let evaluated = crate::alerts::evaluate(&server.state).await;
        let failed = &evaluated["backupFailed"].1;
        assert!(failed.en.contains("answered 503"), "{evaluated:?}");
        assert!(!failed.en.contains("evil") && !failed.de.contains("evil"), "{evaluated:?}");
        assert!(evaluated["backupStale"].1.en.contains("no successful off-site backup"), "{evaluated:?}");

        run_now(&server.state).await.unwrap();
        assert!(problems(&server.state).await.is_empty());
    }

    #[tokio::test]
    async fn secrets_stay_on_the_server() {
        let server = TestServer::new().await;
        let admin = admin(&server).await;
        let path = "/uwu/v1/admin/backups/offsite";
        let body = json!({
            "enabled": false,
            "target": { "kind": "s3", "endpoint": "https://s3.example.com", "region": "eu-central-1",
                "bucket": "backups", "prefix": "lock", "accessKey": "AKIDEXAMPLE", "secretKey": "geheim" },
            "masterPasswordHash": password_hash("admin@example.com"),
        });
        let saved = json(server.call("PUT", path, Some(&admin.token), body).await).await;
        assert_eq!(saved["target"]["secretKeySet"], true);
        assert!(!saved.to_string().contains("geheim"));
        // Left out, the secret stays for the same bucket and key.
        let body = json!({
            "enabled": false,
            "target": { "kind": "s3", "endpoint": "https://s3.example.com", "region": "eu-central-1",
                "bucket": "backups", "prefix": "lock", "accessKey": "AKIDEXAMPLE" },
            "masterPasswordHash": password_hash("admin@example.com"),
        });
        json(server.call("PUT", path, Some(&admin.token), body).await).await;
        let settings = server.state.offsite.settings().await.unwrap();
        assert!(matches!(&settings.target, Some(Target::S3(s3)) if s3.secret_key == "geheim"));
        let raw = server.state.store.setting("offsite.settings").await.unwrap().unwrap();
        assert!(!raw.contains("geheim") && raw.contains("\"v1."), "sealed in the database: {raw}");

        // SFTP with a key: the server makes its own and shows only the public half.
        let body = json!({
            "enabled": false,
            "encrypted": true,
            "target": { "kind": "sftp", "host": "nas.example.com", "user": "backup", "path": "uwulock", "method": "key" },
            "masterPasswordHash": password_hash("admin@example.com"),
        });
        let saved = json(server.call("PUT", path, Some(&admin.token), body).await).await;
        assert!(saved["target"]["publicKey"].as_str().unwrap().starts_with("ssh-ed25519 "), "{saved}");
        assert!(!saved.to_string().contains("PRIVATE KEY"));
        let user = server.account("nyu@example.com").await;
        assert_eq!(server.get_as(&user.token, path).await.status(), StatusCode::FORBIDDEN);
    }

    /// Backups H1, R4-2, M1: a session token alone cannot send the database elsewhere, nothing
    /// unencrypted leaves the machine, the recovery key is not dropped by the way, and an
    /// unencrypted repository does not go back into the running server.
    #[tokio::test]
    async fn the_target_needs_the_password_and_only_a_folder_takes_backups_unencrypted() {
        let server = TestServer::new().await;
        let admin = admin(&server).await;
        let path = "/uwu/v1/admin/backups/offsite";
        let target = tempfile::tempdir().unwrap();
        let mut body = folder_body(target.path(), true);
        for hash in [json!(null), json!("wrong")] {
            body["masterPasswordHash"] = hash;
            let refused = server.call("PUT", path, Some(&admin.token), body.clone()).await;
            assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
            assert!(json(refused).await.get("recoveryKey").is_none());
        }
        assert!(server.state.offsite.settings().await.unwrap().target.is_none(), "nothing saved");
        let forget = server.call("POST", &format!("{path}/forget-host-key"), Some(&admin.token), json!({})).await;
        assert_eq!(forget.status(), StatusCode::BAD_REQUEST);

        let s3 = json!({
            "enabled": true,
            "encrypted": false,
            "target": { "kind": "s3", "endpoint": "https://s3.example.com", "region": "eu-central-1",
                "bucket": "backups", "prefix": "lock", "accessKey": "AKIDEXAMPLE", "secretKey": "geheim" },
            "masterPasswordHash": password_hash("admin@example.com"),
        });
        let refused = server.call("PUT", path, Some(&admin.token), s3).await;
        assert_eq!(json(refused).await["code"], "encryption_required");

        // Encrypted first; switching it off drops the key only when that is said.
        let saved = json(server.call("PUT", path, Some(&admin.token), folder_body(target.path(), true)).await).await;
        assert!(saved["recoveryKey"].is_string());
        let elsewhere = tempfile::tempdir().unwrap();
        let plain = folder_body(elsewhere.path(), false);
        let refused = server.call("PUT", path, Some(&admin.token), plain.clone()).await;
        assert_eq!(json(refused).await["code"], "key_would_be_forgotten");
        assert!(server.state.offsite.settings().await.unwrap().key.is_some());
        let mut confirmed = plain;
        confirmed["forgetKey"] = json!(true);
        let saved = json(server.call("PUT", path, Some(&admin.token), confirmed).await).await;
        assert_eq!(saved["encrypted"], false, "{saved}");

        // An unencrypted snapshot goes back only with the command line.
        run_now(&server.state).await.unwrap();
        let list = json(server.get_as(&admin.token, &format!("{path}/snapshots")).await).await;
        let snapshot = list["data"][0]["id"].as_str().unwrap().to_string();
        let body = json!({ "snapshot": snapshot, "masterPasswordHash": password_hash("admin@example.com") });
        let refused = server.call("POST", &format!("{path}/restore"), Some(&admin.token), body).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert!(json(refused).await["message"].as_str().unwrap().contains("command line"));

        // Settings from before that send unencrypted backups over SFTP do not run, and say so.
        let old = OffsiteSettings {
            enabled: false,
            target: Some(Target::Sftp(SftpTarget {
                host: "nas.example.com".into(),
                port: 22,
                user: "backup".into(),
                path: "lock".into(),
                login: Login::Password { password: "pw".into() },
                host_key: None,
            })),
            ..OffsiteSettings::default()
        };
        server.state.offsite.save_settings(&old).await.unwrap();
        let raw = serde_json::to_string(&OffsiteSettings { enabled: true, ..old }).unwrap();
        server.state.store.set_setting("offsite.settings", &raw).await.unwrap();
        let shown = json(server.get_as(&admin.token, path).await).await;
        assert_eq!(shown["encryptionRequired"], true);
        let error = run_now(&server.state).await.unwrap_err();
        assert!(error.to_string().contains("encrypted"), "{error}");
        let evaluated = crate::alerts::evaluate(&server.state).await;
        assert!(evaluated["backupFailed"].1.en.contains("encrypted"), "{evaluated:?}");
    }
}
