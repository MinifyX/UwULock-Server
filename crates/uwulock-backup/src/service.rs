//! Off-site backups as the server runs them: settings in the database, a daily run at a chosen
//! time, a run on request, and how the last one went.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify, OwnedMutexGuard};
use uwulock_store::Store;
use uwulock_store::secret::{ServerSecret, is_sealed};

use crate::{BackupReport, Error, Manifest, RepoKey, Repository, Retention, Source, Storage, TEMP_DIR, Target};

const SETTINGS_KEY: &str = "offsite.settings";
const STATUS_KEY: &str = "offsite.status";
/// After a failed run, the next attempt waits this long.
const RETRY_SECS: i64 = 3600;
/// The longest a backup, or fetching a snapshot, may take. Each request to the backup server has
/// its own timeout, but a server that answers just in time, slowly, for ever, would otherwise hold
/// the lock that restores need, and skip every nightly run after it. A first backup of 100 GB
/// at 5 MB/s takes under 6 hours.
const RUN_DEADLINE: Duration = Duration::from_secs(12 * 3600);
/// The longest listing the snapshots may take, for the portal.
const LIST_DEADLINE: Duration = Duration::from_secs(10 * 60);
/// The most of each kind of retention, and the latest a warning may come.
const RETENTION_MAX: usize = 1000;
const WARN_MAX_HOURS: u32 = 24 * 90;

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs() as i64)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct OffsiteSettings {
    pub enabled: bool,
    pub target: Option<Target>,
    /// The recovery key of an encrypted repository; `None` backs up without encryption.
    pub key: Option<String>,
    pub retention: Retention,
    /// The time (UTC) the daily backup runs at.
    pub hour: u8,
    pub minute: u8,
    /// How old the last successful backup may get before the admins hear of it.
    pub warn_after_hours: u32,
    /// When the backups were switched on, as seconds since 1970: what "too old" counts from
    /// before the first one worked.
    pub enabled_since: Option<i64>,
}

impl Default for OffsiteSettings {
    fn default() -> Self {
        OffsiteSettings {
            enabled: false,
            target: None,
            key: None,
            retention: Retention::default(),
            hour: 2,
            minute: 30,
            warn_after_hours: 48,
            enabled_since: None,
        }
    }
}

impl OffsiteSettings {
    pub fn check(&self) -> Result<(), Error> {
        if self.hour > 23 || self.minute > 59 {
            return Err(Error::Config("the time is an hour from 0 to 23 and a minute from 0 to 59".into()));
        }
        let Retention { days, weeks, months } = self.retention;
        if days.max(weeks).max(months) > RETENTION_MAX {
            return Err(Error::Config(format!("keep at most {RETENTION_MAX} of each")));
        }
        if !(1..=WARN_MAX_HOURS).contains(&self.warn_after_hours) {
            return Err(Error::Config(format!("the warning comes after 1 to {WARN_MAX_HOURS} hours")));
        }
        if let Some(key) = &self.key {
            RepoKey::from_recovery_text(key)?;
        }
        if self.enabled && self.target.is_none() {
            return Err(Error::Config("say where the backups go first".into()));
        }
        if self.enabled && self.plain_elsewhere() {
            return Err(Error::Config(PLAIN_ELSEWHERE.into()));
        }
        Ok(())
    }

    /// Each password or key in the settings, with what it is for.
    fn secrets(&mut self, mut each: impl FnMut(&mut Option<String>, &str) -> Result<(), String>) -> Result<(), String> {
        let mut text = |value: &mut String, purpose: &str| {
            let mut field = Some(std::mem::take(value));
            let done = each(&mut field, purpose);
            *value = field.unwrap_or_default();
            done
        };
        match self.target.as_mut() {
            Some(Target::S3(s3)) => text(&mut s3.secret_key, "offsite.s3.secretKey")?,
            Some(Target::Sftp(sftp)) => match &mut sftp.login {
                crate::Login::Password { password } => text(password, "offsite.sftp.password")?,
                crate::Login::Key { private_key } => text(private_key, "offsite.sftp.privateKey")?,
            },
            Some(Target::Folder(_)) | None => {}
        }
        if let Some(key) = self.key.as_mut() {
            text(key, "offsite.recoveryKey")?;
        }
        Ok(())
    }

    /// Backups without encryption to another machine: not any more. Only a folder of this
    /// machine may take them unencrypted — it holds nothing the data directory does not.
    /// Settings from before are kept, but do not run until they are saved with encryption.
    pub fn plain_elsewhere(&self) -> bool {
        self.key.is_none() && matches!(self.target, Some(Target::Sftp(_) | Target::S3(_)))
    }
}

/// Why settings that send backups unencrypted to SFTP or S3 do not run.
pub const PLAIN_ELSEWHERE: &str = "backups to SFTP or S3 are encrypted; save the settings again with encryption on (at a new place, since the backups there are not encrypted)";

/// How much of an error the portal shows.
const ERROR_SHOWN: usize = 500;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct OffsiteStatus {
    pub last_attempt: Option<i64>,
    pub last_success: Option<i64>,
    pub started: Option<i64>,
    pub finished: Option<i64>,
    /// Seconds the last run took.
    pub last_duration: Option<i64>,
    pub last_error: Option<String>,
    /// The error in our own words, for the alerts (see `Error::summary`).
    pub last_failure: Option<String>,
    pub last_report: Option<BackupReport>,
}

struct Inner {
    store: Store,
    data_dir: PathBuf,
    hostname: String,
    version: String,
    wakeup: Notify,
    /// Held while anything reads or writes the backup server at length: a backup or a restore.
    /// A backup prunes what no snapshot needs, and must not do that under a restore reading it.
    busy: Arc<Mutex<()>>,
    /// Whether the one holding `busy` is a backup.
    backing_up: AtomicBool,
    /// [`RUN_DEADLINE`], shorter in tests.
    deadline: Duration,
    /// Seals the passwords and keys in the settings (`secret.key` in the data directory).
    secret: Arc<ServerSecret>,
}

/// The off-site backups of one server. Cheap to clone.
#[derive(Clone)]
pub struct Offsite {
    inner: Arc<Inner>,
}

/// A snapshot fetched for a restore into the running server: its database is at `database`,
/// and nothing else uses the backup server until this is dropped.
pub struct Fetched {
    pub manifest: Manifest,
    pub database: PathBuf,
    repo: Repository,
    _busy: OwnedMutexGuard<()>,
}

impl Fetched {
    /// Puts the snapshot's files into the data directory.
    pub async fn put_files(&self, data_dir: &Path) -> Result<usize, Error> {
        crate::restore_files(&self.repo, &self.manifest, data_dir).await
    }

    pub async fn close(self) {
        let _ = tokio::fs::remove_file(&self.database).await;
        self.repo.storage.close().await;
    }
}

impl Offsite {
    pub fn new(store: Store, data_dir: &Path, hostname: &str, version: &str) -> Offsite {
        Offsite {
            inner: Arc::new(Inner {
                store,
                data_dir: data_dir.to_owned(),
                hostname: hostname.to_owned(),
                version: version.to_owned(),
                wakeup: Notify::new(),
                busy: Arc::new(Mutex::new(())),
                backing_up: AtomicBool::new(false),
                deadline: RUN_DEADLINE,
                secret: Arc::new(ServerSecret::new(data_dir)),
            }),
        }
    }

    /// The same, with another deadline for a run: for tests.
    #[doc(hidden)]
    pub fn with_deadline(store: Store, data_dir: &Path, deadline: Duration) -> Offsite {
        let mut offsite = Offsite::new(store, data_dir, "lock.example.com", "0.0.0-test");
        Arc::get_mut(&mut offsite.inner).expect("not shared yet").deadline = deadline;
        offsite
    }

    /// The server's secret for values at rest, which the rest of the server shares.
    pub fn secret(&self) -> Arc<ServerSecret> {
        self.inner.secret.clone()
    }

    /// The settings, with the passwords and keys opened.
    pub async fn settings(&self) -> Result<OffsiteSettings, Error> {
        let mut settings = self.stored_settings().await?;
        settings.secrets(|field, purpose| self.inner.secret.open_field(field, purpose)).map_err(Error::Config)?;
        Ok(settings)
    }

    async fn stored_settings(&self) -> Result<OffsiteSettings, Error> {
        Ok(match self.inner.store.setting(SETTINGS_KEY).await? {
            Some(raw) => serde_json::from_str(&raw)
                .map_err(|_| Error::Config("the off-site backup settings are damaged".into()))?,
            None => OffsiteSettings::default(),
        })
    }

    /// Saved with the passwords, keys and the recovery key sealed (SV-L18).
    pub async fn save_settings(&self, settings: &OffsiteSettings) -> Result<(), Error> {
        settings.check()?;
        let mut sealed = settings.clone();
        sealed.secrets(|field, purpose| self.inner.secret.seal_field(field, purpose)).map_err(Error::Config)?;
        let raw = serde_json::to_string(&sealed).expect("settings serialize");
        self.inner.store.set_setting(SETTINGS_KEY, &raw).await?;
        Ok(())
    }

    /// Seals what an older server kept in plain. Once, at the start.
    pub async fn seal_stored(&self) -> Result<(), Error> {
        let mut stored = self.stored_settings().await?;
        let mut plain = false;
        stored
            .secrets(|field, _| {
                plain |= field.as_deref().is_some_and(|value| !value.is_empty() && !is_sealed(value));
                Ok(())
            })
            .map_err(Error::Config)?;
        if plain {
            let settings = self.settings().await?;
            let mut sealed = settings.clone();
            sealed.secrets(|field, purpose| self.inner.secret.seal_field(field, purpose)).map_err(Error::Config)?;
            let raw = serde_json::to_string(&sealed).expect("settings serialize");
            self.inner.store.set_setting(SETTINGS_KEY, &raw).await?;
            tracing::info!("the off-site backup secrets are sealed now");
        }
        Ok(())
    }

    pub async fn status(&self) -> OffsiteStatus {
        match self.inner.store.setting(STATUS_KEY).await {
            Ok(Some(raw)) => serde_json::from_str(&raw).unwrap_or_default(),
            _ => OffsiteStatus::default(),
        }
    }

    pub async fn save_status(&self, status: &OffsiteStatus) {
        let raw = serde_json::to_string(status).expect("status serializes");
        if let Err(error) = self.inner.store.set_setting(STATUS_KEY, &raw).await {
            tracing::warn!(%error, "saving how the off-site backup went failed");
        }
    }

    pub fn is_running(&self) -> bool {
        self.inner.backing_up.load(Ordering::SeqCst)
    }

    /// Asks the scheduler to back up right away.
    pub fn run_soon(&self) {
        self.inner.wakeup.notify_one();
    }

    /// Waits until a backup is asked for, or `timeout` passed.
    pub async fn asked(&self, timeout: std::time::Duration) -> bool {
        tokio::time::timeout(timeout, self.inner.wakeup.notified()).await.is_ok()
    }

    /// Opens the repository, remembering an SFTP server's host key the first time.
    async fn open(&self, settings: &mut OffsiteSettings, create: bool) -> Result<Repository, Error> {
        let target = settings.target.as_mut().ok_or_else(|| Error::Config("no backup target is set up".into()))?;
        let storage = Storage::open(target).await?;
        if let (Some(sftp), Some(seen)) = (target.as_sftp_mut(), storage.host_key())
            && sftp.host_key.is_none()
        {
            sftp.host_key = Some(seen.to_owned());
            self.save_settings(settings).await?;
        }
        let key = settings.key.as_deref().map(RepoKey::from_recovery_text).transpose()?;
        if create { Repository::open(storage, key, now()).await } else { Repository::open_existing(storage, key).await }
    }

    /// Connects to the target and writes a small file there and takes it away: whether backups
    /// can go there. Remembers an SFTP server's host key the first time. Answers the host key,
    /// and whether it was known before.
    pub async fn test(&self) -> Result<(Option<String>, bool), Error> {
        let mut settings = self.settings().await?;
        let target = settings.target.as_mut().ok_or_else(|| Error::Config("no backup target is set up".into()))?;
        let known = target.as_sftp().is_some_and(|sftp| sftp.host_key.is_some());
        let storage = Storage::open(target).await?;
        let host_key = storage.host_key().map(str::to_owned);
        let written = storage.check_writable().await;
        storage.close().await;
        written?;
        if let (Some(sftp), Some(seen)) = (target.as_sftp_mut(), &host_key)
            && sftp.host_key.is_none()
        {
            sftp.host_key = Some(seen.clone());
            self.save_settings(&settings).await?;
        }
        Ok((host_key, known))
    }

    /// Backs up now, unless one is running already.
    pub async fn run_now(&self) -> Result<BackupReport, Error> {
        let _busy = self
            .inner
            .busy
            .try_lock()
            .map_err(|_| Error::Busy("an off-site backup or restore is running already".into()))?;
        let _flag = RunningFlag::raise(&self.inner.backing_up);
        let mut status = self.status().await;
        let started = now();
        status.last_attempt = Some(started);
        status.started = Some(started);
        status.finished = None;
        self.save_status(&status).await;

        let run = async {
            let mut settings = self.settings().await?;
            if settings.plain_elsewhere() {
                return Err(Error::Config(PLAIN_ELSEWHERE.into()));
            }
            let repo = self.open(&mut settings, true).await?;
            let source = Source {
                store: &self.inner.store,
                data_dir: &self.inner.data_dir,
                hostname: &self.inner.hostname,
                version: &self.inner.version,
            };
            let report = crate::backup(&source, &repo, settings.retention, now()).await;
            repo.storage.close().await;
            report
        };
        // Dropped at the deadline, the run lets go of the connection and the lock with it.
        let result = within(self.inner.deadline, "the backup", run).await;
        let _ = tokio::fs::remove_dir_all(self.inner.data_dir.join(TEMP_DIR)).await;
        let finished = now();
        match &result {
            Ok(report) => {
                status.last_success = Some(finished);
                status.last_error = None;
                status.last_failure = None;
                status.last_report = Some(report.clone());
                tracing::info!(snapshot = %report.snapshot, uploaded = report.uploaded, "off-site backup done");
            }
            Err(error) => {
                // The portal shows it; a storage server's long answer is cut there.
                status.last_error = Some(error.to_string().chars().take(ERROR_SHOWN).collect());
                status.last_failure = Some(error.summary());
                tracing::warn!(%error, "off-site backup failed");
            }
        }
        status.finished = Some(finished);
        status.last_duration = Some(finished - started);
        self.save_status(&status).await;
        result
    }

    /// The snapshots in the repository, newest first.
    pub async fn snapshots(&self) -> Result<Vec<Manifest>, Error> {
        within(LIST_DEADLINE.min(self.inner.deadline), "listing the snapshots", async {
            let mut settings = self.settings().await?;
            let repo = self.open(&mut settings, false).await?;
            let listing = repo.listing().await;
            repo.storage.close().await;
            listing
        })
        .await
    }

    /// Fetches a snapshot's database for a restore into the running server.
    pub async fn fetch(&self, snapshot: &str) -> Result<Fetched, Error> {
        let busy = self
            .inner
            .busy
            .clone()
            .try_lock_owned()
            .map_err(|_| Error::Busy("an off-site backup or restore is running already".into()))?;
        within(self.inner.deadline, "fetching the snapshot", self.fetch_locked(snapshot, busy)).await
    }

    async fn fetch_locked(&self, snapshot: &str, busy: OwnedMutexGuard<()>) -> Result<Fetched, Error> {
        let mut settings = self.settings().await?;
        let repo = self.open(&mut settings, false).await?;
        if !repo.config.encrypted {
            repo.storage.close().await;
            // Whoever can write there could have put any database there: without the key that
            // seals every object, nothing ties a snapshot to this server.
            return Err(Error::Config(
                "an unencrypted backup goes back only with the command line, into a new server".into(),
            ));
        }
        let fetched = async {
            let manifest = repo.manifest(snapshot).await?;
            crate::fits_this_server(&manifest)?;
            let dir = self.inner.data_dir.join(TEMP_DIR);
            tokio::fs::create_dir_all(&dir).await?;
            let database = dir.join(format!("restore-{snapshot}.db"));
            crate::fetch_database(&repo, &manifest, &database).await?;
            Ok::<_, Error>((manifest, database))
        }
        .await;
        match fetched {
            Ok((manifest, database)) => Ok(Fetched { manifest, database, repo, _busy: busy }),
            Err(error) => {
                repo.storage.close().await;
                Err(error)
            }
        }
    }

    /// Whether the daily backup is due: its time has come today and there was none since, or the
    /// last attempt failed an hour ago.
    pub fn due(settings: &OffsiteSettings, status: &OffsiteStatus, now: i64) -> bool {
        if !settings.enabled || settings.target.is_none() {
            return false;
        }
        let today = now.div_euclid(86_400) * 86_400;
        let at = today + i64::from(settings.hour) * 3600 + i64::from(settings.minute) * 60;
        if now < at {
            return false;
        }
        match (status.last_success, status.last_attempt) {
            (Some(success), _) if success >= at => false,
            (_, Some(attempt)) if attempt >= at => now - attempt >= RETRY_SECS,
            _ => true,
        }
    }

    /// When the last successful backup is too old, how old it is in hours. A server that never
    /// had one counts from when off-site backups were switched on.
    pub fn stale_hours(settings: &OffsiteSettings, status: &OffsiteStatus, now: i64) -> Option<i64> {
        if !settings.enabled || settings.target.is_none() {
            return None;
        }
        let from = status.last_success.or(settings.enabled_since)?;
        let hours = (now - from) / 3600;
        (hours >= i64::from(settings.warn_after_hours)).then_some(hours)
    }
}

/// `work`, given up once `deadline` passed.
async fn within<T>(
    deadline: Duration,
    what: &str,
    work: impl std::future::Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    tokio::time::timeout(deadline, work).await.unwrap_or_else(|_| {
        Err(Error::Storage(format!("{what} took longer than {} minutes and was stopped", deadline.as_secs() / 60)))
    })
}

/// Says "a backup is running" for as long as it lives.
struct RunningFlag<'a>(&'a AtomicBool);

impl<'a> RunningFlag<'a> {
    fn raise(flag: &'a AtomicBool) -> RunningFlag<'a> {
        flag.store(true, Ordering::SeqCst);
        RunningFlag(flag)
    }
}

impl Drop for RunningFlag<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FolderTarget;

    fn settings() -> OffsiteSettings {
        OffsiteSettings {
            enabled: true,
            target: Some(Target::Folder(FolderTarget { path: "/backup".into() })),
            hour: 3,
            minute: 15,
            ..Default::default()
        }
    }

    #[test]
    fn alerts_get_our_words_not_the_storage_servers() {
        let summary = |text: &str| Error::Storage(text.into()).summary();
        assert_eq!(
            summary("s3.example.com answered 503 Service Unavailable: whatever"),
            "the backup server answered 503"
        );
        assert_eq!(
            summary("s3.example.com answered AccessDenied: <script>"),
            "the backup server answered AccessDenied"
        );
        assert_eq!(
            summary("s3.example.com answered Hi-admins!: call me"),
            "the backup server could not be reached or did not work"
        );
        assert_eq!(
            summary("connecting to 192.0.2.1:22: refused"),
            "the backup server could not be reached or did not work"
        );
        let damaged = Error::Damaged("chunk 1 said hello".into()).summary();
        assert!(!damaged.contains("hello"));
    }

    #[test]
    fn the_daily_backup_waits_for_its_time_and_retries_hourly() {
        let settings = settings();
        let day = 20_000 * 86_400;
        let at = day + 3 * 3600 + 15 * 60;
        let fresh = OffsiteStatus::default();
        assert!(!Offsite::due(&settings, &fresh, at - 60), "a minute early");
        assert!(Offsite::due(&settings, &fresh, at));
        let done = OffsiteStatus { last_success: Some(at + 60), last_attempt: Some(at), ..fresh.clone() };
        assert!(!Offsite::due(&settings, &done, day + 20 * 3600), "once a day");
        assert!(Offsite::due(&settings, &done, at + 86_400), "the next day");
        let failed = OffsiteStatus { last_attempt: Some(at), ..fresh.clone() };
        assert!(!Offsite::due(&settings, &failed, at + 600));
        assert!(Offsite::due(&settings, &failed, at + 3600), "again an hour later");
        let off = OffsiteSettings { enabled: false, ..settings.clone() };
        assert!(!Offsite::due(&off, &fresh, at + 3600));
    }

    #[test]
    fn too_old_counts_from_the_last_success() {
        let settings = settings();
        let now = 20_000 * 86_400;
        let status = OffsiteStatus { last_success: Some(now - 47 * 3600), ..Default::default() };
        assert_eq!(Offsite::stale_hours(&settings, &status, now), None);
        let status = OffsiteStatus { last_success: Some(now - 50 * 3600), ..Default::default() };
        assert_eq!(Offsite::stale_hours(&settings, &status, now), Some(50));
        let never = OffsiteStatus::default();
        let recently = OffsiteSettings { enabled_since: Some(now - 3600), ..settings.clone() };
        assert_eq!(Offsite::stale_hours(&recently, &never, now), None);
        let long_ago = OffsiteSettings { enabled_since: Some(now - 49 * 3600), ..settings };
        assert_eq!(Offsite::stale_hours(&long_ago, &never, now), Some(49));
    }

    #[test]
    fn settings_are_checked() {
        assert!(settings().check().is_ok());
        assert!(OffsiteSettings { hour: 24, ..settings() }.check().is_err());
        assert!(OffsiteSettings { warn_after_hours: 0, ..settings() }.check().is_err());
        assert!(OffsiteSettings { key: Some("nonsense".into()), ..settings() }.check().is_err());
        assert!(OffsiteSettings { target: None, ..settings() }.check().is_err());
        let key = RepoKey::generate().recovery_text();
        assert!(OffsiteSettings { key: Some(key.clone()), ..settings() }.check().is_ok());
        // Unencrypted only into a folder of this machine.
        let sftp = Target::Sftp(crate::SftpTarget {
            host: "nas.example.com".into(),
            port: 22,
            user: "backup".into(),
            path: "lock".into(),
            login: crate::Login::Password { password: "pw".into() },
            host_key: None,
        });
        let plain = OffsiteSettings { target: Some(sftp.clone()), ..settings() };
        assert!(plain.plain_elsewhere() && plain.check().is_err());
        assert!(OffsiteSettings { enabled: false, ..plain }.check().is_ok(), "kept, but it does not run");
        assert!(OffsiteSettings { target: Some(sftp), key: Some(key), ..settings() }.check().is_ok());
        assert!(!settings().plain_elsewhere());
    }
}
