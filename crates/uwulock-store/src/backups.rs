//! Backups: one a night, one before every update, a week of them kept.
//!
//! Each is a whole, consistent copy of the database under `backups/`, next to it in the same
//! volume. That protects against a bad update and a mistake, not against a dead disk: copying
//! `backups/` somewhere else is up to whoever runs the server (docs/deployment.md says how).
//!
//! The nightly job, the `backup` command and the admin portal all write them through here.

use crate::{Store, with_suffix};
use std::path::{Path, PathBuf};

/// Backups kept: a week of nights, the ones before updates counted in.
pub const KEPT: usize = 7;

/// Write a backup to `path`, or to a dated file in `dir`. Returns where it went.
pub async fn write(store: &Store, dir: &Path, path: Option<PathBuf>) -> Result<PathBuf, String> {
    let path = path.unwrap_or_else(|| dated_path(dir, now_ms()));
    room_for(store.path(), &path)?;
    store.backup_to(&path).await.map_err(|error| error.to_string())?;
    Ok(path)
}

/// `backups/uwulock-<when>.db`, to the second — the nightly one and one taken before an update
/// can fall on the same day, and `VACUUM INTO` will not write over a file.
pub fn dated_path(dir: &Path, ms: u64) -> PathBuf {
    dir.join(format!("uwulock-{}.db", stamp(ms)))
}

/// When a backup was written, from its name. Nothing for a file that is not one.
pub fn stamp_of(name: &str) -> Option<&str> {
    name.strip_prefix("uwulock-")?.strip_suffix(".db")
}

/// The backups under `dir`, oldest first, with their sizes.
pub fn list(dir: &Path) -> Vec<(String, u64)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut backups: Vec<(String, u64)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            stamp_of(&name)?;
            Some((name, entry.metadata().map(|meta| meta.len()).unwrap_or(0)))
        })
        .collect();
    backups.sort_by(|(a, _), (b, _)| stamp_of(a).cmp(&stamp_of(b)));
    backups
}

/// Keep the newest `keep` backups and remove the rest.
pub fn keep_newest(dir: &Path, keep: usize) {
    let backups = list(dir);
    for (name, _) in backups.iter().rev().skip(keep) {
        let _ = std::fs::remove_file(dir.join(name));
    }
}

/// Whether a backup of `database` to `path` leaves the disk with room to spare. A backup is about
/// as large as the database, and one that fills the disk takes the database down with it: the
/// next write has nowhere to go. So it is only written when what is free afterwards is still a
/// twentieth of the disk, and at least 256 MiB.
fn room_for(database: &Path, path: &Path) -> Result<(), String> {
    let size = |path: &Path| std::fs::metadata(path).map_or(0, |meta| meta.len());
    let need = size(database) + size(&with_suffix(database, "-wal"));
    // The directory it goes into may not be there yet; the disk it will be on is that of the
    // nearest one that is.
    let Some((free, total)) = path.ancestors().skip(1).find_map(disk_space) else {
        return Ok(());
    };
    enough_room(free, total, need).then_some(()).ok_or_else(|| {
        format!(
            "{} MiB free, and a backup of about {} MiB would leave less than the disk needs to keep going. \
             Make room, or copy the backups under backups/ elsewhere and remove old ones",
            free / (1024 * 1024),
            need.div_ceil(1024 * 1024)
        )
    })
}

fn enough_room(free: u64, total: u64, need: u64) -> bool {
    let margin = (total / 20).max(256 * 1024 * 1024);
    free >= need.saturating_add(margin)
}

/// Free and total bytes of the file system `path` is on, for whoever may write there.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn disk_space(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs reads a NUL-terminated path and writes one struct, both of which live on
    // this stack for the length of the call; the struct is plain data, for which all zeroes is a
    // valid value.
    let stat = unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(path.as_ptr(), &mut stat) != 0 {
            return None;
        }
        stat
    };
    let unit = stat.f_frsize as u64;
    Some((stat.f_bavail as u64 * unit, stat.f_blocks as u64 * unit))
}

#[cfg(not(unix))]
fn disk_space(_path: &Path) -> Option<(u64, u64)> {
    None
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_millis() as u64)
}

/// `YYYY-MM-DD` from milliseconds since the epoch. (Howard Hinnant's civil-from-days.)
pub fn date(ms: u64) -> String {
    let days = (ms / 86_400_000) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DD-HHMMSS`, in UTC. Sorts the way it reads.
pub fn stamp(ms: u64) -> String {
    let seconds = (ms / 1000) % 86_400;
    format!("{}-{:02}{:02}{:02}", date(ms), seconds / 3600, seconds / 60 % 60, seconds % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_date_is_the_date() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_700_000_000_000), "2023-11-14");
        assert_eq!(date(1_789_000_000_000), "2026-09-10");
    }

    #[test]
    fn a_stamp_sorts_by_time() {
        assert_eq!(stamp(0), "1970-01-01-000000");
        assert_eq!(stamp(1_700_000_000_000), "2023-11-14-221320");
    }

    #[test]
    fn a_backup_is_written_only_with_room_to_spare() {
        const MIB: u64 = 1024 * 1024;
        let disk = 32 * 1024 * MIB;
        assert!(enough_room(10 * 1024 * MIB, disk, 100 * MIB));
        assert!(!enough_room(1700 * MIB, disk, 100 * MIB), "under the margin after");
        assert!(!enough_room(300 * MIB, 1024 * MIB, 50 * MIB), "a small disk still keeps 256 MiB");
        assert!(enough_room(400 * MIB, 1024 * MIB, 50 * MIB));
        assert!(!enough_room(disk, disk, u64::MAX), "no overflow");
    }

    #[test]
    fn only_the_newest_backups_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        for day in 1..=5 {
            std::fs::write(dir.path().join(format!("uwulock-2026-09-0{day}-030000.db")), b"x").unwrap();
        }
        std::fs::write(dir.path().join("notes.txt"), b"x").unwrap();
        keep_newest(dir.path(), 2);
        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        left.sort();
        assert_eq!(left, vec!["notes.txt", "uwulock-2026-09-04-030000.db", "uwulock-2026-09-05-030000.db"]);
    }
}
