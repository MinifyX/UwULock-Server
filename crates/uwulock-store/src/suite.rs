//! The suite vault (docs/uwu-api.md §6): UwUSSH's, UwURDP's and the other UwU apps' records, in
//! UwUSync's record model. The server keeps what the apps sealed and decides only one thing:
//! whether a write is based on the record as it is here now (`baseSeq` is its `seq`). Every
//! accepted write takes the account's next change number, so a pull is "everything above n".

use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, Row, Transaction, params};

/// A space as the account has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteSpace {
    pub space: String,
    pub id: String,
    /// The space key under the extras key.
    pub key: String,
    /// Records and tombstones in it, and the bytes they take.
    pub records: i64,
    pub bytes: i64,
    pub created: String,
    pub revision: String,
    /// The account's change number when it got its key; pulls from before start over.
    pub epoch: i64,
}

pub(crate) const SPACE_COLUMNS: &str = "space, id, key, \
     (SELECT count(*) FROM suite_records r WHERE r.user_id = s.user_id AND r.space = s.space), \
     (SELECT coalesce(sum(length(r.blob) + length(r.nonce)), 0) FROM suite_records r \
      WHERE r.user_id = s.user_id AND r.space = s.space), \
     created, revision, epoch";

pub(crate) fn space_from(row: &Row<'_>) -> rusqlite::Result<SuiteSpace> {
    Ok(SuiteSpace {
        space: row.get(0)?,
        id: row.get(1)?,
        key: row.get(2)?,
        records: row.get(3)?,
        bytes: row.get(4)?,
        created: row.get(5)?,
        revision: row.get(6)?,
        epoch: row.get(7)?,
    })
}

/// A record as an app sealed it (UwUSync's `Envelope`, the space in place of the vault id).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SuiteRecord {
    pub id: String,
    pub space: String,
    pub kind: String,
    pub wall_ms: u64,
    pub counter: u32,
    pub device: u32,
    pub deleted: bool,
    pub nonce: Vec<u8>,
    pub blob: Vec<u8>,
    /// The change number of the record as the app last saw it: 0 for a new one. Only on a push.
    pub base_seq: i64,
    /// The change number of its last write here.
    pub seq: i64,
}

pub(crate) const RECORD_COLUMNS: &str = "id, space, kind, wall_ms, counter, device, deleted, nonce, blob, seq";

pub(crate) fn record_from(row: &Row<'_>) -> rusqlite::Result<SuiteRecord> {
    Ok(SuiteRecord {
        id: row.get(0)?,
        space: row.get(1)?,
        kind: row.get(2)?,
        wall_ms: row.get::<_, i64>(3)? as u64,
        counter: row.get::<_, i64>(4)? as u32,
        device: row.get::<_, i64>(5)? as u32,
        deleted: row.get(6)?,
        nonce: row.get(7)?,
        blob: row.get(8)?,
        base_seq: 0,
        seq: row.get(9)?,
    })
}

/// Why a space could not be made or given a new key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceRefusal {
    /// The account has this space already (another device was quicker).
    Exists,
    /// The id is taken, by another space or account.
    IdTaken,
    /// There is no such space.
    Missing,
    /// A new key has to bring every record, each based on what is here: one is missing or stale.
    Conflict,
}

/// A page of a pull.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuitePull {
    /// The cursor is from before the space's key or the oldest tombstone kept: pull from 0 again.
    pub reset: bool,
    pub records: Vec<SuiteRecord>,
    pub cursor: i64,
    pub has_more: bool,
}

/// What a push did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuitePush {
    /// Ids and their new numbers.
    pub accepted: Vec<(String, i64)>,
    /// Records as they are here, where the push was based on something older.
    pub conflicts: Vec<SuiteRecord>,
    /// The account's number after the push.
    pub cursor: i64,
}

/// Why a push was refused as a whole; nothing of it was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushRefusal {
    NoSpace,
    /// The push names another space id than the space has: it was rekeyed since.
    SpaceChanged,
    /// A record id belongs to another space or account.
    Exists,
    /// It would go past the account's records or bytes.
    Quota,
}

/// How much one account may keep in its spaces together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuiteQuota {
    pub records: i64,
    pub bytes: i64,
}

fn next_seq(tx: &Transaction<'_>, user_id: &str) -> rusqlite::Result<i64> {
    tx.prepare_cached("UPDATE users SET seq = seq + 1 WHERE id = ?1 RETURNING seq")?
        .query_row([user_id], |row| row.get(0))
}

fn space_of(conn: &rusqlite::Connection, user_id: &str, space: &str) -> rusqlite::Result<Option<SuiteSpace>> {
    conn.prepare_cached(&format!("SELECT {SPACE_COLUMNS} FROM suite_spaces s WHERE user_id = ?1 AND space = ?2"))?
        .query_row([user_id, space], space_from)
        .optional()
}

fn write_record(tx: &Transaction<'_>, user_id: &str, record: &SuiteRecord, seq: i64, now: i64) -> rusqlite::Result<()> {
    tx.prepare_cached(
        "INSERT INTO suite_records (id, user_id, space, kind, wall_ms, counter, device, deleted, nonce, blob, seq, updated) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
         ON CONFLICT (id) DO UPDATE SET kind = excluded.kind, wall_ms = excluded.wall_ms, counter = excluded.counter, \
         device = excluded.device, deleted = excluded.deleted, nonce = excluded.nonce, blob = excluded.blob, \
         seq = excluded.seq, updated = excluded.updated",
    )?
    .execute(params![
        record.id,
        user_id,
        record.space,
        record.kind,
        record.wall_ms as i64,
        record.counter,
        record.device,
        record.deleted,
        record.nonce,
        record.blob,
        seq,
        now,
    ])?;
    Ok(())
}

fn stored(tx: &rusqlite::Connection, id: &str) -> rusqlite::Result<Option<(String, SuiteRecord)>> {
    tx.prepare_cached(&format!("SELECT user_id, {RECORD_COLUMNS} FROM suite_records WHERE id = ?1"))?
        .query_row([id], |row| {
            let user: String = row.get(0)?;
            let record = SuiteRecord {
                id: row.get(1)?,
                space: row.get(2)?,
                kind: row.get(3)?,
                wall_ms: row.get::<_, i64>(4)? as u64,
                counter: row.get::<_, i64>(5)? as u32,
                device: row.get::<_, i64>(6)? as u32,
                deleted: row.get(7)?,
                nonce: row.get(8)?,
                blob: row.get(9)?,
                base_seq: 0,
                seq: row.get(10)?,
            };
            Ok((user, record))
        })
        .optional()
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

impl Store {
    pub async fn suite_spaces(&self, user_id: &str) -> Result<Vec<SuiteSpace>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {SPACE_COLUMNS} FROM suite_spaces s WHERE user_id = ?1 ORDER BY space"
            ))?
            .query_map([user_id], space_from)?
            .collect()
        })
        .await
    }

    pub async fn suite_space(&self, user_id: &str, space: &str) -> Result<Option<SuiteSpace>> {
        let (user_id, space) = (user_id.to_string(), space.to_string());
        self.sqlite_read(move |conn| space_of(conn, &user_id, &space)).await
    }

    /// A new space with the id and key an app made.
    pub async fn create_suite_space(
        &self,
        user_id: &str,
        space: &str,
        id: &str,
        key: &str,
    ) -> Result<std::result::Result<SuiteSpace, SpaceRefusal>> {
        let (user_id, space, id, key) = (user_id.to_string(), space.to_string(), id.to_string(), key.to_string());
        self.sqlite_write(move |tx| {
            if space_of(tx, &user_id, &space)?.is_some() {
                return Ok(Err(SpaceRefusal::Exists));
            }
            let taken: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM suite_spaces WHERE id = ?1) OR EXISTS (SELECT 1 FROM suite_records WHERE id = ?1)",
                [&id],
                |row| row.get(0),
            )?;
            if taken {
                return Ok(Err(SpaceRefusal::IdTaken));
            }
            let seq = next_seq(tx, &user_id)?;
            let now = clock::now();
            tx.execute(
                "INSERT INTO suite_spaces (user_id, space, id, key, seq, epoch, created, revision) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?6)",
                params![user_id, space, id, key, seq, now],
            )?;
            Ok(space_of(tx, &user_id, &space)?.ok_or(SpaceRefusal::Missing))
        })
        .await
    }

    /// A new id and key for a space, with every record sealed again for them: each one based on
    /// its number here, none left out. All or nothing.
    pub async fn rekey_suite_space(
        &self,
        user_id: &str,
        space: &str,
        id: &str,
        key: &str,
        records: Vec<SuiteRecord>,
    ) -> Result<std::result::Result<SuiteSpace, SpaceRefusal>> {
        let (user_id, space, id, key) = (user_id.to_string(), space.to_string(), id.to_string(), key.to_string());
        self.sqlite_write(move |tx| {
            let Some(current) = space_of(tx, &user_id, &space)? else { return Ok(Err(SpaceRefusal::Missing)) };
            let taken: bool = tx.query_row(
                "SELECT (EXISTS (SELECT 1 FROM suite_spaces WHERE id = ?1) AND ?1 != ?2) \
                 OR EXISTS (SELECT 1 FROM suite_records WHERE id = ?1)",
                [&id, &current.id],
                |row| row.get(0),
            )?;
            if taken {
                return Ok(Err(SpaceRefusal::IdTaken));
            }
            let held: std::collections::HashMap<String, i64> = tx
                .prepare_cached("SELECT id, seq FROM suite_records WHERE user_id = ?1 AND space = ?2")?
                .query_map([&user_id, &space], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            let mut seen = std::collections::HashSet::new();
            for record in &records {
                if held.get(&record.id) != Some(&record.base_seq) || !seen.insert(record.id.as_str()) {
                    return Ok(Err(SpaceRefusal::Conflict));
                }
            }
            if seen.len() != held.len() {
                return Ok(Err(SpaceRefusal::Conflict));
            }
            let now = now_unix();
            for record in &records {
                let seq = next_seq(tx, &user_id)?;
                write_record(tx, &user_id, record, seq, now)?;
            }
            let seq = next_seq(tx, &user_id)?;
            tx.execute(
                "UPDATE suite_spaces SET id = ?3, key = ?4, seq = ?5, epoch = ?5, revision = ?6 \
                 WHERE user_id = ?1 AND space = ?2",
                params![user_id, space, id, key, seq, clock::now()],
            )?;
            Ok(space_of(tx, &user_id, &space)?.ok_or(SpaceRefusal::Missing))
        })
        .await
    }

    /// The space goes, with all its records. False when there was none.
    pub async fn delete_suite_space(&self, user_id: &str, space: &str) -> Result<bool> {
        let (user_id, space) = (user_id.to_string(), space.to_string());
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM suite_records WHERE user_id = ?1 AND space = ?2", [&user_id, &space])?;
            Ok(tx.execute("DELETE FROM suite_spaces WHERE user_id = ?1 AND space = ?2", [&user_id, &space])? == 1)
        })
        .await
    }

    /// Records of the space above `since`, in order: at most `limit`, and no more than
    /// `max_bytes` of sealed data (but always one). Nothing when there is no such space.
    pub async fn suite_pull(
        &self,
        user_id: &str,
        space: &str,
        since: i64,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Option<SuitePull>> {
        let (user_id, space) = (user_id.to_string(), space.to_string());
        self.sqlite_read(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let Some(current) = space_of(&tx, &user_id, &space)? else { return Ok(None) };
            let pruned: i64 =
                tx.query_row("SELECT pruned_seq FROM users WHERE id = ?1", [&user_id], |row| row.get(0))?;
            if since > 0 && (since < current.epoch || since < pruned) {
                return Ok(Some(SuitePull { reset: true, records: Vec::new(), cursor: since, has_more: false }));
            }
            let mut records = Vec::new();
            let mut bytes = 0usize;
            let mut has_more = false;
            let mut statement = tx.prepare_cached(&format!(
                "SELECT {RECORD_COLUMNS} FROM suite_records WHERE user_id = ?1 AND space = ?2 AND seq > ?3 ORDER BY seq"
            ))?;
            let mut rows = statement.query(params![user_id, space, since])?;
            while let Some(row) = rows.next()? {
                let record = record_from(row)?;
                bytes += record.blob.len();
                if records.len() == limit || (!records.is_empty() && bytes > max_bytes) {
                    has_more = true;
                    break;
                }
                records.push(record);
            }
            let cursor = records.last().map_or(since, |record| record.seq);
            Ok(Some(SuitePull { reset: false, records, cursor, has_more }))
        })
        .await
    }

    /// Write what an app pushed: each record whose `base_seq` is its number here (or that is
    /// new) takes the account's next number; the others come back as they are here. One
    /// transaction.
    pub async fn suite_push(
        &self,
        user_id: &str,
        space: &str,
        space_id: Option<String>,
        records: Vec<SuiteRecord>,
        quota: SuiteQuota,
    ) -> Result<std::result::Result<SuitePush, PushRefusal>> {
        let (user_id, space) = (user_id.to_string(), space.to_string());
        self.sqlite_write(move |tx| {
            let Some(current) = space_of(tx, &user_id, &space)? else {
                return Ok(Err(PushRefusal::NoSpace));
            };
            // Sealed for a space id that is not the space's any more: under a key nobody else has.
            if space_id.is_some_and(|id| id != current.id) {
                return Ok(Err(PushRefusal::SpaceChanged));
            }
            // First what would be taken, and whether it fits; then the writes.
            let mut accepted = Vec::new();
            let mut conflicts = Vec::new();
            let (mut more_records, mut more_bytes) = (0i64, 0i64);
            let mut seen = std::collections::HashSet::new();
            for record in records {
                if !seen.insert(record.id.clone()) {
                    continue;
                }
                match stored(tx, &record.id)? {
                    Some((owner, _)) if owner != user_id => return Ok(Err(PushRefusal::Exists)),
                    Some((_, here)) if here.space != space => return Ok(Err(PushRefusal::Exists)),
                    Some((_, here)) if here.seq != record.base_seq => conflicts.push(here),
                    Some((_, here)) => {
                        more_bytes += (record.blob.len() + record.nonce.len()) as i64
                            - (here.blob.len() + here.nonce.len()) as i64;
                        accepted.push(record);
                    }
                    None => {
                        more_records += 1;
                        more_bytes += (record.blob.len() + record.nonce.len()) as i64;
                        accepted.push(record);
                    }
                }
            }
            if more_records > 0 || more_bytes > 0 {
                let (count, bytes): (i64, i64) = tx.query_row(
                    "SELECT count(*), coalesce(sum(length(blob) + length(nonce)), 0) FROM suite_records WHERE user_id = ?1",
                    [&user_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                if count + more_records > quota.records || bytes + more_bytes > quota.bytes {
                    return Ok(Err(PushRefusal::Quota));
                }
            }
            let now = now_unix();
            let mut numbers = Vec::with_capacity(accepted.len());
            for record in &accepted {
                let seq = next_seq(tx, &user_id)?;
                let record = SuiteRecord { space: space.clone(), ..record.clone() };
                write_record(tx, &user_id, &record, seq, now)?;
                numbers.push((record.id, seq));
            }
            if !numbers.is_empty() {
                tx.execute(
                    "UPDATE suite_spaces SET revision = ?3 WHERE user_id = ?1 AND space = ?2",
                    params![user_id, space, clock::now()],
                )?;
            }
            let cursor: i64 = tx.query_row("SELECT seq FROM users WHERE id = ?1", [&user_id], |row| row.get(0))?;
            Ok(Ok(SuitePush { accepted: numbers, conflicts, cursor }))
        })
        .await
    }

    /// Records and bytes of all the account's spaces.
    pub async fn suite_usage(&self, user_id: &str) -> Result<(i64, i64)> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT count(*), coalesce(sum(length(blob) + length(nonce)), 0) FROM suite_records WHERE user_id = ?1",
                [user_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Options;

    async fn store_with_user() -> (Store, String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_sqlite(&dir.path().join("db"), &Options { readers: 1 }).unwrap();
        let user = store.create_user(crate::accounts::tests::new_user("nyu@example.com")).await.unwrap();
        (store, user.id, dir)
    }

    fn record(id: &str, base: i64, blob: &[u8]) -> SuiteRecord {
        SuiteRecord {
            id: id.into(),
            kind: "host".into(),
            wall_ms: 1_790_000_000_000,
            nonce: vec![1; 24],
            blob: blob.to_vec(),
            base_seq: base,
            ..SuiteRecord::default()
        }
    }

    const QUOTA: SuiteQuota = SuiteQuota { records: 100, bytes: 1 << 20 };

    #[tokio::test]
    async fn a_push_takes_what_is_based_on_the_record_here_and_returns_the_rest() {
        let (store, user, _dir) = store_with_user().await;
        assert_eq!(store.suite_push(&user, "ssh", None, vec![], QUOTA).await.unwrap(), Err(PushRefusal::NoSpace));
        store.create_suite_space(&user, "ssh", "space-1", "2.k").await.unwrap().unwrap();
        assert_eq!(store.create_suite_space(&user, "ssh", "space-2", "2.k").await.unwrap(), Err(SpaceRefusal::Exists));
        let first =
            store.suite_push(&user, "ssh", None, vec![record("r1", 0, b"a"), record("r2", 0, b"b")], QUOTA).await;
        let first = first.unwrap().unwrap();
        assert_eq!(first.accepted.len(), 2);
        let r1 = first.accepted[0].1;
        let stale =
            store.suite_push(&user, "ssh", None, vec![record("r1", r1 - 1, b"x")], QUOTA).await.unwrap().unwrap();
        assert!(stale.accepted.is_empty());
        assert_eq!(stale.conflicts[0].blob, b"a", "as it is here");
        let next = store.suite_push(&user, "ssh", None, vec![record("r1", r1, b"c")], QUOTA).await.unwrap().unwrap();
        assert!(next.accepted[0].1 > first.cursor);

        let page = store.suite_pull(&user, "ssh", 0, 1, 1 << 20).await.unwrap().unwrap();
        assert_eq!((page.records.len(), page.has_more), (1, true));
        assert_eq!(page.records[0].id, "r2", "in order of change");
        let rest = store.suite_pull(&user, "ssh", page.cursor, 10, 1 << 20).await.unwrap().unwrap();
        assert_eq!((rest.records[0].id.as_str(), rest.records[0].blob.as_slice()), ("r1", &b"c"[..]));

        // Another account's id, or one of another space: refused as a whole.
        let other = store.create_user(crate::accounts::tests::new_user("other@example.com")).await.unwrap();
        store.create_suite_space(&other.id, "ssh", "space-o", "2.k").await.unwrap().unwrap();
        assert_eq!(
            store.suite_push(&other.id, "ssh", None, vec![record("r1", 0, b"z")], QUOTA).await.unwrap(),
            Err(PushRefusal::Exists)
        );
        let tight = SuiteQuota { records: 2, bytes: 1 << 20 };
        assert_eq!(
            store.suite_push(&user, "ssh", None, vec![record("r3", 0, b"d")], tight).await.unwrap(),
            Err(PushRefusal::Quota)
        );
    }

    #[tokio::test]
    async fn a_new_key_brings_every_record_or_nothing_and_older_pulls_start_over() {
        let (store, user, _dir) = store_with_user().await;
        store.create_suite_space(&user, "rdp", "space-1", "2.k").await.unwrap().unwrap();
        let pushed = store.suite_push(&user, "rdp", None, vec![record("r1", 0, b"a"), record("r2", 0, b"b")], QUOTA);
        let pushed = pushed.await.unwrap().unwrap();
        let (r1, r2) = (pushed.accepted[0].1, pushed.accepted[1].1);
        let only_one = store.rekey_suite_space(&user, "rdp", "space-2", "2.n", vec![record("r1", r1, b"A")]).await;
        assert_eq!(only_one.unwrap(), Err(SpaceRefusal::Conflict));
        let all = vec![record("r1", r1, b"A"), record("r2", r2, b"B")];
        let space = store.rekey_suite_space(&user, "rdp", "space-2", "2.n", all).await.unwrap().unwrap();
        assert_eq!((space.id.as_str(), space.records), ("space-2", 2));
        let old = store.suite_pull(&user, "rdp", r2, 10, 1 << 20).await.unwrap().unwrap();
        assert!(old.reset);
        let fresh = store.suite_pull(&user, "rdp", 0, 10, 1 << 20).await.unwrap().unwrap();
        assert_eq!(
            fresh.records.iter().map(|r| r.blob.clone()).collect::<Vec<_>>(),
            vec![b"A".to_vec(), b"B".to_vec()]
        );
        assert!(store.delete_suite_space(&user, "rdp").await.unwrap());
        assert!(store.suite_pull(&user, "rdp", 0, 10, 1 << 20).await.unwrap().is_none());
    }
}
