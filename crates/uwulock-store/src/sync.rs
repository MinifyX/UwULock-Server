//! Delta sync (docs/uwu-api.md §4): what changed for an account since its last look.
//!
//! The change numbers themselves are handed out by the triggers of migration 0012: every row an
//! account sees carries the number of its last change, from the account's counter or from its
//! organisation's, and what is deleted for good leaves a tombstone. Here they are read back:
//! the counters as they are now ([`Store::sync_counters`]), and everything in a window of them
//! ([`Store::delta`]), a page at a time.
//!
//! A page is cut by change numbers, never inside one: every source says which of its numbers
//! are next (from an index, without reading the rows), the page takes the lowest `limit` of them
//! all, and then each source reads its rows up to the last number taken. The whole delta is read
//! in one transaction, so it is one state of the database.

use crate::file_requests::ExtrasKey;
use crate::icons::OwnIcon;
use crate::organizations::{
    Access, CONFIRMED, Collection, OrgCipher, access_to, collection_from, collections_of, memberships, reachable,
};
use crate::sends::Send;
use crate::suite::{RECORD_COLUMNS, SPACE_COLUMNS, SuiteRecord, SuiteSpace, record_from, space_from};
use crate::vault::{CIPHER_COLUMNS, Folder, cipher_from};
use crate::{Cipher, Result, Store};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{HashMap, HashSet};

/// How long a tombstone is kept, and with it how old a cursor may be.
pub const TOMBSTONE_DAYS: i64 = 90;

/// An account's counters as they are now: what a cursor is made of, and checked against.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Counters {
    /// Changes with every backup that is put back into the running server.
    pub server_epoch: String,
    /// The account's sync epoch: a new key, a membership, travel mode.
    pub epoch: i64,
    pub seq: i64,
    /// Tombstones up to this number are gone.
    pub pruned: i64,
    /// The organisations the account is in (accepted or confirmed).
    pub orgs: Vec<OrgCounter>,
    /// The account's suite spaces and the change number each got its key at.
    pub spaces: Vec<(String, i64)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OrgCounter {
    pub id: String,
    pub seq: i64,
    pub pruned: i64,
}

/// What a delta is to cover.
#[derive(Debug, Clone, Default)]
pub struct DeltaRequest {
    pub user_id: String,
    /// The account's number the last delta reached.
    pub since: i64,
    /// The same per organisation, for those the account is in.
    pub orgs: HashMap<String, i64>,
    /// Bitwarden's objects: items, folders, Sends, collections, the profile and policies.
    pub vault: bool,
    /// UwULock's own: the extras key, own icons, reminders, Send domains, masked links.
    pub uwu: bool,
    /// Suite records of these spaces; none for no suite at all.
    pub spaces: Option<Vec<String>>,
    /// The most objects one page holds.
    pub limit: usize,
}

/// One page of changes.
#[derive(Debug, Default)]
pub struct Delta {
    /// Where the next page starts: the account's number…
    pub until: i64,
    /// …and each organisation's.
    pub org_until: HashMap<String, i64>,
    pub has_more: bool,
    /// The profile (and with it the domains and the unlock options) changed.
    pub profile: bool,
    /// An organisation's policies changed: all of them go out again.
    pub policies: bool,
    pub folders: Vec<Folder>,
    pub ciphers: Vec<Cipher>,
    pub org_ciphers: Vec<OrgCipher>,
    pub collections: Vec<(Collection, Access)>,
    pub sends: Vec<Send>,
    pub deleted_folders: Vec<String>,
    pub deleted_ciphers: Vec<String>,
    pub deleted_sends: Vec<String>,
    pub deleted_collections: Vec<String>,
    /// The extras key, when it changed (and whether it is lost).
    pub extras_key: Option<(ExtrasKey, bool)>,
    pub icons: Vec<OwnIcon>,
    pub icons_deleted: Vec<String>,
    /// Beside `deleted_ciphers` while an organisation's tombstones are read: each item's
    /// collections when it went (JSON), for the member's access check. Empty in a delta.
    tombstone_collections: Vec<Option<String>>,
    /// A reminder changed: the whole list goes out again.
    pub reminders: bool,
    /// The send domain of each Send that changed: `(send id, domain id)`.
    pub send_domains: Vec<(String, Option<String>)>,
    /// A masked address's link to an item changed: the whole map goes out again.
    pub masked_links: bool,
    pub records: Vec<SuiteRecord>,
    pub spaces: Vec<SuiteSpace>,
}

/// `?,?,?` for `n` parameters.
fn marks(n: usize) -> String {
    vec!["?"; n].join(",")
}

/// The next change numbers of one source above `since`, at most `limit` of them.
fn next_numbers(
    conn: &Connection,
    sql: &str,
    args: &[&dyn rusqlite::ToSql],
    limit: usize,
) -> rusqlite::Result<Vec<i64>> {
    let mut statement = conn.prepare_cached(sql)?;
    let rows = statement.query_map(args, |row| row.get::<_, i64>(0))?;
    rows.take(limit).collect()
}

/// Where a window of `numbers` (all above `since`) ends when it may hold `budget` of them, and
/// whether some are left over; `current` is the counter now.
fn cut(mut numbers: Vec<i64>, budget: usize, current: i64) -> (i64, bool, usize) {
    numbers.sort_unstable();
    numbers.dedup();
    if numbers.len() > budget {
        let until = if budget == 0 { numbers[0] - 1 } else { numbers[budget - 1] };
        (until, true, budget)
    } else {
        (current.max(numbers.last().copied().unwrap_or(0)), false, numbers.len())
    }
}

impl Store {
    /// The account's counters as they are now; nothing when there is no such account.
    pub async fn sync_counters(&self, user_id: &str) -> Result<Option<Counters>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| counters(conn, &user_id)).await
    }

    /// A page of what changed for the account in the windows `request` names, with the
    /// counters it was read against. Nothing when there is no such account.
    pub async fn delta(&self, request: DeltaRequest) -> Result<Option<(Delta, Counters)>> {
        self.sqlite_read(move |conn| {
            // One snapshot for the counters and every table.
            let tx = conn.unchecked_transaction()?;
            let Some(counters) = counters(&tx, &request.user_id)? else { return Ok(None) };
            let delta = read_delta(&tx, &request, &counters)?;
            drop(tx);
            Ok(Some((delta, counters)))
        })
        .await
    }

    /// Forget tombstones older than [`TOMBSTONE_DAYS`] (and deleted suite records), and remember
    /// up to which number they went: a cursor from before cannot be served a delta any more.
    /// The maintenance calls it once a day. How many went.
    pub async fn prune_tombstones(&self, now_unix: i64) -> Result<usize> {
        let before = now_unix - TOMBSTONE_DAYS * 86_400;
        self.sqlite_write(move |tx| {
            // Owners that are gone take their tombstones along.
            let orphans = tx.execute(
                "DELETE FROM tombstones WHERE owner NOT IN (SELECT id FROM users) \
                 AND owner NOT IN (SELECT id FROM organizations)",
                [],
            )?;
            tx.execute(
                "UPDATE users SET pruned_seq = max(pruned_seq, (SELECT max(seq) FROM tombstones t \
                 WHERE t.owner = users.id AND t.time < ?1)) \
                 WHERE id IN (SELECT owner FROM tombstones WHERE time < ?1)",
                [before],
            )?;
            tx.execute(
                "UPDATE organizations SET pruned_seq = max(pruned_seq, (SELECT max(seq) FROM tombstones t \
                 WHERE t.owner = organizations.id AND t.time < ?1)) \
                 WHERE id IN (SELECT owner FROM tombstones WHERE time < ?1)",
                [before],
            )?;
            let old = tx.execute("DELETE FROM tombstones WHERE time < ?1", [before])?;
            tx.execute(
                "UPDATE users SET pruned_seq = max(pruned_seq, (SELECT max(seq) FROM suite_records r \
                 WHERE r.user_id = users.id AND r.deleted AND r.updated < ?1)) \
                 WHERE id IN (SELECT user_id FROM suite_records WHERE deleted AND updated < ?1)",
                [before],
            )?;
            let records = tx.execute("DELETE FROM suite_records WHERE deleted AND updated < ?1", [before])?;
            Ok(orphans + old + records)
        })
        .await
    }

    /// A backup was put back, or the data came from elsewhere: every cursor starts over.
    pub async fn new_sync_epoch(&self) -> Result<()> {
        self.sqlite_write(new_server_epoch).await
    }

    /// Everything of the account starts over at its next delta: a purge, a large import.
    pub async fn bump_sync_epoch(&self, user_id: &str) -> Result<()> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("UPDATE users SET sync_epoch = sync_epoch + 1 WHERE id = ?1", [user_id]).map(drop)
        })
        .await
    }
}

pub(crate) fn new_server_epoch(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO server (key, value) VALUES ('sync_epoch', lower(hex(randomblob(8)))) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        [],
    )
    .map(drop)
}

fn counters(conn: &Connection, user_id: &str) -> rusqlite::Result<Option<Counters>> {
    let Some((epoch, seq, pruned)) = conn
        .prepare_cached("SELECT sync_epoch, seq, pruned_seq FROM users WHERE id = ?1")?
        .query_row([user_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .optional()?
    else {
        return Ok(None);
    };
    let server_epoch: String = conn
        .prepare_cached("SELECT value FROM server WHERE key = 'sync_epoch'")?
        .query_row([], |row| row.get(0))
        .optional()?
        .unwrap_or_default();
    let orgs = conn
        .prepare_cached(
            "SELECT o.id, o.seq, o.pruned_seq FROM org_members m JOIN organizations o ON o.id = m.org_id \
             WHERE m.user_id = ?1 AND m.status IN (1, 2) ORDER BY o.id",
        )?
        .query_map([user_id], |row| Ok(OrgCounter { id: row.get(0)?, seq: row.get(1)?, pruned: row.get(2)? }))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let spaces = conn
        .prepare_cached("SELECT space, epoch FROM suite_spaces WHERE user_id = ?1 ORDER BY space")?
        .query_map([user_id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Some(Counters { server_epoch, epoch, seq, pruned, orgs, spaces }))
}

/// Tombstone kinds a request covers.
fn tombstone_kinds(request: &DeltaRequest) -> Vec<&'static str> {
    let mut kinds = Vec::new();
    if request.vault {
        kinds.extend(["cipher", "folder", "send", "collection"]);
    }
    if request.uwu {
        kinds.extend(["icon", "reminder"]);
    }
    kinds
}

fn read_delta(conn: &Connection, request: &DeltaRequest, counters: &Counters) -> rusqlite::Result<Delta> {
    let user = request.user_id.as_str();
    let since = request.since;
    let fetch = request.limit + 1;
    let kinds = tombstone_kinds(request);
    let kind_list = kinds.iter().map(|kind| format!("'{kind}'")).collect::<Vec<_>>().join(",");
    let spaces: Vec<String> = request.spaces.clone().unwrap_or_default();
    let mut delta = Delta::default();

    // ── The account's own counter ──
    let mut numbers = Vec::new();
    if request.vault {
        for sql in [
            "SELECT seq FROM ciphers WHERE user_id = ?1 AND seq > ?2 ORDER BY seq",
            "SELECT seq FROM folders WHERE user_id = ?1 AND seq > ?2 ORDER BY seq",
            "SELECT seq FROM sends WHERE user_id = ?1 AND seq > ?2 ORDER BY seq",
            "SELECT seq FROM cipher_preferences WHERE user_id = ?1 AND seq > ?2 ORDER BY seq",
            "SELECT profile_seq FROM users WHERE id = ?1 AND profile_seq > ?2",
        ] {
            numbers.extend(next_numbers(conn, sql, &[&user, &since], fetch)?);
        }
    }
    if request.uwu {
        for sql in [
            "SELECT seq FROM own_icons WHERE owner = ?1 AND seq > ?2 ORDER BY seq",
            "SELECT seq FROM reminders WHERE user_id = ?1 AND seq > ?2 ORDER BY seq",
            "SELECT seq FROM extras_keys WHERE user_id = ?1 AND seq > ?2",
            "SELECT masked_seq FROM users WHERE id = ?1 AND masked_seq > ?2",
        ] {
            numbers.extend(next_numbers(conn, sql, &[&user, &since], fetch)?);
        }
        // A Send's domain is a change of the Send; counted here too when the vault is not asked.
        if !request.vault {
            let sql = "SELECT seq FROM sends WHERE user_id = ?1 AND seq > ?2 ORDER BY seq";
            numbers.extend(next_numbers(conn, sql, &[&user, &since], fetch)?);
        }
    }
    if !kinds.is_empty() {
        let sql =
            format!("SELECT seq FROM tombstones WHERE owner = ?1 AND seq > ?2 AND kind IN ({kind_list}) ORDER BY seq");
        numbers.extend(next_numbers(conn, &sql, &[&user, &since], fetch)?);
    }
    if !spaces.is_empty() {
        let space_marks = marks(spaces.len());
        let mut args: Vec<&dyn rusqlite::ToSql> = vec![&user, &since];
        args.extend(spaces.iter().map(|space| space as &dyn rusqlite::ToSql));
        let sql = format!(
            "SELECT seq FROM suite_records WHERE user_id = ?1 AND seq > ?2 AND space IN ({space_marks}) ORDER BY seq"
        );
        numbers.extend(next_numbers(conn, &sql, &args, fetch)?);
        let sql = format!("SELECT seq FROM suite_spaces WHERE user_id = ?1 AND seq > ?2 AND space IN ({space_marks})");
        numbers.extend(next_numbers(conn, &sql, &args, fetch)?);
    }
    let (until, more, used) = cut(numbers, request.limit, counters.seq);
    delta.until = until;
    delta.has_more = more;
    let mut budget = request.limit - used;

    let hidden = crate::travel::hidden_folders(conn, user)?;
    // Organisation items whose member-side (folder, star) changed, to show again.
    let mut org_cipher_ids: HashSet<String> = HashSet::new();
    if request.vault && until > since {
        delta.profile = conn
            .prepare_cached("SELECT profile_seq > ?2 AND profile_seq <= ?3 FROM users WHERE id = ?1")?
            .query_row(params![user, since, until], |row| row.get(0))?;
        for folder in conn
            .prepare_cached(
                "SELECT id, user_id, name, created, revision FROM folders WHERE user_id = ?1 AND seq > ?2 AND seq <= ?3",
            )?
            .query_map(params![user, since, until], |row| {
                Ok(Folder {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    name: row.get(2)?,
                    created: row.get(3)?,
                    revision: row.get(4)?,
                })
            })?
        {
            let folder = folder?;
            if hidden.contains(&folder.id) {
                delta.deleted_folders.push(folder.id);
            } else {
                delta.folders.push(folder);
            }
        }
        for cipher in conn
            .prepare_cached(&format!(
                "SELECT {CIPHER_COLUMNS} FROM ciphers WHERE user_id = ?1 AND seq > ?2 AND seq <= ?3 ORDER BY seq"
            ))?
            .query_map(params![user, since, until], cipher_from)?
        {
            let cipher = cipher?;
            if cipher.folder_id.as_ref().is_some_and(|folder| hidden.contains(folder)) {
                delta.deleted_ciphers.push(cipher.id);
            } else {
                delta.ciphers.push(cipher);
            }
        }
        delta.sends = crate::sends::sends_between(conn, user, since, until)?;
        for id in conn
            .prepare_cached("SELECT cipher_id FROM cipher_preferences WHERE user_id = ?1 AND seq > ?2 AND seq <= ?3")?
            .query_map(params![user, since, until], |row| row.get::<_, String>(0))?
        {
            org_cipher_ids.insert(id?);
        }
    }
    if request.uwu && until > since {
        delta.extras_key = conn
            .prepare_cached(&format!(
                "{} WHERE e.user_id = ?1 AND e.seq > ?2 AND e.seq <= ?3",
                crate::file_requests::EXTRAS_KEY_SELECT
            ))?
            .query_row(params![user, since, until], crate::file_requests::extras_key_row)
            .optional()?;
        delta.reminders = conn
            .prepare_cached(
                "SELECT EXISTS (SELECT 1 FROM reminders WHERE user_id = ?1 AND seq > ?2 AND seq <= ?3) \
                 OR EXISTS (SELECT 1 FROM tombstones WHERE owner = ?1 AND kind = 'reminder' AND seq > ?2 AND seq <= ?3)",
            )?
            .query_row(params![user, since, until], |row| row.get(0))?;
        delta.masked_links = conn
            .prepare_cached("SELECT masked_seq > ?2 AND masked_seq <= ?3 FROM users WHERE id = ?1")?
            .query_row(params![user, since, until], |row| row.get(0))?;
        delta.send_domains = conn
            .prepare_cached(
                "SELECT id, domain_id FROM sends WHERE user_id = ?1 AND seq > ?2 AND seq <= ?3 ORDER BY seq",
            )?
            .query_map(params![user, since, until], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        icons_between(conn, user, since, until, &mut delta)?;
    }
    if !kinds.is_empty() && until > since {
        tombstones_between(conn, user, since, until, &kind_list, &mut delta)?;
    }
    if !spaces.is_empty() && until > since {
        let space_marks = marks(spaces.len());
        let mut args: Vec<&dyn rusqlite::ToSql> = vec![&user, &since, &until];
        args.extend(spaces.iter().map(|space| space as &dyn rusqlite::ToSql));
        let sql = format!(
            "SELECT {RECORD_COLUMNS} FROM suite_records WHERE user_id = ?1 AND seq > ?2 AND seq <= ?3 \
             AND space IN ({space_marks}) ORDER BY seq"
        );
        delta.records = conn.prepare(&sql)?.query_map(&args[..], record_from)?.collect::<rusqlite::Result<_>>()?;
        let sql = format!(
            "SELECT {SPACE_COLUMNS} FROM suite_spaces s WHERE user_id = ?1 AND seq > ?2 AND seq <= ?3 \
             AND space IN ({space_marks})"
        );
        delta.spaces = conn.prepare(&sql)?.query_map(&args[..], space_from)?.collect::<rusqlite::Result<_>>()?;
    }

    // ── Each organisation's counter ──
    let org_kinds: Vec<&str> =
        kinds.iter().copied().filter(|kind| matches!(*kind, "cipher" | "collection" | "icon")).collect();
    let org_kind_list = org_kinds.iter().map(|kind| format!("'{kind}'")).collect::<Vec<_>>().join(",");
    let members: HashMap<String, crate::organizations::Member> = if request.vault || request.uwu {
        memberships(conn, user)?.into_iter().map(|(org, member)| (org.id, member)).collect()
    } else {
        HashMap::new()
    };
    let mut org_windows: Vec<(String, i64, i64)> = Vec::new();
    for org in &counters.orgs {
        let org_since = request.orgs.get(&org.id).copied().unwrap_or(0);
        if !(request.vault || request.uwu) || org.seq <= org_since {
            delta.org_until.insert(org.id.clone(), org.seq.max(org_since));
            continue;
        }
        let mut numbers = Vec::new();
        let org_id = org.id.as_str();
        if request.vault {
            for sql in [
                "SELECT seq FROM ciphers WHERE organization_id = ?1 AND seq > ?2 ORDER BY seq",
                "SELECT seq FROM collections WHERE org_id = ?1 AND seq > ?2 ORDER BY seq",
                "SELECT policies_seq FROM organizations WHERE id = ?1 AND policies_seq > ?2",
            ] {
                numbers.extend(next_numbers(conn, sql, &[&org_id, &org_since], budget + 1)?);
            }
        }
        if request.uwu {
            numbers.extend(next_numbers(
                conn,
                "SELECT seq FROM own_icons WHERE owner = ?1 AND seq > ?2 ORDER BY seq",
                &[&org_id, &org_since],
                budget + 1,
            )?);
        }
        if !org_kinds.is_empty() {
            let sql = format!(
                "SELECT seq FROM tombstones WHERE owner = ?1 AND seq > ?2 AND kind IN ({org_kind_list}) ORDER BY seq"
            );
            numbers.extend(next_numbers(conn, &sql, &[&org_id, &org_since], budget + 1)?);
        }
        let (org_until, more, used) = cut(numbers, budget, org.seq);
        budget -= used;
        delta.has_more |= more;
        delta.org_until.insert(org.id.clone(), org_until);
        if org_until > org_since {
            org_windows.push((org.id.clone(), org_since, org_until));
        }
    }
    for (org_id, org_since, org_until) in &org_windows {
        let Some(member) = members.get(org_id) else { continue };
        if request.vault {
            delta.policies |= conn
                .prepare_cached("SELECT policies_seq > ?2 AND policies_seq <= ?3 FROM organizations WHERE id = ?1")?
                .query_row(params![org_id, org_since, org_until], |row| row.get::<_, bool>(0))?;
        }
        // Items, their icons and deletions only for confirmed members, and of those only what the
        // member can see: the same check as for the items themselves.
        if member.status != CONFIRMED {
            continue;
        }
        let reach = reachable(conn, member)?;
        let visible = |collections: &[String]| access_to(member, &reach, collections).is_some();
        if request.vault {
            for collection in conn
                .prepare_cached(
                    "SELECT id, org_id, name, external_id, created, revision FROM collections \
                     WHERE org_id = ?1 AND seq > ?2 AND seq <= ?3",
                )?
                .query_map(params![org_id, org_since, org_until], collection_from)?
            {
                let collection = collection?;
                // One out of reach was never theirs: losing access to a collection moves the
                // member's sync epoch on, and they get everything again (R1-7).
                if let Some(access) = reach.get(&collection.id) {
                    delta.collections.push((collection, *access));
                }
            }
            for id in conn
                .prepare_cached("SELECT id FROM ciphers WHERE organization_id = ?1 AND seq > ?2 AND seq <= ?3")?
                .query_map(params![org_id, org_since, org_until], |row| row.get::<_, String>(0))?
            {
                org_cipher_ids.insert(id?);
            }
        }
        let first_icon = delta.icons.len();
        if request.uwu {
            icons_between(conn, org_id, *org_since, *org_until, &mut delta)?;
        }
        let mut kept = Vec::with_capacity(delta.icons.len());
        for icon in delta.icons.drain(first_icon..) {
            if visible(&collections_of(conn, &icon.cipher_id)?) {
                kept.push(icon);
            }
        }
        delta.icons.extend(kept);
        if !org_kinds.is_empty() {
            let mut org_delta = Delta::default();
            tombstones_between(conn, org_id, *org_since, *org_until, &org_kind_list, &mut org_delta)?;
            // A deleted item's collections are kept with its tombstone.
            for (id, collections) in org_delta.deleted_ciphers.into_iter().zip(org_delta.tombstone_collections) {
                let collections: Vec<String> =
                    collections.and_then(|list| serde_json::from_str(&list).ok()).unwrap_or_default();
                if visible(&collections) || left_visible(conn, org_id, &id, *org_since, member, &reach)? {
                    delta.deleted_ciphers.push(id);
                }
            }
            // An icon taken off an item that is still there; one gone with its item is in the
            // item's tombstone.
            for id in org_delta.icons_deleted {
                let item: Option<String> = conn
                    .prepare_cached("SELECT id FROM ciphers WHERE id = ?1")?
                    .query_row([&id], |row| row.get(0))
                    .optional()?;
                let shown = match item {
                    Some(_) => visible(&collections_of(conn, &id)?),
                    None => member.sees_everything(),
                };
                if shown {
                    delta.icons_deleted.push(id);
                }
            }
            // A collection the member reached by name or group went with an epoch of its own
            // (its access rows went with it); only who sees everything hears of it here (R1-7).
            if member.sees_everything() {
                delta.deleted_collections.extend(org_delta.deleted_collections);
            }
        }
    }
    if !org_cipher_ids.is_empty() {
        let since: HashMap<String, i64> =
            org_windows.iter().map(|(org_id, org_since, _)| (org_id.clone(), *org_since)).collect();
        org_ciphers(conn, user, &members, &hidden, org_cipher_ids, &since, &mut delta)?;
    }

    delta.tombstone_collections.clear();
    // Given away and back, or moved between owners: what is there now wins over its tombstone.
    let present: HashSet<&str> = delta
        .ciphers
        .iter()
        .map(|cipher| cipher.id.as_str())
        .chain(delta.org_ciphers.iter().map(|item| item.cipher.id.as_str()))
        .collect();
    let present: HashSet<String> = present.into_iter().map(str::to_string).collect();
    delta.deleted_ciphers.retain(|id| !present.contains(id));
    delta.deleted_ciphers.sort_unstable();
    delta.deleted_ciphers.dedup();
    let icons: HashSet<String> = delta.icons.iter().map(|icon| icon.cipher_id.clone()).collect();
    delta.icons_deleted.retain(|id| !icons.contains(id));
    Ok(delta)
}

fn icons_between(conn: &Connection, owner: &str, since: i64, until: i64, delta: &mut Delta) -> rusqlite::Result<()> {
    for icon in conn
        .prepare_cached(
            "SELECT cipher_id, key_type, NULL, revision FROM own_icons WHERE owner = ?1 AND seq > ?2 AND seq <= ?3",
        )?
        .query_map(params![owner, since, until], |row| {
            Ok(OwnIcon { cipher_id: row.get(0)?, key_type: row.get(1)?, data: row.get(2)?, revision: row.get(3)? })
        })?
    {
        delta.icons.push(icon?);
    }
    Ok(())
}

fn tombstones_between(
    conn: &Connection,
    owner: &str,
    since: i64,
    until: i64,
    kind_list: &str,
    delta: &mut Delta,
) -> rusqlite::Result<()> {
    let sql = format!(
        "SELECT kind, object_id, collections FROM tombstones WHERE owner = ?1 AND seq > ?2 AND seq <= ?3 \
         AND kind IN ({kind_list})"
    );
    for row in conn.prepare_cached(&sql)?.query_map(params![owner, since, until], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?))
    })? {
        let (kind, id, collections) = row?;
        match kind.as_str() {
            "cipher" => {
                delta.deleted_ciphers.push(id);
                delta.tombstone_collections.push(collections);
            }
            "folder" => delta.deleted_folders.push(id),
            "send" => delta.deleted_sends.push(id),
            "collection" => delta.deleted_collections.push(id),
            "icon" => delta.icons_deleted.push(id),
            _ => {}
        }
    }
    Ok(())
}

/// An item's `cipher-left` tombstones in a window: found by the index `tombstones_left`
/// (migration 0026), not by reading every tombstone of the organisation (R5 I-3).
const LEFT_VISIBLE: &str =
    "SELECT collections FROM tombstones WHERE owner = ?1 AND kind = 'cipher-left' AND object_id = ?2 AND seq > ?3";

/// Whether the item `id` left a collection the member sees since `since`: then it was theirs,
/// and is gone for them now.
fn left_visible(
    conn: &Connection,
    org_id: &str,
    id: &str,
    since: i64,
    member: &crate::organizations::Member,
    reach: &HashMap<String, Access>,
) -> rusqlite::Result<bool> {
    let mut statement = conn.prepare_cached(LEFT_VISIBLE)?;
    for collections in statement.query_map(params![org_id, id, since], |row| row.get::<_, Option<String>>(0))? {
        let collections: Vec<String> =
            collections?.and_then(|list| serde_json::from_str(&list).ok()).unwrap_or_default();
        if access_to(member, reach, &collections).is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Organisation items by id, as `user` sees them: with their collections, the member's access,
/// folder and star. What the member cannot see any more is deleted for them — when they could
/// have had it (R1-7); what they never saw is left out, id and all.
#[allow(clippy::too_many_arguments)]
fn org_ciphers(
    conn: &Connection,
    user: &str,
    members: &HashMap<String, crate::organizations::Member>,
    hidden: &HashSet<String>,
    ids: HashSet<String>,
    since: &HashMap<String, i64>,
    delta: &mut Delta,
) -> rusqlite::Result<()> {
    let mut reaches: HashMap<String, HashMap<String, Access>> = HashMap::new();
    let mut ids: Vec<String> = ids.into_iter().collect();
    ids.sort_unstable();
    for id in ids {
        let Some(mut cipher) = conn
            .prepare_cached(&format!(
                "SELECT {CIPHER_COLUMNS} FROM ciphers WHERE id = ?1 AND organization_id IS NOT NULL"
            ))?
            .query_row([&id], cipher_from)
            .optional()?
        else {
            continue;
        };
        let org_id = cipher.organization_id.clone().unwrap_or_default();
        let Some(member) = members.get(&org_id) else {
            delta.deleted_ciphers.push(id);
            continue;
        };
        if !reaches.contains_key(&org_id) {
            reaches.insert(org_id.clone(), reachable(conn, member)?);
        }
        let collection_ids = collections_of(conn, &id)?;
        let Some(access) = access_to(member, &reaches[&org_id], &collection_ids) else {
            let from = since.get(&org_id).copied().unwrap_or(0);
            if left_visible(conn, &org_id, &id, from, member, &reaches[&org_id])? {
                delta.deleted_ciphers.push(id);
            }
            continue;
        };
        let (folder, favorite): (Option<String>, bool) = conn
            .prepare_cached("SELECT folder_id, favorite FROM cipher_preferences WHERE cipher_id = ?1 AND user_id = ?2")?
            .query_row([&id, &user.to_string()], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?
            .unwrap_or((None, false));
        if folder.as_ref().is_some_and(|folder| hidden.contains(folder)) {
            delta.deleted_ciphers.push(id);
            continue;
        }
        cipher.folder_id = folder;
        cipher.favorite = favorite;
        delta.org_ciphers.push(OrgCipher { cipher, collection_ids, access, viewer: user.to_string() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_is_cut_between_numbers() {
        assert_eq!(cut(vec![5, 3, 9], 10, 12), (12, false, 3), "all of them, and up to the counter");
        assert_eq!(cut(vec![5, 3, 9, 4], 2, 12), (4, true, 2));
        assert_eq!(cut(vec![5, 5, 6], 1, 7), (5, true, 1), "one number is one object");
        assert_eq!(cut(vec![7], 0, 9), (6, true, 0), "no room: nothing, and more to come");
        assert_eq!(cut(vec![], 0, 9), (9, false, 0));
    }

    #[tokio::test]
    async fn left_tombstones_are_found_by_their_index() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::Store::open_sqlite(&dir.path().join("uwulock.db"), &crate::Options { readers: 1 }).unwrap();
        let plan: Vec<String> = store
            .sqlite_read(|conn| {
                conn.prepare(&format!("EXPLAIN QUERY PLAN {LEFT_VISIBLE}"))?
                    .query_map(params!["org", "item", 0], |row| row.get::<_, String>(3))?
                    .collect()
            })
            .await
            .unwrap();
        assert!(plan.iter().any(|step| step.contains("tombstones_left")), "{plan:?}");
    }
}
