//! Organisations in the vault: those a vault brings from Vaultwarden, with their members,
//! collections, groups and policies, and the families made here (Stufe 4d) — shown in the sync,
//! and their items saved by whoever may. Making and managing them is in `org_management`.
//!
//! Who sees what, the way Bitwarden has it: a confirmed member sees the items of the collections
//! they are given, directly or by a group; owners, admins and members with `access_all` see every
//! collection and every item, also those in none. A collection can be read-only for somebody, or
//! hide its passwords from them. Whoever may edit an item may also delete it, as in Vaultwarden
//! with "limit item deletion" off; `manage` is kept for the clients and matters once
//! organisations are managed here.

use crate::accounts::bump_revision;
use crate::vault::{CIPHER_COLUMNS, cipher_from, write_cipher};
use crate::{Cipher, Result, Store, clock};
use rusqlite::{OptionalExtension, Row, Transaction, params};
use std::collections::{HashMap, HashSet};

pub const OWNER: i64 = 0;
pub const ADMIN: i64 = 1;
pub const USER: i64 = 2;

/// Bitwarden's plans, as far as they matter here: what an organisation is.
pub const FAMILY: i64 = 22;
pub const ORGANIZATION: i64 = 20;

pub const REVOKED: i64 = -1;
pub const INVITED: i64 = 0;
pub const ACCEPTED: i64 = 1;
pub const CONFIRMED: i64 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub billing_email: String,
    pub public_key: Option<String>,
    pub private_key: Option<String>,
    /// [`FAMILY`] or [`ORGANIZATION`].
    pub plan_type: i64,
    pub created: String,
    pub revision: String,
}

impl Organization {
    pub fn is_family(&self) -> bool {
        self.plan_type == FAMILY
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub id: String,
    pub org_id: String,
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub key: Option<String>,
    pub status: i64,
    pub kind: i64,
    pub access_all: bool,
    pub permissions: String,
    pub external_id: Option<String>,
    pub reset_password_key: Option<String>,
    pub created: String,
    pub revision: String,
}

/// The confirmed members of an organisation with the collections each reaches, from
/// [`Store::org_reach`].
#[derive(Debug, Clone, Default)]
pub struct OrgReach {
    members: Vec<(Member, HashMap<String, Access>)>,
}

impl OrgReach {
    /// The user ids of the members who see an item in `collections`.
    pub fn seeing(&self, collections: &[String]) -> HashSet<String> {
        self.members
            .iter()
            .filter(|(member, reach)| access_to(member, reach, collections).is_some())
            .filter_map(|(member, _)| member.user_id.clone())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collection {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub external_id: Option<String>,
    pub created: String,
    pub revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub access_all: bool,
    pub external_id: Option<String>,
    pub created: String,
    pub revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub id: String,
    pub org_id: String,
    pub kind: i64,
    pub enabled: bool,
    pub data: Option<String>,
    pub revision: String,
}

/// What somebody may do with a collection, or with an item through its collections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Access {
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}

impl Access {
    /// Everything: an owner's, an admin's, or `access_all`.
    pub const FULL: Access = Access { read_only: false, hide_passwords: false, manage: true };

    /// The more generous of two ways to the same thing.
    fn union(self, other: Access) -> Access {
        Access {
            read_only: self.read_only && other.read_only,
            hide_passwords: self.hide_passwords && other.hide_passwords,
            manage: self.manage || other.manage,
        }
    }
}

/// An organisation's item as one member sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgCipher {
    pub cipher: Cipher,
    pub collection_ids: Vec<String>,
    pub access: Access,
    /// The member it is shown to: download links are bound to them (travel mode).
    pub viewer: String,
}

/// Everything of organisations a sync hands one user.
#[derive(Debug, Default)]
pub struct OrgVault {
    /// Organisations the user belongs to (accepted or confirmed), with their membership.
    pub memberships: Vec<(Organization, Member)>,
    pub collections: Vec<(Collection, Access)>,
    pub ciphers: Vec<OrgCipher>,
    pub policies: Vec<Policy>,
}

pub(crate) const ORG_COLUMNS: &str = "id, name, billing_email, public_key, private_key, plan_type, created, revision";
pub(crate) const MEMBER_COLUMNS: &str = "id, org_id, user_id, email, key, status, type, access_all, permissions, external_id, \
     reset_password_key, created, revision";

pub(crate) fn org_from(row: &Row<'_>) -> rusqlite::Result<Organization> {
    Ok(Organization {
        id: row.get(0)?,
        name: row.get(1)?,
        billing_email: row.get(2)?,
        public_key: row.get(3)?,
        private_key: row.get(4)?,
        plan_type: row.get(5)?,
        created: row.get(6)?,
        revision: row.get(7)?,
    })
}

/// Make an organisation that came from elsewhere a family if it needs no more than a family
/// has: owners and members only, no groups, no policies. Otherwise it is an organisation.
pub(crate) fn classify(tx: &Transaction<'_>, org_id: &str) -> rusqlite::Result<()> {
    tx.execute(
        "UPDATE organizations SET plan_type = CASE WHEN \
             NOT EXISTS (SELECT 1 FROM org_members m WHERE m.org_id = ?1 AND m.type NOT IN (0, 2)) \
             AND NOT EXISTS (SELECT 1 FROM groups g WHERE g.org_id = ?1) \
             AND NOT EXISTS (SELECT 1 FROM policies p WHERE p.org_id = ?1) \
         THEN ?2 ELSE ?3 END WHERE id = ?1",
        params![org_id, FAMILY, ORGANIZATION],
    )?;
    Ok(())
}

pub(crate) fn member_from(row: &Row<'_>, at: usize) -> rusqlite::Result<Member> {
    Ok(Member {
        id: row.get(at)?,
        org_id: row.get(at + 1)?,
        user_id: row.get(at + 2)?,
        email: row.get(at + 3)?,
        key: row.get(at + 4)?,
        status: row.get(at + 5)?,
        kind: row.get(at + 6)?,
        access_all: row.get(at + 7)?,
        permissions: row.get(at + 8)?,
        external_id: row.get(at + 9)?,
        reset_password_key: row.get(at + 10)?,
        created: row.get(at + 11)?,
        revision: row.get(at + 12)?,
    })
}

pub(crate) fn collection_from(row: &Row<'_>) -> rusqlite::Result<Collection> {
    Ok(Collection {
        id: row.get(0)?,
        org_id: row.get(1)?,
        name: row.get(2)?,
        external_id: row.get(3)?,
        created: row.get(4)?,
        revision: row.get(5)?,
    })
}

impl Member {
    /// Whether the member sees everything of the organisation.
    pub fn sees_everything(&self) -> bool {
        self.kind == OWNER || self.kind == ADMIN || self.access_all
    }
}

/// The user's memberships that count: accepted or confirmed, by organisation.
pub(crate) fn memberships(conn: &rusqlite::Connection, user_id: &str) -> rusqlite::Result<Vec<(Organization, Member)>> {
    let columns = ORG_COLUMNS.split(", ").map(|c| format!("o.{c}")).collect::<Vec<_>>().join(", ");
    let members = MEMBER_COLUMNS.split(", ").map(|c| format!("m.{c}")).collect::<Vec<_>>().join(", ");
    conn.prepare_cached(&format!(
        "SELECT {columns}, {members} FROM org_members m JOIN organizations o ON o.id = m.org_id \
         WHERE m.user_id = ?1 AND m.status IN (1, 2) ORDER BY o.name"
    ))?
    .query_map([user_id], |row| Ok((org_from(row)?, member_from(row, 8)?)))?
    .collect()
}

/// The collections a confirmed member reaches, with the most they may do in each.
pub(crate) fn reachable(conn: &rusqlite::Connection, member: &Member) -> rusqlite::Result<HashMap<String, Access>> {
    let mut access: HashMap<String, Access> = HashMap::new();
    if member.status != CONFIRMED {
        return Ok(access);
    }
    let all_by_group: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON g.id = gm.group_id \
         WHERE gm.member_id = ?1 AND g.access_all)",
        [&member.id],
        |row| row.get(0),
    )?;
    if member.sees_everything() || all_by_group {
        for id in conn
            .prepare_cached("SELECT id FROM collections WHERE org_id = ?1")?
            .query_map([&member.org_id], |row| row.get::<_, String>(0))?
        {
            access.insert(id?, Access::FULL);
        }
        return Ok(access);
    }
    let direct = conn
        .prepare_cached(
            "SELECT collection_id, read_only, hide_passwords, manage FROM collection_members WHERE member_id = ?1 \
             UNION ALL \
             SELECT cg.collection_id, cg.read_only, cg.hide_passwords, cg.manage FROM collection_groups cg \
             JOIN group_members gm ON gm.group_id = cg.group_id WHERE gm.member_id = ?1",
        )?
        .query_map([&member.id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                Access { read_only: row.get(1)?, hide_passwords: row.get(2)?, manage: row.get(3)? },
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (id, found) in direct {
        access.entry(id).and_modify(|have| *have = have.union(found)).or_insert(found);
    }
    Ok(access)
}

pub(crate) fn collections_of(tx: &rusqlite::Connection, cipher_id: &str) -> rusqlite::Result<Vec<String>> {
    tx.prepare_cached("SELECT collection_id FROM collection_ciphers WHERE cipher_id = ?1")?
        .query_map([cipher_id], |row| row.get(0))?
        .collect()
}

/// What `member` may do with an item in `collections` (none: in no collection).
pub(crate) fn access_to(member: &Member, reach: &HashMap<String, Access>, collections: &[String]) -> Option<Access> {
    if member.status != CONFIRMED {
        return None;
    }
    if member.sees_everything() {
        return Some(Access::FULL);
    }
    collections.iter().filter_map(|id| reach.get(id).copied()).reduce(Access::union)
}

/// Whether `user_id` sees the item `cipher_id` at all: their own, or an organisation's they are
/// a confirmed member of with access to it (travel mode aside: see `travel::is_hidden`).
pub(crate) fn sees(conn: &rusqlite::Connection, user_id: &str, cipher_id: &str) -> rusqlite::Result<bool> {
    let owner: Option<(Option<String>, Option<String>)> = conn
        .prepare_cached("SELECT user_id, organization_id FROM ciphers WHERE id = ?1")?
        .query_row([cipher_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?;
    let Some((owner, org)) = owner else { return Ok(false) };
    if owner.as_deref() == Some(user_id) {
        return Ok(true);
    }
    let Some(org) = org else { return Ok(false) };
    let Some((_, member)) = memberships(conn, user_id)?.into_iter().find(|(o, _)| o.id == org) else {
        return Ok(false);
    };
    let reach = reachable(conn, &member)?;
    Ok(access_to(&member, &reach, &collections_of(conn, cipher_id)?).is_some())
}

/// Every confirmed member's user id: whose revision moves when the organisation's items change.
pub(crate) fn member_users(conn: &rusqlite::Connection, org_id: &str) -> rusqlite::Result<Vec<String>> {
    conn.prepare_cached("SELECT user_id FROM org_members WHERE org_id = ?1 AND status = 2 AND user_id IS NOT NULL")?
        .query_map([org_id], |row| row.get(0))?
        .collect()
}

pub(crate) fn bump_org(tx: &Transaction<'_>, org_id: &str) -> rusqlite::Result<Vec<String>> {
    let users = member_users(tx, org_id)?;
    for user in &users {
        bump_revision(tx, user)?;
    }
    Ok(users)
}

impl Store {
    /// Everything of organisations the sync hands `user_id`.
    pub async fn org_vault(&self, user_id: &str) -> Result<OrgVault> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            let memberships = memberships(conn, &user_id)?;
            let hidden = crate::travel::hidden_folders(conn, &user_id)?;
            let mut vault = OrgVault::default();
            let preferences: HashMap<String, (Option<String>, bool)> = conn
                .prepare_cached("SELECT cipher_id, folder_id, favorite FROM cipher_preferences WHERE user_id = ?1")?
                .query_map([&user_id], |row| Ok((row.get(0)?, (row.get(1)?, row.get(2)?))))?
                .collect::<rusqlite::Result<_>>()?;
            for (org, member) in &memberships {
                let reach = reachable(conn, member)?;
                for collection in conn
                    .prepare_cached(
                        "SELECT id, org_id, name, external_id, created, revision FROM collections WHERE org_id = ?1",
                    )?
                    .query_map([&org.id], collection_from)?
                {
                    let collection = collection?;
                    if let Some(access) = reach.get(&collection.id) {
                        vault.collections.push((collection, *access));
                    }
                }
                if member.status == CONFIRMED {
                    let mut in_collections: HashMap<String, Vec<String>> = HashMap::new();
                    for pair in conn
                        .prepare_cached(
                            "SELECT cc.cipher_id, cc.collection_id FROM collection_ciphers cc \
                             JOIN collections c ON c.id = cc.collection_id WHERE c.org_id = ?1",
                        )?
                        .query_map([&org.id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
                    {
                        let (cipher, collection) = pair?;
                        in_collections.entry(cipher).or_default().push(collection);
                    }
                    for cipher in conn
                        .prepare_cached(&format!("SELECT {CIPHER_COLUMNS} FROM ciphers WHERE organization_id = ?1"))?
                        .query_map([&org.id], cipher_from)?
                    {
                        let mut cipher = cipher?;
                        let collection_ids = in_collections.remove(&cipher.id).unwrap_or_default();
                        let Some(access) = access_to(member, &reach, &collection_ids) else { continue };
                        let (folder, favorite) = preferences.get(&cipher.id).cloned().unwrap_or((None, false));
                        if folder.as_ref().is_some_and(|folder| hidden.contains(folder)) {
                            continue;
                        }
                        cipher.folder_id = folder;
                        cipher.favorite = favorite;
                        vault.ciphers.push(OrgCipher { cipher, collection_ids, access, viewer: user_id.clone() });
                    }
                }
                vault.policies.extend(
                    conn.prepare_cached(
                        "SELECT id, org_id, type, enabled, data, revision FROM policies WHERE org_id = ?1",
                    )?
                    .query_map([&org.id], |row| {
                        Ok(Policy {
                            id: row.get(0)?,
                            org_id: row.get(1)?,
                            kind: row.get(2)?,
                            enabled: row.get(3)?,
                            data: row.get(4)?,
                            revision: row.get(5)?,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?,
                );
            }
            vault.memberships = memberships;
            Ok(vault)
        })
        .await
    }

    /// An organisation's item as `user_id` sees it; nothing when they may not.
    pub async fn org_cipher(&self, user_id: &str, id: &str) -> Result<Option<OrgCipher>> {
        let (user_id, id) = (user_id.to_string(), id.to_string());
        self.sqlite_read(move |conn| {
            let Some(mut cipher) = conn
                .prepare_cached(&format!(
                    "SELECT {CIPHER_COLUMNS} FROM ciphers WHERE id = ?1 AND organization_id IS NOT NULL"
                ))?
                .query_row([&id], cipher_from)
                .optional()?
            else {
                return Ok(None);
            };
            let org = cipher.organization_id.clone().unwrap_or_default();
            let Some((_, member)) = memberships(conn, &user_id)?.into_iter().find(|(o, _)| o.id == org) else {
                return Ok(None);
            };
            let collection_ids = collections_of(conn, &id)?;
            let Some(access) = access_to(&member, &reachable(conn, &member)?, &collection_ids) else { return Ok(None) };
            let preference: Option<(Option<String>, bool)> = conn
                .query_row(
                    "SELECT folder_id, favorite FROM cipher_preferences WHERE cipher_id = ?1 AND user_id = ?2",
                    [&id, &user_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let (folder, favorite) = preference.unwrap_or((None, false));
            if let Some(folder) = &folder
                && crate::travel::hidden_folders(conn, &user_id)?.contains(folder)
            {
                return Ok(None);
            }
            cipher.folder_id = folder;
            cipher.favorite = favorite;
            Ok(Some(OrgCipher { cipher, collection_ids, access, viewer: user_id.clone() }))
        })
        .await
    }

    /// The collections of `org_id` that `user_id` may put items in: reached, and not read-only.
    pub async fn writable_collections(&self, user_id: &str, org_id: &str) -> Result<HashSet<String>> {
        let (user_id, org_id) = (user_id.to_string(), org_id.to_string());
        self.sqlite_read(move |conn| {
            let Some((_, member)) = memberships(conn, &user_id)?.into_iter().find(|(o, _)| o.id == org_id) else {
                return Ok(HashSet::new());
            };
            Ok(reachable(conn, &member)?
                .into_iter()
                .filter(|(_, access)| !access.read_only)
                .map(|(id, _)| id)
                .collect())
        })
        .await
    }

    /// Write an organisation's item, new or changed, and — when given — the collections it is in.
    /// The user's own folder and star for it go with it. Every member's revision moves on; their
    /// user ids come back, for telling them.
    pub async fn save_org_cipher(
        &self,
        user_id: &str,
        mut cipher: Cipher,
        collection_ids: Option<Vec<String>>,
        attachments: Vec<crate::AttachmentKey>,
    ) -> Result<(Cipher, Vec<String>)> {
        let user_id = user_id.to_string();
        let rule = self.version_rule();
        let (saved, users) = self
            .sqlite_write(move |tx| {
                let org = cipher.organization_id.clone().unwrap_or_default();
                let (folder, favorite) = (cipher.folder_id.take(), cipher.favorite);
                cipher.favorite = false;
                cipher.user_id = String::new();
                cipher.revision = clock::now();
                let before = crate::versions::current(tx, &cipher.id)?
                    .filter(|before| before.organization_id.as_deref() == Some(org.as_str()));
                write_cipher(tx, &cipher)?;
                crate::versions::changed(tx, rule, before.as_ref(), &cipher)?;
                crate::attachments::set_keys(tx, &cipher.id, &attachments)?;
                if let Some(ids) = collection_ids {
                    tx.execute("DELETE FROM collection_ciphers WHERE cipher_id = ?1", [&cipher.id])?;
                    for id in ids {
                        tx.execute(
                            "INSERT INTO collection_ciphers (collection_id, cipher_id) \
                             SELECT id, ?2 FROM collections WHERE id = ?1 AND org_id = ?3",
                            params![id, cipher.id, org],
                        )?;
                    }
                }
                set_preference(tx, &cipher.id, &user_id, folder.as_deref(), favorite)?;
                let users = bump_org(tx, &org)?;
                cipher.folder_id = folder;
                cipher.favorite = favorite;
                Ok((cipher, users))
            })
            .await?;
        for user in &users {
            self.forget_session_of(user);
        }
        Ok((saved, users))
    }

    /// A member's own folder and star for an organisation's item.
    pub async fn set_org_preference(
        &self,
        user_id: &str,
        cipher_id: &str,
        folder_id: Option<String>,
        favorite: bool,
    ) -> Result<()> {
        let (owned, cipher_id) = (user_id.to_string(), cipher_id.to_string());
        self.sqlite_write(move |tx| {
            set_preference(tx, &cipher_id, &owned, folder_id.as_deref(), favorite)?;
            bump_revision(tx, &owned)
        })
        .await?;
        self.forget_session_of(user_id);
        Ok(())
    }

    /// Into the trash, out, or gone for good — an organisation's item. The members' user ids.
    pub async fn org_bulk(&self, org_id: &str, id: &str, what: crate::Bulk) -> Result<Vec<String>> {
        let (org_id, id) = (org_id.to_string(), id.to_string());
        let users = self
            .sqlite_write(move |tx| {
                let now = clock::now();
                let sql = match what {
                    crate::Bulk::Trash => {
                        "UPDATE ciphers SET deleted = ?3, revision = ?3 WHERE id = ?1 AND organization_id = ?2"
                    }
                    crate::Bulk::Restore => {
                        "UPDATE ciphers SET deleted = NULL, revision = ?3 WHERE id = ?1 AND organization_id = ?2"
                    }
                    crate::Bulk::Archive => {
                        "UPDATE ciphers SET archived = ?3, revision = ?3 WHERE id = ?1 AND organization_id = ?2"
                    }
                    crate::Bulk::Unarchive => {
                        "UPDATE ciphers SET archived = NULL, revision = ?3 WHERE id = ?1 AND organization_id = ?2"
                    }
                    crate::Bulk::Delete => "DELETE FROM ciphers WHERE id = ?1 AND organization_id = ?2 AND ?3 = ?3",
                };
                if tx.execute(sql, params![id, org_id, now])? == 0 {
                    return Ok(Vec::new());
                }
                bump_org(tx, &org_id)
            })
            .await?;
        for user in &users {
            self.forget_session_of(user);
        }
        Ok(users)
    }

    /// A user's item moves into an organisation, encrypted anew under its key by the client.
    /// Nothing when the item is not the user's.
    pub async fn share_cipher(
        &self,
        user_id: &str,
        cipher: Cipher,
        collection_ids: Vec<String>,
        attachments: Vec<crate::AttachmentKey>,
    ) -> Result<Option<(Cipher, Vec<String>)>> {
        let owned = user_id.to_string();
        let shared = self
            .sqlite_write(move |tx| {
                let theirs: bool = tx.query_row(
                    "SELECT EXISTS (SELECT 1 FROM ciphers WHERE id = ?1 AND user_id = ?2)",
                    [&cipher.id, &owned],
                    |row| row.get(0),
                )?;
                if !theirs {
                    return Ok(None);
                }
                let org = cipher.organization_id.clone().unwrap_or_default();
                let (folder, favorite) = (cipher.folder_id.clone(), cipher.favorite);
                let now = clock::now();
                tx.execute(
                    "UPDATE ciphers SET user_id = NULL, organization_id = ?2, folder_id = NULL, favorite = 0, \
                     type = ?3, name = ?4, notes = ?5, key = ?6, data = ?7, fields = ?8, password_history = ?9, \
                     reprompt = ?10, revision = ?11 WHERE id = ?1",
                    params![
                        cipher.id,
                        org,
                        cipher.kind,
                        cipher.name,
                        cipher.notes,
                        cipher.key,
                        cipher.data,
                        cipher.fields,
                        cipher.password_history,
                        cipher.reprompt,
                        now
                    ],
                )?;
                crate::attachments::set_keys(tx, &cipher.id, &attachments)?;
                // Under the account's keys, which the organisation's members do not have.
                tx.execute("DELETE FROM cipher_versions WHERE cipher_id = ?1", [&cipher.id])?;
                tx.execute("DELETE FROM own_icons WHERE cipher_id = ?1", [&cipher.id])?;
                for id in &collection_ids {
                    tx.execute(
                        "INSERT OR IGNORE INTO collection_ciphers (collection_id, cipher_id) \
                         SELECT id, ?2 FROM collections WHERE id = ?1 AND org_id = ?3",
                        params![id, cipher.id, org],
                    )?;
                }
                set_preference(tx, &cipher.id, &owned, folder.as_deref(), favorite)?;
                bump_revision(tx, &owned)?;
                let users = bump_org(tx, &org)?;
                let mut saved = tx.query_row(
                    &format!("SELECT {CIPHER_COLUMNS} FROM ciphers WHERE id = ?1"),
                    [&cipher.id],
                    cipher_from,
                )?;
                saved.folder_id = folder;
                saved.favorite = favorite;
                Ok(Some((saved, users)))
            })
            .await?;
        if let Some((_, users)) = &shared {
            for user in users {
                self.forget_session_of(user);
            }
        }
        self.forget_session_of(user_id);
        Ok(shared)
    }

    /// Take `user_id` out of every organisation they do not own, the way Bitwarden does when an
    /// emergency contact takes an account over: the contact gets the account, not what other
    /// people shared with it. The ids of everybody whose organisations changed.
    pub async fn leave_organizations(&self, user_id: &str) -> Result<Vec<String>> {
        let user_id = user_id.to_string();
        let changed = self
            .sqlite_write(move |tx| {
                let orgs: Vec<String> = tx
                    .prepare("SELECT org_id FROM org_members WHERE user_id = ?1 AND type <> ?2")?
                    .query_map(params![user_id, OWNER], |row| row.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                tx.execute("DELETE FROM org_members WHERE user_id = ?1 AND type <> ?2", params![user_id, OWNER])?;
                bump_revision(tx, &user_id)?;
                let mut changed = HashSet::from([user_id.clone()]);
                for org in orgs {
                    changed.extend(bump_org(tx, &org)?);
                }
                Ok(changed.into_iter().collect::<Vec<_>>())
            })
            .await?;
        for user in &changed {
            self.forget_session_of(user);
        }
        Ok(changed)
    }

    /// The organisations the user is in (accepted or confirmed), with the membership.
    pub async fn memberships_of(&self, user_id: &str) -> Result<Vec<(Organization, Member)>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| memberships(conn, &user_id)).await
    }

    /// The policies of every organisation the user is in, as the sync lists them.
    pub async fn policies_of(&self, user_id: &str) -> Result<Vec<Policy>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(
                "SELECT p.id, p.org_id, p.type, p.enabled, p.data, p.revision FROM policies p \
                 JOIN org_members m ON m.org_id = p.org_id JOIN organizations o ON o.id = p.org_id \
                 WHERE m.user_id = ?1 AND m.status IN (1, 2) ORDER BY o.name",
            )?
            .query_map([user_id], |row| {
                Ok(Policy {
                    id: row.get(0)?,
                    org_id: row.get(1)?,
                    kind: row.get(2)?,
                    enabled: row.get(3)?,
                    data: row.get(4)?,
                    revision: row.get(5)?,
                })
            })?
            .collect()
        })
        .await
    }

    /// The organisation an item belongs to; none for a person's own (or no such item).
    pub async fn cipher_organization(&self, cipher_id: &str) -> Result<Option<String>> {
        let cipher_id = cipher_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached("SELECT organization_id FROM ciphers WHERE id = ?1")?
                .query_row([cipher_id], |row| row.get::<_, Option<String>>(0))
                .optional()
                .map(Option::flatten)
        })
        .await
    }

    /// Of the organisation's confirmed members, the user ids of those who see an item in
    /// `collections` (R1-8: only they hear its id).
    pub async fn org_members_seeing(&self, org_id: &str, collections: &[String]) -> Result<HashSet<String>> {
        Ok(self.org_reach(org_id).await?.seeing(collections))
    }

    /// What each confirmed member of the organisation reaches, worked out once: a batch of
    /// changed items asks [`OrgReach::seeing`] for every item without reading it all again (R5-6).
    pub async fn org_reach(&self, org_id: &str) -> Result<OrgReach> {
        let org_id = org_id.to_string();
        self.sqlite_read(move |conn| {
            let members: Vec<Member> = conn
                .prepare_cached(&format!(
                    "SELECT {MEMBER_COLUMNS} FROM org_members WHERE org_id = ?1 AND status = 2 AND user_id IS NOT NULL"
                ))?
                .query_map([&org_id], |row| member_from(row, 0))?
                .collect::<rusqlite::Result<_>>()?;
            let mut reach = Vec::with_capacity(members.len());
            for member in members {
                let collections = reachable(conn, &member)?;
                reach.push((member, collections));
            }
            Ok(OrgReach { members: reach })
        })
        .await
    }

    /// The user ids of an organisation's confirmed members.
    pub async fn org_members_users(&self, org_id: &str) -> Result<Vec<String>> {
        let org_id = org_id.to_string();
        self.sqlite_read(move |conn| member_users(conn, &org_id)).await
    }
}

fn set_preference(
    tx: &Transaction<'_>,
    cipher_id: &str,
    user_id: &str,
    folder_id: Option<&str>,
    favorite: bool,
) -> rusqlite::Result<()> {
    // Only a folder of the user's own.
    let folder = match folder_id {
        Some(id) => tx
            .query_row("SELECT id FROM folders WHERE id = ?1 AND user_id = ?2", [id, user_id], |row| {
                row.get::<_, String>(0)
            })
            .optional()?,
        None => None,
    };
    if folder.is_none() && !favorite {
        tx.execute("DELETE FROM cipher_preferences WHERE cipher_id = ?1 AND user_id = ?2", [cipher_id, user_id])?;
    } else {
        tx.execute(
            "INSERT INTO cipher_preferences (cipher_id, user_id, folder_id, favorite) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT (cipher_id, user_id) DO UPDATE SET folder_id = excluded.folder_id, favorite = excluded.favorite",
            params![cipher_id, user_id, folder, favorite],
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::accounts::tests::{new_user, store};
    use crate::vault::tests::cipher;

    /// An organisation with an owner, a member who sees one collection read-only, and an item in
    /// each of two collections and one in none.
    pub(crate) async fn setting(store: &Store) -> (String, String, String) {
        let owner = store.create_user(new_user("owner@example.com")).await.unwrap();
        let member = store.create_user(new_user("member@example.com")).await.unwrap();
        let (o, m) = (owner.id.clone(), member.id.clone());
        store
            .sqlite_write(move |tx| {
                let now = clock::now();
                tx.execute(
                    "INSERT INTO organizations (id, name, created, revision) VALUES ('org', 'Familie', ?1, ?1)",
                    [&now],
                )?;
                for (id, user, kind) in [("m-owner", &o, OWNER), ("m-member", &m, 2)] {
                    tx.execute(
                        "INSERT INTO org_members (id, org_id, user_id, key, status, type, created, revision) \
                         VALUES (?1, 'org', ?2, '4.orgkey', 2, ?3, ?4, ?4)",
                        params![id, user, kind, now],
                    )?;
                }
                for id in ["col-a", "col-b"] {
                    tx.execute(
                        "INSERT INTO collections (id, org_id, name, created, revision) VALUES (?1, 'org', '2.n|n|n', ?2, ?2)",
                        [id, &now],
                    )?;
                }
                tx.execute(
                    "INSERT INTO collection_members (collection_id, member_id, read_only) VALUES ('col-a', 'm-member', 1)",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        for (id, collection) in [("in-a", Some("col-a")), ("in-b", Some("col-b")), ("in-none", None)] {
            let mut item = cipher("", id, None);
            item.organization_id = Some("org".into());
            store
                .save_org_cipher(&owner.id, item, Some(collection.into_iter().map(Into::into).collect()), Vec::new())
                .await
                .unwrap();
        }
        (owner.id, member.id, "org".into())
    }

    #[tokio::test]
    async fn leaving_takes_every_organisation_but_owned_ones() {
        let (store, _dir) = store();
        let (owner, member, _) = setting(&store).await;
        let changed = store.leave_organizations(&member).await.unwrap();
        assert!(changed.contains(&owner) && changed.contains(&member));
        let theirs = store.org_vault(&member).await.unwrap();
        assert!(theirs.memberships.is_empty() && theirs.ciphers.is_empty());
        store.leave_organizations(&owner).await.unwrap();
        assert_eq!(store.org_vault(&owner).await.unwrap().memberships.len(), 1, "an owner stays");
    }

    #[tokio::test]
    async fn a_member_sees_what_their_collections_give_them() {
        let (store, _dir) = store();
        let (owner, member, _) = setting(&store).await;
        let theirs = store.org_vault(&member).await.unwrap();
        assert_eq!(theirs.memberships.len(), 1);
        assert_eq!(theirs.collections.len(), 1);
        assert_eq!(theirs.ciphers.iter().map(|c| c.cipher.id.as_str()).collect::<Vec<_>>(), ["in-a"]);
        assert!(theirs.ciphers[0].access.read_only);
        let everything = store.org_vault(&owner).await.unwrap();
        assert_eq!(everything.ciphers.len(), 3, "the owner sees items in no collection too");
        assert_eq!(everything.collections.len(), 2);
        assert!(store.org_cipher(&member, "in-b").await.unwrap().is_none());
        assert!(store.writable_collections(&member, "org").await.unwrap().is_empty());
        assert_eq!(store.writable_collections(&owner, "org").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn folders_and_stars_are_each_member_s_own() {
        let (store, _dir) = store();
        let (owner, member, _) = setting(&store).await;
        let folder = store.save_folder(&member, None, "2.f|f|f".into()).await.unwrap().unwrap();
        store.set_org_preference(&member, "in-a", Some(folder.id.clone()), true).await.unwrap();
        let mine = store.org_cipher(&member, "in-a").await.unwrap().unwrap();
        assert_eq!((mine.cipher.folder_id.as_deref(), mine.cipher.favorite), (Some(folder.id.as_str()), true));
        let theirs = store.org_cipher(&owner, "in-a").await.unwrap().unwrap();
        assert_eq!((theirs.cipher.folder_id, theirs.cipher.favorite), (None, false));
        // Somebody else's folder does not stick.
        store.set_org_preference(&owner, "in-a", Some(folder.id), false).await.unwrap();
        assert!(store.org_cipher(&owner, "in-a").await.unwrap().unwrap().cipher.folder_id.is_none());
    }

    #[tokio::test]
    async fn a_personal_item_moves_into_the_organisation() {
        let (store, _dir) = store();
        let (owner, member, org) = setting(&store).await;
        store.save_cipher(cipher(&owner, "mine", None)).await.unwrap();
        let mut moved = cipher(&owner, "mine", None);
        moved.organization_id = Some(org.clone());
        moved.name = "2.org|org|org".into();
        assert!(store.share_cipher(&member, moved.clone(), vec!["col-a".into()], Vec::new()).await.unwrap().is_none());
        let (saved, users) =
            store.share_cipher(&owner, moved, vec!["col-a".into()], Vec::new()).await.unwrap().unwrap();
        assert_eq!(saved.organization_id.as_deref(), Some(org.as_str()));
        assert_eq!(users.len(), 2);
        assert!(store.cipher(&owner, "mine").await.unwrap().is_none(), "not personal any more");
        assert!(store.org_cipher(&member, "mine").await.unwrap().is_some(), "in the member's collection");
    }

    #[tokio::test]
    async fn the_sweep_takes_an_organisation_s_old_trash_too() {
        let (store, _dir) = store();
        let (owner, member, org) = setting(&store).await;
        store.org_bulk(&org, "in-a", crate::Bulk::Trash).await.unwrap();
        store
            .sqlite_write(|tx| {
                tx.execute("UPDATE ciphers SET deleted = '2020-01-01T00:00:00.000000Z' WHERE id = 'in-a'", [])
            })
            .await
            .unwrap();
        let before = store.user(&member).await.unwrap().unwrap().revision;
        store.sweep(90).await.unwrap();
        assert!(store.org_cipher(&owner, "in-a").await.unwrap().is_none());
        assert_ne!(store.user(&member).await.unwrap().unwrap().revision, before, "the members hear of it");
    }
}
