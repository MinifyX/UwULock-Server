//! Making and managing organisations: families since Stufe 4d, Stufe 5's organisations on the
//! same ground. An organisation, its members (invited, accepted, confirmed), its collections and
//! who may do what in them.
//!
//! Everything that has to hold across a change is checked in the same transaction that makes
//! it: the seats a family has, the families one account may own, that an organisation always
//! keeps an owner. Whose revision moves is everybody who sees a difference in their sync; their
//! user ids come back, for telling them.

use crate::accounts::bump_revision;
use crate::organizations::{
    ACCEPTED, Access, CONFIRMED, Collection, INVITED, MEMBER_COLUMNS, Member, ORG_COLUMNS, OWNER, Organization, USER,
    bump_org, collection_from, member_from, member_users, org_from,
};
use crate::{Result, Store, clock, normalize_email};
use rusqlite::{OptionalExtension, Transaction, params};
use std::collections::HashSet;

/// Why a change to an organisation was not made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgRefusal {
    /// No such member, collection or organisation — or not in this one.
    NotFound,
    /// It would leave the organisation without a confirmed owner.
    LastOwner,
    /// More members than the organisation has seats for.
    Seats,
    /// The account owns as many organisations of this kind as it may.
    Owned,
    /// This address is a member or invited already.
    Exists(String),
    /// Not in the state the step needs: accepting an accepted member, confirming an invited one.
    State,
}

pub type Refused<T> = std::result::Result<T, OrgRefusal>;

/// A new organisation, with its first owner and first collection.
#[derive(Debug, Clone)]
pub struct NewOrganization {
    pub name: String,
    pub billing_email: String,
    pub plan_type: i64,
    pub public_key: String,
    pub private_key: String,
    pub owner_id: String,
    /// The organisation key, wrapped for the owner's public key.
    pub owner_key: String,
    /// The first collection's name, encrypted under the organisation key.
    pub collection_name: Option<String>,
}

/// A member as the organisation's pages list them.
#[derive(Debug, Clone)]
pub struct MemberDetails {
    pub member: Member,
    /// The account's name and address; an invited member has only the address invited.
    pub name: Option<String>,
    pub email: String,
    pub avatar_color: Option<String>,
    pub two_factor: bool,
    pub collections: Vec<(String, Access)>,
}

/// An organisation for the admin portal: no vault content, only who is in it.
#[derive(Debug, Clone)]
pub struct OrgSummary {
    pub organization: Organization,
    pub members: i64,
    pub owners: Vec<String>,
}

/// A member's access to one collection, by member id.
pub type MemberAccess = (String, Access);

fn organization_in(conn: &rusqlite::Connection, id: &str) -> rusqlite::Result<Option<Organization>> {
    conn.prepare_cached(&format!("SELECT {ORG_COLUMNS} FROM organizations WHERE id = ?1"))?
        .query_row([id], org_from)
        .optional()
}

fn member_in(conn: &rusqlite::Connection, org_id: &str, id: &str) -> rusqlite::Result<Option<Member>> {
    conn.prepare_cached(&format!("SELECT {MEMBER_COLUMNS} FROM org_members WHERE id = ?1 AND org_id = ?2"))?
        .query_row([id, org_id], |row| member_from(row, 0))
        .optional()
}

/// Confirmed owners of `org_id` other than `member_id`.
fn other_owners(conn: &rusqlite::Connection, org_id: &str, member_id: &str) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM org_members WHERE org_id = ?1 AND id <> ?2 AND type = ?3 AND status = ?4",
        params![org_id, member_id, OWNER, CONFIRMED],
        |row| row.get(0),
    )
}

/// How many organisations of `plan_type` `user_id` owns (confirmed).
fn owned(conn: &rusqlite::Connection, user_id: &str, plan_type: i64) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM org_members m JOIN organizations o ON o.id = m.org_id \
         WHERE m.user_id = ?1 AND m.type = ?2 AND m.status = ?3 AND o.plan_type = ?4",
        params![user_id, OWNER, CONFIRMED, plan_type],
        |row| row.get(0),
    )
}

/// Set which collections a member reaches, and how: only collections of the organisation count.
fn set_member_collections(
    tx: &Transaction<'_>,
    org_id: &str,
    member_id: &str,
    collections: &[MemberAccess],
) -> rusqlite::Result<()> {
    tx.execute("DELETE FROM collection_members WHERE member_id = ?1", [member_id])?;
    for (id, access) in collections {
        tx.execute(
            "INSERT OR REPLACE INTO collection_members (collection_id, member_id, read_only, hide_passwords, manage) \
             SELECT id, ?2, ?3, ?4, ?5 FROM collections WHERE id = ?1 AND org_id = ?6",
            params![id, member_id, access.read_only, access.hide_passwords, access.manage, org_id],
        )?;
    }
    Ok(())
}

/// Set who reaches a collection, and how: only members of the organisation count.
fn set_collection_members(
    tx: &Transaction<'_>,
    org_id: &str,
    collection_id: &str,
    users: &[MemberAccess],
) -> rusqlite::Result<()> {
    tx.execute("DELETE FROM collection_members WHERE collection_id = ?1", [collection_id])?;
    for (member, access) in users {
        tx.execute(
            "INSERT OR REPLACE INTO collection_members (collection_id, member_id, read_only, hide_passwords, manage) \
             SELECT ?1, id, ?3, ?4, ?5 FROM org_members WHERE id = ?2 AND org_id = ?6",
            params![collection_id, member, access.read_only, access.hide_passwords, access.manage, org_id],
        )?;
    }
    Ok(())
}

fn access_from(row: &rusqlite::Row<'_>, at: usize) -> rusqlite::Result<Access> {
    Ok(Access { read_only: row.get(at)?, hide_passwords: row.get(at + 1)?, manage: row.get(at + 2)? })
}

/// Take a member out: their row, their own filing of the organisation's items. Everybody who
/// saw them (and they themselves) hear of it.
fn remove(tx: &Transaction<'_>, org_id: &str, member: &Member) -> rusqlite::Result<Vec<String>> {
    let mut users: HashSet<String> = member_users(tx, org_id)?.into_iter().collect();
    tx.execute("DELETE FROM org_members WHERE id = ?1", [&member.id])?;
    if let Some(user) = &member.user_id {
        tx.execute(
            "DELETE FROM cipher_preferences WHERE user_id = ?1 AND cipher_id IN \
             (SELECT id FROM ciphers WHERE organization_id = ?2)",
            [user, org_id],
        )?;
        users.insert(user.clone());
    }
    for user in &users {
        bump_revision(tx, user)?;
    }
    Ok(users.into_iter().collect())
}

impl Store {
    fn forget_all(&self, users: &[String]) {
        for user in users {
            self.forget_session_of(user);
        }
    }

    /// Make an organisation: the owner confirmed in it, and the first collection. Refused with
    /// [`OrgRefusal::Owned`] when the owner has `most` of this kind already.
    pub async fn create_organization(&self, new: NewOrganization, most: i64) -> Result<Refused<Organization>> {
        let owner = new.owner_id.clone();
        let made = self
            .sqlite_write(move |tx| {
                if owned(tx, &new.owner_id, new.plan_type)? >= most {
                    return Ok(Err(OrgRefusal::Owned));
                }
                let now = clock::now();
                let id = uuid::Uuid::new_v4().to_string();
                tx.execute(
                    "INSERT INTO organizations (id, name, billing_email, public_key, private_key, plan_type, created, \
                     revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                    params![id, new.name, new.billing_email, new.public_key, new.private_key, new.plan_type, now],
                )?;
                tx.execute(
                    "INSERT INTO org_members (id, org_id, user_id, key, status, type, created, revision) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                    params![uuid::Uuid::new_v4().to_string(), id, new.owner_id, new.owner_key, CONFIRMED, OWNER, now],
                )?;
                if let Some(name) = &new.collection_name {
                    tx.execute(
                        "INSERT INTO collections (id, org_id, name, created, revision) VALUES (?1, ?2, ?3, ?4, ?4)",
                        params![uuid::Uuid::new_v4().to_string(), id, name, now],
                    )?;
                }
                bump_revision(tx, &new.owner_id)?;
                Ok(Ok(organization_in(tx, &id)?.expect("just made")))
            })
            .await?;
        self.forget_session_of(&owner);
        Ok(made)
    }

    pub async fn organization(&self, id: &str) -> Result<Option<Organization>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| organization_in(conn, &id)).await
    }

    /// `user_id`'s membership of `org_id`, in whatever state.
    pub async fn org_membership(&self, org_id: &str, user_id: &str) -> Result<Option<(Organization, Member)>> {
        let (org_id, user_id) = (org_id.to_string(), user_id.to_string());
        self.sqlite_read(move |conn| {
            let Some(org) = organization_in(conn, &org_id)? else { return Ok(None) };
            let member = conn
                .prepare_cached(&format!(
                    "SELECT {MEMBER_COLUMNS} FROM org_members WHERE org_id = ?1 AND user_id = ?2"
                ))?
                .query_row([&org_id, &user_id], |row| member_from(row, 0))
                .optional()?;
            Ok(member.map(|member| (org, member)))
        })
        .await
    }

    pub async fn org_member(&self, org_id: &str, id: &str) -> Result<Option<Member>> {
        let (org_id, id) = (org_id.to_string(), id.to_string());
        self.sqlite_read(move |conn| member_in(conn, &org_id, &id)).await
    }

    /// How many organisations of `plan_type` the account owns.
    pub async fn owned_organizations(&self, user_id: &str, plan_type: i64) -> Result<i64> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| owned(conn, &user_id, plan_type)).await
    }

    /// Organisations `user_id` is the only confirmed owner of while others are in them: an
    /// account that goes would leave them without anybody to manage them. Their names.
    pub async fn sole_owner_of(&self, user_id: &str) -> Result<Vec<String>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(
                "SELECT o.name FROM org_members m JOIN organizations o ON o.id = m.org_id \
                 WHERE m.user_id = ?1 AND m.type = 0 AND m.status = 2 \
                 AND NOT EXISTS (SELECT 1 FROM org_members x WHERE x.org_id = m.org_id AND x.id <> m.id \
                     AND x.type = 0 AND x.status = 2) \
                 AND EXISTS (SELECT 1 FROM org_members y WHERE y.org_id = m.org_id AND y.id <> m.id)",
            )?
            .query_map([&user_id], |row| row.get(0))?
            .collect()
        })
        .await
    }

    /// Everybody in an organisation, invited ones too, with the collections they reach directly.
    pub async fn member_details(&self, org_id: &str) -> Result<Vec<MemberDetails>> {
        let org_id = org_id.to_string();
        self.sqlite_read(move |conn| {
            let members = MEMBER_COLUMNS.split(", ").map(|c| format!("m.{c}")).collect::<Vec<_>>().join(", ");
            let rows = conn
                .prepare_cached(&format!(
                    "SELECT {members}, u.name, u.email, u.avatar_color, \
                     EXISTS (SELECT 1 FROM two_factor t WHERE t.user_id = m.user_id AND t.enabled) \
                     FROM org_members m LEFT JOIN users u ON u.id = m.user_id WHERE m.org_id = ?1 \
                     ORDER BY m.type, coalesce(u.email, m.email)"
                ))?
                .query_map([&org_id], |row| {
                    let member = member_from(row, 0)?;
                    let email: Option<String> = row.get(14)?;
                    Ok(MemberDetails {
                        email: email.or_else(|| member.email.clone()).unwrap_or_default(),
                        member,
                        name: row.get(13)?,
                        avatar_color: row.get(15)?,
                        two_factor: row.get(16)?,
                        collections: Vec::new(),
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut reach = conn.prepare_cached(
                "SELECT cm.collection_id, cm.read_only, cm.hide_passwords, cm.manage FROM collection_members cm \
                 WHERE cm.member_id = ?1",
            )?;
            rows.into_iter()
                .map(|mut details| {
                    details.collections = reach
                        .query_map([&details.member.id], |row| Ok((row.get(0)?, access_from(row, 1)?)))?
                        .collect::<rusqlite::Result<_>>()?;
                    Ok(details)
                })
                .collect()
        })
        .await
    }

    pub async fn rename_organization(&self, id: &str, name: String, billing_email: String) -> Result<Vec<String>> {
        let id = id.to_string();
        let users = self
            .sqlite_write(move |tx| {
                tx.execute(
                    "UPDATE organizations SET name = ?2, billing_email = ?3, revision = ?4 WHERE id = ?1",
                    params![id, name, billing_email, clock::now()],
                )?;
                bump_org(tx, &id)
            })
            .await?;
        self.forget_all(&users);
        Ok(users)
    }

    /// The organisation and everything in it, its items too. Who was in it.
    pub async fn delete_organization(&self, id: &str) -> Result<Vec<String>> {
        let id = id.to_string();
        let users = self
            .sqlite_write(move |tx| {
                let users: Vec<String> = tx
                    .prepare("SELECT user_id FROM org_members WHERE org_id = ?1 AND user_id IS NOT NULL")?
                    .query_map([&id], |row| row.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                tx.execute("DELETE FROM organizations WHERE id = ?1", [&id])?;
                for user in &users {
                    bump_revision(tx, user)?;
                }
                Ok(users)
            })
            .await?;
        self.forget_all(&users);
        Ok(users)
    }

    /// Invite `emails` as `kind`, reaching `collections`. Refused as a whole when that makes more
    /// than `seats` members (invited ones count), or an address is in already.
    pub async fn invite_members(
        &self,
        org_id: &str,
        emails: Vec<String>,
        kind: i64,
        collections: Vec<MemberAccess>,
        seats: i64,
    ) -> Result<Refused<Vec<Member>>> {
        let org_id = org_id.to_string();
        self.sqlite_write(move |tx| {
            let count: i64 =
                tx.query_row("SELECT count(*) FROM org_members WHERE org_id = ?1", [&org_id], |row| row.get(0))?;
            if count + emails.len() as i64 > seats {
                return Ok(Err(OrgRefusal::Seats));
            }
            let now = clock::now();
            let mut invited = Vec::new();
            for email in emails {
                let email = normalize_email(&email);
                let there: bool = tx.query_row(
                    "SELECT EXISTS (SELECT 1 FROM org_members WHERE org_id = ?1 AND email = ?2) \
                     OR EXISTS (SELECT 1 FROM org_members m JOIN users u ON u.id = m.user_id \
                         WHERE m.org_id = ?1 AND u.email = ?2)",
                    [&org_id, &email],
                    |row| row.get(0),
                )?;
                if there {
                    return Ok(Err(OrgRefusal::Exists(email)));
                }
                let id = uuid::Uuid::new_v4().to_string();
                tx.execute(
                    "INSERT INTO org_members (id, org_id, email, status, type, created, revision) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                    params![id, org_id, email, INVITED, kind, now],
                )?;
                if kind == USER {
                    set_member_collections(tx, &org_id, &id, &collections)?;
                }
                invited.push(member_in(tx, &org_id, &id)?.expect("just made"));
            }
            Ok(Ok(invited))
        })
        .await
    }

    /// Pending invitations to `email`, with their organisation.
    pub async fn org_invitations_for(&self, email: &str) -> Result<Vec<(Organization, Member)>> {
        let email = normalize_email(email);
        self.sqlite_read(move |conn| {
            let columns = ORG_COLUMNS.split(", ").map(|c| format!("o.{c}")).collect::<Vec<_>>().join(", ");
            let members = MEMBER_COLUMNS.split(", ").map(|c| format!("m.{c}")).collect::<Vec<_>>().join(", ");
            conn.prepare_cached(&format!(
                "SELECT {columns}, {members} FROM org_members m JOIN organizations o ON o.id = m.org_id \
                 WHERE m.email = ?1 AND m.status = ?2 ORDER BY m.created"
            ))?
            .query_map(params![email, INVITED], |row| Ok((org_from(row)?, member_from(row, 8)?)))?
            .collect()
        })
        .await
    }

    /// The account with `email` takes the invitation `id`. Refused when it is no invitation (any
    /// more), not for this address, or the account is in the organisation already.
    pub async fn accept_member(&self, org_id: &str, id: &str, user_id: &str, email: &str) -> Result<Refused<Member>> {
        let (org_id, id, user, email) =
            (org_id.to_string(), id.to_string(), user_id.to_string(), normalize_email(email));
        let accepted = self
            .sqlite_write(move |tx| {
                let Some(member) = member_in(tx, &org_id, &id)? else { return Ok(Err(OrgRefusal::NotFound)) };
                if member.status != INVITED || member.email.as_deref() != Some(email.as_str()) {
                    return Ok(Err(OrgRefusal::State));
                }
                let already: bool = tx.query_row(
                    "SELECT EXISTS (SELECT 1 FROM org_members WHERE org_id = ?1 AND user_id = ?2)",
                    [&org_id, &user],
                    |row| row.get(0),
                )?;
                if already {
                    return Ok(Err(OrgRefusal::Exists(email)));
                }
                tx.execute(
                    "UPDATE org_members SET user_id = ?2, status = ?3, email = NULL, revision = ?4 WHERE id = ?1",
                    params![id, user, ACCEPTED, clock::now()],
                )?;
                bump_revision(tx, &user)?;
                Ok(Ok(member_in(tx, &org_id, &id)?.expect("still there")))
            })
            .await?;
        self.forget_session_of(user_id);
        Ok(accepted)
    }

    /// The public keys of accepted members (by member id), for wrapping the organisation key.
    pub async fn member_public_keys(&self, org_id: &str, ids: Vec<String>) -> Result<Vec<(String, String, String)>> {
        let org_id = org_id.to_string();
        self.sqlite_read(move |conn| {
            let mut query = conn.prepare_cached(
                "SELECT m.id, u.id, u.public_key FROM org_members m JOIN users u ON u.id = m.user_id \
                 WHERE m.org_id = ?1 AND m.id = ?2 AND u.public_key IS NOT NULL",
            )?;
            let mut found = Vec::new();
            for id in ids {
                if let Some(row) =
                    query.query_row([&org_id, &id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).optional()?
                {
                    found.push(row);
                }
            }
            Ok(found)
        })
        .await
    }

    /// Confirm an accepted member with the organisation key wrapped for them. The member's
    /// revision moves, and everybody's who sees the organisation.
    pub async fn confirm_member(&self, org_id: &str, id: &str, key: String) -> Result<Refused<(Member, Vec<String>)>> {
        let (org_id, id) = (org_id.to_string(), id.to_string());
        let done = self
            .sqlite_write(move |tx| {
                let Some(member) = member_in(tx, &org_id, &id)? else { return Ok(Err(OrgRefusal::NotFound)) };
                if member.status != ACCEPTED || member.user_id.is_none() {
                    return Ok(Err(OrgRefusal::State));
                }
                tx.execute(
                    "UPDATE org_members SET status = ?2, key = ?3, revision = ?4 WHERE id = ?1",
                    params![id, CONFIRMED, key, clock::now()],
                )?;
                let users = bump_org(tx, &org_id)?;
                Ok(Ok((member_in(tx, &org_id, &id)?.expect("still there"), users)))
            })
            .await?;
        if let Ok((_, users)) = &done {
            self.forget_all(users);
        }
        Ok(done)
    }

    /// A member's role and collections. An organisation keeps a confirmed owner; making somebody
    /// an owner counts against their `most` owned organisations of this kind.
    pub async fn update_member(
        &self,
        org_id: &str,
        id: &str,
        kind: i64,
        collections: Option<Vec<MemberAccess>>,
        most: i64,
    ) -> Result<Refused<(Member, Vec<String>)>> {
        let (org_id, id) = (org_id.to_string(), id.to_string());
        let done = self
            .sqlite_write(move |tx| {
                let Some(member) = member_in(tx, &org_id, &id)? else { return Ok(Err(OrgRefusal::NotFound)) };
                if member.kind == OWNER && kind != OWNER && other_owners(tx, &org_id, &id)? == 0 {
                    return Ok(Err(OrgRefusal::LastOwner));
                }
                if kind == OWNER && member.kind != OWNER {
                    let plan: i64 =
                        tx.query_row("SELECT plan_type FROM organizations WHERE id = ?1", [&org_id], |row| row.get(0))?;
                    if let Some(user) = &member.user_id
                        && owned(tx, user, plan)? >= most
                    {
                        return Ok(Err(OrgRefusal::Owned));
                    }
                }
                tx.execute(
                    "UPDATE org_members SET type = ?2, access_all = 0, revision = ?3 WHERE id = ?1",
                    params![id, kind, clock::now()],
                )?;
                if let Some(collections) = &collections {
                    set_member_collections(tx, &org_id, &id, collections)?;
                }
                let mut users = bump_org(tx, &org_id)?;
                if let Some(user) = &member.user_id
                    && !users.contains(user)
                {
                    bump_revision(tx, user)?;
                    users.push(user.clone());
                }
                Ok(Ok((member_in(tx, &org_id, &id)?.expect("still there"), users)))
            })
            .await?;
        if let Ok((_, users)) = &done {
            self.forget_all(users);
        }
        Ok(done)
    }

    /// Take a member out of the organisation (an owner removes them, or they leave). Never the
    /// last confirmed owner.
    pub async fn remove_member(&self, org_id: &str, id: &str) -> Result<Refused<(Member, Vec<String>)>> {
        let (org_id, id) = (org_id.to_string(), id.to_string());
        let done = self
            .sqlite_write(move |tx| {
                let Some(member) = member_in(tx, &org_id, &id)? else { return Ok(Err(OrgRefusal::NotFound)) };
                if member.kind == OWNER && member.status == CONFIRMED && other_owners(tx, &org_id, &id)? == 0 {
                    return Ok(Err(OrgRefusal::LastOwner));
                }
                let users = remove(tx, &org_id, &member)?;
                Ok(Ok((member, users)))
            })
            .await?;
        if let Ok((_, users)) = &done {
            self.forget_all(users);
        }
        Ok(done)
    }

    /// Collections of an organisation, with who reaches each directly.
    pub async fn collection_details(&self, org_id: &str) -> Result<Vec<(Collection, Vec<MemberAccess>)>> {
        let org_id = org_id.to_string();
        self.sqlite_read(move |conn| {
            let collections = conn
                .prepare_cached(
                    "SELECT id, org_id, name, external_id, created, revision FROM collections WHERE org_id = ?1",
                )?
                .query_map([&org_id], collection_from)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut users = conn.prepare_cached(
                "SELECT member_id, read_only, hide_passwords, manage FROM collection_members WHERE collection_id = ?1",
            )?;
            collections
                .into_iter()
                .map(|collection| {
                    let list = users
                        .query_map([&collection.id], |row| Ok((row.get(0)?, access_from(row, 1)?)))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok((collection, list))
                })
                .collect()
        })
        .await
    }

    /// A new collection (`id` none) or a change to one: its name, and — when given — who reaches
    /// it. Nothing when `id` is not a collection of the organisation.
    pub async fn save_collection(
        &self,
        org_id: &str,
        id: Option<String>,
        name: String,
        external_id: Option<String>,
        users: Option<Vec<MemberAccess>>,
    ) -> Result<Option<(Collection, Vec<String>)>> {
        let org_id = org_id.to_string();
        let done = self
            .sqlite_write(move |tx| {
                let now = clock::now();
                let id = match id {
                    Some(id) => {
                        let changed = tx.execute(
                            "UPDATE collections SET name = ?3, external_id = ?4, revision = ?5 WHERE id = ?1 AND org_id = ?2",
                            params![id, org_id, name, external_id, now],
                        )?;
                        if changed == 0 {
                            return Ok(None);
                        }
                        id
                    }
                    None => {
                        let id = uuid::Uuid::new_v4().to_string();
                        tx.execute(
                            "INSERT INTO collections (id, org_id, name, external_id, created, revision) \
                             VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                            params![id, org_id, name, external_id, now],
                        )?;
                        id
                    }
                };
                if let Some(users) = &users {
                    set_collection_members(tx, &org_id, &id, users)?;
                }
                let users = bump_org(tx, &org_id)?;
                let collection = tx.query_row(
                    "SELECT id, org_id, name, external_id, created, revision FROM collections WHERE id = ?1",
                    [&id],
                    collection_from,
                )?;
                Ok(Some((collection, users)))
            })
            .await?;
        if let Some((_, users)) = &done {
            self.forget_all(users);
        }
        Ok(done)
    }

    /// Collections gone; their items stay in the organisation (owners still see them). How many
    /// were deleted, and who hears of it.
    pub async fn delete_collections(&self, org_id: &str, ids: Vec<String>) -> Result<(usize, Vec<String>)> {
        let org_id = org_id.to_string();
        let done = self
            .sqlite_write(move |tx| {
                let mut deleted = 0;
                for id in &ids {
                    deleted += tx.execute("DELETE FROM collections WHERE id = ?1 AND org_id = ?2", [id, &org_id])?;
                }
                let users = if deleted > 0 { bump_org(tx, &org_id)? } else { Vec::new() };
                Ok((deleted, users))
            })
            .await?;
        self.forget_all(&done.1);
        Ok(done)
    }

    /// Every organisation, for the admin portal.
    pub async fn organization_summaries(&self) -> Result<Vec<OrgSummary>> {
        self.sqlite_read(|conn| {
            let orgs = conn
                .prepare(&format!("SELECT {ORG_COLUMNS} FROM organizations ORDER BY name"))?
                .query_map([], org_from)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut members = conn.prepare_cached("SELECT count(*) FROM org_members WHERE org_id = ?1")?;
            let mut owners = conn.prepare_cached(
                "SELECT u.email FROM org_members m JOIN users u ON u.id = m.user_id \
                 WHERE m.org_id = ?1 AND m.type = 0 AND m.status = 2 ORDER BY u.email",
            )?;
            orgs.into_iter()
                .map(|organization| {
                    let count = members.query_row([&organization.id], |row| row.get(0))?;
                    let list =
                        owners.query_map([&organization.id], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
                    Ok(OrgSummary { organization, members: count, owners: list })
                })
                .collect()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::{new_user, store};

    fn access(read_only: bool) -> Access {
        Access { read_only, hide_passwords: false, manage: false }
    }

    async fn family(store: &Store, owner: &str) -> Organization {
        let new = NewOrganization {
            name: "Familie".into(),
            billing_email: "nyu@example.com".into(),
            plan_type: crate::organizations::FAMILY,
            public_key: "MIIB".into(),
            private_key: "2.p|p|p".into(),
            owner_id: owner.into(),
            owner_key: "4.key".into(),
            collection_name: Some("2.c|c|c".into()),
        };
        store.create_organization(new, 1).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn a_family_from_invitation_to_confirmed_member() {
        let (store, _dir) = store();
        let owner = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let mio = store.create_user(new_user("mio@example.com")).await.unwrap();
        let org = family(&store, &owner.id).await;
        assert!(org.is_family());
        let again = NewOrganization {
            name: "Zweite".into(),
            billing_email: String::new(),
            plan_type: crate::organizations::FAMILY,
            public_key: String::new(),
            private_key: String::new(),
            owner_id: owner.id.clone(),
            owner_key: String::new(),
            collection_name: None,
        };
        assert_eq!(store.create_organization(again, 1).await.unwrap(), Err(OrgRefusal::Owned));

        let (collection, _) = store.collection_details(&org.id).await.unwrap().remove(0);
        let invited = store
            .invite_members(
                &org.id,
                vec!["Mio@Example.com".into()],
                USER,
                vec![(collection.id.clone(), access(true))],
                6,
            )
            .await
            .unwrap()
            .unwrap();
        let id = invited[0].id.clone();
        assert_eq!(invited[0].email.as_deref(), Some("mio@example.com"));
        assert_eq!(
            store.invite_members(&org.id, vec!["mio@example.com".into()], USER, Vec::new(), 6).await.unwrap(),
            Err(OrgRefusal::Exists("mio@example.com".into()))
        );
        assert_eq!(
            store
                .invite_members(&org.id, vec!["a@example.com".into(), "b@example.com".into()], USER, Vec::new(), 3)
                .await
                .unwrap(),
            Err(OrgRefusal::Seats)
        );
        assert_eq!(store.org_invitations_for("mio@example.com").await.unwrap().len(), 1);

        // Only the address it went to.
        assert_eq!(
            store.accept_member(&org.id, &id, &owner.id, "nyu@example.com").await.unwrap(),
            Err(OrgRefusal::State)
        );
        let accepted = store.accept_member(&org.id, &id, &mio.id, "mio@example.com").await.unwrap().unwrap();
        assert_eq!((accepted.status, accepted.user_id.as_deref()), (ACCEPTED, Some(mio.id.as_str())));
        assert!(store.org_vault(&mio.id).await.unwrap().collections.is_empty(), "nothing before confirming");

        let keys = store.member_public_keys(&org.id, vec![id.clone()]).await.unwrap();
        assert_eq!(keys.len(), 1);
        let (confirmed, users) = store.confirm_member(&org.id, &id, "4.forMio".into()).await.unwrap().unwrap();
        assert_eq!(confirmed.status, CONFIRMED);
        assert!(users.contains(&mio.id) && users.contains(&owner.id));
        let theirs = store.org_vault(&mio.id).await.unwrap();
        assert_eq!(theirs.collections.len(), 1);
        assert!(theirs.collections[0].1.read_only);
        assert_eq!(store.confirm_member(&org.id, &id, "4.again".into()).await.unwrap(), Err(OrgRefusal::State));

        let details = store.member_details(&org.id).await.unwrap();
        assert_eq!(details.len(), 2);
        assert_eq!(details[1].email, "mio@example.com");
        assert_eq!(details[1].collections, vec![(collection.id.clone(), access(true))]);
    }

    #[tokio::test]
    async fn a_family_keeps_an_owner() {
        let (store, _dir) = store();
        let owner = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let mio = store.create_user(new_user("mio@example.com")).await.unwrap();
        let org = family(&store, &owner.id).await;
        let me = store.org_membership(&org.id, &owner.id).await.unwrap().unwrap().1;
        assert_eq!(store.update_member(&org.id, &me.id, USER, None, 1).await.unwrap(), Err(OrgRefusal::LastOwner));
        assert_eq!(store.remove_member(&org.id, &me.id).await.unwrap(), Err(OrgRefusal::LastOwner));
        assert!(store.sole_owner_of(&owner.id).await.unwrap().is_empty(), "alone in it: nobody is left behind");

        let id = store.invite_members(&org.id, vec![mio.email.clone()], USER, Vec::new(), 6).await.unwrap().unwrap()[0]
            .id
            .clone();
        store.accept_member(&org.id, &id, &mio.id, &mio.email).await.unwrap().unwrap();
        store.confirm_member(&org.id, &id, "4.k".into()).await.unwrap().unwrap();
        assert_eq!(store.sole_owner_of(&owner.id).await.unwrap(), vec!["Familie".to_string()]);

        // Handing it over: the member becomes an owner, then the first one may go.
        store.update_member(&org.id, &id, OWNER, None, 1).await.unwrap().unwrap();
        store.remove_member(&org.id, &me.id).await.unwrap().unwrap();
        assert!(store.org_membership(&org.id, &owner.id).await.unwrap().is_none());
        let summaries = store.organization_summaries().await.unwrap();
        assert_eq!((summaries[0].members, summaries[0].owners.clone()), (1, vec![mio.email.clone()]));

        let users = store.delete_organization(&org.id).await.unwrap();
        assert_eq!(users, vec![mio.id.clone()]);
        assert!(store.organization(&org.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn collections_come_and_go_with_their_members() {
        let (store, _dir) = store();
        let owner = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let org = family(&store, &owner.id).await;
        let other = family(&store, &store.create_user(new_user("rin@example.com")).await.unwrap().id).await;
        let id =
            store.invite_members(&org.id, vec!["mio@example.com".into()], USER, Vec::new(), 6).await.unwrap().unwrap()
                [0]
            .id
            .clone();
        let (made, _) = store
            .save_collection(&org.id, None, "2.n|n|n".into(), None, Some(vec![(id.clone(), access(false))]))
            .await
            .unwrap()
            .unwrap();
        let details = store.collection_details(&org.id).await.unwrap();
        assert_eq!(details.iter().find(|(c, _)| c.id == made.id).unwrap().1, vec![(id.clone(), access(false))]);
        // Not through another organisation.
        assert!(
            store
                .save_collection(&other.id, Some(made.id.clone()), "2.x|x|x".into(), None, None)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(store.delete_collections(&other.id, vec![made.id.clone()]).await.unwrap().0, 0);
        assert_eq!(store.delete_collections(&org.id, vec![made.id]).await.unwrap().0, 1);
        assert_eq!(store.collection_details(&org.id).await.unwrap().len(), 1);
    }
}
