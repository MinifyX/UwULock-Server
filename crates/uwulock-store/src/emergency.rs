//! Emergency access: a grantor names somebody (the grantee) who may see — or take over — the
//! vault if they ask for it and the grantor does not say no within a wait.
//!
//! The steps, as Bitwarden has them: the grantor invites (0), the grantee accepts (1), the
//! grantor confirms and hands over the user key wrapped for the grantee's public key (2). Later
//! the grantee asks (3), and after the wait or the grantor's yes it is approved (4).

use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, Row, params};

pub const INVITED: i64 = 0;
pub const ACCEPTED: i64 = 1;
pub const CONFIRMED: i64 = 2;
pub const RECOVERY_ASKED: i64 = 3;
pub const RECOVERY_APPROVED: i64 = 4;

/// See the vault.
pub const VIEW: i64 = 0;
/// Set a new master password for it.
pub const TAKEOVER: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyAccess {
    pub id: String,
    pub grantor_id: String,
    pub grantee_id: Option<String>,
    /// Where the invitation went.
    pub email: String,
    pub key_encrypted: Option<String>,
    pub kind: i64,
    pub status: i64,
    pub wait_days: i64,
    pub token_hash: Option<Vec<u8>>,
    pub recovery_asked: Option<String>,
    pub last_notification: Option<String>,
    pub created: String,
    pub revision: String,
}

const COLUMNS: &str = "id, grantor_id, grantee_id, email, key_encrypted, type, status, wait_days, token_hash, \
     recovery_asked, last_notification, created, revision";

fn access_from(row: &Row<'_>) -> rusqlite::Result<EmergencyAccess> {
    Ok(EmergencyAccess {
        id: row.get(0)?,
        grantor_id: row.get(1)?,
        grantee_id: row.get(2)?,
        email: row.get(3)?,
        key_encrypted: row.get(4)?,
        kind: row.get(5)?,
        status: row.get(6)?,
        wait_days: row.get(7)?,
        token_hash: row.get(8)?,
        recovery_asked: row.get(9)?,
        last_notification: row.get(10)?,
        created: row.get(11)?,
        revision: row.get(12)?,
    })
}

impl Store {
    /// Whom the user trusts.
    pub async fn emergency_trusted(&self, grantor_id: &str) -> Result<Vec<EmergencyAccess>> {
        let id = grantor_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM emergency_access WHERE grantor_id = ?1 ORDER BY created"
            ))?
            .query_map([id], access_from)?
            .collect()
        })
        .await
    }

    /// Who trusts the user, and invitations to the user's address that wait for a yes.
    pub async fn emergency_granted(&self, grantee_id: &str, email: &str) -> Result<Vec<EmergencyAccess>> {
        let (id, email) = (grantee_id.to_string(), email.to_string());
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM emergency_access \
                 WHERE grantee_id = ?1 OR (grantee_id IS NULL AND status = ?3 AND email = ?2) ORDER BY created"
            ))?
            .query_map(params![id, email, INVITED], access_from)?
            .collect()
        })
        .await
    }

    pub async fn emergency_access(&self, id: &str) -> Result<Option<EmergencyAccess>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {COLUMNS} FROM emergency_access WHERE id = ?1"))?
                .query_row([id], access_from)
                .optional()
        })
        .await
    }

    /// Whether the grantor has named this address already.
    pub async fn emergency_by_email(&self, grantor_id: &str, email: &str) -> Result<Option<EmergencyAccess>> {
        let (id, email) = (grantor_id.to_string(), email.to_string());
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM emergency_access WHERE grantor_id = ?1 AND email = ?2"
            ))?
            .query_row([id, email], access_from)
            .optional()
        })
        .await
    }

    /// A new one, as the grantor names the contact.
    pub async fn add_emergency_access(&self, mut access: EmergencyAccess) -> Result<EmergencyAccess> {
        self.sqlite_write(move |tx| {
            access.revision = clock::now();
            tx.execute(
                &format!(
                    "INSERT INTO emergency_access ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"
                ),
                params![
                    access.id,
                    access.grantor_id,
                    access.grantee_id,
                    access.email,
                    access.key_encrypted,
                    access.kind,
                    access.status,
                    access.wait_days,
                    access.token_hash,
                    access.recovery_asked,
                    access.last_notification,
                    access.created,
                    access.revision,
                ],
            )?;
            Ok(access)
        })
        .await
    }

    /// Write back a change to one that was read before; its revision is set to now. Nothing
    /// when it changed in between or is gone: two steps at once — a request while the grantor
    /// ends it, say — must not undo each other or bring a deleted one back.
    pub async fn save_emergency_access(&self, mut access: EmergencyAccess) -> Result<Option<EmergencyAccess>> {
        self.sqlite_write(move |tx| {
            let seen = std::mem::replace(&mut access.revision, clock::now());
            let written = tx.execute(
                "UPDATE emergency_access SET grantee_id = ?3, email = ?4, key_encrypted = ?5, type = ?6, status = ?7, \
                 wait_days = ?8, token_hash = ?9, recovery_asked = ?10, last_notification = ?11, revision = ?12 \
                 WHERE id = ?1 AND revision = ?2",
                params![
                    access.id,
                    seen,
                    access.grantee_id,
                    access.email,
                    access.key_encrypted,
                    access.kind,
                    access.status,
                    access.wait_days,
                    access.token_hash,
                    access.recovery_asked,
                    access.last_notification,
                    access.revision,
                ],
            )?;
            Ok((written > 0).then_some(access))
        })
        .await
    }

    pub async fn delete_emergency_access(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.sqlite_write(move |tx| Ok(tx.execute("DELETE FROM emergency_access WHERE id = ?1", [id])? > 0)).await
    }

    /// Recoveries that were asked for and whose wait is over: approved now, and handed back so
    /// both sides can be told.
    pub async fn approve_waited_recoveries(&self) -> Result<Vec<EmergencyAccess>> {
        self.sqlite_write(|tx| {
            let now = clock::now();
            let waiting: Vec<EmergencyAccess> = tx
                .prepare(&format!("SELECT {COLUMNS} FROM emergency_access WHERE status = ?1"))?
                .query_map([RECOVERY_ASKED], access_from)?
                .collect::<rusqlite::Result<_>>()?;
            let mut approved = Vec::new();
            for mut access in waiting {
                let Some(asked) = access.recovery_asked.as_deref().and_then(clock::parse) else { continue };
                if clock::format(asked + time::Duration::days(access.wait_days)) > now {
                    continue;
                }
                tx.execute(
                    "UPDATE emergency_access SET status = ?2, revision = ?3 WHERE id = ?1",
                    params![access.id, RECOVERY_APPROVED, now],
                )?;
                access.status = RECOVERY_APPROVED;
                approved.push(access);
            }
            Ok(approved)
        })
        .await
    }

    /// Recoveries still waiting whose grantor was last reminded a day ago or longer. Marked as
    /// reminded now.
    pub async fn recoveries_to_remind(&self) -> Result<Vec<EmergencyAccess>> {
        self.sqlite_write(|tx| {
            let now = clock::now();
            let day_ago = clock::in_seconds(-86_400);
            let due: Vec<EmergencyAccess> = tx
                .prepare(&format!(
                    "SELECT {COLUMNS} FROM emergency_access WHERE status = ?1 \
                     AND (last_notification IS NULL OR last_notification < ?2)"
                ))?
                .query_map(params![RECOVERY_ASKED, day_ago], access_from)?
                .collect::<rusqlite::Result<_>>()?;
            for access in &due {
                tx.execute("UPDATE emergency_access SET last_notification = ?2 WHERE id = ?1", [&access.id, &now])?;
            }
            Ok(due)
        })
        .await
    }
}

/// New wrapped keys for the grantor's emergency contacts, the way a key rotation brings
/// them. Refused (`false`) unless every contact that holds a key gets a new one.
pub(crate) fn rotate_keys(
    tx: &rusqlite::Transaction<'_>,
    grantor_id: &str,
    keys: &[(String, String)],
) -> rusqlite::Result<bool> {
    let mut holding: Vec<String> = tx
        .prepare("SELECT id FROM emergency_access WHERE grantor_id = ?1 AND key_encrypted IS NOT NULL")?
        .query_map([grantor_id], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    holding.sort();
    let mut given: Vec<String> = keys.iter().map(|(id, _)| id.clone()).collect();
    given.sort();
    if holding != given {
        return Ok(false);
    }
    let now = clock::now();
    for (id, key) in keys {
        tx.execute(
            "UPDATE emergency_access SET key_encrypted = ?3, revision = ?4 WHERE id = ?1 AND grantor_id = ?2",
            params![id, grantor_id, key, now],
        )?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::{new_user, store};

    fn access(grantor: &str, email: &str) -> EmergencyAccess {
        EmergencyAccess {
            id: uuid::Uuid::new_v4().to_string(),
            grantor_id: grantor.into(),
            grantee_id: None,
            email: email.into(),
            key_encrypted: None,
            kind: VIEW,
            status: INVITED,
            wait_days: 2,
            token_hash: Some(vec![1; 32]),
            recovery_asked: None,
            last_notification: None,
            created: clock::now(),
            revision: clock::now(),
        }
    }

    #[tokio::test]
    async fn a_recovery_is_approved_once_the_wait_is_over() {
        let (store, _dir) = store();
        let grantor = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let grantee = store.create_user(new_user("friend@example.com")).await.unwrap();
        let mut waiting = access(&grantor.id, "friend@example.com");
        waiting.grantee_id = Some(grantee.id.clone());
        waiting.status = RECOVERY_ASKED;
        waiting.recovery_asked = Some(clock::in_seconds(-86_400));
        let waiting = store.add_emergency_access(waiting).await.unwrap();
        let mut over = access(&grantor.id, "other@example.com");
        over.status = RECOVERY_ASKED;
        over.recovery_asked = Some(clock::in_seconds(-3 * 86_400));
        let over = store.add_emergency_access(over).await.unwrap();

        let approved = store.approve_waited_recoveries().await.unwrap();
        assert_eq!(approved.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(), [over.id.as_str()]);
        assert_eq!(store.emergency_access(&waiting.id).await.unwrap().unwrap().status, RECOVERY_ASKED);
        assert_eq!(store.emergency_granted(&grantee.id, &grantee.email).await.unwrap().len(), 1);

        assert_eq!(store.recoveries_to_remind().await.unwrap().len(), 1, "the one still waiting");
        assert!(store.recoveries_to_remind().await.unwrap().is_empty(), "not twice a day");
    }

    #[tokio::test]
    async fn contacts_go_with_the_grantor() {
        let (store, _dir) = store();
        let grantor = store.create_user(new_user("nyu@example.com")).await.unwrap();
        store.add_emergency_access(access(&grantor.id, "friend@example.com")).await.unwrap();
        assert!(store.emergency_by_email(&grantor.id, "friend@example.com").await.unwrap().is_some());
        store.delete_user(&grantor.id).await.unwrap();
        assert!(store.emergency_by_email(&grantor.id, "friend@example.com").await.unwrap().is_none());
    }
}
