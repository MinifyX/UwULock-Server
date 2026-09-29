//! Logging in through an OpenID Connect provider, and what the provider pushes over SCIM
//! (docs/uwu-api.md §19).
//!
//! - **Identities** say which login at which provider (`issuer`, `subject`) is which account.
//! - **States** and **codes** carry a login across the provider and back to the client; both
//!   are kept by their SHA-256 and run out after minutes.
//! - **Provisioned** people and **groups** are what the provider pushed: an address that may
//!   sign up through SSO, the id the provider knows an account by, and who is in which group.

use crate::{Result, Store, StoreError, clock};
use rusqlite::{OptionalExtension, Row, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoIdentity {
    pub user_id: String,
    pub issuer: String,
    pub subject: String,
    pub created: String,
    pub last_login: Option<String>,
}

/// A login on its way to the provider and back.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SsoState {
    pub client_id: String,
    pub redirect_uri: String,
    pub client_state: String,
    pub code_challenge: String,
    pub nonce: String,
    /// This server's PKCE verifier towards the provider.
    pub verifier: Option<String>,
    /// SHA-256 of the cookie that ties the login to the browser that started it.
    pub binding_hash: Vec<u8>,
    pub expires: String,
}

/// A code the client trades for its tokens.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SsoCode {
    pub user_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub expires: String,
}

/// Somebody the provider pushed over SCIM.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScimUser {
    pub id: String,
    pub email: String,
    /// The account, once there is one.
    pub user_id: Option<String>,
    pub external_id: Option<String>,
    pub display_name: Option<String>,
    /// For somebody without an account: whether they may sign up. An account's own
    /// `disabled` says it for everybody else.
    pub active: bool,
    pub created: String,
    pub updated: String,
}

/// A group the provider pushed over SCIM, with the SCIM ids of its members.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScimGroup {
    pub id: String,
    pub display_name: String,
    pub external_id: Option<String>,
    pub members: Vec<String>,
    pub created: String,
    pub updated: String,
}

const IDENTITY_COLUMNS: &str = "user_id, issuer, subject, created, last_login";

fn identity_from(row: &Row<'_>) -> rusqlite::Result<SsoIdentity> {
    Ok(SsoIdentity {
        user_id: row.get(0)?,
        issuer: row.get(1)?,
        subject: row.get(2)?,
        created: row.get(3)?,
        last_login: row.get(4)?,
    })
}

const SCIM_USER_COLUMNS: &str = "id, email, user_id, external_id, display_name, active, created, updated";

fn scim_user_from(row: &Row<'_>) -> rusqlite::Result<ScimUser> {
    Ok(ScimUser {
        id: row.get(0)?,
        email: row.get(1)?,
        user_id: row.get(2)?,
        external_id: row.get(3)?,
        display_name: row.get(4)?,
        active: row.get(5)?,
        created: row.get(6)?,
        updated: row.get(7)?,
    })
}

const SCIM_GROUP_COLUMNS: &str = "id, display_name, external_id, members, created, updated";

fn scim_group_from(row: &Row<'_>) -> rusqlite::Result<ScimGroup> {
    let members: String = row.get(3)?;
    Ok(ScimGroup {
        id: row.get(0)?,
        display_name: row.get(1)?,
        external_id: row.get(2)?,
        members: serde_json::from_str(&members).unwrap_or_default(),
        created: row.get(4)?,
        updated: row.get(5)?,
    })
}

/// States and codes that ran out.
pub(crate) fn sweep(tx: &rusqlite::Transaction<'_>, now: &str) -> rusqlite::Result<()> {
    tx.execute("DELETE FROM sso_states WHERE expires < ?1", [now])?;
    tx.execute("DELETE FROM sso_codes WHERE expires < ?1", [now])?;
    Ok(())
}

impl Store {
    // ── Identities ─────────────────────────────────────────

    /// The account a login at `issuer` belongs to.
    pub async fn sso_identity(&self, issuer: &str, subject: &str) -> Result<Option<SsoIdentity>> {
        let (issuer, subject) = (issuer.to_string(), subject.to_string());
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {IDENTITY_COLUMNS} FROM sso_identities WHERE issuer = ?1 AND subject = ?2"
            ))?
            .query_row([issuer, subject], identity_from)
            .optional()
        })
        .await
    }

    /// The login an account has at `issuer`, if any.
    pub async fn sso_identity_of(&self, user_id: &str, issuer: &str) -> Result<Option<SsoIdentity>> {
        let (user_id, issuer) = (user_id.to_string(), issuer.to_string());
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {IDENTITY_COLUMNS} FROM sso_identities WHERE user_id = ?1 AND issuer = ?2"
            ))?
            .query_row([user_id, issuer], identity_from)
            .optional()
        })
        .await
    }

    /// Every login an account has, for the admin portal.
    pub async fn sso_identities_of(&self, user_id: &str) -> Result<Vec<SsoIdentity>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {IDENTITY_COLUMNS} FROM sso_identities WHERE user_id = ?1"))?
                .query_map([user_id], identity_from)?
                .collect()
        })
        .await
    }

    /// Link a login to an account. [`StoreError::Exists`] when the login belongs to an account
    /// already, or the account has another login at this issuer.
    pub async fn link_sso(&self, user_id: &str, issuer: &str, subject: &str) -> Result<SsoIdentity> {
        let (user_id, issuer, subject) = (user_id.to_string(), issuer.to_string(), subject.to_string());
        let linked = self
            .sqlite_write(move |tx| {
                let now = clock::now();
                let inserted = tx.execute(
                    "INSERT INTO sso_identities (user_id, issuer, subject, created, last_login) \
                     VALUES (?1, ?2, ?3, ?4, ?4) ON CONFLICT DO NOTHING",
                    params![user_id, issuer, subject, now],
                )?;
                if inserted == 0 {
                    return Ok(None);
                }
                Ok(Some(SsoIdentity { user_id, issuer, subject, created: now.clone(), last_login: Some(now) }))
            })
            .await?;
        linked.ok_or(StoreError::Exists)
    }

    /// A login through this identity happened now.
    pub async fn sso_logged_in(&self, issuer: &str, subject: &str) -> Result<()> {
        let (issuer, subject) = (issuer.to_string(), subject.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "UPDATE sso_identities SET last_login = ?3 WHERE issuer = ?1 AND subject = ?2",
                params![issuer, subject, clock::now()],
            )
        })
        .await?;
        Ok(())
    }

    /// Forget every login of an account at `issuer`, or at every issuer.
    pub async fn unlink_sso(&self, user_id: &str, issuer: Option<&str>) -> Result<usize> {
        let (user_id, issuer) = (user_id.to_string(), issuer.map(str::to_string));
        self.sqlite_write(move |tx| match issuer {
            Some(issuer) => {
                tx.execute("DELETE FROM sso_identities WHERE user_id = ?1 AND issuer = ?2", [user_id, issuer])
            }
            None => tx.execute("DELETE FROM sso_identities WHERE user_id = ?1", [user_id]),
        })
        .await
    }

    // ── States and codes ───────────────────────────────────

    pub async fn put_sso_state(&self, state_hash: Vec<u8>, state: SsoState) -> Result<()> {
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO sso_states (state_hash, client_id, redirect_uri, client_state, code_challenge, nonce, \
                 verifier, binding_hash, expires) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    state_hash,
                    state.client_id,
                    state.redirect_uri,
                    state.client_state,
                    state.code_challenge,
                    state.nonce,
                    state.verifier,
                    state.binding_hash,
                    state.expires
                ],
            )
        })
        .await?;
        Ok(())
    }

    /// The login `state_hash` stands for, taken: a state works once. Nothing when there is none
    /// or it ran out.
    pub async fn take_sso_state(&self, state_hash: Vec<u8>) -> Result<Option<SsoState>> {
        self.sqlite_write(move |tx| {
            let found = tx
                .prepare_cached(
                    "DELETE FROM sso_states WHERE state_hash = ?1 RETURNING client_id, redirect_uri, client_state, \
                     code_challenge, nonce, verifier, binding_hash, expires",
                )?
                .query_row([state_hash], |row| {
                    Ok(SsoState {
                        client_id: row.get(0)?,
                        redirect_uri: row.get(1)?,
                        client_state: row.get(2)?,
                        code_challenge: row.get(3)?,
                        nonce: row.get(4)?,
                        verifier: row.get(5)?,
                        binding_hash: row.get(6)?,
                        expires: row.get(7)?,
                    })
                })
                .optional()?;
            Ok(found.filter(|state| state.expires > clock::now()))
        })
        .await
    }

    pub async fn put_sso_code(&self, code_hash: Vec<u8>, code: SsoCode) -> Result<()> {
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO sso_codes (code_hash, user_id, client_id, redirect_uri, code_challenge, expires) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![code_hash, code.user_id, code.client_id, code.redirect_uri, code.code_challenge, code.expires],
            )
        })
        .await?;
        Ok(())
    }

    /// The code, if it is there and has not run out. It stays: see [`Store::take_sso_code`].
    pub async fn sso_code(&self, code_hash: Vec<u8>) -> Result<Option<SsoCode>> {
        self.sqlite_read(move |conn| {
            let found = conn
                .prepare_cached(
                    "SELECT user_id, client_id, redirect_uri, code_challenge, expires FROM sso_codes \
                     WHERE code_hash = ?1",
                )?
                .query_row([code_hash], |row| {
                    Ok(SsoCode {
                        user_id: row.get(0)?,
                        client_id: row.get(1)?,
                        redirect_uri: row.get(2)?,
                        code_challenge: row.get(3)?,
                        expires: row.get(4)?,
                    })
                })
                .optional()?;
            Ok(found.filter(|code| code.expires > clock::now()))
        })
        .await
    }

    /// Use the code up, once the login it is for went through. False when another request did
    /// that first.
    pub async fn take_sso_code(&self, code_hash: Vec<u8>) -> Result<bool> {
        self.sqlite_write(move |tx| Ok(tx.execute("DELETE FROM sso_codes WHERE code_hash = ?1", [code_hash])? > 0))
            .await
    }

    // ── SCIM: people ───────────────────────────────────────

    pub async fn scim_user(&self, id: &str) -> Result<Option<ScimUser>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {SCIM_USER_COLUMNS} FROM scim_provisioned WHERE id = ?1"))?
                .query_row([id], scim_user_from)
                .optional()
        })
        .await
    }

    /// The SCIM entry of an account.
    pub async fn scim_user_of(&self, user_id: &str) -> Result<Option<ScimUser>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {SCIM_USER_COLUMNS} FROM scim_provisioned WHERE user_id = ?1"))?
                .query_row([user_id], scim_user_from)
                .optional()
        })
        .await
    }

    /// The entry for an address that has no account (yet).
    pub async fn scim_provisioned(&self, email: &str) -> Result<Option<ScimUser>> {
        let email = crate::normalize_email(email);
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {SCIM_USER_COLUMNS} FROM scim_provisioned WHERE email = ?1 AND user_id IS NULL"
            ))?
            .query_row([email], scim_user_from)
            .optional()
        })
        .await
    }

    /// Every entry, in the order they came.
    pub async fn scim_users(&self) -> Result<Vec<ScimUser>> {
        self.sqlite_read(|conn| {
            conn.prepare_cached(&format!("SELECT {SCIM_USER_COLUMNS} FROM scim_provisioned ORDER BY created, id"))?
                .query_map([], scim_user_from)?
                .collect()
        })
        .await
    }

    /// Entries whose `externalId` is this.
    pub async fn scim_users_by_external(&self, external_id: &str) -> Result<Vec<ScimUser>> {
        let external_id = external_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {SCIM_USER_COLUMNS} FROM scim_provisioned WHERE external_id = ?1 ORDER BY created, id"
            ))?
            .query_map([external_id], scim_user_from)?
            .collect()
        })
        .await
    }

    /// Keep an entry as it is given. [`StoreError::Exists`] when the address has an entry
    /// without an account already, or the account one of its own.
    pub async fn put_scim_user(&self, user: ScimUser) -> Result<()> {
        let done = self
            .sqlite_write(move |tx| {
                let result = tx.execute(
                    "INSERT INTO scim_provisioned (id, email, user_id, external_id, display_name, active, created, \
                     updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
                     ON CONFLICT (id) DO UPDATE SET email = excluded.email, user_id = excluded.user_id, \
                     external_id = excluded.external_id, display_name = excluded.display_name, \
                     active = excluded.active, updated = excluded.updated",
                    params![
                        user.id,
                        crate::normalize_email(&user.email),
                        user.user_id,
                        user.external_id,
                        user.display_name,
                        user.active,
                        user.created,
                        user.updated
                    ],
                );
                match result {
                    Ok(_) => Ok(true),
                    Err(rusqlite::Error::SqliteFailure(error, _))
                        if error.code == rusqlite::ErrorCode::ConstraintViolation =>
                    {
                        Ok(false)
                    }
                    Err(error) => Err(error),
                }
            })
            .await?;
        if done { Ok(()) } else { Err(StoreError::Exists) }
    }

    /// The entry for `email` without an account belongs to `user_id` now: the account was made.
    pub async fn claim_scim_user(&self, email: &str, user_id: &str) -> Result<()> {
        let (email, user_id) = (crate::normalize_email(email), user_id.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "UPDATE scim_provisioned SET user_id = ?2, updated = ?3 WHERE email = ?1 AND user_id IS NULL \
                 AND NOT EXISTS (SELECT 1 FROM scim_provisioned WHERE user_id = ?2)",
                params![email, user_id, clock::now()],
            )
        })
        .await?;
        Ok(())
    }

    pub async fn delete_scim_user(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.sqlite_write(move |tx| Ok(tx.execute("DELETE FROM scim_provisioned WHERE id = ?1", [id])? > 0)).await
    }

    // ── SCIM: groups ───────────────────────────────────────

    pub async fn scim_group(&self, id: &str) -> Result<Option<ScimGroup>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {SCIM_GROUP_COLUMNS} FROM scim_groups WHERE id = ?1"))?
                .query_row([id], scim_group_from)
                .optional()
        })
        .await
    }

    /// A group by its name, in any case.
    pub async fn scim_group_named(&self, name: &str) -> Result<Option<ScimGroup>> {
        let name = name.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {SCIM_GROUP_COLUMNS} FROM scim_groups WHERE display_name = ?1"))?
                .query_row([name], scim_group_from)
                .optional()
        })
        .await
    }

    pub async fn scim_groups(&self) -> Result<Vec<ScimGroup>> {
        self.sqlite_read(|conn| {
            conn.prepare_cached(&format!("SELECT {SCIM_GROUP_COLUMNS} FROM scim_groups ORDER BY created, id"))?
                .query_map([], scim_group_from)?
                .collect()
        })
        .await
    }

    /// Keep a group as it is given, members and all. [`StoreError::Exists`] when another group
    /// has its name.
    pub async fn put_scim_group(&self, group: ScimGroup) -> Result<()> {
        let done = self
            .sqlite_write(move |tx| {
                let members = serde_json::to_string(&group.members).expect("a list of strings serializes");
                let result = tx.execute(
                    "INSERT INTO scim_groups (id, display_name, external_id, members, created, updated) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                     ON CONFLICT (id) DO UPDATE SET display_name = excluded.display_name, \
                     external_id = excluded.external_id, members = excluded.members, updated = excluded.updated",
                    params![group.id, group.display_name, group.external_id, members, group.created, group.updated],
                );
                match result {
                    Ok(_) => Ok(true),
                    Err(rusqlite::Error::SqliteFailure(error, _))
                        if error.code == rusqlite::ErrorCode::ConstraintViolation =>
                    {
                        Ok(false)
                    }
                    Err(error) => Err(error),
                }
            })
            .await?;
        if done { Ok(()) } else { Err(StoreError::Exists) }
    }

    pub async fn delete_scim_group(&self, id: &str) -> Result<Option<ScimGroup>> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            tx.prepare_cached(&format!("DELETE FROM scim_groups WHERE id = ?1 RETURNING {SCIM_GROUP_COLUMNS}"))?
                .query_row([id], scim_group_from)
                .optional()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::{new_user, store};

    #[tokio::test]
    async fn one_login_per_account_and_provider() {
        let (store, _dir) = store();
        let nyu = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let mia = store.create_user(new_user("mia@example.com")).await.unwrap();
        let issuer = "https://auth.example.com";
        store.link_sso(&nyu.id, issuer, "sub-1").await.unwrap();
        assert!(matches!(store.link_sso(&mia.id, issuer, "sub-1").await, Err(StoreError::Exists)), "taken");
        assert!(matches!(store.link_sso(&nyu.id, issuer, "sub-2").await, Err(StoreError::Exists)), "one per issuer");
        store.link_sso(&nyu.id, "https://other.example.com", "sub-1").await.unwrap();
        assert_eq!(store.sso_identity(issuer, "sub-1").await.unwrap().unwrap().user_id, nyu.id);
        assert_eq!(store.sso_identity_of(&nyu.id, issuer).await.unwrap().unwrap().subject, "sub-1");
        assert_eq!(store.sso_identities_of(&nyu.id).await.unwrap().len(), 2);
        store.delete_user(&nyu.id).await.unwrap();
        assert!(store.sso_identity(issuer, "sub-1").await.unwrap().is_none(), "gone with the account");
    }

    #[tokio::test]
    async fn states_work_once_and_codes_until_taken() {
        let (store, _dir) = store();
        let nyu = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let state = SsoState {
            client_id: "web".into(),
            redirect_uri: "https://vault.example.com/sso-connector.html".into(),
            client_state: "s".into(),
            code_challenge: "c".into(),
            nonce: "n".into(),
            verifier: Some("v".into()),
            binding_hash: vec![1; 32],
            expires: clock::in_seconds(600),
        };
        store.put_sso_state(vec![2; 32], state.clone()).await.unwrap();
        assert_eq!(store.take_sso_state(vec![2; 32]).await.unwrap(), Some(state.clone()));
        assert_eq!(store.take_sso_state(vec![2; 32]).await.unwrap(), None, "once");
        store.put_sso_state(vec![3; 32], SsoState { expires: clock::in_seconds(-1), ..state }).await.unwrap();
        assert_eq!(store.take_sso_state(vec![3; 32]).await.unwrap(), None, "ran out");

        let code = SsoCode {
            user_id: nyu.id.clone(),
            client_id: "web".into(),
            redirect_uri: "r".into(),
            code_challenge: "c".into(),
            expires: clock::in_seconds(300),
        };
        store.put_sso_code(vec![4; 32], code.clone()).await.unwrap();
        assert_eq!(store.sso_code(vec![4; 32]).await.unwrap(), Some(code.clone()));
        assert_eq!(store.sso_code(vec![4; 32]).await.unwrap(), Some(code), "still there for the second step");
        assert!(store.take_sso_code(vec![4; 32]).await.unwrap());
        assert!(!store.take_sso_code(vec![4; 32]).await.unwrap(), "used up");
    }

    #[tokio::test]
    async fn provisioned_people_become_accounts() {
        let (store, _dir) = store();
        let now = clock::now();
        let entry = ScimUser {
            id: "p1".into(),
            email: "Mia@Example.com".into(),
            external_id: Some("ext-1".into()),
            active: true,
            created: now.clone(),
            updated: now.clone(),
            ..ScimUser::default()
        };
        store.put_scim_user(entry.clone()).await.unwrap();
        let again = ScimUser { id: "p2".into(), ..entry.clone() };
        assert!(matches!(store.put_scim_user(again).await, Err(StoreError::Exists)), "one entry per address");
        assert_eq!(store.scim_provisioned("mia@example.com").await.unwrap().unwrap().id, "p1");
        assert_eq!(store.scim_users_by_external("ext-1").await.unwrap().len(), 1);

        let mia = store.create_user(new_user("mia@example.com")).await.unwrap();
        store.claim_scim_user("mia@example.com", &mia.id).await.unwrap();
        assert!(store.scim_provisioned("mia@example.com").await.unwrap().is_none());
        assert_eq!(store.scim_user_of(&mia.id).await.unwrap().unwrap().id, "p1");
        store.delete_user(&mia.id).await.unwrap();
        assert!(store.scim_user("p1").await.unwrap().is_none(), "gone with the account");
    }

    #[tokio::test]
    async fn groups_have_unique_names_in_any_case() {
        let (store, _dir) = store();
        let now = clock::now();
        let group = ScimGroup {
            id: "g1".into(),
            display_name: "vault-admins".into(),
            members: vec!["a".into(), "b".into()],
            created: now.clone(),
            updated: now,
            ..ScimGroup::default()
        };
        store.put_scim_group(group.clone()).await.unwrap();
        let other = ScimGroup { id: "g2".into(), display_name: "Vault-Admins".into(), ..group.clone() };
        assert!(matches!(store.put_scim_group(other).await, Err(StoreError::Exists)));
        assert_eq!(store.scim_group_named("VAULT-ADMINS").await.unwrap().unwrap().members, ["a", "b"]);
        let deleted = store.delete_scim_group("g1").await.unwrap().unwrap();
        assert_eq!(deleted.display_name, "vault-admins");
        assert!(store.scim_groups().await.unwrap().is_empty());
    }
}
