//! Accounts: users, their devices, invitations, two-step login and the codes sent by mail.
//!
//! Every request a client makes asks who it is — whether the account still exists, is not
//! disabled, whether the session's security stamp is still the account's, whether the device is
//! still logged in. That is answered from memory ([`Store::session_user`]), kept in step by every
//! method here that changes one of those things. The one other writer is the command line
//! (`uwulock-server admin …` in a second process), so what memory holds is read again after
//! half a minute at the latest.

use crate::{Result, Store, StoreError, clock};
use rusqlite::{OptionalExtension, Row, Transaction, params};
use std::collections::HashSet;
use std::sync::Arc;

/// How the client derives the master key: Bitwarden's `kdf`, `kdfIterations`, `kdfMemory`,
/// `kdfParallelism`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kdf {
    /// 0 PBKDF2-SHA256, 1 Argon2id.
    pub kind: i64,
    pub iterations: i64,
    pub memory: Option<i64>,
    pub parallelism: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub password_hash: String,
    pub password_hint: Option<String>,
    pub user_key: String,
    pub user_key_id: Option<String>,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub kdf: Kdf,
    pub security_stamp: String,
    pub language: String,
    pub avatar_color: Option<String>,
    pub equivalent_domains: String,
    pub excluded_globals: String,
    pub recovery_code: Option<String>,
    pub admin: bool,
    pub disabled: bool,
    pub created: String,
    pub updated: String,
    pub revision: String,
    pub last_login: Option<String>,
}

const USER_COLUMNS: &str = "id, email, name, password_hash, password_hint, user_key, private_key, public_key, \
     kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, language, avatar_color, \
     equivalent_domains, excluded_globals, recovery_code, admin, disabled, created, updated, revision, last_login, \
     user_key_id";

fn user_from(row: &Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        email: row.get(1)?,
        name: row.get(2)?,
        password_hash: row.get(3)?,
        password_hint: row.get(4)?,
        user_key: row.get(5)?,
        private_key: row.get(6)?,
        public_key: row.get(7)?,
        kdf: Kdf { kind: row.get(8)?, iterations: row.get(9)?, memory: row.get(10)?, parallelism: row.get(11)? },
        security_stamp: row.get(12)?,
        language: row.get(13)?,
        avatar_color: row.get(14)?,
        equivalent_domains: row.get(15)?,
        excluded_globals: row.get(16)?,
        recovery_code: row.get(17)?,
        admin: row.get(18)?,
        disabled: row.get(19)?,
        created: row.get(20)?,
        updated: row.get(21)?,
        revision: row.get(22)?,
        last_login: row.get(23)?,
        user_key_id: row.get(24)?,
    })
}

fn load_user(conn: &rusqlite::Connection, id: &str) -> rusqlite::Result<Option<User>> {
    conn.prepare_cached(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1"))?
        .query_row([id], user_from)
        .optional()
}

pub(crate) fn save_user_in(tx: &Transaction<'_>, user: &User) -> rusqlite::Result<()> {
    tx.prepare_cached(
        "UPDATE users SET email = ?2, name = ?3, password_hash = ?4, password_hint = ?5, user_key = ?6, \
         private_key = ?7, public_key = ?8, kdf_type = ?9, kdf_iterations = ?10, kdf_memory = ?11, \
         kdf_parallelism = ?12, security_stamp = ?13, language = ?14, avatar_color = ?15, \
         equivalent_domains = ?16, excluded_globals = ?17, recovery_code = ?18, admin = ?19, disabled = ?20, \
         updated = ?21, revision = ?22, last_login = ?23, user_key_id = ?24 WHERE id = ?1",
    )?
    .execute(params![
        user.id,
        user.email,
        user.name,
        user.password_hash,
        user.password_hint,
        user.user_key,
        user.private_key,
        user.public_key,
        user.kdf.kind,
        user.kdf.iterations,
        user.kdf.memory,
        user.kdf.parallelism,
        user.security_stamp,
        user.language,
        user.avatar_color,
        user.equivalent_domains,
        user.excluded_globals,
        user.recovery_code,
        user.admin,
        user.disabled,
        user.updated,
        user.revision,
        user.last_login,
        user.user_key_id,
    ])?;
    Ok(())
}

/// A user as a request sees it: the account, and which of its devices are logged in.
#[derive(Debug, Clone)]
pub struct SessionUser {
    pub user: Arc<User>,
    pub devices: Arc<HashSet<String>>,
}

/// A new account, from a registration.
#[derive(Debug, Clone)]
pub struct NewUser {
    pub email: String,
    pub name: Option<String>,
    pub password_hash: String,
    pub password_hint: Option<String>,
    pub user_key: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub kdf: Kdf,
    pub language: String,
    pub admin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub user_id: String,
    pub id: String,
    pub name: String,
    pub kind: i64,
    pub created: String,
    pub last_seen: String,
    pub last_ip: Option<String>,
    pub logged_in: bool,
    pub refresh_expires: Option<String>,
    pub remember_hash: Option<Vec<u8>>,
    pub remember_expires: Option<String>,
    pub push_token: Option<String>,
}

const DEVICE_COLUMNS: &str = "user_id, id, name, type, created, last_seen, last_ip, refresh_hash IS NOT NULL, \
     refresh_expires, remember_hash, remember_expires, push_token";

fn device_from(row: &Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        user_id: row.get(0)?,
        id: row.get(1)?,
        name: row.get(2)?,
        kind: row.get(3)?,
        created: row.get(4)?,
        last_seen: row.get(5)?,
        last_ip: row.get(6)?,
        logged_in: row.get(7)?,
        refresh_expires: row.get(8)?,
        remember_hash: row.get(9)?,
        remember_expires: row.get(10)?,
        push_token: row.get(11)?,
    })
}

/// A login on a device: who, where from, and the new refresh token's hash.
#[derive(Debug, Clone)]
pub struct DeviceLogin {
    pub user_id: String,
    pub id: String,
    pub name: String,
    pub kind: i64,
    pub ip: Option<String>,
    pub refresh_hash: Vec<u8>,
    pub refresh_expires: String,
    /// A new token that skips two-step login here, when "remember me" was ticked.
    pub remember: Option<(Vec<u8>, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub email: String,
    pub admin: bool,
    pub invited_by: Option<String>,
    pub language: String,
    pub created: String,
    pub expires: String,
}

fn invitation_from(row: &Row<'_>) -> rusqlite::Result<Invitation> {
    Ok(Invitation {
        email: row.get(0)?,
        admin: row.get(1)?,
        invited_by: row.get(2)?,
        language: row.get(3)?,
        created: row.get(4)?,
        expires: row.get(5)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoFactor {
    /// Bitwarden's provider number: 0 authenticator app, 1 mail.
    pub kind: i64,
    pub enabled: bool,
    /// JSON: the authenticator secret, or the address mail codes go to.
    pub data: String,
    pub last_used: i64,
}

/// Why a code by mail was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeRefusal {
    /// None was sent, or it was used up.
    Missing,
    Wrong,
    Expired,
    /// Too many wrong ones: it is gone, and a new one has to be sent.
    TooManyAttempts,
}

/// How long a session is answered from memory before it is read again.
const SESSION_MEMORY: std::time::Duration = std::time::Duration::from_secs(30);

/// Wrong codes allowed before a code is thrown away.
pub const CODE_ATTEMPTS: i64 = 5;

/// One line of the admin portal's list of users.
#[derive(Debug, Clone)]
pub struct UserOverview {
    pub user: User,
    pub devices: i64,
    pub ciphers: i64,
    pub two_factor: bool,
}

impl Store {
    // ── Users ──────────────────────────────────────────────

    /// A new account. The invitation for its address is used up in the same step, so one
    /// invitation makes one account. [`StoreError::Exists`] when the address has one already.
    pub async fn create_user(&self, new: NewUser) -> Result<User> {
        let user = self
            .sqlite_write(move |tx| {
                let exists: bool =
                    tx.query_row("SELECT EXISTS (SELECT 1 FROM users WHERE email = ?1)", [&new.email], |row| {
                        row.get(0)
                    })?;
                if exists {
                    return Ok(None);
                }
                let now = clock::now();
                let id = uuid::Uuid::new_v4().to_string();
                tx.execute(
                    "INSERT INTO users (id, email, name, password_hash, password_hint, user_key, private_key, \
                     public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, language, \
                     admin, created, updated, revision) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16, ?16)",
                    params![
                        id,
                        new.email,
                        new.name,
                        new.password_hash,
                        new.password_hint,
                        new.user_key,
                        new.private_key,
                        new.public_key,
                        new.kdf.kind,
                        new.kdf.iterations,
                        new.kdf.memory,
                        new.kdf.parallelism,
                        uuid::Uuid::new_v4().to_string(),
                        new.language,
                        new.admin,
                        now,
                    ],
                )?;
                tx.execute("DELETE FROM invitations WHERE email = ?1", [&new.email])?;
                load_user(tx, &id)
            })
            .await?;
        user.ok_or(StoreError::Exists)
    }

    pub async fn user(&self, id: &str) -> Result<Option<User>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| load_user(conn, &id)).await
    }

    /// By address, which is looked up trimmed and in lower case.
    pub async fn user_by_email(&self, email: &str) -> Result<Option<User>> {
        let email = normalize_email(email);
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {USER_COLUMNS} FROM users WHERE email = ?1"))?
                .query_row([email], user_from)
                .optional()
        })
        .await
    }

    /// Who a request is from, from memory. Nothing for an account that is gone.
    pub async fn session_user(&self, id: &str) -> Result<Option<SessionUser>> {
        let forgotten = {
            let sessions = self.sessions.read();
            if let Some((found, since)) = sessions.by_user.get(id)
                && since.elapsed() < SESSION_MEMORY
            {
                return Ok(Some(found.clone()));
            }
            sessions.forgotten
        };
        let owned = id.to_string();
        let loaded = self
            .sqlite_read(move |conn| {
                let Some(user) = load_user(conn, &owned)? else { return Ok(None) };
                let devices = conn
                    .prepare_cached("SELECT id FROM devices WHERE user_id = ?1 AND refresh_hash IS NOT NULL")?
                    .query_map([&owned], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<HashSet<_>>>()?;
                Ok(Some(SessionUser { user: Arc::new(user), devices: Arc::new(devices) }))
            })
            .await?;
        if let Some(session) = &loaded {
            let mut sessions = self.sessions.write();
            if sessions.forgotten == forgotten {
                sessions.by_user.insert(id.to_string(), (session.clone(), std::time::Instant::now()));
            }
        }
        Ok(loaded)
    }

    /// Forget what memory holds for `user_id`; the next request reads it again.
    pub(crate) fn forget_session_of(&self, user_id: &str) {
        let mut sessions = self.sessions.write();
        sessions.forgotten += 1;
        sessions.by_user.remove(user_id);
    }

    /// Change a user in one step: `change` gets the user as the database has it now and says
    /// what it should be. `updated` is set by this; the revision only if `change` sets it.
    /// Nothing for a user that is gone.
    pub async fn update_user<F>(&self, id: &str, change: F) -> Result<Option<User>>
    where
        F: FnOnce(&mut User) + Send + 'static,
    {
        let owned = id.to_string();
        let user = self
            .sqlite_write(move |tx| {
                let Some(mut user) = load_user(tx, &owned)? else { return Ok(None) };
                let stamp = user.security_stamp.clone();
                change(&mut user);
                user.updated = clock::now();
                save_user_in(tx, &user)?;
                // A new stamp ends every session: no device stays logged in with the old one.
                if user.security_stamp != stamp {
                    tx.execute(
                        "UPDATE devices SET refresh_hash = NULL, refresh_expires = NULL, remember_hash = NULL, \
                         remember_expires = NULL WHERE user_id = ?1",
                        [&user.id],
                    )?;
                }
                Ok(Some(user))
            })
            .await?;
        self.forget_session_of(id);
        Ok(user)
    }

    /// Mark that something the clients sync changed.
    pub async fn touch_revision(&self, user_id: &str) -> Result<()> {
        let owned = user_id.to_string();
        self.sqlite_write(move |tx| bump_revision(tx, &owned)).await?;
        self.forget_session_of(user_id);
        Ok(())
    }

    /// The account and everything in it.
    pub async fn delete_user(&self, id: &str) -> Result<bool> {
        let owned = id.to_string();
        let deleted = self
            .sqlite_write(move |tx| {
                // The vault goes first: ciphers point at folders.
                tx.execute("DELETE FROM ciphers WHERE user_id = ?1", [&owned])?;
                Ok(tx.execute("DELETE FROM users WHERE id = ?1", [&owned])? > 0)
            })
            .await?;
        self.forget_session_of(id);
        Ok(deleted)
    }

    /// Every account, with how much it has, for the admin portal.
    pub async fn users(&self) -> Result<Vec<UserOverview>> {
        self.sqlite_read(|conn| {
            let columns = USER_COLUMNS.split(", ").map(|c| format!("u.{c}")).collect::<Vec<_>>().join(", ");
            conn.prepare(&format!(
                "SELECT {columns}, \
                 (SELECT count(*) FROM devices d WHERE d.user_id = u.id AND d.refresh_hash IS NOT NULL), \
                 (SELECT count(*) FROM ciphers c WHERE c.user_id = u.id), \
                 EXISTS (SELECT 1 FROM two_factor t WHERE t.user_id = u.id AND t.enabled) \
                 FROM users u ORDER BY u.email"
            ))?
            .query_map([], |row| {
                Ok(UserOverview {
                    user: user_from(row)?,
                    devices: row.get(25)?,
                    ciphers: row.get(26)?,
                    two_factor: row.get(27)?,
                })
            })?
            .collect()
        })
        .await
    }

    pub async fn admin_count(&self) -> Result<i64> {
        self.sqlite_read(|conn| {
            conn.query_row("SELECT count(*) FROM users WHERE admin AND NOT disabled", [], |row| row.get(0))
        })
        .await
    }

    // ── Devices ────────────────────────────────────────────

    pub async fn device(&self, user_id: &str, id: &str) -> Result<Option<Device>> {
        let (user_id, id) = (user_id.to_string(), id.to_string());
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {DEVICE_COLUMNS} FROM devices WHERE user_id = ?1 AND id = ?2"))?
                .query_row([user_id, id], device_from)
                .optional()
        })
        .await
    }

    /// A user's devices, the most recently seen first.
    pub async fn devices(&self, user_id: &str) -> Result<Vec<Device>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {DEVICE_COLUMNS} FROM devices WHERE user_id = ?1 ORDER BY last_seen DESC"
            ))?
            .query_map([user_id], device_from)?
            .collect()
        })
        .await
    }

    /// A device logs in: made if it is new, and given its refresh token. Says whether it was new.
    pub async fn log_in_device(&self, login: DeviceLogin) -> Result<bool> {
        let user_id = login.user_id.clone();
        let new = self
            .sqlite_write(move |tx| {
                let now = clock::now();
                let known: bool = tx.query_row(
                    "SELECT EXISTS (SELECT 1 FROM devices WHERE user_id = ?1 AND id = ?2)",
                    [&login.user_id, &login.id],
                    |row| row.get(0),
                )?;
                tx.execute(
                    "INSERT INTO devices (user_id, id, name, type, created, last_seen, last_ip, refresh_hash, \
                     refresh_expires) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?8) \
                     ON CONFLICT (user_id, id) DO UPDATE SET name = excluded.name, type = excluded.type, \
                     last_seen = excluded.last_seen, last_ip = excluded.last_ip, refresh_hash = excluded.refresh_hash, \
                     refresh_expires = excluded.refresh_expires",
                    params![
                        login.user_id,
                        login.id,
                        login.name,
                        login.kind,
                        now,
                        login.ip,
                        login.refresh_hash,
                        login.refresh_expires
                    ],
                )?;
                if let Some((hash, expires)) = login.remember {
                    tx.execute(
                        "UPDATE devices SET remember_hash = ?3, remember_expires = ?4 WHERE user_id = ?1 AND id = ?2",
                        params![login.user_id, login.id, hash, expires],
                    )?;
                }
                tx.execute("UPDATE users SET last_login = ?2 WHERE id = ?1", params![login.user_id, now])?;
                Ok(!known)
            })
            .await?;
        self.forget_session_of(&user_id);
        Ok(new)
    }

    /// The device a refresh token belongs to, if it is still valid — with a new expiry, from
    /// `expires` given the device's type, since a device in use stays logged in.
    pub async fn refresh_device<F>(
        &self,
        refresh_hash: Vec<u8>,
        expires: F,
        ip: Option<String>,
    ) -> Result<Option<Device>>
    where
        F: FnOnce(i64) -> String + Send + 'static,
    {
        self.sqlite_write(move |tx| {
            let now = clock::now();
            let found = tx
                .prepare_cached(&format!(
                    "SELECT {DEVICE_COLUMNS} FROM devices WHERE refresh_hash = ?1 AND refresh_expires > ?2"
                ))?
                .query_row(params![refresh_hash, now], device_from)
                .optional()?;
            if let Some(device) = &found {
                tx.execute(
                    "UPDATE devices SET last_seen = ?3, last_ip = coalesce(?4, last_ip), refresh_expires = ?5 \
                     WHERE user_id = ?1 AND id = ?2",
                    params![device.user_id, device.id, now, ip, expires(device.kind)],
                )?;
            }
            Ok(found)
        })
        .await
    }

    /// The device is logged out: its refresh token and remembered two-step login are gone.
    pub async fn log_out_device(&self, user_id: &str, id: &str) -> Result<bool> {
        let (owned_user, owned_id) = (user_id.to_string(), id.to_string());
        let done = self
            .sqlite_write(move |tx| {
                Ok(tx.execute(
                    "UPDATE devices SET refresh_hash = NULL, refresh_expires = NULL, remember_hash = NULL, \
                     remember_expires = NULL WHERE user_id = ?1 AND id = ?2",
                    [owned_user, owned_id],
                )? > 0)
            })
            .await?;
        self.forget_session_of(user_id);
        Ok(done)
    }

    /// Forget the device altogether.
    pub async fn delete_device(&self, user_id: &str, id: &str) -> Result<bool> {
        let (owned_user, owned_id) = (user_id.to_string(), id.to_string());
        let done = self
            .sqlite_write(move |tx| {
                Ok(tx.execute("DELETE FROM devices WHERE user_id = ?1 AND id = ?2", [owned_user, owned_id])? > 0)
            })
            .await?;
        self.forget_session_of(user_id);
        Ok(done)
    }

    /// The push token a mobile app registers for itself.
    pub async fn set_push_token(&self, user_id: &str, id: &str, token: Option<String>) -> Result<bool> {
        let (user_id, id) = (user_id.to_string(), id.to_string());
        self.sqlite_write(move |tx| {
            Ok(tx.execute(
                "UPDATE devices SET push_token = ?3 WHERE user_id = ?1 AND id = ?2",
                params![user_id, id, token],
            )? > 0)
        })
        .await
    }

    /// Two-step login is no longer skipped on any device of the user.
    pub async fn forget_remembered_devices(&self, user_id: &str) -> Result<()> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("UPDATE devices SET remember_hash = NULL, remember_expires = NULL WHERE user_id = ?1", [user_id])
                .map(drop)
        })
        .await
    }

    // ── Invitations ────────────────────────────────────────

    /// Invite an address, or invite it again with a new token.
    pub async fn invite(
        &self,
        email: &str,
        token_hash: Vec<u8>,
        admin: bool,
        invited_by: Option<String>,
        language: &str,
        expires: String,
    ) -> Result<Invitation> {
        let email = normalize_email(email);
        let language = language.to_string();
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO invitations (email, token_hash, admin, invited_by, language, created, expires) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                 ON CONFLICT (email) DO UPDATE SET token_hash = excluded.token_hash, admin = excluded.admin, \
                 invited_by = excluded.invited_by, language = excluded.language, created = excluded.created, \
                 expires = excluded.expires",
                params![email, token_hash, admin, invited_by, language, clock::now(), expires],
            )?;
            tx.query_row(
                "SELECT email, admin, invited_by, language, created, expires FROM invitations WHERE email = ?1",
                [&email],
                invitation_from,
            )
        })
        .await
    }

    /// The invitation a token is for, if it has not run out.
    pub async fn invitation_by_token(&self, token_hash: Vec<u8>) -> Result<Option<Invitation>> {
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT email, admin, invited_by, language, created, expires FROM invitations \
                 WHERE token_hash = ?1 AND expires > ?2",
                params![token_hash, clock::now()],
                invitation_from,
            )
            .optional()
        })
        .await
    }

    pub async fn invitation(&self, email: &str) -> Result<Option<Invitation>> {
        let email = normalize_email(email);
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT email, admin, invited_by, language, created, expires FROM invitations WHERE email = ?1",
                [email],
                invitation_from,
            )
            .optional()
        })
        .await
    }

    /// Every invitation, run out or not, the newest first.
    pub async fn invitations(&self) -> Result<Vec<Invitation>> {
        self.sqlite_read(|conn| {
            conn.prepare(
                "SELECT email, admin, invited_by, language, created, expires FROM invitations ORDER BY created DESC",
            )?
            .query_map([], invitation_from)?
            .collect()
        })
        .await
    }

    pub async fn uninvite(&self, email: &str) -> Result<bool> {
        let email = normalize_email(email);
        self.sqlite_write(move |tx| Ok(tx.execute("DELETE FROM invitations WHERE email = ?1", [email])? > 0)).await
    }

    // ── Two-step login ─────────────────────────────────────

    pub async fn two_factors(&self, user_id: &str) -> Result<Vec<TwoFactor>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(
                "SELECT type, enabled, data, last_used FROM two_factor WHERE user_id = ?1 ORDER BY type",
            )?
            .query_map([user_id], |row| {
                Ok(TwoFactor { kind: row.get(0)?, enabled: row.get(1)?, data: row.get(2)?, last_used: row.get(3)? })
            })?
            .collect()
        })
        .await
    }

    /// Set up (or replace) one way of two-step login. The first one also gets the account a
    /// recovery code, if it has none.
    pub async fn set_two_factor(&self, user_id: &str, kind: i64, data: String, recovery_code: String) -> Result<()> {
        let owned = user_id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO two_factor (user_id, type, enabled, data, last_used) VALUES (?1, ?2, 1, ?3, 0) \
                 ON CONFLICT (user_id, type) DO UPDATE SET enabled = 1, data = excluded.data, last_used = 0",
                params![owned, kind, data],
            )?;
            tx.execute(
                "UPDATE users SET recovery_code = coalesce(recovery_code, ?2), updated = ?3 WHERE id = ?1",
                params![owned, recovery_code, clock::now()],
            )?;
            Ok(())
        })
        .await?;
        self.forget_session_of(user_id);
        Ok(())
    }

    /// Turn off one way of two-step login, or all of them (`None`). With the last one gone, the
    /// recovery code and remembered devices go too.
    pub async fn remove_two_factor(&self, user_id: &str, kind: Option<i64>) -> Result<()> {
        let owned = user_id.to_string();
        self.sqlite_write(move |tx| {
            match kind {
                Some(kind) => {
                    tx.execute("DELETE FROM two_factor WHERE user_id = ?1 AND type = ?2", params![owned, kind])?
                }
                None => tx.execute("DELETE FROM two_factor WHERE user_id = ?1", [&owned])?,
            };
            let left: bool =
                tx.query_row("SELECT EXISTS (SELECT 1 FROM two_factor WHERE user_id = ?1)", [&owned], |row| {
                    row.get(0)
                })?;
            if !left {
                tx.execute(
                    "UPDATE users SET recovery_code = NULL, updated = ?2 WHERE id = ?1",
                    params![owned, clock::now()],
                )?;
                tx.execute(
                    "UPDATE devices SET remember_hash = NULL, remember_expires = NULL WHERE user_id = ?1",
                    [&owned],
                )?;
            }
            Ok(())
        })
        .await?;
        self.forget_session_of(user_id);
        Ok(())
    }

    /// Take the authenticator code of time step `step`, unless that step or a later one was
    /// taken already: a code seen once over someone's shoulder does not log in a second time.
    pub async fn use_totp_step(&self, user_id: &str, step: i64) -> Result<bool> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| {
            Ok(tx.execute(
                "UPDATE two_factor SET last_used = ?2 WHERE user_id = ?1 AND type = 0 AND last_used < ?2",
                params![user_id, step],
            )? > 0)
        })
        .await
    }

    // ── Codes by mail ──────────────────────────────────────

    /// A new code for `purpose`, replacing the one before.
    pub async fn put_code(
        &self,
        user_id: &str,
        purpose: &str,
        code_hash: Vec<u8>,
        data: Option<String>,
        expires: String,
    ) -> Result<()> {
        let (user_id, purpose) = (user_id.to_string(), purpose.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO codes (user_id, purpose, code_hash, data, attempts, expires) VALUES (?1, ?2, ?3, ?4, 0, ?5) \
                 ON CONFLICT (user_id, purpose) DO UPDATE SET code_hash = excluded.code_hash, data = excluded.data, \
                 attempts = 0, expires = excluded.expires",
                params![user_id, purpose, code_hash, data, expires],
            )
            .map(drop)
        })
        .await
    }

    /// Check a code for `purpose`. A right one is used up and hands back what was kept with it;
    /// a wrong one counts, and after [`CODE_ATTEMPTS`] of them the code is gone.
    pub async fn take_code(
        &self,
        user_id: &str,
        purpose: &str,
        code_hash: Vec<u8>,
    ) -> Result<std::result::Result<Option<String>, CodeRefusal>> {
        let (user_id, purpose) = (user_id.to_string(), purpose.to_string());
        self.sqlite_write(move |tx| {
            let found: Option<(Vec<u8>, Option<String>, i64, String)> = tx
                .query_row(
                    "SELECT code_hash, data, attempts, expires FROM codes WHERE user_id = ?1 AND purpose = ?2",
                    [&user_id, &purpose],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let Some((hash, data, attempts, expires)) = found else { return Ok(Err(CodeRefusal::Missing)) };
            let forget = |tx: &Transaction<'_>| {
                tx.execute("DELETE FROM codes WHERE user_id = ?1 AND purpose = ?2", [&user_id, &purpose]).map(drop)
            };
            if expires <= clock::now() {
                forget(tx)?;
                return Ok(Err(CodeRefusal::Expired));
            }
            if constant_time_eq(&hash, &code_hash) {
                forget(tx)?;
                return Ok(Ok(data));
            }
            if attempts + 1 >= CODE_ATTEMPTS {
                forget(tx)?;
                return Ok(Err(CodeRefusal::TooManyAttempts));
            }
            tx.execute(
                "UPDATE codes SET attempts = attempts + 1 WHERE user_id = ?1 AND purpose = ?2",
                [&user_id, &purpose],
            )?;
            Ok(Err(CodeRefusal::Wrong))
        })
        .await
    }
}

pub(crate) fn bump_revision(tx: &Transaction<'_>, user_id: &str) -> rusqlite::Result<()> {
    tx.prepare_cached("UPDATE users SET revision = ?2 WHERE id = ?1")?.execute(params![user_id, clock::now()])?;
    Ok(())
}

/// Bitwarden salts with the address as it was registered, trimmed and in lower case, so that is
/// how it is kept and looked up.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::Options;

    pub(crate) fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (Store::open_sqlite(&dir.path().join("uwulock.db"), &Options { readers: 2 }).unwrap(), dir)
    }

    pub(crate) fn new_user(email: &str) -> NewUser {
        NewUser {
            email: email.into(),
            name: Some("Nyu".into()),
            password_hash: "$argon2id$hash".into(),
            password_hint: None,
            user_key: "2.key|key|key".into(),
            private_key: Some("2.private|private|private".into()),
            public_key: Some("public".into()),
            kdf: Kdf { kind: 0, iterations: 600_000, memory: None, parallelism: None },
            language: "de".into(),
            admin: false,
        }
    }

    fn login(user_id: &str, device: &str, hash: u8) -> DeviceLogin {
        DeviceLogin {
            user_id: user_id.into(),
            id: device.into(),
            name: "firefox".into(),
            kind: 3,
            ip: Some("192.0.2.1".into()),
            refresh_hash: vec![hash; 32],
            refresh_expires: clock::in_seconds(3600),
            remember: None,
        }
    }

    #[tokio::test]
    async fn an_invitation_makes_one_account() {
        let (store, _dir) = store();
        store.invite("Nyu@Example.com ", vec![1; 32], true, None, "de", clock::in_seconds(60)).await.unwrap();
        let invitation = store.invitation_by_token(vec![1; 32]).await.unwrap().unwrap();
        assert_eq!(invitation.email, "nyu@example.com");
        assert!(invitation.admin);

        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        assert!(store.invitation("nyu@example.com").await.unwrap().is_none(), "used up");
        assert!(matches!(store.create_user(new_user("nyu@example.com")).await, Err(StoreError::Exists)));
        assert_eq!(store.user_by_email(" NYU@example.com").await.unwrap().unwrap().id, user.id);
        assert_eq!(user.created, user.revision);
    }

    #[tokio::test]
    async fn an_invitation_that_ran_out_opens_nothing() {
        let (store, _dir) = store();
        store.invite("a@example.com", vec![2; 32], false, None, "en", clock::in_seconds(-1)).await.unwrap();
        assert!(store.invitation_by_token(vec![2; 32]).await.unwrap().is_none());
        assert_eq!(store.invitations().await.unwrap().len(), 1, "still listed");
    }

    #[tokio::test]
    async fn sessions_follow_logins_logouts_and_new_stamps() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        assert!(store.log_in_device(login(&user.id, "one", 1)).await.unwrap(), "new");
        assert!(!store.log_in_device(login(&user.id, "one", 3)).await.unwrap(), "known");
        store.log_in_device(login(&user.id, "two", 2)).await.unwrap();
        let session = store.session_user(&user.id).await.unwrap().unwrap();
        assert!(session.devices.contains("one") && session.devices.contains("two"));

        store.log_out_device(&user.id, "one").await.unwrap();
        let session = store.session_user(&user.id).await.unwrap().unwrap();
        assert!(!session.devices.contains("one") && session.devices.contains("two"));

        let old = session.user.security_stamp.clone();
        store.update_user(&user.id, |user| user.security_stamp = "new".into()).await.unwrap();
        let session = store.session_user(&user.id).await.unwrap().unwrap();
        assert_ne!(session.user.security_stamp, old);
        assert!(session.devices.is_empty(), "a new stamp logs every device out");
        assert!(store.refresh_device(vec![2; 32], |_| clock::in_seconds(60), None).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_refresh_token_finds_its_device_until_it_runs_out() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        store.log_in_device(login(&user.id, "one", 7)).await.unwrap();
        let device = store.refresh_device(vec![7; 32], |_| clock::in_seconds(-5), None).await.unwrap().unwrap();
        assert_eq!(device.id, "one");
        assert!(store.refresh_device(vec![7; 32], |_| clock::in_seconds(60), None).await.unwrap().is_none(), "ran out");
        assert!(store.refresh_device(vec![8; 32], |_| clock::in_seconds(60), None).await.unwrap().is_none(), "unknown");
    }

    #[tokio::test]
    async fn codes_count_wrong_tries() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        store.put_code(&user.id, "login", vec![1], Some("x".into()), clock::in_seconds(60)).await.unwrap();
        assert_eq!(store.take_code(&user.id, "login", vec![2]).await.unwrap(), Err(CodeRefusal::Wrong));
        assert_eq!(store.take_code(&user.id, "login", vec![1]).await.unwrap(), Ok(Some("x".into())));
        assert_eq!(store.take_code(&user.id, "login", vec![1]).await.unwrap(), Err(CodeRefusal::Missing), "used up");

        store.put_code(&user.id, "login", vec![1], None, clock::in_seconds(60)).await.unwrap();
        for _ in 1..CODE_ATTEMPTS {
            assert_eq!(store.take_code(&user.id, "login", vec![2]).await.unwrap(), Err(CodeRefusal::Wrong));
        }
        assert_eq!(store.take_code(&user.id, "login", vec![2]).await.unwrap(), Err(CodeRefusal::TooManyAttempts));
        assert_eq!(store.take_code(&user.id, "login", vec![1]).await.unwrap(), Err(CodeRefusal::Missing));

        store.put_code(&user.id, "login", vec![1], None, clock::in_seconds(-1)).await.unwrap();
        assert_eq!(store.take_code(&user.id, "login", vec![1]).await.unwrap(), Err(CodeRefusal::Expired));
    }

    #[tokio::test]
    async fn an_authenticator_code_counts_once() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        store.set_two_factor(&user.id, 0, "{}".into(), "RECOVER".into()).await.unwrap();
        assert!(store.use_totp_step(&user.id, 100).await.unwrap());
        assert!(!store.use_totp_step(&user.id, 100).await.unwrap(), "the same step again");
        assert!(!store.use_totp_step(&user.id, 99).await.unwrap(), "an older one");
        assert!(store.use_totp_step(&user.id, 101).await.unwrap());
        assert_eq!(store.user(&user.id).await.unwrap().unwrap().recovery_code.as_deref(), Some("RECOVER"));

        store.remove_two_factor(&user.id, Some(0)).await.unwrap();
        assert!(store.two_factors(&user.id).await.unwrap().is_empty());
        assert_eq!(store.user(&user.id).await.unwrap().unwrap().recovery_code, None, "no recovery without 2FA");
    }
}
