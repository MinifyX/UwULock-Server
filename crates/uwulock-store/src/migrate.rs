//! Moving in: a whole other server's accounts at once — Vaultwarden's, read by the server crate
//! and handed over here as rows. All of it is written in one transaction: either everything
//! arrives, or nothing does.

use crate::emergency::EmergencyAccess;
use crate::organizations::{Collection, Group, Member, Organization, Policy};
use crate::passkeys::Passkey;
use crate::sends::{Send, write_send};
use crate::vault::write_cipher;
use crate::{Attachment, Cipher, Folder, Kdf, Result, Store, StoreError, clock};
use rusqlite::params;

/// An account as it comes over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MovedUser {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    /// The server's hash of the master password hash, in whatever form verifies it.
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
    pub api_key: Option<String>,
}

/// A device that stays logged in: its refresh token's and "remember me" token's SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MovedDevice {
    pub user_id: String,
    pub id: String,
    pub name: String,
    pub kind: i64,
    pub created: String,
    pub last_seen: String,
    pub refresh_hash: Option<Vec<u8>>,
    pub remember_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MovedTwoFactor {
    pub user_id: String,
    pub kind: i64,
    pub enabled: bool,
    pub data: String,
    pub last_used: i64,
}

/// Everything that moves in.
#[derive(Debug, Default, Clone)]
pub struct Migration {
    pub users: Vec<MovedUser>,
    pub devices: Vec<MovedDevice>,
    pub two_factor: Vec<MovedTwoFactor>,
    pub folders: Vec<Folder>,
    pub ciphers: Vec<Cipher>,
    /// (collection, item)
    pub collection_ciphers: Vec<(String, String)>,
    /// (item, user, folder, favorite): a member's own filing of an organisation's item.
    pub preferences: Vec<(String, String, Option<String>, bool)>,
    pub attachments: Vec<Attachment>,
    pub sends: Vec<Send>,
    pub emergency: Vec<EmergencyAccess>,
    pub passkeys: Vec<Passkey>,
    pub organizations: Vec<Organization>,
    pub members: Vec<Member>,
    pub collections: Vec<Collection>,
    pub groups: Vec<Group>,
    /// (group, member)
    pub group_members: Vec<(String, String)>,
    /// (collection, member, read only, hide passwords, manage)
    pub collection_members: Vec<(String, String, bool, bool, bool)>,
    /// (collection, group, read only, hide passwords, manage)
    pub collection_groups: Vec<(String, String, bool, bool, bool)>,
    pub policies: Vec<Policy>,
}

impl Store {
    /// Write everything of `migration`, or nothing. [`StoreError::Exists`] when an address that
    /// moves in has an account here already.
    pub async fn migrate(&self, migration: Migration) -> Result<()> {
        let done = self
            .sqlite_write(move |tx| {
                for user in &migration.users {
                    let taken: bool = tx.query_row(
                        "SELECT EXISTS (SELECT 1 FROM users WHERE email = ?1 OR id = ?2)",
                        [&user.email, &user.id],
                        |row| row.get(0),
                    )?;
                    if taken {
                        return Ok(false);
                    }
                }
                let now = clock::now();
                for user in &migration.users {
                    tx.execute(
                        "INSERT INTO users (id, email, name, password_hash, password_hint, user_key, user_key_id, \
                         private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, \
                         language, avatar_color, equivalent_domains, excluded_globals, recovery_code, admin, disabled, \
                         created, updated, revision) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, \
                         ?21, ?22, ?23, ?24)",
                        params![
                            user.id,
                            user.email,
                            user.name,
                            user.password_hash,
                            user.password_hint,
                            user.user_key,
                            user.user_key_id,
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
                            user.created,
                            user.updated,
                            now,
                        ],
                    )?;
                    if let Some(key) = &user.api_key {
                        tx.execute(
                            "INSERT INTO api_keys (user_id, secret, revision) VALUES (?1, ?2, ?3)",
                            params![user.id, key, now],
                        )?;
                    }
                    tx.execute("DELETE FROM invitations WHERE email = ?1", [&user.email])?;
                }
                for device in &migration.devices {
                    tx.execute(
                        "INSERT INTO devices (user_id, id, name, type, created, last_seen, refresh_hash, refresh_expires, \
                         remember_hash, remember_expires) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        params![
                            device.user_id,
                            device.id,
                            device.name,
                            device.kind,
                            device.created,
                            device.last_seen,
                            device.refresh_hash,
                            device.refresh_hash.as_ref().map(|_| clock::in_seconds(30 * 86_400)),
                            device.remember_hash,
                            device.remember_hash.as_ref().map(|_| clock::in_seconds(30 * 86_400)),
                        ],
                    )?;
                }
                for factor in &migration.two_factor {
                    tx.execute(
                        "INSERT INTO two_factor (user_id, type, enabled, data, last_used) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![factor.user_id, factor.kind, factor.enabled, factor.data, factor.last_used],
                    )?;
                }
                for folder in &migration.folders {
                    tx.execute(
                        "INSERT INTO folders (id, user_id, name, created, revision) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![folder.id, folder.user_id, folder.name, folder.created, folder.revision],
                    )?;
                }
                for org in &migration.organizations {
                    tx.execute(
                        "INSERT INTO organizations (id, name, billing_email, public_key, private_key, created, revision, \
                         plan_type) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        params![
                            org.id,
                            org.name,
                            org.billing_email,
                            org.public_key,
                            org.private_key,
                            org.created,
                            org.revision,
                            org.plan_type
                        ],
                    )?;
                }
                for member in &migration.members {
                    tx.execute(
                        "INSERT INTO org_members (id, org_id, user_id, email, key, status, type, access_all, permissions, \
                         external_id, reset_password_key, created, revision) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                        params![
                            member.id,
                            member.org_id,
                            member.user_id,
                            member.email,
                            member.key,
                            member.status,
                            member.kind,
                            member.access_all,
                            member.permissions,
                            member.external_id,
                            member.reset_password_key,
                            member.created,
                            member.revision,
                        ],
                    )?;
                }
                for collection in &migration.collections {
                    tx.execute(
                        "INSERT INTO collections (id, org_id, name, external_id, created, revision) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            collection.id,
                            collection.org_id,
                            collection.name,
                            collection.external_id,
                            collection.created,
                            collection.revision
                        ],
                    )?;
                }
                for group in &migration.groups {
                    tx.execute(
                        "INSERT INTO groups (id, org_id, name, access_all, external_id, created, revision) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            group.id,
                            group.org_id,
                            group.name,
                            group.access_all,
                            group.external_id,
                            group.created,
                            group.revision
                        ],
                    )?;
                }
                for (group, member) in &migration.group_members {
                    tx.execute("INSERT INTO group_members (group_id, member_id) VALUES (?1, ?2)", [group, member])?;
                }
                for (collection, member, read_only, hide, manage) in &migration.collection_members {
                    tx.execute(
                        "INSERT INTO collection_members (collection_id, member_id, read_only, hide_passwords, manage) \
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![collection, member, read_only, hide, manage],
                    )?;
                }
                for (collection, group, read_only, hide, manage) in &migration.collection_groups {
                    tx.execute(
                        "INSERT INTO collection_groups (collection_id, group_id, read_only, hide_passwords, manage) \
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![collection, group, read_only, hide, manage],
                    )?;
                }
                for policy in &migration.policies {
                    tx.execute(
                        "INSERT INTO policies (id, org_id, type, enabled, data, revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![policy.id, policy.org_id, policy.kind, policy.enabled, policy.data, policy.revision],
                    )?;
                }
                for org in &migration.organizations {
                    crate::organizations::classify(tx, &org.id)?;
                }
                for cipher in &migration.ciphers {
                    write_cipher(tx, cipher)?;
                }
                for (collection, cipher) in &migration.collection_ciphers {
                    tx.execute(
                        "INSERT OR IGNORE INTO collection_ciphers (collection_id, cipher_id) VALUES (?1, ?2)",
                        [collection, cipher],
                    )?;
                }
                for (cipher, user, folder, favorite) in &migration.preferences {
                    tx.execute(
                        "INSERT OR REPLACE INTO cipher_preferences (cipher_id, user_id, folder_id, favorite) \
                         VALUES (?1, ?2, ?3, ?4)",
                        params![cipher, user, folder, favorite],
                    )?;
                }
                for attachment in &migration.attachments {
                    tx.execute(
                        "INSERT INTO attachments (id, cipher_id, file_name, key, size, uploaded, created) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            attachment.id,
                            attachment.cipher_id,
                            attachment.file_name,
                            attachment.key,
                            attachment.size,
                            attachment.uploaded,
                            attachment.created
                        ],
                    )?;
                }
                for send in &migration.sends {
                    write_send(tx, send)?;
                }
                for access in &migration.emergency {
                    tx.execute(
                        "INSERT INTO emergency_access (id, grantor_id, grantee_id, email, key_encrypted, type, status, \
                         wait_days, token_hash, recovery_asked, last_notification, created, revision) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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
                }
                for passkey in &migration.passkeys {
                    tx.execute(
                        "INSERT INTO passkeys (id, user_id, name, public_key, counter, supports_prf, encrypted_user_key, \
                         encrypted_public_key, encrypted_private_key, created, last_used) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                        params![
                            passkey.id,
                            passkey.user_id,
                            passkey.name,
                            passkey.public_key,
                            passkey.counter,
                            passkey.supports_prf,
                            passkey.encrypted_user_key,
                            passkey.encrypted_public_key,
                            passkey.encrypted_private_key,
                            passkey.created,
                            passkey.last_used,
                        ],
                    )?;
                }
                Ok(true)
            })
            .await?;
        if !done {
            return Err(StoreError::Exists);
        }
        let mut sessions = self.sessions.write();
        sessions.by_user.clear();
        sessions.forgotten += 1;
        Ok(())
    }
}
