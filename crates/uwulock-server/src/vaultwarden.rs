//! Moving in from Vaultwarden: `uwulock-server import-vaultwarden <data>`.
//!
//! Reads a Vaultwarden data directory — `db.sqlite3` (read-only), `rsa_key.pem`, the files of
//! attachments and Sends — and brings every account over as it is: the same ids, the same
//! encrypted vaults, devices that stay logged in, two-step login, organisations with their
//! collections, groups and policies, Sends, emergency access. Nothing is decrypted on the way:
//! there is nothing to decrypt it with, and nothing needs to be.
//!
//! What does not come: accounts that were invited but never registered, events, pending "log
//! in with a device" requests, and kinds of two-step login this server does not have (Duo,
//! YubiKey OTP) — those are named in the summary, so their owners can set up another.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ciborium::Value as Cbor;
use rusqlite::{Connection, OptionalExtension, Row};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use uwulock_api::files::valid_id;
use uwulock_store::emergency::EmergencyAccess;
use uwulock_store::organizations::{Collection, Group, Member, Organization, Policy};
use uwulock_store::sends::Send;
use uwulock_store::{Attachment, Cipher, Folder, Kdf, Migration, MovedDevice, MovedTwoFactor, MovedUser, Store, clock};

/// The name of a kind of two-step login this server does not have, for the mail about it.
fn method_name(kind: i64) -> String {
    match kind {
        2 | 6 => "Duo".into(),
        3 => "YubiKey OTP".into(),
        4 => "U2F".into(),
        kind => format!("type {kind}"),
    }
}

/// What an import found, and what it left behind.
#[derive(Debug, Default)]
pub struct Summary {
    pub users: usize,
    pub devices: usize,
    pub folders: usize,
    pub ciphers: usize,
    pub attachments: usize,
    pub sends: usize,
    pub organizations: usize,
    pub collections: usize,
    pub emergency: usize,
    /// What did not come over, for the person running the import.
    pub notes: Vec<String>,
    /// Accounts whose two-step login did not come over, and whose alone it was: address,
    /// language, and the method. They are told by mail when mail is set up.
    pub lost_two_factor: Vec<(String, String, String)>,
}

impl std::fmt::Display for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "accounts:          {}", self.users)?;
        writeln!(f, "devices:           {}", self.devices)?;
        writeln!(f, "folders:           {}", self.folders)?;
        writeln!(f, "items:             {}", self.ciphers)?;
        writeln!(f, "attachments:       {}", self.attachments)?;
        writeln!(f, "Sends:             {}", self.sends)?;
        writeln!(f, "organisations:     {}", self.organizations)?;
        writeln!(f, "collections:       {}", self.collections)?;
        writeln!(f, "emergency access:  {}", self.emergency)?;
        for note in &self.notes {
            writeln!(f, "note: {note}")?;
        }
        Ok(())
    }
}

/// A time as Vaultwarden's SQLite keeps it (`2026-09-25 12:00:00.123456`), in this server's
/// format.
fn time(text: Option<String>) -> Option<String> {
    let text = text?;
    let iso = text.trim().replacen(' ', "T", 1);
    clock::parse(&iso).map(clock::format).or(Some(text))
}

fn now_or(text: Option<String>) -> String {
    time(text).unwrap_or_else(clock::now)
}

/// `Name` becomes `name`, all the way down: what older Vaultwardens kept in PascalCase.
fn lower_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    let mut chars = key.chars();
                    let key = match chars.next() {
                        Some(first) => first.to_lowercase().chain(chars).collect(),
                        None => key,
                    };
                    (key, lower_keys(value))
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(lower_keys).collect()),
        other => other,
    }
}

/// A hash Vaultwarden made (PBKDF2-SHA256), the way this server checks it until it replaces it.
fn legacy_hash(hash: &[u8], salt: &[u8], rounds: i64) -> String {
    format!("{}{rounds}${}${}", uwulock_api::LEGACY_HASH, STANDARD.encode(salt), STANDARD.encode(hash))
}

fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().to_vec()
}

/// Bytes as webauthn-rs writes them: base64url (sometimes padded, sometimes standard base64) or,
/// in older versions, a list of numbers.
fn bytes_of(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::String(text) => {
            URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok().or_else(|| STANDARD.decode(text).ok())
        }
        Value::Array(items) => items.iter().map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok())).collect(),
        _ => None,
    }
}

/// A security key as webauthn-rs keeps it, as the COSE key this server checks signatures with.
fn cose_key(credential: &Value) -> Option<Vec<u8>> {
    let key = credential.pointer("/cred/cred/key").or_else(|| credential.pointer("/cred/key"))?;
    let int = |n: i64| Cbor::Integer(n.into());
    let map = if let Some(ec) = key.get("EC_EC2") {
        vec![
            (int(1), int(2)),
            (int(3), int(-7)),
            (int(-1), int(1)),
            (int(-2), Cbor::Bytes(bytes_of(ec.get("x")?)?)),
            (int(-3), Cbor::Bytes(bytes_of(ec.get("y")?)?)),
        ]
    } else if let Some(okp) = key.get("EC_OKP") {
        vec![(int(1), int(1)), (int(3), int(-8)), (int(-1), int(6)), (int(-2), Cbor::Bytes(bytes_of(okp.get("x")?)?))]
    } else {
        let rsa = key.get("RSA")?;
        vec![
            (int(1), int(3)),
            (int(3), int(-257)),
            (int(-1), Cbor::Bytes(bytes_of(rsa.get("n")?)?)),
            (int(-2), Cbor::Bytes(bytes_of(rsa.get("e")?)?)),
        ]
    };
    let mut out = Vec::new();
    ciborium::into_writer(&Cbor::Map(map), &mut out).ok()?;
    Some(out)
}

/// Vaultwarden's security keys for the second step, in this server's form.
fn security_keys(data: &str) -> Vec<Value> {
    let Ok(Value::Array(keys)) = serde_json::from_str::<Value>(data) else { return Vec::new() };
    keys.iter()
        .filter_map(|key| {
            let credential = key.get("credential")?;
            // webauthn-rs 0.5 (Vaultwarden 1.33 and later) wraps the credential in a `Passkey`.
            let inner = if credential.pointer("/cred/cred_id").is_some() { &credential["cred"] } else { credential };
            let id = URL_SAFE_NO_PAD.encode(bytes_of(inner.get("cred_id")?)?);
            Some(json!({
                "id": key.get("id")?.as_i64()?,
                "name": key.get("name").and_then(Value::as_str).unwrap_or("Security key"),
                "credentialId": id,
                "publicKey": URL_SAFE_NO_PAD.encode(cose_key(credential)?),
                "counter": inner.get("counter").and_then(Value::as_u64).unwrap_or(0),
                "migrated": key.get("migrated").and_then(Value::as_bool).unwrap_or(false),
            }))
        })
        .collect()
}

/// The public half of Vaultwarden's `rsa_key.pem`, as DER, for the refresh tokens it signed.
fn public_key(pem: &[u8]) -> Result<Vec<u8>, String> {
    let item = rustls_pemfile::read_one_from_slice(pem)
        .map_err(|_| "rsa_key.pem is not PEM".to_string())?
        .ok_or("rsa_key.pem holds no key")?
        .0;
    let pair = match item {
        rustls_pemfile::Item::Pkcs1Key(der) => ring::rsa::KeyPair::from_der(der.secret_pkcs1_der()),
        rustls_pemfile::Item::Pkcs8Key(der) => ring::rsa::KeyPair::from_pkcs8(der.secret_pkcs8_der()),
        _ => return Err("rsa_key.pem holds no RSA key".into()),
    }
    .map_err(|error| format!("rsa_key.pem: {error}"))?;
    Ok(ring::signature::KeyPair::public_key(&pair).as_ref().to_vec())
}

fn read<T>(conn: &Connection, sql: &str, map: impl FnMut(&Row<'_>) -> rusqlite::Result<T>) -> Result<Vec<T>, String> {
    let mut statement = conn.prepare(sql).map_err(|error| format!("{sql}: {error}"))?;
    statement.query_map([], map).and_then(Iterator::collect).map_err(|error| format!("{sql}: {error}"))
}

/// `column` of `table` when that Vaultwarden has it, a stand-in when it is older.
fn column_or(conn: &Connection, table: &str, column: &str, stand_in: &str) -> String {
    if conn.prepare(&format!("SELECT {column} FROM {table} LIMIT 0")).is_ok() { column.into() } else { stand_in.into() }
}

fn has_table(conn: &Connection, name: &str) -> bool {
    conn.query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [name], |_| Ok(()))
        .optional()
        .ok()
        .flatten()
        .is_some()
}

/// Everything in Vaultwarden's data directory `data`, as this server's rows. `admins` become
/// admins here; `language` is what the accounts' mails start in.
pub fn read_vaultwarden(
    data: &Path,
    admins: &[String],
    language: &str,
) -> Result<(Migration, Option<Vec<u8>>, Summary), String> {
    let path = data.join("db.sqlite3");
    if !path.exists() {
        return Err(format!(
            "{} has no db.sqlite3. Only a Vaultwarden on SQLite can be moved over; one on MySQL or PostgreSQL has to \
             move to SQLite first.",
            data.display()
        ));
    }
    // A copy, with the write-ahead log next to it: what Vaultwarden wrote last may still be in
    // there, and SQLite only reads it with a file it may write beside it — which a data
    // directory owned by the container's root is not.
    let copy = tempfile::tempdir().map_err(|error| error.to_string())?;
    for suffix in ["", "-wal"] {
        let from = data.join(format!("db.sqlite3{suffix}"));
        if from.exists() {
            std::fs::copy(&from, copy.path().join(format!("db.sqlite3{suffix}")))
                .map_err(|error| format!("{}: {error}", from.display()))?;
        }
    }
    let conn =
        Connection::open(copy.path().join("db.sqlite3")).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut summary = Summary::default();
    let mut migration = Migration::default();

    // ── Accounts ─────────────────────────────────────────
    let has_key_id = conn.prepare("SELECT key_id FROM users LIMIT 0").is_ok();
    let users = read(
        &conn,
        &format!(
            "SELECT uuid, enabled, created_at, updated_at, email, name, password_hash, salt, password_iterations, \
             password_hint, akey, private_key, public_key, totp_recover, security_stamp, equivalent_domains, \
             excluded_globals, client_kdf_type, client_kdf_iter, client_kdf_memory, client_kdf_parallelism, api_key, \
             avatar_color, {} FROM users",
            if has_key_id { "key_id" } else { "NULL" }
        ),
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, String>(14)?,
                row.get::<_, String>(15)?,
                row.get::<_, String>(16)?,
                row.get::<_, i64>(17)?,
                row.get::<_, i64>(18)?,
                row.get::<_, Option<i64>>(19)?,
                row.get::<_, Option<i64>>(20)?,
                row.get::<_, Option<String>>(21)?,
                row.get::<_, Option<String>>(22)?,
                row.get::<_, Option<String>>(23)?,
            ))
        },
    )?;
    let mut moved_users: HashSet<String> = HashSet::new();
    let mut emails: HashMap<String, String> = HashMap::new();
    let admins: HashSet<String> = admins.iter().map(|email| uwulock_store::normalize_email(email)).collect();
    for u in users {
        let email = uwulock_store::normalize_email(&u.4);
        if u.6.is_empty() || u.10.is_empty() {
            summary.notes.push(format!("{email} was invited but never registered: not moved over"));
            continue;
        }
        moved_users.insert(u.0.clone());
        emails.insert(u.0.clone(), email.clone());
        migration.users.push(MovedUser {
            id: u.0,
            admin: admins.contains(&email),
            email,
            name: Some(u.5).filter(|name| !name.trim().is_empty()),
            password_hash: legacy_hash(&u.6, &u.7, u.8),
            password_hint: u.9.filter(|hint| !hint.is_empty()),
            user_key: u.10,
            user_key_id: u.23,
            private_key: u.11,
            public_key: u.12,
            kdf: Kdf { kind: u.17, iterations: u.18, memory: u.19, parallelism: u.20 },
            security_stamp: u.14,
            language: language.to_string(),
            avatar_color: u.22,
            equivalent_domains: u.15,
            excluded_globals: u.16,
            recovery_code: u.13,
            disabled: !u.1,
            created: now_or(u.2),
            updated: now_or(u.3),
            api_key: u.21,
        });
    }
    summary.users = migration.users.len();
    for email in &admins {
        if !migration.users.iter().any(|user| &user.email == email) {
            summary.notes.push(format!("{email} is to be an admin, but has no account in this Vaultwarden"));
        }
    }

    // ── Devices, two-step login ──────────────────────────
    for d in read(
        &conn,
        &format!(
            "SELECT uuid, user_uuid, name, atype, created_at, updated_at, refresh_token, twofactor_remember, {}, {} \
             FROM devices",
            column_or(&conn, "devices", "push_uuid", "NULL"),
            column_or(&conn, "devices", "push_token", "NULL")
        ),
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
            ))
        },
    )? {
        if !moved_users.contains(&d.1) {
            continue;
        }
        migration.devices.push(MovedDevice {
            user_id: d.1,
            id: d.0,
            name: d.2,
            kind: d.3,
            created: now_or(d.4),
            last_seen: now_or(d.5),
            refresh_hash: Some(d.6)
                .filter(|token| !token.is_empty())
                .map(|token| uwulock_api::vaultwarden::moved_token_hash(&token)),
            remember_hash: d.7.filter(|token| !token.is_empty()).map(|token| sha256(token.as_bytes())),
            push_token: d.9.filter(|token| !token.is_empty()),
            push_id: d.8,
        });
    }
    summary.devices = migration.devices.len();

    let mut with_factor: HashSet<String> = HashSet::new();
    let mut lost: Vec<(String, String)> = Vec::new();
    for f in read(&conn, "SELECT user_uuid, atype, enabled, data, last_used FROM twofactor", |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, bool>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })? {
        if !moved_users.contains(&f.0) {
            continue;
        }
        let email = emails.get(&f.0).cloned().unwrap_or_default();
        let data = match f.1 {
            0 => Some(f.3.trim().to_uppercase()),
            1 => serde_json::from_str::<Value>(&f.3).ok().and_then(|value| {
                value.get("email").and_then(Value::as_str).map(|email| json!({ "email": email }).to_string())
            }),
            7 => {
                let keys = security_keys(&f.3);
                (!keys.is_empty()).then(|| Value::Array(keys).to_string())
            }
            // Vaultwarden's own bookkeeping: challenges, codes on their way.
            kind if kind >= 1000 => continue,
            _ => None,
        };
        match data {
            Some(data) => {
                if f.2 {
                    with_factor.insert(f.0.clone());
                }
                migration.two_factor.push(MovedTwoFactor {
                    user_id: f.0,
                    kind: f.1,
                    enabled: f.2,
                    data,
                    last_used: f.4,
                });
            }
            None if f.2 => {
                summary.notes.push(format!(
                    "{email} had two-step login of a kind this server does not have (type {}): it did not come over",
                    f.1
                ));
                lost.push((f.0.clone(), method_name(f.1)));
            }
            None => {}
        }
    }
    // Whoever is left with no second step at all is told; whoever still has one is not.
    for (user_id, method) in lost {
        if with_factor.contains(&user_id) {
            continue;
        }
        if let Some(user) = migration.users.iter().find(|user| user.id == user_id)
            && !summary.lost_two_factor.iter().any(|(email, _, _)| *email == user.email)
        {
            summary.lost_two_factor.push((user.email.clone(), user.language.clone(), method));
        }
    }
    for user in &mut migration.users {
        if !with_factor.contains(&user.id) {
            // A recovery code without a way of two-step login would only confuse.
            user.recovery_code = None;
        }
    }

    // ── Folders and items ────────────────────────────────
    for f in read(&conn, "SELECT uuid, user_uuid, name, created_at, updated_at FROM folders", |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
        ))
    })? {
        if moved_users.contains(&f.1) {
            migration.folders.push(Folder {
                id: f.0,
                user_id: f.1,
                name: f.2,
                created: now_or(f.3),
                revision: now_or(f.4),
            });
        }
    }
    summary.folders = migration.folders.len();
    let folder_owner: HashMap<String, String> =
        migration.folders.iter().map(|folder| (folder.id.clone(), folder.user_id.clone())).collect();

    let organizations: Vec<Organization> =
        read(&conn, "SELECT uuid, name, billing_email, public_key, private_key FROM organizations", |row| {
            let now = clock::now();
            Ok(Organization {
                id: row.get(0)?,
                name: row.get(1)?,
                billing_email: row.get(2)?,
                public_key: row.get(3)?,
                private_key: row.get(4)?,
                created: now.clone(),
                revision: now,
            })
        })?;
    let orgs: HashSet<String> = organizations.iter().map(|org| org.id.clone()).collect();

    let folders_of: Vec<(String, String)> =
        read(&conn, "SELECT cipher_uuid, folder_uuid FROM folders_ciphers", |row| Ok((row.get(0)?, row.get(1)?)))?;
    let favorites: Vec<(String, String)> =
        read(&conn, "SELECT user_uuid, cipher_uuid FROM favorites", |row| Ok((row.get(0)?, row.get(1)?)))?;
    let archives: Vec<(String, String, Option<String>)> = if has_table(&conn, "archives") {
        read(&conn, "SELECT user_uuid, cipher_uuid, archived_at FROM archives", |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
    } else {
        Vec::new()
    };

    for c in read(
        &conn,
        "SELECT uuid, created_at, updated_at, user_uuid, organization_uuid, key, atype, name, notes, fields, data, \
         password_history, deleted_at, reprompt FROM ciphers",
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, Option<i64>>(13)?,
            ))
        },
    )? {
        let (user_id, org) = match (c.3, c.4) {
            (Some(user), None) if moved_users.contains(&user) => (user, None),
            (None, Some(org)) if orgs.contains(&org) => (String::new(), Some(org)),
            _ => continue,
        };
        let data = serde_json::from_str::<Value>(&c.10).map(lower_keys).unwrap_or_else(|_| json!({}));
        // What the clients read is the object of the item's type, without what Vaultwarden kept
        // beside it long ago.
        let data = match data {
            Value::Object(mut map) => {
                for key in ["name", "notes", "fields", "passwordHistory", "response"] {
                    map.remove(key);
                }
                if c.6 == 1 {
                    let first = map
                        .get("uris")
                        .and_then(Value::as_array)
                        .and_then(|uris| uris.first())
                        .and_then(|uri| uri.get("uri"))
                        .cloned()
                        .unwrap_or(Value::Null);
                    map.insert("uri".into(), first);
                }
                if c.6 == 2 && !map.get("type").is_some_and(Value::is_number) {
                    map.insert("type".into(), json!(0));
                }
                Value::Object(map)
            }
            _ => json!({}),
        };
        let folder_id = if org.is_none() {
            folders_of
                .iter()
                .find(|(cipher, folder)| cipher == &c.0 && folder_owner.get(folder) == Some(&user_id))
                .map(|(_, folder)| folder.clone())
        } else {
            None
        };
        let favorite = org.is_none() && favorites.iter().any(|(user, cipher)| user == &user_id && cipher == &c.0);
        let archived = if org.is_none() {
            archives
                .iter()
                .find(|(user, cipher, _)| user == &user_id && cipher == &c.0)
                .map(|(_, _, at)| now_or(at.clone()))
        } else {
            None
        };
        migration.ciphers.push(Cipher {
            id: c.0.clone(),
            user_id,
            organization_id: org.clone(),
            folder_id,
            kind: c.6,
            name: c.7,
            notes: c.8.filter(|notes| !notes.is_empty()),
            key: c.5,
            data: data.to_string(),
            fields: c
                .9
                .and_then(|fields| serde_json::from_str::<Value>(&fields).ok())
                .map(|fields| lower_keys(fields).to_string()),
            password_history: c
                .11
                .and_then(|history| serde_json::from_str::<Value>(&history).ok())
                .map(|history| lower_keys(history).to_string()),
            favorite,
            reprompt: c.13.unwrap_or(0),
            created: now_or(c.1),
            revision: now_or(c.2),
            deleted: time(c.12),
            archived,
        });
        if org.is_some() {
            // Each member files an organisation's item for themselves.
            for (cipher, folder) in folders_of.iter().filter(|(cipher, _)| cipher == &c.0) {
                if let Some(user) = folder_owner.get(folder) {
                    let favorite = favorites.iter().any(|(u, cipher)| u == user && cipher == &c.0);
                    migration.preferences.push((cipher.clone(), user.clone(), Some(folder.clone()), favorite));
                }
            }
            for (user, _) in favorites.iter().filter(|(user, cipher)| cipher == &c.0 && moved_users.contains(user)) {
                if !migration.preferences.iter().any(|(cipher, u, _, _)| cipher == &c.0 && u == user) {
                    migration.preferences.push((c.0.clone(), user.clone(), None, true));
                }
            }
        }
    }
    summary.ciphers = migration.ciphers.len();
    let ciphers: HashSet<String> = migration.ciphers.iter().map(|cipher| cipher.id.clone()).collect();

    for a in read(&conn, "SELECT id, cipher_uuid, file_name, file_size, akey FROM attachments", |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Option<String>>(4)?,
        ))
    })? {
        if !ciphers.contains(&a.1) {
            continue;
        }
        // Ids become paths; one that is not an id of Vaultwarden's does not get to be one.
        if !valid_id(&a.0) || !valid_id(&a.1) {
            summary.notes.push(format!("attachment {:?} has an id no Vaultwarden makes: not moved over", a.0));
            continue;
        }
        if !data.join("attachments").join(&a.1).join(&a.0).exists() {
            summary.notes.push(format!("the file of attachment {} is missing: not moved over", a.0));
            continue;
        }
        migration.attachments.push(Attachment {
            id: a.0,
            cipher_id: a.1,
            file_name: a.2,
            key: a.4,
            size: a.3,
            uploaded: true,
            created: clock::now(),
        });
    }
    summary.attachments = migration.attachments.len();

    // ── Sends ────────────────────────────────────────────
    for s in read(
        &conn,
        "SELECT uuid, user_uuid, name, notes, atype, data, akey, password_hash, password_salt, password_iter, \
         max_access_count, access_count, creation_date, revision_date, expiration_date, deletion_date, disabled, \
         hide_email FROM sends",
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
                row.get::<_, Option<Vec<u8>>>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, Option<String>>(14)?,
                row.get::<_, Option<String>>(15)?,
                row.get::<_, bool>(16)?,
                row.get::<_, Option<bool>>(17)?,
            ))
        },
    )? {
        let Some(user) = s.1.filter(|user| moved_users.contains(user)) else { continue };
        if !valid_id(&s.0) {
            summary.notes.push(format!("Send {:?} has an id no Vaultwarden makes: not moved over", s.0));
            continue;
        }
        let data = serde_json::from_str::<Value>(&s.5).map(lower_keys).unwrap_or_else(|_| json!({}));
        // A file Send's file is looked for below.
        let uploaded = s.4 != 1;
        migration.sends.push(Send {
            id: s.0,
            user_id: user,
            kind: s.4,
            name: s.2,
            notes: s.3,
            data: data.to_string(),
            key: s.6,
            password_hash: match (s.7, s.8, s.9) {
                (Some(hash), Some(salt), Some(rounds)) => Some(legacy_hash(&hash, &salt, rounds)),
                _ => None,
            },
            max_access_count: s.10,
            access_count: s.11,
            created: now_or(s.12),
            revision: now_or(s.13),
            expiration: time(s.14),
            deletion: now_or(s.15),
            disabled: s.16,
            hide_email: s.17.unwrap_or(false),
            uploaded,
        });
    }
    // A file Send's file is at `sends/<send>/<file>`.
    for send in &mut migration.sends {
        if send.kind == 1 {
            let file = serde_json::from_str::<Value>(&send.data)
                .ok()
                .and_then(|data| data.get("id").and_then(Value::as_str).map(str::to_string));
            send.uploaded =
                file.is_some_and(|file| valid_id(&file) && data.join("sends").join(&send.id).join(file).exists());
        }
    }
    summary.sends = migration.sends.len();

    // ── Emergency access ─────────────────────────────────
    for e in read(
        &conn,
        "SELECT uuid, grantor_uuid, grantee_uuid, email, key_encrypted, atype, status, wait_time_days, \
         recovery_initiated_at, last_notification_at, updated_at, created_at FROM emergency_access",
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
            ))
        },
    )? {
        if !moved_users.contains(&e.1) || e.2.as_ref().is_some_and(|grantee| !moved_users.contains(grantee)) {
            continue;
        }
        let email = e.3.or_else(|| e.2.as_ref().and_then(|grantee| emails.get(grantee).cloned())).unwrap_or_default();
        migration.emergency.push(EmergencyAccess {
            id: e.0,
            grantor_id: e.1,
            grantee_id: e.2,
            email: uwulock_store::normalize_email(&email),
            key_encrypted: e.4,
            kind: e.5,
            status: e.6,
            wait_days: e.7,
            token_hash: None,
            recovery_asked: time(e.8),
            last_notification: time(e.9),
            created: now_or(e.11),
            revision: now_or(e.10),
        });
    }
    summary.emergency = migration.emergency.len();

    // ── Organisations ────────────────────────────────────
    let now = clock::now();
    let members: Vec<Member> = read(
        &conn,
        "SELECT uuid, org_uuid, user_uuid, akey, status, atype, access_all, reset_password_key, external_id \
         FROM users_organizations",
        |row| {
            Ok(Member {
                id: row.get(0)?,
                org_id: row.get(1)?,
                user_id: row.get(2)?,
                email: None,
                key: Some(row.get::<_, String>(3)?).filter(|key| !key.is_empty()),
                status: row.get(4)?,
                kind: row.get(5)?,
                access_all: row.get(6)?,
                permissions: "{}".into(),
                reset_password_key: row.get(7)?,
                external_id: row.get(8)?,
                created: now.clone(),
                revision: now.clone(),
            })
        },
    )?
    .into_iter()
    .filter(|member| {
        orgs.contains(&member.org_id) && member.user_id.as_ref().is_some_and(|user| moved_users.contains(user))
    })
    .collect();
    let member_of: HashMap<(String, String), String> = members
        .iter()
        .filter_map(|member| Some(((member.user_id.clone()?, member.org_id.clone()), member.id.clone())))
        .collect();
    let members_ids: HashSet<String> = members.iter().map(|member| member.id.clone()).collect();
    let collections: Vec<Collection> =
        read(&conn, "SELECT uuid, org_uuid, name, external_id FROM collections", |row| {
            Ok(Collection {
                id: row.get(0)?,
                org_id: row.get(1)?,
                name: row.get(2)?,
                external_id: row.get(3)?,
                created: now.clone(),
                revision: now.clone(),
            })
        })?
        .into_iter()
        .filter(|collection| orgs.contains(&collection.org_id))
        .collect();
    let collection_org: HashMap<String, String> =
        collections.iter().map(|collection| (collection.id.clone(), collection.org_id.clone())).collect();
    for (user, collection, read_only, hide, manage) in read(
        &conn,
        &format!(
            "SELECT user_uuid, collection_uuid, read_only, hide_passwords, {} FROM users_collections",
            column_or(&conn, "users_collections", "manage", "0")
        ),
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, bool>(4)?,
            ))
        },
    )? {
        let Some(org) = collection_org.get(&collection) else { continue };
        if let Some(member) = member_of.get(&(user, org.clone())) {
            migration.collection_members.push((collection, member.clone(), read_only, hide, manage));
        }
    }
    let groups: Vec<Group> = if has_table(&conn, "groups") {
        read(
            &conn,
            "SELECT uuid, organizations_uuid, name, access_all, external_id, creation_date, revision_date FROM groups",
            |row| {
                Ok(Group {
                    id: row.get(0)?,
                    org_id: row.get(1)?,
                    name: row.get(2)?,
                    access_all: row.get(3)?,
                    external_id: row.get(4)?,
                    created: now_or(row.get(5)?),
                    revision: now_or(row.get(6)?),
                })
            },
        )?
        .into_iter()
        .filter(|group| orgs.contains(&group.org_id))
        .collect()
    } else {
        Vec::new()
    };
    let group_ids: HashSet<String> = groups.iter().map(|group| group.id.clone()).collect();
    if has_table(&conn, "groups_users") {
        for (group, member) in read(&conn, "SELECT groups_uuid, users_organizations_uuid FROM groups_users", |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            if group_ids.contains(&group) && members_ids.contains(&member) {
                migration.group_members.push((group, member));
            }
        }
    }
    if has_table(&conn, "collections_groups") {
        for (collection, group, read_only, hide, manage) in read(
            &conn,
            &format!(
                "SELECT collections_uuid, groups_uuid, read_only, hide_passwords, {} FROM collections_groups",
                column_or(&conn, "collections_groups", "manage", "0")
            ),
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, bool>(4)?,
                ))
            },
        )? {
            if group_ids.contains(&group) && collection_org.contains_key(&collection) {
                migration.collection_groups.push((collection, group, read_only, hide, manage));
            }
        }
    }
    for (cipher, collection) in read(&conn, "SELECT cipher_uuid, collection_uuid FROM ciphers_collections", |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })? {
        if ciphers.contains(&cipher) && collection_org.contains_key(&collection) {
            migration.collection_ciphers.push((collection, cipher));
        }
    }
    migration.policies = read(&conn, "SELECT uuid, org_uuid, atype, enabled, data FROM org_policies", |row| {
        Ok(Policy {
            id: row.get(0)?,
            org_id: row.get(1)?,
            kind: row.get(2)?,
            enabled: row.get(3)?,
            data: row.get(4)?,
            revision: now.clone(),
        })
    })?
    .into_iter()
    .filter(|policy| orgs.contains(&policy.org_id))
    .collect();
    summary.organizations = organizations.len();
    summary.collections = collections.len();
    migration.organizations = organizations;
    migration.members = members;
    migration.collections = collections;
    migration.groups = groups;

    let rsa = match std::fs::read(data.join("rsa_key.pem")) {
        Ok(pem) => Some(public_key(&pem)?),
        Err(_) => {
            summary.notes.push(
                "no rsa_key.pem: devices keep their refresh tokens only where Vaultwarden did not sign them; the rest log in again"
                    .into(),
            );
            None
        }
    };
    Ok((migration, rsa, summary))
}

/// Move a Vaultwarden over into `store`, whose data directory is `target`: the rows, then the
/// files. With `dry_run`, only read and tell.
pub async fn import(
    store: &Store,
    source: &Path,
    target: &Path,
    admins: &[String],
    language: &str,
    dry_run: bool,
) -> Result<Summary, String> {
    let (source_owned, admins_owned, language_owned) = (source.to_path_buf(), admins.to_vec(), language.to_string());
    let (migration, rsa, summary) =
        tokio::task::spawn_blocking(move || read_vaultwarden(&source_owned, &admins_owned, &language_owned))
            .await
            .map_err(|error| error.to_string())??;
    // Accounts that are here already stop the import before anything is touched, a dry run
    // included.
    for user in &migration.users {
        if store.user_by_email(&user.email).await.map_err(|error| error.to_string())?.is_some() {
            return Err(format!("{} has an account here already: nothing was imported", user.email));
        }
    }
    if dry_run {
        return Ok(summary);
    }
    // The files first: an import whose rows went in without them would show attachments that
    // do not open. None is written over, and when the import stops, only the files it wrote go.
    let mut copied: Vec<PathBuf> = Vec::new();
    let copy = |from: PathBuf, to: PathBuf, copied: &mut Vec<PathBuf>| -> Result<(), String> {
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
        }
        let mut source = std::fs::File::open(&from).map_err(|error| format!("{}: {error}", from.display()))?;
        let mut file = std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&to)
            .map_err(|error| format!("{}: {error}", to.display()))?;
        copied.push(to.clone());
        std::io::copy(&mut source, &mut file).map_err(|error| format!("{}: {error}", from.display()))?;
        Ok(())
    };
    let mut files = Vec::new();
    for attachment in &migration.attachments {
        files.push(Path::new("attachments").join(&attachment.cipher_id).join(&attachment.id));
    }
    for send in migration.sends.iter().filter(|send| send.kind == 1 && send.uploaded) {
        if let Some(file) = serde_json::from_str::<Value>(&send.data)
            .ok()
            .and_then(|data| data.get("id").and_then(Value::as_str).map(str::to_string))
        {
            files.push(Path::new("sends").join(&send.id).join(file));
        }
    }
    let copying: Result<(), String> =
        files.iter().try_for_each(|relative| copy(source.join(relative), target.join(relative), &mut copied));
    let result = match copying {
        Ok(()) => store.migrate(migration).await.map_err(|error| match error {
            uwulock_store::StoreError::Exists => {
                "an account of this Vaultwarden has one here already: nothing was imported".to_string()
            }
            other => other.to_string(),
        }),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        for file in copied {
            let _ = std::fs::remove_file(file);
        }
        return Err(error);
    }
    if let Some(key) = rsa {
        store
            .set_setting(uwulock_api::vaultwarden::PUBLIC_KEY, &STANDARD.encode(key))
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    //! Against `fixtures/vaultwarden`: a real Vaultwarden 1.37.3, filled by
    //! `scripts/e2e/vaultwarden.mjs seed` and dumped as SQL — two accounts (one with an
    //! authenticator app), a folder, three items (one of an organisation), an attachment, two
    //! Sends (one a file), emergency access from one to the other.

    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/vaultwarden")
    }

    fn accounts() -> Value {
        serde_json::from_slice(&std::fs::read(fixture_dir().join("accounts.json")).unwrap()).unwrap()
    }

    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &to.join(entry.file_name()));
            } else {
                std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
            }
        }
    }

    /// Vaultwarden's data directory, as it was.
    fn vaultwarden() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        copy_tree(&fixture_dir(), dir.path());
        std::fs::remove_file(dir.path().join("db.sql")).unwrap();
        let conn = Connection::open(dir.path().join("db.sqlite3")).unwrap();
        // The dump makes tables in the order of their names, not of their references.
        conn.pragma_update(None, "foreign_keys", false).unwrap();
        conn.execute_batch(&std::fs::read_to_string(fixture_dir().join("db.sql")).unwrap()).unwrap();
        dir
    }

    fn store(dir: &Path) -> Store {
        Store::open_sqlite(&dir.join("uwulock.db"), &uwulock_store::Options { readers: 2 }).unwrap()
    }

    #[test]
    fn everything_vaultwarden_had_is_read() {
        let source = vaultwarden();
        let (migration, rsa, summary) = read_vaultwarden(source.path(), &["NYU@example.com".into()], "de").unwrap();
        assert_eq!(
            (summary.users, summary.devices, summary.folders, summary.ciphers, summary.attachments, summary.sends),
            (2, 3, 1, 3, 1, 2)
        );
        assert_eq!((summary.organizations, summary.collections, summary.emergency), (1, 1, 1));
        assert!(summary.notes.is_empty(), "{:?}", summary.notes);
        assert!(rsa.is_some());

        let nyu = migration.users.iter().find(|user| user.email == "nyu@example.com").unwrap();
        let mio = migration.users.iter().find(|user| user.email == "mio@example.com").unwrap();
        assert!(nyu.admin && !mio.admin);
        assert!(nyu.password_hash.starts_with(uwulock_api::LEGACY_HASH));
        assert_eq!(nyu.language, "de");
        assert_eq!(nyu.kdf.iterations, 600_000);
        assert!(nyu.recovery_code.is_none(), "no two-step login, so no recovery code");
        assert!(mio.recovery_code.is_some());
        let factor = migration.two_factor.iter().find(|factor| factor.user_id == mio.id).unwrap();
        assert_eq!((factor.kind, factor.enabled), (0, true));
        assert_eq!(factor.data, accounts()["mio"]["totp"]);

        let fixture = accounts();
        let router = migration.ciphers.iter().find(|cipher| cipher.id == fixture["router"]).unwrap();
        assert!(router.favorite);
        assert_eq!(router.folder_id.as_deref(), fixture["folder"].as_str());
        assert!(router.created.ends_with('Z'), "times in this server's format: {}", router.created);
        let data: Value = serde_json::from_str(&router.data).unwrap();
        assert!(data["password"].is_string() && data.get("name").is_none(), "{data}");
        let shared = migration.ciphers.iter().find(|cipher| cipher.id == fixture["shared"]).unwrap();
        assert_eq!(shared.organization_id.as_deref(), fixture["org"].as_str());
        assert!(shared.user_id.is_empty());
        assert_eq!(migration.collection_ciphers.len(), 1);
        let member = migration.members.iter().find(|member| member.user_id.as_deref() == Some(&nyu.id)).unwrap();
        assert_eq!((member.status, member.kind), (2, 0), "a confirmed owner");
        assert!(member.key.is_some());

        assert!(migration.sends.iter().all(|send| send.uploaded));
        assert!(migration.sends.iter().any(|send| send.password_hash.is_some()));
        let emergency = &migration.emergency[0];
        assert_eq!((emergency.status, emergency.wait_days), (2, 7));
        assert!(emergency.key_encrypted.is_some());
    }

    #[test]
    fn a_directory_without_a_database_is_refused() {
        let empty = tempfile::tempdir().unwrap();
        let error = read_vaultwarden(empty.path(), &[], "en").unwrap_err();
        assert!(error.contains("db.sqlite3"), "{error}");
    }

    #[test]
    fn who_loses_their_only_second_step_is_named_and_odd_ids_stay_out() {
        let source = vaultwarden();
        let conn = Connection::open(source.path().join("db.sqlite3")).unwrap();
        let nyu: String =
            conn.query_row("SELECT uuid FROM users WHERE email = 'nyu@example.com'", [], |row| row.get(0)).unwrap();
        let mio: String =
            conn.query_row("SELECT uuid FROM users WHERE email = 'mio@example.com'", [], |row| row.get(0)).unwrap();
        for (user, kind) in [(&nyu, 2), (&mio, 3)] {
            conn.execute(
                "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, 1, '{}', 0)",
                rusqlite::params![format!("tf-{kind}"), user, kind],
            )
            .unwrap();
        }
        conn.execute("UPDATE sends SET uuid = '../../escape' WHERE atype = 0", []).unwrap();
        drop(conn);
        let (migration, _, summary) = read_vaultwarden(source.path(), &[], "en").unwrap();
        let lost: Vec<_> =
            summary.lost_two_factor.iter().map(|(email, _, method)| (email.as_str(), method.as_str())).collect();
        assert_eq!(lost, [("nyu@example.com", "Duo")], "mio still has the authenticator app");
        assert!(migration.sends.iter().all(|send| valid_id(&send.id)));
        assert!(summary.notes.iter().any(|note| note.contains("no Vaultwarden makes")));
    }

    async fn call(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    fn token_request(form: &[(&str, &str)]) -> Request<Body> {
        let body =
            form.iter().map(|(key, value)| format!("{key}={}", urlencoding(value))).collect::<Vec<_>>().join("&");
        Request::post("/identity/connect/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap()
    }

    fn urlencoding(value: &str) -> String {
        value
            .bytes()
            .map(|byte| match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (byte as char).to_string(),
                _ => format!("%{byte:02X}"),
            })
            .collect()
    }

    /// A refresh token as Vaultwarden signs them, with its key, for `device_token`.
    fn vaultwarden_refresh_token(device_token: &str) -> String {
        let pem = std::fs::read(fixture_dir().join("rsa_key.pem")).unwrap();
        let rustls_pemfile::Item::Pkcs1Key(der) = rustls_pemfile::read_one_from_slice(&pem).unwrap().unwrap().0 else {
            panic!("a PKCS#1 key")
        };
        let pair = ring::rsa::KeyPair::from_der(der.secret_pkcs1_der()).unwrap();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"RS256"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            json!({ "nbf": now, "exp": now + 3600, "iss": "https://localhost:18444|login", "sub": "x", "device_token": device_token })
                .to_string(),
        );
        let signed = format!("{header}.{claims}");
        let mut signature = vec![0; pair.public().modulus_len()];
        pair.sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &ring::rand::SystemRandom::new(),
            signed.as_bytes(),
            &mut signature,
        )
        .unwrap();
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    #[tokio::test]
    async fn an_imported_account_logs_in_refreshes_and_syncs() {
        let source = vaultwarden();
        let target = tempfile::tempdir().unwrap();
        let store = store(target.path());
        let fixture = accounts();
        import(&store, source.path(), target.path(), &[], "en", false).await.unwrap();
        assert!(store.legacy_rounds().await.unwrap() >= 5000, "hashes of Vaultwarden's wait for their login");
        // The files came along.
        let router_id = fixture["router"].as_str().unwrap();
        assert_eq!(std::fs::read_dir(target.path().join("attachments").join(router_id)).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(target.path().join("sends")).unwrap().count(), 1);

        let config = uwulock_api::ApiConfig {
            public: "https://vault.example.com".into(),
            trust_forwarded: false,
            hash_cost: uwulock_api::HashCost::cheap(),
            backups: target.path().join("backups"),
            data: target.path().to_path_buf(),
            hibp_url: "http://127.0.0.1:9".into(),
            login_attempts: 10,
            start_settings: uwulock_api::Settings::default(),
            certificate_probe: None,
            time_sources: Vec::new(),
        };
        let mut state =
            uwulock_api::AppState::new(store.clone(), config, "0.0.0-test", uwulock_api::LogBuffer::new(10))
                .await
                .unwrap();
        state.mailer = uwulock_mail::Mailer::capturing();
        let app = uwulock_api::router(state);

        // A device of Vaultwarden's stays logged in: its refresh token works once, and is replaced.
        let device = fixture["nyu"]["device"].as_str().unwrap();
        let conn = Connection::open(source.path().join("db.sqlite3")).unwrap();
        let device_token: String =
            conn.query_row("SELECT refresh_token FROM devices WHERE uuid = ?1", [device], |row| row.get(0)).unwrap();
        let old = vaultwarden_refresh_token(&device_token);
        let (status, refreshed) = call(
            &app,
            token_request(&[("grant_type", "refresh_token"), ("client_id", "web"), ("refresh_token", &old)]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{refreshed}");
        assert_ne!(refreshed["refresh_token"].as_str(), Some(old.as_str()));
        let (status, _) = call(
            &app,
            token_request(&[("grant_type", "refresh_token"), ("client_id", "web"), ("refresh_token", &old)]),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "only once");

        // An older Vaultwarden's device holds the bare token: taken once, and replaced too.
        let bare: String = conn
            .query_row("SELECT refresh_token FROM devices WHERE uuid <> ?1 LIMIT 1", [device], |row| row.get(0))
            .unwrap();
        let refresh = |token: String| {
            token_request(&[("grant_type", "refresh_token"), ("client_id", "web"), ("refresh_token", &token)])
        };
        let (status, replaced) = call(&app, refresh(bare.clone())).await;
        assert_eq!(status, StatusCode::OK, "{replaced}");
        assert_ne!(replaced["refresh_token"].as_str(), Some(bare.as_str()));
        assert_eq!(call(&app, refresh(bare)).await.0, StatusCode::BAD_REQUEST, "the old database's copy is dead");
        let fresh = replaced["refresh_token"].as_str().unwrap().to_string();
        assert_eq!(call(&app, refresh(fresh)).await.0, StatusCode::OK);

        let access = refreshed["access_token"].as_str().unwrap();
        let (status, sync) = call(
            &app,
            Request::get("/api/sync").header("authorization", format!("Bearer {access}")).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(sync["profile"]["organizations"][0]["id"], fixture["org"]);
        assert_eq!(sync["ciphers"].as_array().unwrap().len(), 3);
        assert_eq!(sync["collections"].as_array().unwrap().len(), 1);
        assert_eq!(sync["sends"].as_array().unwrap().len(), 2);
        let router = sync["ciphers"].as_array().unwrap().iter().find(|cipher| cipher["id"] == router_id).unwrap();
        assert_eq!(router["attachments"].as_array().unwrap().len(), 1);
        assert_eq!(router["folderId"], fixture["folder"]);

        // The old password works, and is hashed anew on the way.
        let login = |account: &Value| {
            token_request(&[
                ("grant_type", "password"),
                ("username", account["email"].as_str().unwrap()),
                ("password", account["hash"].as_str().unwrap()),
                ("scope", "api offline_access"),
                ("client_id", "web"),
                ("deviceType", "9"),
                ("deviceIdentifier", "0b4e0a43-2f3e-4e3c-9a37-0d4a3b4b1c11"),
                ("deviceName", "test"),
            ])
        };
        let (status, body) = call(&app, login(&fixture["nyu"])).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let user = store.user_by_email("nyu@example.com").await.unwrap().unwrap();
        assert!(!user.password_hash.starts_with(uwulock_api::LEGACY_HASH));
        let (status, _) = call(&app, login(&fixture["nyu"])).await;
        assert_eq!(status, StatusCode::OK, "and again, with the new hash");

        // Two-step login came along.
        let (status, body) = call(&app, login(&fixture["mio"])).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["TwoFactorProviders2"].get("0").is_some(), "{body}");
    }

    #[tokio::test]
    async fn an_import_goes_in_whole_or_not_at_all() {
        let source = vaultwarden();
        let target = tempfile::tempdir().unwrap();
        let store = store(target.path());
        import(&store, source.path(), target.path(), &[], "en", true).await.unwrap();
        assert!(store.user_by_email("nyu@example.com").await.unwrap().is_none(), "a dry run writes nothing");
        assert!(!target.path().join("attachments").exists());

        import(&store, source.path(), target.path(), &[], "en", false).await.unwrap();
        let files = |dir: &str| -> usize {
            std::fs::read_dir(target.path().join(dir))
                .unwrap()
                .map(|folder| std::fs::read_dir(folder.unwrap().path()).unwrap().count())
                .sum()
        };
        assert_eq!((files("attachments"), files("sends")), (1, 1));
        for dry_run in [true, false] {
            let error = import(&store, source.path(), target.path(), &[], "en", dry_run).await.unwrap_err();
            assert!(error.contains("nothing was imported"), "{error}");
        }
        assert_eq!((files("attachments"), files("sends")), (1, 1), "the files of the first import stay");

        // A file that is in the way is not written over, and the import stops whole.
        let other = tempfile::tempdir().unwrap();
        let fresh = self::store(other.path());
        let taken = std::fs::read_dir(target.path().join("sends")).unwrap().next().unwrap().unwrap().file_name();
        std::fs::create_dir_all(other.path().join("sends").join(&taken)).unwrap();
        let first = std::fs::read_dir(target.path().join("sends").join(&taken)).unwrap().next().unwrap().unwrap();
        std::fs::write(other.path().join("sends").join(&taken).join(first.file_name()), b"mine").unwrap();
        assert!(import(&fresh, source.path(), other.path(), &[], "en", false).await.is_err());
        assert_eq!(std::fs::read(other.path().join("sends").join(&taken).join(first.file_name())).unwrap(), b"mine");
        assert_eq!(
            std::fs::read_dir(other.path().join("attachments")).map_or(0, |dir| {
                dir.map(|folder| std::fs::read_dir(folder.unwrap().path()).unwrap().count()).sum::<usize>()
            }),
            0,
            "what it wrote before is gone again"
        );
        assert!(fresh.user_by_email("nyu@example.com").await.unwrap().is_none());
    }

    #[test]
    fn security_keys_come_over_in_both_of_webauthn_rs_s_forms() {
        let x = URL_SAFE_NO_PAD.encode([1u8; 32]);
        let y = URL_SAFE_NO_PAD.encode([2u8; 32]);
        let key = json!({ "type_": "ES256", "key": { "EC_EC2": { "curve": "SECP256R1", "x": x, "y": y } } });
        let passkey = json!([{ "id": 1, "name": "Stick", "migrated": false,
            "credential": { "cred": { "cred_id": "AQID", "cred": key, "counter": 7 } } }]);
        let older = json!([{ "id": 2, "name": "Alt", "migrated": true,
            "credential": { "cred_id": [1, 2, 3], "cred": key, "counter": 3 } }]);
        for (data, counter) in [(passkey, 7), (older, 3)] {
            let keys = security_keys(&data.to_string());
            assert_eq!(keys.len(), 1, "{data}");
            assert_eq!(keys[0]["credentialId"], "AQID");
            assert_eq!(keys[0]["counter"], counter);
            let cose: Cbor = ciborium::from_reader(
                URL_SAFE_NO_PAD.decode(keys[0]["publicKey"].as_str().unwrap()).unwrap().as_slice(),
            )
            .unwrap();
            let map = cose.into_map().unwrap();
            assert!(map.contains(&(Cbor::Integer(3.into()), Cbor::Integer((-7).into()))), "ES256");
            assert!(map.contains(&(Cbor::Integer((-2).into()), Cbor::Bytes(vec![1; 32]))));
        }
        assert!(security_keys("not json").is_empty());
    }

    #[test]
    fn vaultwarden_s_times_become_this_server_s() {
        assert_eq!(time(Some("2026-09-25 12:00:00.123456".into())).unwrap(), "2026-09-25T12:00:00.123456Z");
        assert_eq!(time(Some("2026-09-25 12:00:00".into())).unwrap(), "2026-09-25T12:00:00.000000Z");
        assert!(time(None).is_none());
    }
}
