//! What only the web vault does to an account: make one, and change how it is unlocked — a new
//! master password, a new KDF, a new address, a new user key.
//!
//! The server never sees the master password. It gets the hash of the one that is there now,
//! to prove it is the owner asking, and the hash of the new one with the user key wrapped under
//! the new master key.

use crate::{Failure, Result, Unlocked};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use serde_json::{Value, json};
use uwulock_core::crypto::{self, EncString, Kdf, SymmetricKey};

/// The KDF the way the server writes it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfNumbers {
    kdf_type: u32,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
}

pub fn numbers(kdf: Kdf) -> KdfNumbers {
    match kdf {
        Kdf::Pbkdf2 { iterations } => KdfNumbers { kdf_type: 0, iterations, memory: None, parallelism: None },
        Kdf::Argon2id { iterations, memory_mib, parallelism } => {
            KdfNumbers { kdf_type: 1, iterations, memory: Some(memory_mib), parallelism: Some(parallelism) }
        }
    }
}

/// The hash of `password`, if it is the master password: it has to open the user key.
pub fn check_password(unlocked: &Unlocked, password: &str) -> Result<String> {
    let master = crypto::master_key(password, &unlocked.email, unlocked.kdf)?;
    let protected: EncString = unlocked.protected_key.parse()?;
    crypto::decrypt_user_key(&master, &protected)
        .map_err(|_| Failure::new("wrong-password", "The master password is wrong."))?;
    Ok(crypto::master_password_hash(&master, password))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccount {
    hash: String,
    key: String,
    encrypted_private_key: String,
}

pub fn new_account(email: &str, password: &str, kdf: &Kdf, private_key: &str) -> Result<NewAccount> {
    let master = crypto::master_key(password, email, *kdf)?;
    let user_key = SymmetricKey::generate();
    let private = STANDARD.decode(private_key).map_err(|_| Failure::new("invalid", "The private key is not base64."))?;
    Ok(NewAccount {
        hash: crypto::master_password_hash(&master, password),
        key: EncString::encrypt(&user_key.to_bytes(), &SymmetricKey::stretch(&master)).to_string(),
        encrypted_private_key: EncString::encrypt(&private, &user_key).to_string(),
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rewrapped {
    current_hash: String,
    new_hash: String,
    /// The user key under the new master key.
    new_key: String,
    email: String,
    kdf: KdfNumbers,
}

/// The user key wrapped again: under the master key of `new_password`, with `kdf` and `email`
/// if they change.
pub fn rewrap(unlocked: &Unlocked, current: &str, new_password: &str, kdf: Option<Kdf>, email: Option<&str>) -> Result<Rewrapped> {
    let current_hash = check_password(unlocked, current)?;
    let kdf = kdf.unwrap_or(unlocked.kdf);
    let email = email.map(crypto::normalize_email).unwrap_or_else(|| unlocked.email.clone());
    let master = crypto::master_key(new_password, &email, kdf)?;
    Ok(Rewrapped {
        current_hash,
        new_hash: crypto::master_password_hash(&master, new_password),
        new_key: EncString::encrypt(&unlocked.user_key.to_bytes(), &SymmetricKey::stretch(&master)).to_string(),
        email,
        kdf: numbers(kdf),
    })
}

/// A new user key: every item and folder name encrypted again under it, the private key
/// wrapped again, and the new user key under the master key. The body of
/// `rotate-user-account-keys`.
pub fn rotate(unlocked: &Unlocked, password: &str, public_key: &str) -> Result<Value> {
    let current_hash = check_password(unlocked, password)?;
    let private = unlocked
        .private_key
        .as_ref()
        .ok_or_else(|| Failure::new("invalid", "This account has no key pair to rotate."))?;
    let private = private.parse::<EncString>()?.decrypt(&unlocked.user_key)?;
    let new_key = SymmetricKey::generate();
    let master = crypto::master_key(password, &unlocked.email, unlocked.kdf)?;

    let mut ciphers = Vec::with_capacity(unlocked.vault.items.len());
    for item in &unlocked.vault.items {
        if item.organization_id.is_some() {
            continue;
        }
        if item.broken {
            return Err(Failure::new(
                "refused",
                format!("The item “{}” does not open completely, so the vault cannot get a new key.", item.name.as_str()),
            ));
        }
        let mut item = item.clone();
        // An item with a key of its own keeps it; only the wrapping is new.
        if let Some(own) = &item.key {
            item.wrapped_key = Some(EncString::encrypt(&own.to_bytes(), &new_key).to_string());
        }
        let mut sealed = serde_json::to_value(item.seal(&new_key)?)?;
        sealed["id"] = Value::String(item.id.clone());
        ciphers.push(sealed);
    }
    let folders: Vec<Value> = unlocked
        .vault
        .folders
        .iter()
        .map(|folder| json!({ "id": folder.id, "name": EncString::encrypt(folder.name.as_bytes(), &new_key).to_string() }))
        .collect();
    let kdf = numbers(unlocked.kdf);
    Ok(json!({
        "oldMasterKeyAuthenticationHash": current_hash,
        "accountUnlockData": {
            "masterPasswordUnlockData": {
                "kdfType": kdf.kdf_type,
                "kdfIterations": kdf.iterations,
                "kdfMemory": kdf.memory,
                "kdfParallelism": kdf.parallelism,
                "email": unlocked.email,
                "masterKeyAuthenticationHash": current_hash,
                "masterKeyEncryptedUserKey": EncString::encrypt(&new_key.to_bytes(), &SymmetricKey::stretch(&master)).to_string(),
            },
            "emergencyAccessUnlockData": [],
            "organizationAccountRecoveryUnlockData": [],
        },
        "accountKeys": {
            "userKeyEncryptedAccountPrivateKey": EncString::encrypt(&private, &new_key).to_string(),
            "accountPublicKey": public_key,
        },
        "accountData": { "ciphers": ciphers, "folders": folders, "sends": [] },
    }))
}
