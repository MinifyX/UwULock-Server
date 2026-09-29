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
    pub(crate) kdf_type: u32,
    pub(crate) iterations: u32,
    pub(crate) memory: Option<u32>,
    pub(crate) parallelism: Option<u32>,
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
    let private =
        STANDARD.decode(private_key).map_err(|_| Failure::new("invalid", "The private key is not base64."))?;
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
pub fn rewrap(
    unlocked: &Unlocked,
    current: &str,
    new_password: &str,
    kdf: Option<Kdf>,
    email: Option<&str>,
) -> Result<Rewrapped> {
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

/// Who else holds the user key, for a rotation: emergency contacts with their public keys, and
/// passkeys that unlock with theirs (under the user key).
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Holders {
    emergency: Vec<Holder>,
    passkeys: Vec<PasskeyHolder>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Holder {
    id: String,
    public_key: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyHolder {
    id: String,
    encrypted_public_key: String,
}

/// A new user key: every item and folder name encrypted again under it, attachments and Sends
/// whose keys hang on it, the private key wrapped again, the new user key under the master key
/// and for everybody in `holders`. The body of `rotate-user-account-keys`.
pub fn rotate(unlocked: &Unlocked, password: &str, public_key: &str, holders: Holders) -> Result<Value> {
    Ok(rotate_with_key(unlocked, password, public_key, holders)?.0)
}

/// [`rotate`], and the new user key, for what UwULock re-encrypts beside it.
pub fn rotate_with_key(
    unlocked: &Unlocked,
    password: &str,
    public_key: &str,
    holders: Holders,
) -> Result<(Value, SymmetricKey)> {
    let current_hash = check_password(unlocked, password)?;
    let private = unlocked
        .private_key
        .as_ref()
        .ok_or_else(|| Failure::new("invalid", "This account has no key pair to rotate."))?;
    let private = private.parse::<EncString>()?.decrypt(&unlocked.user_key)?;
    // The public key the server has for the account has to be the half of the private key the
    // user key opens: one swapped on the server would be made official by the new keys, and
    // organisations and contacts would wrap keys for it from then on.
    let (_, stated) = crate::keys::public_key(public_key)?;
    if crypto::PrivateKey::from_der(&private)?.public() != stated {
        return Err(Failure::new(
            "refused",
            "The server has another public key for this account than the one that belongs to it. The vault gets no new keys like this.",
        ));
    }
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
                format!(
                    "The item “{}” does not open completely, so the vault cannot get a new key.",
                    item.name.as_str()
                ),
            ));
        }
        let mut item = item.clone();
        // An item with a key of its own keeps it; only the wrapping is new. One without has its
        // passkeys under the user key, which the core carries through as they are: those are
        // encrypted again here, or they would stay under the key this is meant to replace.
        if let Some(own) = &item.key {
            item.wrapped_key = Some(EncString::encrypt(&own.to_bytes(), &new_key).to_string());
        } else if let Some(passkeys) = item.login.as_mut().and_then(|login| login.passkeys.as_mut()) {
            crate::transfer::reseal_passkeys(passkeys, &unlocked.user_key, &new_key)?;
        }
        let mut sealed = serde_json::to_value(item.seal(&new_key)?)?;
        sealed["id"] = Value::String(item.id.clone());
        // Attachments of an item without a key of its own hang on the user key: name and key.
        if item.key.is_none()
            && let Some(attachments) = unlocked.attachments.get(&item.id)
        {
            let mut rewrapped = serde_json::Map::new();
            for attachment in attachments {
                let name = match &attachment.file_name {
                    Some(name) => name.parse::<EncString>()?.decrypt(&unlocked.user_key)?,
                    None => continue,
                };
                let Some(key) = &attachment.key else { continue };
                let key = key.parse::<EncString>()?.decrypt(&unlocked.user_key)?;
                rewrapped.insert(
                    attachment.id.clone(),
                    json!({
                        "fileName": EncString::encrypt(&name, &new_key).to_string(),
                        "key": EncString::encrypt(&key, &new_key).to_string(),
                    }),
                );
            }
            sealed["attachments2"] = Value::Object(rewrapped);
        }
        ciphers.push(sealed);
    }
    // A Send's seed is under the user key; everything else of it under the Send's own key.
    let mut sends = Vec::with_capacity(unlocked.sends.len());
    for send in &unlocked.sends {
        let seed = send
            .key
            .as_deref()
            .ok_or_else(|| Failure::new("crypto", "A Send has no key."))?
            .parse::<EncString>()?
            .decrypt(&unlocked.user_key)?;
        sends.push(json!({
            "id": send.id,
            "type": send.kind,
            "key": EncString::encrypt(&seed, &new_key).to_string(),
            "name": send.name,
            "notes": send.notes,
            "text": send.text.as_ref().map(|text| json!({ "text": text.text, "hidden": text.hidden })),
            "file": send.file.as_ref().map(|file| json!({ "fileName": file.file_name })),
            "maxAccessCount": send.max_access_count,
            "expirationDate": send.expiration_date,
            "deletionDate": send.deletion_date,
            "disabled": send.disabled.unwrap_or(false),
            "hideEmail": send.hide_email.unwrap_or(false),
        }));
    }
    let mut emergency = Vec::with_capacity(holders.emergency.len());
    for holder in &holders.emergency {
        let (_, key) = crate::keys::public_key(&holder.public_key)?;
        emergency.push(json!({ "id": holder.id, "keyEncrypted": crypto::wrap_for(&key, &new_key)?.to_string() }));
    }
    let mut passkeys = Vec::with_capacity(holders.passkeys.len());
    for holder in &holders.passkeys {
        let der = holder.encrypted_public_key.parse::<EncString>()?.decrypt(&unlocked.user_key)?;
        let key = crypto::PublicKey::from_der(&der)?;
        passkeys.push(json!({
            "id": holder.id,
            "encryptedUserKey": crypto::wrap_for(&key, &new_key)?.to_string(),
            "encryptedPublicKey": EncString::encrypt(&der, &new_key).to_string(),
        }));
    }
    let folders: Vec<Value> = unlocked
        .vault
        .folders
        .iter()
        .map(|folder| json!({ "id": folder.id, "name": EncString::encrypt(folder.name.as_bytes(), &new_key).to_string() }))
        .collect();
    let kdf = numbers(unlocked.kdf);
    let body = json!({
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
            "emergencyAccessUnlockData": emergency,
            "organizationAccountRecoveryUnlockData": [],
            "passkeyUnlockData": passkeys,
        },
        "accountKeys": {
            "userKeyEncryptedAccountPrivateKey": EncString::encrypt(&private, &new_key).to_string(),
            "accountPublicKey": public_key,
        },
        "accountData": { "ciphers": ciphers, "folders": folders, "sends": sends },
    });
    Ok((body, new_key))
}
