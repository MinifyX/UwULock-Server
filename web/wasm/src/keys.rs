//! Handing the user key to somebody else, and getting it without the master password: emergency
//! access, logging in with another device, passkeys that unlock — and the fingerprint phrases
//! that let two people check they see the same key before one of them hands it over.

use crate::{Failure, Result, Unlocked};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use uwulock_core::crypto::{self, EncString, Kdf, PrivateKey, PublicKey, SymmetricKey};
use uwulock_core::vault::Vault;
use uwulock_core::wire;

pub fn public_key(text: &str) -> Result<(Vec<u8>, PublicKey)> {
    let der = STANDARD.decode(text.trim()).map_err(|_| Failure::new("invalid", "The public key is not base64."))?;
    let key = PublicKey::from_der(&der)?;
    Ok((der, key))
}

/// The account's own private key, opened.
pub fn private_key(unlocked: &Unlocked) -> Result<PrivateKey> {
    let wrapped = unlocked
        .private_key
        .as_deref()
        .ok_or_else(|| Failure::new("unsupported", "This account has no key pair yet. Log in again once."))?;
    let der = wrapped.parse::<EncString>()?.decrypt(&unlocked.user_key)?;
    Ok(PrivateKey::from_der(&der)?)
}

/// The fingerprint phrase of a public key, for `material`: an address or a user id.
pub fn fingerprint(material: &str, public_key_text: &str) -> Result<String> {
    let (der, _) = public_key(public_key_text)?;
    Ok(crypto::fingerprint(material, &der))
}

/// The user key, wrapped for somebody's public key: an emergency contact, or a device that
/// asks to be let in.
pub fn wrap_user_key(unlocked: &Unlocked, public_key_text: &str) -> Result<String> {
    let (_, key) = public_key(public_key_text)?;
    Ok(crypto::wrap_for(&key, &unlocked.user_key)?.to_string())
}

// ── Emergency access, as the contact ──────────────────────

fn grantor_key(unlocked: &Unlocked, key_encrypted: &str) -> Result<SymmetricKey> {
    let private = private_key(unlocked)?;
    Ok(key_encrypted.parse::<EncString>()?.decrypt_key_rsa(&private)?)
}

/// The grantor's vault, from what `emergency-access/<id>/view` answered: Bitwarden's export of
/// it, readable, for the page to show and to save.
pub fn emergency_view(unlocked: &Unlocked, key_encrypted: &str, ciphers: &str) -> Result<String> {
    let key = grantor_key(unlocked, key_encrypted)?;
    let value: Value = serde_json::from_str(ciphers)?;
    let ciphers: Vec<wire::Cipher> = serde_json::from_value(wire::lowercase_keys(value))?;
    let sync = wire::Sync { ciphers, ..wire::Sync::default() };
    let vault = Vault::open(&sync, &key)?;
    let grantor = Unlocked {
        email: String::new(),
        kdf: unlocked.kdf,
        protected_key: String::new(),
        user_key: key,
        private_key: None,
        vault,
        reprompt_ok: Default::default(),
        attachments: Default::default(),
        sends: Vec::new(),
        send_auth: Default::default(),
        report: Vec::new(),
        extras: None,
    };
    crate::transfer::export(&grantor, "json")
}

/// A new master password for the grantor: what `emergency-access/<id>/password` takes.
pub fn takeover(unlocked: &Unlocked, key_encrypted: &str, email: &str, kdf: Kdf, password: &str) -> Result<Value> {
    let key = grantor_key(unlocked, key_encrypted)?;
    // The key derivation comes from the server. Weaker than today's defaults, the new password
    // gets those instead, and the server is told.
    let today = match kdf {
        Kdf::Pbkdf2 { .. } => Kdf::Pbkdf2 { iterations: 600_000 },
        Kdf::Argon2id { .. } => Kdf::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 },
    };
    let stronger = kdf.is_weaker_than(&today).then_some(today);
    let master = crypto::master_key(password, email, stronger.unwrap_or(kdf))?;
    let mut body = json!({
        "newMasterPasswordHash": crypto::master_password_hash(&master, password),
        "key": EncString::encrypt(&key.to_bytes(), &SymmetricKey::stretch(&master)).to_string(),
    });
    if let Some(kdf) = stronger {
        let numbers = crate::account::numbers(kdf);
        body["kdf"] = numbers.kdf_type.into();
        body["kdfIterations"] = numbers.iterations.into();
        body["kdfMemory"] = numbers.memory.into();
        body["kdfParallelism"] = numbers.parallelism.into();
    }
    Ok(body)
}

// ── Logging in with another device, as the new one ────────

/// The access code the new device makes: 25 letters and digits, like Bitwarden's.
fn access_code() -> String {
    const LETTERS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut bytes = [0u8; 25];
    getrandom::getrandom(&mut bytes).expect("the browser has randomness");
    bytes.iter().map(|byte| LETTERS[usize::from(*byte) % LETTERS.len()] as char).collect()
}

/// A key pair for the request, kept here until the answer comes; its public key, the phrase to
/// compare, and the code.
pub fn start_request(email: &str) -> Result<(PrivateKey, Value)> {
    let private = PrivateKey::generate()?;
    let der = private.public().to_der()?;
    let email = crypto::normalize_email(email);
    let answer = json!({
        "publicKey": STANDARD.encode(&der),
        "fingerprint": crypto::fingerprint(&email, &der),
        "accessCode": access_code(),
    });
    Ok((private, answer))
}

/// The user key, from the answer to a request.
pub fn finish_request(private: &PrivateKey, key: &str) -> Result<SymmetricKey> {
    Ok(key.parse::<EncString>()?.decrypt_key_rsa(private)?)
}

// ── Passkeys that unlock ──────────────────────────────────

pub fn prf_salt() -> String {
    STANDARD.encode(crypto::prf_salt())
}

fn prf_bytes(prf: &str) -> Result<Vec<u8>> {
    STANDARD.decode(prf.trim()).map_err(|_| Failure::new("invalid", "The passkey's answer is not base64."))
}

/// The keys to keep with a passkey, from its PRF output.
pub fn prf_key_set(unlocked: &Unlocked, prf: &str) -> Result<Value> {
    let set = crypto::PrfKeySet::create(&prf_bytes(prf)?, &unlocked.user_key)?;
    Ok(json!({
        "encryptedUserKey": set.encrypted_user_key.to_string(),
        "encryptedPublicKey": set.encrypted_public_key.to_string(),
        "encryptedPrivateKey": set.encrypted_private_key.to_string(),
    }))
}

/// The user key, from a passkey login's answer and the passkey's PRF output.
pub fn open_prf(prf: &str, private_key: &str, user_key: &str) -> Result<SymmetricKey> {
    Ok(crypto::open_prf_key_set(&prf_bytes(prf)?, &private_key.parse()?, &user_key.parse()?)?)
}
