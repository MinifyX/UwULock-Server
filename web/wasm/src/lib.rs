//! The web vault's crypto and vault, compiled to WebAssembly.
//!
//! The page never holds a key. It hands this module the master password once, and from then on
//! asks for what it shows: the list of items, one item's details without its secrets, a secret
//! when somebody clicks to see it. Encrypting what is saved happens in here too. The keys live
//! in this module's memory until the vault is locked, which wipes them.
//!
//! Everything goes in and out as JSON text, and every error as `{"kind", "message"}`, the way
//! the desktop app's Rust side answers its page — the web vault uses the same page.
//!
//! What is here is the desktop app's vault logic (UwULock-Client, `apps/desktop/src-tauri`)
//! and UwULock's crypto (`uwulock-core`), plus what only the web vault does: registering,
//! changing the master password, the KDF or the address, new keys, import and export.

mod account;
mod draft;
mod transfer;
mod view;

use serde::Serialize;
use std::cell::RefCell;
use std::collections::HashSet;
use uwulock_core::crypto::{self, EncString, Kdf, SymmetricKey};
use uwulock_core::vault::Vault;
use uwulock_core::wire;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// An error for the page: what kind, and a message a person can read.
#[derive(Debug, Serialize)]
pub struct Failure {
    kind: &'static str,
    message: String,
}

impl Failure {
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Failure { kind, message: message.into() }
    }
}

impl From<uwulock_core::Error> for Failure {
    fn from(error: uwulock_core::Error) -> Self {
        let kind = match &error {
            uwulock_core::Error::WrongKey => "wrong-password",
            uwulock_core::Error::Refused(_) => "refused",
            uwulock_core::Error::Unsupported(_) => "unsupported",
            _ => "crypto",
        };
        Failure::new(kind, error.to_string())
    }
}

impl From<serde_json::Error> for Failure {
    fn from(error: serde_json::Error) -> Self {
        Failure::new("invalid", error.to_string())
    }
}

impl From<Failure> for JsValue {
    fn from(failure: Failure) -> Self {
        JsValue::from_str(&serde_json::to_string(&failure).unwrap_or_default())
    }
}

pub type Result<T, E = Failure> = std::result::Result<T, E>;

/// The account, unlocked.
pub struct Unlocked {
    pub email: String,
    pub kdf: Kdf,
    /// The user key as the server keeps it, wrapped under the master key.
    pub protected_key: String,
    pub user_key: SymmetricKey,
    /// The private key as the server keeps it, wrapped under the user key.
    pub private_key: Option<String>,
    pub vault: Vault,
    /// Items with a master password re-prompt whose prompt was answered.
    pub reprompt_ok: HashSet<String>,
}

thread_local! {
    /// The master key between the login's first step and the unlock.
    static PENDING: RefCell<Option<Zeroizing<[u8; 32]>>> = const { RefCell::new(None) };
    static UNLOCKED: RefCell<Option<Unlocked>> = const { RefCell::new(None) };
}

pub fn with_unlocked<T>(work: impl FnOnce(&mut Unlocked) -> Result<T>) -> Result<T> {
    UNLOCKED.with(|cell| match cell.borrow_mut().as_mut() {
        Some(unlocked) => work(unlocked),
        None => Err(Failure::new("locked", "The vault is locked.")),
    })
}

fn json<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string(value)?)
}

/// A KDF as the server's prelogin gives it: `{"kdf", "kdfIterations", "kdfMemory",
/// "kdfParallelism"}`.
pub fn kdf_from(text: &str) -> Result<Kdf> {
    let value: serde_json::Value = serde_json::from_str(text)?;
    let number = |key: &str| value.get(key).and_then(serde_json::Value::as_u64).map(|n| n as u32);
    let kdf = match number("kdf").unwrap_or(0) {
        0 => Kdf::Pbkdf2 { iterations: number("kdfIterations").unwrap_or(600_000) },
        1 => Kdf::Argon2id {
            iterations: number("kdfIterations").unwrap_or(3),
            memory_mib: number("kdfMemory").unwrap_or(64),
            parallelism: number("kdfParallelism").unwrap_or(4),
        },
        other => return Err(Failure::new("unsupported", format!("key derivation type {other}"))),
    };
    kdf.check()?;
    kdf.check_ceilings()?;
    Ok(kdf)
}

// ── Logging in and unlocking ──────────────────────────────

/// The master key from the password, kept for [`unlock`]; the hash the server gets.
#[wasm_bindgen(js_name = deriveLogin)]
pub fn derive_login(email: &str, password: &str, kdf: &str) -> Result<String, JsValue> {
    let kdf = kdf_from(kdf)?;
    let master = crypto::master_key(password, email, kdf).map_err(Failure::from)?;
    let hash = crypto::master_password_hash(&master, password);
    PENDING.with(|cell| *cell.borrow_mut() = Some(master));
    Ok(hash)
}

/// Open the user key with the master key from [`derive_login`]. A wrong master password
/// shows up here.
#[wasm_bindgen]
pub fn unlock(email: &str, kdf: &str, protected_key: &str) -> Result<(), JsValue> {
    let kdf = kdf_from(kdf)?;
    let master = PENDING
        .with(|cell| cell.borrow_mut().take())
        .ok_or_else(|| Failure::new("locked", "Log in first."))?;
    let protected: EncString = protected_key.parse().map_err(Failure::from)?;
    let user_key = crypto::decrypt_user_key(&master, &protected)
        .map_err(|_| Failure::new("wrong-password", "The master password is wrong."))?;
    UNLOCKED.with(|cell| {
        *cell.borrow_mut() = Some(Unlocked {
            email: crypto::normalize_email(email),
            kdf,
            protected_key: protected_key.to_string(),
            user_key,
            private_key: None,
            vault: Vault::default(),
            reprompt_ok: HashSet::new(),
        })
    });
    Ok(())
}

/// Wipe every key.
#[wasm_bindgen]
pub fn lock() {
    PENDING.with(|cell| *cell.borrow_mut() = None);
    UNLOCKED.with(|cell| *cell.borrow_mut() = None);
}

#[wasm_bindgen(js_name = isUnlocked)]
pub fn is_unlocked() -> bool {
    UNLOCKED.with(|cell| cell.borrow().is_some())
}

// ── The vault ─────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Overview {
    folders: Vec<uwulock_core::vault::Folder>,
    collections: Vec<uwulock_core::vault::Collection>,
    organizations: Vec<uwulock_core::vault::Organization>,
    skipped: usize,
}

/// Open a sync, as the server sent it.
#[wasm_bindgen]
pub fn open(sync: &str) -> Result<(), JsValue> {
    let value: serde_json::Value = serde_json::from_str(sync).map_err(Failure::from)?;
    let sync: wire::Sync = serde_json::from_value(wire::lowercase_keys(value)).map_err(Failure::from)?;
    with_unlocked(|unlocked| {
        unlocked.vault = Vault::open(&sync, &unlocked.user_key)?;
        unlocked.private_key = sync.profile.private_key.clone();
        Ok(())
    })?;
    Ok(())
}

#[wasm_bindgen]
pub fn overview() -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| {
        let vault = &unlocked.vault;
        json(&Overview {
            folders: vault.folders.clone(),
            collections: vault.collections.clone(),
            organizations: vault.organizations.clone(),
            skipped: vault.skipped,
        })
    })?)
}

#[wasm_bindgen]
pub fn items() -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&unlocked.vault.items.iter().map(view::summary).collect::<Vec<_>>()))?)
}

#[wasm_bindgen]
pub fn item(id: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&view::detail(unlocked, id)?))?)
}

/// One secret of an item, by name (see `view::value_of`). `now` is `Date.now() / 1000`, for a
/// TOTP code.
#[wasm_bindgen]
pub fn reveal(id: &str, field: &str, now: f64) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| Ok(view::value_of(unlocked, id, field, now as u64)?.to_string()))?)
}

#[wasm_bindgen]
pub fn totp(id: &str, now: f64) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&view::totp(unlocked, id, now as u64)?))?)
}

/// The master password again, for an item that asks for it before showing anything.
#[wasm_bindgen(js_name = verifyReprompt)]
pub fn verify_reprompt(id: &str, password: &str) -> Result<(), JsValue> {
    with_unlocked(|unlocked| {
        account::check_password(unlocked, password)?;
        unlocked.reprompt_ok.insert(id.to_string());
        Ok(())
    })?;
    Ok(())
}

/// An item as the server takes it: a new one (`id` empty) or a change to one, from what the
/// editor sends. `now` is an ISO date for the password history.
#[wasm_bindgen(js_name = sealDraft)]
pub fn seal_draft(id: &str, draft: &str, now: &str) -> Result<String, JsValue> {
    let draft: draft::Draft = serde_json::from_str(draft).map_err(Failure::from)?;
    Ok(with_unlocked(|unlocked| json(&draft::seal(unlocked, id, draft, now)?))?)
}

/// Text encrypted under the user key: a folder name.
#[wasm_bindgen(js_name = encryptText)]
pub fn encrypt_text(text: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| Ok(EncString::encrypt(text.as_bytes(), &unlocked.user_key).to_string()))?)
}

#[wasm_bindgen]
pub fn generate(options: &str) -> Result<String, JsValue> {
    let options: uwulock_core::generator::Options = serde_json::from_str(options).map_err(Failure::from)?;
    let password = uwulock_core::generator::password(&options);
    let bits = uwulock_core::generator::entropy_bits(&password);
    Ok(json(&serde_json::json!({ "password": password.as_str(), "bits": bits }))?)
}

/// How strong a password is, in bits, for the strength meter.
#[wasm_bindgen(js_name = entropyBits)]
pub fn entropy_bits(password: &str) -> u32 {
    uwulock_core::generator::entropy_bits(password)
}

// ── The account ───────────────────────────────────────────

/// A new account: the hash the server gets, the user key wrapped under the master key, and —
/// for the RSA key pair the page made with WebCrypto — its private key wrapped under the user
/// key. `private_key` is PKCS#8 DER, base64.
#[wasm_bindgen(js_name = newAccount)]
pub fn new_account(email: &str, password: &str, kdf: &str, private_key: &str) -> Result<String, JsValue> {
    Ok(json(&account::new_account(email, password, &kdf_from(kdf)?, private_key)?)?)
}

/// For changing the master password: the current hash, and the new one with the user key wrapped
/// under the new master key.
#[wasm_bindgen(js_name = changePassword)]
pub fn change_password(current: &str, new: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&account::rewrap(unlocked, current, new, None, None)?))?)
}

/// For changing the KDF.
#[wasm_bindgen(js_name = changeKdf)]
pub fn change_kdf(password: &str, kdf: &str) -> Result<String, JsValue> {
    let kdf = kdf_from(kdf)?;
    Ok(with_unlocked(|unlocked| json(&account::rewrap(unlocked, password, password, Some(kdf), None)?))?)
}

/// For moving to another address, which is the salt of the master key.
#[wasm_bindgen(js_name = changeEmail)]
pub fn change_email(password: &str, email: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&account::rewrap(unlocked, password, password, None, Some(email))?))?)
}

/// The master password hash, checked against the unlocked key first: for everything the
/// server asks the password for.
#[wasm_bindgen(js_name = passwordHash)]
pub fn password_hash(password: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| account::check_password(unlocked, password))?)
}

/// Everything for a new user key: the body of `rotate-user-account-keys`.
#[wasm_bindgen]
pub fn rotate(password: &str, public_key: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&account::rotate(unlocked, password, public_key)?))?)
}

// ── Import and export ─────────────────────────────────────

/// The vault as Bitwarden's unencrypted JSON export, or its CSV (`format`: `json`, `csv`).
#[wasm_bindgen(js_name = exportVault)]
pub fn export_vault(format: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| transfer::export(unlocked, format))?)
}

/// What an import sends, from a Bitwarden JSON or CSV export (`format`: `json`, `csv`), every
/// item encrypted.
#[wasm_bindgen(js_name = importVault)]
pub fn import_vault(format: &str, text: &str, now: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&transfer::import(unlocked, format, text, now)?))?)
}
