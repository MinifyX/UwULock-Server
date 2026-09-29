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
mod files;
mod health;
mod keys;
mod requests;
mod transfer;
mod view;

use serde::Serialize;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
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
    /// Attachments by item id, as the sync brought them.
    pub attachments: HashMap<String, Vec<wire::Attachment>>,
    pub sends: Vec<wire::Send>,
    /// What the last password check keeps for the answers from Have I Been Pwned.
    pub report: Vec<health::Checked>,
    /// The extras key (UwULock's own things, like the labels of file requests), once opened.
    pub extras: Option<SymmetricKey>,
}

thread_local! {
    /// The master key between the login's first step and the unlock.
    static PENDING: RefCell<Option<Zeroizing<[u8; 32]>>> = const { RefCell::new(None) };
    static UNLOCKED: RefCell<Option<Unlocked>> = const { RefCell::new(None) };
    /// The key pair of a request to log in with another device, until the answer comes.
    static REQUEST: RefCell<Option<crypto::PrivateKey>> = const { RefCell::new(None) };
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
pub fn derive_login(email: &str, password: String, kdf: &str) -> Result<String, JsValue> {
    let password = Zeroizing::new(password);
    let kdf = kdf_from(kdf)?;
    let master = crypto::master_key(&password, email, kdf).map_err(Failure::from)?;
    let hash = crypto::master_password_hash(&master, &password);
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
    unlock_with(email, kdf, protected_key.to_string(), user_key);
    Ok(())
}

/// The vault is open with `user_key`, however it was got.
fn unlock_with(email: &str, kdf: Kdf, protected_key: String, user_key: SymmetricKey) {
    UNLOCKED.with(|cell| {
        *cell.borrow_mut() = Some(Unlocked {
            email: crypto::normalize_email(email),
            kdf,
            protected_key,
            user_key,
            private_key: None,
            vault: Vault::default(),
            reprompt_ok: HashSet::new(),
            attachments: HashMap::new(),
            sends: Vec::new(),
            report: Vec::new(),
            extras: None,
        })
    });
}

/// Wipe every key.
#[wasm_bindgen]
pub fn lock() {
    PENDING.with(|cell| *cell.borrow_mut() = None);
    UNLOCKED.with(|cell| *cell.borrow_mut() = None);
    REQUEST.with(|cell| *cell.borrow_mut() = None);
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
    let mut sync: wire::Sync = serde_json::from_value(wire::lowercase_keys(value)).map_err(Failure::from)?;
    with_unlocked(|unlocked| {
        unlocked.vault = Vault::open(&sync, &unlocked.user_key)?;
        unlocked.private_key = sync.profile.private_key.clone();
        // An unlock by passkey or by another device had no wrapped user key to keep until now.
        if let Some(key) = sync.profile.key.clone() {
            unlocked.protected_key = key;
        }
        unlocked.attachments = sync
            .ciphers
            .iter_mut()
            .filter(|cipher| !cipher.attachments.is_empty())
            .map(|cipher| (cipher.id.clone(), std::mem::take(&mut cipher.attachments)))
            .collect();
        unlocked.sends = std::mem::take(&mut sync.sends);
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
///
/// Every password comes in as a `String`, not a `&str`: wasm-bindgen hands a `String` over, so
/// it is wiped here when it drops, where the copy behind a `&str` would be freed as it is and
/// linger in the module's memory.
#[wasm_bindgen(js_name = verifyReprompt)]
pub fn verify_reprompt(id: &str, password: String) -> Result<(), JsValue> {
    let password = Zeroizing::new(password);
    with_unlocked(|unlocked| {
        account::check_password(unlocked, &password)?;
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
pub fn entropy_bits(password: String) -> u32 {
    let password = Zeroizing::new(password);
    uwulock_core::generator::entropy_bits(&password)
}

// ── The account ───────────────────────────────────────────

/// A new account: the hash the server gets, the user key wrapped under the master key, and —
/// for the RSA key pair the page made with WebCrypto — its private key wrapped under the user
/// key. `private_key` is PKCS#8 DER, base64.
#[wasm_bindgen(js_name = newAccount)]
pub fn new_account(email: &str, password: String, kdf: &str, private_key: &str) -> Result<String, JsValue> {
    let password = Zeroizing::new(password);
    Ok(json(&account::new_account(email, &password, &kdf_from(kdf)?, private_key)?)?)
}

/// For changing the master password: the current hash, and the new one with the user key wrapped
/// under the new master key.
#[wasm_bindgen(js_name = changePassword)]
pub fn change_password(current: String, new: String) -> Result<String, JsValue> {
    let (current, new) = (Zeroizing::new(current), Zeroizing::new(new));
    Ok(with_unlocked(|unlocked| json(&account::rewrap(unlocked, &current, &new, None, None)?))?)
}

/// For changing the KDF.
#[wasm_bindgen(js_name = changeKdf)]
pub fn change_kdf(password: String, kdf: &str) -> Result<String, JsValue> {
    let password = Zeroizing::new(password);
    let kdf = kdf_from(kdf)?;
    Ok(with_unlocked(|unlocked| json(&account::rewrap(unlocked, &password, &password, Some(kdf), None)?))?)
}

/// For moving to another address, which is the salt of the master key.
#[wasm_bindgen(js_name = changeEmail)]
pub fn change_email(password: String, email: &str) -> Result<String, JsValue> {
    let password = Zeroizing::new(password);
    Ok(with_unlocked(|unlocked| json(&account::rewrap(unlocked, &password, &password, None, Some(email))?))?)
}

/// The master password hash, checked against the unlocked key first: for everything the
/// server asks the password for.
#[wasm_bindgen(js_name = passwordHash)]
pub fn password_hash(password: String) -> Result<String, JsValue> {
    let password = Zeroizing::new(password);
    Ok(with_unlocked(|unlocked| account::check_password(unlocked, &password))?)
}

/// Everything for a new user key: the body of `rotate-user-account-keys`. `holders` are the
/// emergency contacts and passkeys that hold the user key too (see `account::Holders`).
#[wasm_bindgen]
pub fn rotate(password: String, public_key: &str, holders: &str) -> Result<String, JsValue> {
    let password = Zeroizing::new(password);
    let holders: account::Holders = serde_json::from_str(holders).map_err(Failure::from)?;
    Ok(with_unlocked(|unlocked| json(&account::rotate(unlocked, &password, public_key, holders)?))?)
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

// ── Attachments ───────────────────────────────────────────

#[wasm_bindgen]
pub fn attachments(item_id: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&files::list(unlocked, item_id)?))?)
}

/// A file for an item, encrypted: `meta` is what `attachment/v2` takes, the data what is
/// uploaded after.
#[wasm_bindgen(js_name = sealAttachment)]
pub fn seal_attachment(item_id: &str, file_name: &str, data: &[u8]) -> Result<files::Sealed, JsValue> {
    Ok(with_unlocked(|unlocked| files::seal(unlocked, item_id, file_name, data))?)
}

#[wasm_bindgen(js_name = openAttachment)]
pub fn open_attachment(item_id: &str, id: &str, data: &[u8]) -> Result<Vec<u8>, JsValue> {
    Ok(with_unlocked(|unlocked| files::open(unlocked, item_id, id, data))?)
}

// ── Sends ─────────────────────────────────────────────────

#[wasm_bindgen]
pub fn sends() -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&files::sends(unlocked)))?)
}

/// A Send as the server takes it, new (`id` empty) or changed; for a new file Send, `data` is the
/// file, encrypted in `Sealed`'s data.
#[wasm_bindgen(js_name = sealSend)]
pub fn seal_send(id: &str, draft: &str, data: Option<Vec<u8>>) -> Result<files::Sealed, JsValue> {
    let draft: files::SendDraft = serde_json::from_str(draft).map_err(Failure::from)?;
    Ok(with_unlocked(|unlocked| files::seal_send(unlocked, id, draft, data.as_deref()))?)
}

/// For somebody with a Send's link: the password's hash, to open it. No login needed.
#[wasm_bindgen(js_name = sendAccessPassword)]
pub fn send_access_password(password: String, url_key: &str) -> Result<String, JsValue> {
    let password = Zeroizing::new(password);
    Ok(files::access_password(&password, url_key)?)
}

#[wasm_bindgen(js_name = openSendAccess)]
pub fn open_send_access(access: &str, url_key: &str) -> Result<String, JsValue> {
    Ok(json(&files::open_access(access, url_key)?)?)
}

#[wasm_bindgen(js_name = openSendFile)]
pub fn open_send_file(url_key: &str, data: &[u8]) -> Result<Vec<u8>, JsValue> {
    Ok(files::open_file(url_key, data)?)
}

// ── Keys for others ───────────────────────────────────────

/// The fingerprint phrase of a public key (base64 SPKI) for `material`: an address, or a user id.
#[wasm_bindgen]
pub fn fingerprint(material: &str, public_key: &str) -> Result<String, JsValue> {
    Ok(keys::fingerprint(material, public_key)?)
}

/// The account's own fingerprint phrase: its user id and its public key.
#[wasm_bindgen(js_name = ownFingerprint)]
pub fn own_fingerprint(user_id: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| {
        let private = keys::private_key(unlocked)?;
        Ok(crypto::fingerprint(user_id, &private.public().to_der()?))
    })?)
}

/// The user key, wrapped for a public key (base64 SPKI): for an emergency contact, or a device
/// that asks to be let in.
#[wasm_bindgen(js_name = wrapUserKey)]
pub fn wrap_user_key(public_key: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| keys::wrap_user_key(unlocked, public_key))?)
}

/// The grantor's vault, readable, from what `emergency-access/<id>/view` answered.
#[wasm_bindgen(js_name = emergencyView)]
pub fn emergency_view(key_encrypted: &str, ciphers: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| keys::emergency_view(unlocked, key_encrypted, ciphers))?)
}

/// A new master password for the grantor, from `emergency-access/<id>/takeover`'s answer.
#[wasm_bindgen(js_name = emergencyTakeover)]
pub fn emergency_takeover(key_encrypted: &str, email: &str, kdf: &str, password: String) -> Result<String, JsValue> {
    let password = Zeroizing::new(password);
    let kdf = kdf_from(kdf)?;
    Ok(with_unlocked(|unlocked| json(&keys::takeover(unlocked, key_encrypted, email, kdf, &password)?))?)
}

/// Ask to log in with another device: a key pair kept here, and what the request carries.
#[wasm_bindgen(js_name = startDeviceLogin)]
pub fn start_device_login(email: &str) -> Result<String, JsValue> {
    let (private, answer) = keys::start_request(email)?;
    REQUEST.with(|cell| *cell.borrow_mut() = Some(private));
    Ok(json(&answer)?)
}

/// The other device said yes: open the vault with the key it sent.
#[wasm_bindgen(js_name = finishDeviceLogin)]
pub fn finish_device_login(email: &str, kdf: &str, key: &str) -> Result<(), JsValue> {
    let kdf = kdf_from(kdf)?;
    let private = REQUEST
        .with(|cell| cell.borrow_mut().take())
        .ok_or_else(|| Failure::new("locked", "Ask again."))?;
    let user_key = keys::finish_request(&private, key)?;
    unlock_with(email, kdf, String::new(), user_key);
    Ok(())
}

#[wasm_bindgen(js_name = prfSalt)]
pub fn prf_salt() -> String {
    keys::prf_salt()
}

/// The keys to keep with a passkey that unlocks, from its PRF output (base64).
#[wasm_bindgen(js_name = prfKeySet)]
pub fn prf_key_set(prf: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&keys::prf_key_set(unlocked, prf)?))?)
}

/// Open the vault with a passkey: its PRF output, and the keys the login answered with.
#[wasm_bindgen(js_name = unlockWithPasskey)]
pub fn unlock_with_passkey(email: &str, kdf: &str, prf: &str, private_key: &str, user_key: &str) -> Result<(), JsValue> {
    let kdf = kdf_from(kdf)?;
    let key = keys::open_prf(prf, private_key, user_key)?;
    unlock_with(email, kdf, String::new(), key);
    Ok(())
}

// ── The password check ────────────────────────────────────

#[wasm_bindgen(js_name = passwordReport)]
pub fn password_report() -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&health::report(unlocked)))?)
}

// ── File requests ─────────────────────────────────────────

/// What to do with the answer of `GET /uwu/v1/keys`; the extras key is kept from here on.
#[wasm_bindgen(js_name = extrasKey)]
pub fn extras_key(keys: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&requests::extras(unlocked, keys)?))?)
}

#[wasm_bindgen(js_name = sealFileRequest)]
pub fn seal_file_request(draft: &str) -> Result<String, JsValue> {
    let draft = serde_json::from_str(draft).map_err(Failure::from)?;
    Ok(with_unlocked(|unlocked| json(&requests::seal(unlocked, draft)?))?)
}

#[wasm_bindgen(js_name = openFileRequest)]
pub fn open_file_request(request: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&requests::open(unlocked, request)?))?)
}

#[wasm_bindgen(js_name = openSubmission)]
pub fn open_submission(submission: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&requests::open_submission(unlocked, submission)?))?)
}

#[wasm_bindgen(js_name = openSubmissionFile)]
pub fn open_submission_file(submission: &str, file_id: &str, data: &[u8]) -> Result<Vec<u8>, JsValue> {
    Ok(with_unlocked(|unlocked| requests::open_file(unlocked, submission, file_id, data))?)
}

#[wasm_bindgen(js_name = takeSubmissionFile)]
pub fn take_submission_file(submission: &str, file_id: &str, item_id: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&requests::take(unlocked, submission, file_id, item_id)?))?)
}

#[wasm_bindgen(js_name = fileRequestPassword)]
pub fn file_request_password(password: String, secret: &str) -> Result<String, JsValue> {
    let password = Zeroizing::new(password);
    Ok(requests::password_hash(&password, secret)?)
}

#[wasm_bindgen(js_name = fileRequestLink)]
pub fn file_request_link(base: &str, access_id: &str, secret: &str, send_domain: bool) -> Result<String, JsValue> {
    Ok(requests::link(base, access_id, secret, send_domain)?)
}

/// Which items' passwords were in a breach, from HIBP's answer for one prefix.
#[wasm_bindgen]
pub fn breaches(prefix: &str, range: &str) -> Result<String, JsValue> {
    Ok(with_unlocked(|unlocked| json(&health::breaches(unlocked, prefix, range)))?)
}
