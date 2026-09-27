//! Attachments and Sends: files and texts encrypted in here before they go to the server, and
//! opened in here when they come back. The page only ever holds what a person put in or asked
//! to see — the file they picked, the file they download.

use crate::{Failure, Result, Unlocked};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uwulock_core::crypto::{self, EncString, SymmetricKey};
use uwulock_core::wire;
use wasm_bindgen::prelude::*;

/// What the server gets for a file, and the file itself, encrypted.
#[wasm_bindgen]
pub struct Sealed {
    meta: String,
    data: Vec<u8>,
}

#[wasm_bindgen]
impl Sealed {
    /// The JSON the server takes.
    #[wasm_bindgen(getter)]
    pub fn meta(&self) -> String {
        self.meta.clone()
    }

    /// The encrypted file, to upload. Taken once: the module's copy is gone afterwards.
    #[wasm_bindgen(js_name = takeData)]
    pub fn take_data(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }
}

fn text_of(value: &Option<String>, key: &SymmetricKey) -> Result<Option<String>> {
    match value {
        Some(text) if !text.is_empty() => Ok(Some(text.parse::<EncString>()?.decrypt_string(key)?.to_string())),
        _ => Ok(None),
    }
}

// ── Attachments ───────────────────────────────────────────

/// The key an item's attachment keys are under: the item's own, or the one the item is under.
fn item_key<'a>(unlocked: &'a Unlocked, item_id: &str) -> Result<&'a SymmetricKey> {
    let item = unlocked.vault.item(item_id).ok_or_else(|| Failure::new("not-found", "This item isn't in the vault."))?;
    match &item.key {
        Some(key) => Ok(key),
        None => Ok(unlocked.vault.outer_key(item.organization_id.as_deref(), &unlocked.user_key)?),
    }
}

fn attachment<'a>(unlocked: &'a Unlocked, item_id: &str, id: &str) -> Result<&'a wire::Attachment> {
    unlocked
        .attachments
        .get(item_id)
        .and_then(|list| list.iter().find(|attachment| attachment.id == id))
        .ok_or_else(|| Failure::new("not-found", "This attachment isn't there any more."))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentView {
    id: String,
    file_name: String,
    size: u64,
}

/// An item's attachments, with their names opened.
pub fn list(unlocked: &Unlocked, item_id: &str) -> Result<Vec<AttachmentView>> {
    let key = item_key(unlocked, item_id)?;
    let Some(list) = unlocked.attachments.get(item_id) else { return Ok(Vec::new()) };
    list.iter()
        .map(|attachment| {
            // The name is under the item's key, like the attachment's own key.
            let file_name = text_of(&attachment.file_name, key)?.unwrap_or_else(|| "?".into());
            Ok(AttachmentView {
                id: attachment.id.clone(),
                file_name,
                size: attachment.size.as_deref().and_then(|size| size.parse().ok()).unwrap_or(0),
            })
        })
        .collect()
}

/// A new attachment for an item: the name and a fresh key encrypted, and the file under it.
pub fn seal(unlocked: &Unlocked, item_id: &str, file_name: &str, data: &[u8]) -> Result<Sealed> {
    let key = item_key(unlocked, item_id)?;
    let own = SymmetricKey::generate();
    let encrypted = crypto::encrypt_file(data, &own);
    let meta = json!({
        // Bitwarden encrypts the name under the item key, not the attachment's own.
        "fileName": EncString::encrypt(file_name.as_bytes(), key).to_string(),
        "key": EncString::encrypt(&own.to_bytes(), key).to_string(),
        "fileSize": encrypted.len(),
    });
    Ok(Sealed { meta: meta.to_string(), data: encrypted })
}

/// An attachment's file, opened.
pub fn open(unlocked: &Unlocked, item_id: &str, id: &str, data: &[u8]) -> Result<Vec<u8>> {
    let key = item_key(unlocked, item_id)?;
    let found = attachment(unlocked, item_id, id)?;
    let file_key = match &found.key {
        Some(wrapped) => wrapped.parse::<EncString>()?.decrypt_key(key)?,
        None => key.clone(),
    };
    Ok(crypto::decrypt_file(data, &file_key)?.to_vec())
}

// ── Sends ─────────────────────────────────────────────────

fn seed_of(send: &wire::Send, user_key: &SymmetricKey) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let wrapped = send.key.as_deref().ok_or_else(|| Failure::new("crypto", "This Send has no key."))?;
    Ok(wrapped.parse::<EncString>()?.decrypt(user_key)?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendView {
    id: String,
    access_id: String,
    kind: u8,
    name: String,
    notes: Option<String>,
    text: Option<String>,
    hidden: bool,
    file_name: Option<String>,
    size: Option<u64>,
    max_access_count: Option<u32>,
    access_count: u32,
    has_password: bool,
    disabled: bool,
    hide_email: bool,
    revision_date: Option<String>,
    expiration_date: Option<String>,
    deletion_date: Option<String>,
    /// What goes after the access id in the link: the seed, base64url.
    url_key: String,
}

fn view(send: &wire::Send, user_key: &SymmetricKey) -> Result<SendView> {
    let seed = seed_of(send, user_key)?;
    let key = crypto::send_key(&seed)?;
    Ok(SendView {
        id: send.id.clone(),
        access_id: send.access_id.clone().unwrap_or_default(),
        kind: send.kind,
        name: text_of(&send.name, &key)?.unwrap_or_default(),
        notes: text_of(&send.notes, &key)?,
        text: match &send.text {
            Some(text) => text_of(&text.text, &key)?,
            None => None,
        },
        hidden: send.text.as_ref().and_then(|text| text.hidden).unwrap_or(false),
        file_name: match &send.file {
            Some(file) => text_of(&file.file_name, &key)?,
            None => None,
        },
        size: send.file.as_ref().and_then(|file| file.size.as_deref()).and_then(|size| size.parse().ok()),
        max_access_count: send.max_access_count,
        access_count: send.access_count.unwrap_or(0),
        has_password: send.password.is_some(),
        disabled: send.disabled.unwrap_or(false),
        hide_email: send.hide_email.unwrap_or(false),
        revision_date: send.revision_date.clone(),
        expiration_date: send.expiration_date.clone(),
        deletion_date: send.deletion_date.clone(),
        url_key: URL_SAFE_NO_PAD.encode(seed.as_slice()),
    })
}

/// The account's Sends, opened. One that does not open is left out.
pub fn sends(unlocked: &Unlocked) -> Vec<SendView> {
    unlocked.sends.iter().filter_map(|send| view(send, &unlocked.user_key).ok()).collect()
}

/// What the Send editor gives: the text or the file name, and the settings.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendDraft {
    kind: u8,
    name: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    hidden: bool,
    #[serde(default)]
    file_name: Option<String>,
    /// A new password; none keeps the one there is, `""` is none.
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    max_access_count: Option<u32>,
    #[serde(default)]
    expiration_date: Option<String>,
    deletion_date: String,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    hide_email: bool,
}

/// A Send as the server takes it: a new one (`id` empty, with a fresh key) or a change to one.
/// For a new file Send, `data` is the file, which comes back encrypted.
pub fn seal_send(unlocked: &Unlocked, id: &str, draft: SendDraft, data: Option<&[u8]>) -> Result<Sealed> {
    let seed: zeroize::Zeroizing<Vec<u8>> = if id.is_empty() {
        zeroize::Zeroizing::new(crypto::generate_send_seed().to_vec())
    } else {
        let send = unlocked
            .sends
            .iter()
            .find(|send| send.id == id)
            .ok_or_else(|| Failure::new("not-found", "This Send isn't there any more."))?;
        seed_of(send, &unlocked.user_key)?
    };
    let key = crypto::send_key(&seed)?;
    let encrypt = |text: &str| EncString::encrypt(text.as_bytes(), &key).to_string();
    let mut body = json!({
        "type": draft.kind,
        "key": EncString::encrypt(&seed, &unlocked.user_key).to_string(),
        "name": encrypt(&draft.name),
        "notes": draft.notes.as_deref().filter(|notes| !notes.is_empty()).map(encrypt),
        "maxAccessCount": draft.max_access_count,
        "expirationDate": draft.expiration_date,
        "deletionDate": draft.deletion_date,
        "disabled": draft.disabled,
        "hideEmail": draft.hide_email,
        "password": draft.password.as_deref().filter(|password| !password.is_empty())
            .map(|password| crypto::send_password_hash(password, &seed)),
    });
    let mut encrypted = Vec::new();
    if draft.kind == 0 {
        body["text"] = json!({ "text": encrypt(draft.text.as_deref().unwrap_or_default()), "hidden": draft.hidden });
    } else {
        let name = draft.file_name.as_deref().unwrap_or("file");
        body["file"] = json!({ "fileName": encrypt(name) });
        if let Some(data) = data {
            encrypted = crypto::encrypt_file(data, &key);
            body["fileLength"] = json!(encrypted.len());
        }
    }
    if !id.is_empty() {
        body["id"] = json!(id);
    }
    Ok(Sealed { meta: body.to_string(), data: encrypted })
}

// ── For whoever has the link ──────────────────────────────

fn link_key(url_key: &str) -> Result<SymmetricKey> {
    let seed = URL_SAFE_NO_PAD
        .decode(url_key.trim().trim_end_matches('='))
        .map_err(|_| Failure::new("invalid", "The link is not complete."))?;
    Ok(crypto::send_key(&seed)?)
}

/// The hash of a Send's password, to open it.
pub fn access_password(password: &str, url_key: &str) -> Result<String> {
    let seed = URL_SAFE_NO_PAD
        .decode(url_key.trim().trim_end_matches('='))
        .map_err(|_| Failure::new("invalid", "The link is not complete."))?;
    Ok(crypto::send_password_hash(password, &seed))
}

/// A Send as the server hands it to somebody with the link, opened with the key from the link.
pub fn open_access(access: &str, url_key: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(access)?;
    let send: wire::Send = serde_json::from_value(wire::lowercase_keys(value.clone()))?;
    let key = link_key(url_key)?;
    Ok(json!({
        "kind": send.kind,
        "name": text_of(&send.name, &key)?,
        "text": match &send.text { Some(text) => text_of(&text.text, &key)?, None => None },
        "hidden": send.text.as_ref().and_then(|text| text.hidden).unwrap_or(false),
        "fileId": send.file.as_ref().and_then(|file| file.id.clone()),
        "fileName": match &send.file { Some(file) => text_of(&file.file_name, &key)?, None => None },
        "size": send.file.as_ref().and_then(|file| file.size.clone()),
        "expirationDate": send.expiration_date,
        "creator": value.get("creatorIdentifier").cloned().unwrap_or(Value::Null),
    }))
}

/// A Send's file, opened with the key from the link.
pub fn open_file(url_key: &str, data: &[u8]) -> Result<Vec<u8>> {
    Ok(crypto::decrypt_file(data, &link_key(url_key)?)?.to_vec())
}
