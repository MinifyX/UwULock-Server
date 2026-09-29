//! Attachments and Sends: files and texts encrypted in here before they go to the server, and
//! opened in here when they come back. The page only ever holds what a person put in or asked
//! to see — the file they picked, the file they download.

use crate::{Failure, Result, Unlocked};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uwulock_core::crypto::{self, EncString, SymmetricKey};
use uwulock_core::send;
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
pub(crate) fn item_key<'a>(unlocked: &'a Unlocked, item_id: &str) -> Result<&'a SymmetricKey> {
    let item =
        unlocked.vault.item(item_id).ok_or_else(|| Failure::new("not-found", "This item isn't in the vault."))?;
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
    /// Bitwarden's `authType`: 0 only the addresses, 1 a password, 2 anybody with the link.
    auth_type: u8,
    /// Who may open it, when `auth_type` is 0.
    emails: Vec<String>,
    disabled: bool,
    hide_email: bool,
    revision_date: Option<String>,
    expiration_date: Option<String>,
    deletion_date: Option<String>,
    /// What goes after the access id in the link: the seed, base64url.
    url_key: String,
}

fn view(send: &wire::Send, auth: Option<&SendAuth>, user_key: &SymmetricKey) -> Result<SendView> {
    let seed = seed_of(send, user_key)?;
    let emails = auth.map(|auth| auth.emails.clone()).unwrap_or_default();
    let auth_type = match auth.and_then(|auth| auth.auth_type) {
        Some(kind) => kind,
        None if !emails.is_empty() => 0,
        None if send.password.is_some() => 1,
        None => 2,
    };
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
        auth_type,
        emails,
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
    unlocked
        .sends
        .iter()
        .filter_map(|send| view(send, unlocked.send_auth.get(&send.id), &unlocked.user_key).ok())
        .collect()
}

/// What of a Send's sync entry `wire::Send` leaves out: who may open it.
#[derive(Debug, Clone, Default)]
pub struct SendAuth {
    pub auth_type: Option<u8>,
    pub emails: Vec<String>,
}

/// The addresses and `authType` of the Sends in a sync (lower-cased keys), by Send id.
pub fn send_auth(sends: Option<&Value>) -> std::collections::HashMap<String, SendAuth> {
    let Some(Value::Array(list)) = sends else { return Default::default() };
    list.iter()
        .filter_map(|send| {
            let id = send.get("id")?.as_str()?.to_string();
            let emails = send
                .get("emails")
                .and_then(Value::as_str)
                .map(|list| list.split(',').map(str::trim).filter(|e| !e.is_empty()).map(String::from).collect())
                .unwrap_or_default();
            let auth_type = send.get("authtype").and_then(Value::as_u64).and_then(|n| u8::try_from(n).ok());
            Some((id, SendAuth { auth_type, emails }))
        })
        .collect()
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
    /// 0 only `emails`, 1 a password (the new one, or the one there is), 2 anybody.
    #[serde(default)]
    auth_type: Option<u8>,
    #[serde(default)]
    emails: Vec<String>,
}

/// The addresses of a Send as the server takes them: trimmed, lower case, comma-separated.
fn address_list(emails: &[String]) -> Result<Option<String>> {
    let emails: Vec<String> = emails.iter().map(|e| e.trim().to_lowercase()).filter(|e| !e.is_empty()).collect();
    for email in &emails {
        let ok = email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
        }) && !email.contains(char::is_whitespace)
            && !email.contains(',');
        if !ok {
            return Err(Failure::new("invalid", format!("“{email}” is not an email address.")));
        }
    }
    Ok((!emails.is_empty()).then(|| emails.join(",")))
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
    if let Some(auth_type) = draft.auth_type {
        body["authType"] = json!(auth_type);
        match auth_type {
            0 => {
                let emails = address_list(&draft.emails)?
                    .ok_or_else(|| Failure::new("invalid", "Name at least one address."))?;
                body["emails"] = json!(emails);
                body["password"] = Value::Null;
            }
            1 => {}
            _ => body["password"] = Value::Null,
        }
    }
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

// ── Sharing an item as a Send ─────────────────────────────

/// The values of an item that can go into a Send, by uwulock-core's names (`username`,
/// `password`, `uri:0`, `field:2`, …), each with the field's own name where it has one. Only
/// those with a value; never the authenticator key.
pub fn shareable(unlocked: &Unlocked, item_id: &str) -> Result<Vec<Value>> {
    let item = crate::view::find(unlocked, item_id)?;
    let mut names: Vec<String> = ["username", "password"].map(String::from).to_vec();
    if let Some(login) = &item.login {
        names.extend((0..login.uris.len()).map(|n| format!("uri:{n}")));
    }
    names.extend(["card-name", "card-number", "card-expiry", "card-code"].map(String::from));
    names.extend(crate::view::IDENTITY_FIELDS.iter().map(|(name, _)| format!("identity:{name}")));
    names.extend(["ssh-public", "ssh-private", "ssh-fingerprint"].map(String::from));
    names.push("notes".into());
    names.extend((0..item.fields.len()).map(|n| format!("field:{n}")));
    Ok(names
        .into_iter()
        .filter(|name| send::shareable_value(item, name).is_some())
        .map(|name| {
            let label = name
                .strip_prefix("field:")
                .and_then(|n| n.parse::<usize>().ok())
                .and_then(|n| item.fields.get(n)?.name.as_ref().map(|n| n.to_string()));
            json!({ "name": name, "label": label })
        })
        .collect())
}

#[derive(Deserialize)]
pub struct ShareField {
    name: String,
    label: String,
}

/// "Share as Send": which of an item's values, and the Send's settings.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareDraft {
    item_id: String,
    fields: Vec<ShareField>,
    name: String,
    #[serde(default)]
    hidden: bool,
    #[serde(default)]
    max_access_count: Option<u32>,
    deletion_date: String,
    #[serde(default)]
    expiration_date: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default)]
    hide_email: bool,
}

/// A text Send of the chosen values of an item: `{ request, urlKey }`, the body of
/// `POST /api/sends` and what goes after the access id in its link.
pub fn share_item(unlocked: &Unlocked, draft: ShareDraft) -> Result<Value> {
    let item = crate::view::find(unlocked, &draft.item_id)?;
    let fields: Vec<(String, String)> = draft.fields.into_iter().map(|field| (field.name, field.label)).collect();
    let text = send::share_text(item, &fields);
    if text.as_str() == item.name.as_str() {
        return Err(Failure::new("invalid", "Choose at least one field that has a value."));
    }
    let sealed = send::TextSend {
        name: draft.name,
        notes: None,
        text,
        hidden: draft.hidden,
        max_access_count: draft.max_access_count,
        deletion_date: draft.deletion_date,
        expiration_date: draft.expiration_date,
        password: draft.password.filter(|password| !password.is_empty()).map(zeroize::Zeroizing::new),
        emails: draft.emails,
        hide_email: draft.hide_email,
    }
    .seal(&unlocked.user_key)
    .map_err(|error| match error {
        uwulock_core::Error::Crypto(message) => Failure::new("invalid", message),
        other => Failure::from(other),
    })?;
    Ok(json!({ "request": sealed.request, "urlKey": URL_SAFE_NO_PAD.encode(sealed.seed.as_ref()) }))
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
