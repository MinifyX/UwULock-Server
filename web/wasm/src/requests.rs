//! File requests (docs/uwu-api.md §11): the owner's side — the extras key their label and link
//! are under, making and opening a request, opening what arrived and taking a file into an item —
//! and the uploader's, who has no account: the page of the link encrypts for the owner's public
//! key, which it takes from the request's public details, not from the server.

use crate::{Failure, Result, Unlocked};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_core::extras::{self, Keys, Resolved};
use uwulock_core::file_request::{
    self, FileKey, LinkSecret, PublicInfo, SealedFile, Sender, SubmissionKey, open_label, seal_label,
};
use wasm_bindgen::prelude::*;

pub(crate) fn extras_key(unlocked: &Unlocked) -> Result<&uwulock_core::crypto::SymmetricKey> {
    unlocked.extras.as_ref().ok_or_else(|| Failure::new("extras", "UwULock's own key of this account is not open yet."))
}

/// What to do with the answer of `GET /uwu/v1/keys`: `open` (and maybe `rewrap`, for
/// `PUT /uwu/v1/keys/user-wrap`), `create` (the body for `POST /uwu/v1/keys`), or `lost`. The
/// key is kept from here on; after a 409 on `create`, ask again.
pub fn extras(unlocked: &mut Unlocked, keys: &str) -> Result<Value> {
    let keys: Keys = serde_json::from_str(keys)?;
    let private = unlocked.private_key.as_ref().map(|_| crate::keys::private_key(unlocked)).transpose()?;
    Ok(match extras::resolve(&keys, &unlocked.user_key, private.as_ref())? {
        Resolved::Create(new) => {
            unlocked.extras = Some(new.key);
            json!({ "action": "create", "request": new.request })
        }
        Resolved::Open { key, rewrap } => {
            unlocked.extras = Some(key);
            json!({ "action": "open", "rewrap": rewrap })
        }
        Resolved::Lost => {
            unlocked.extras = None;
            json!({ "action": "lost" })
        }
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDraft {
    /// The owner's own label.
    name: String,
    /// What the uploader sees.
    title: String,
    #[serde(default)]
    note: Option<String>,
    /// The owner's name, as the uploader sees it.
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    password: Option<String>,
    /// The link's secret, to keep the link as it is; none makes a new link.
    #[serde(default)]
    secret: Option<String>,
}

/// A request's encrypted parts: the label and the link's secret under the extras key, the public
/// details under the link's key, and the password as the server takes it.
pub fn seal(unlocked: &Unlocked, draft: RequestDraft) -> Result<Value> {
    let extras = extras_key(unlocked)?;
    let secret = match draft.secret.as_deref().filter(|secret| !secret.is_empty()) {
        Some(part) => LinkSecret::from_link_part(part)?,
        None => LinkSecret::generate(),
    };
    // The key pair's public half, from the private key the user key opens: never one the server
    // hands out.
    let public = crate::keys::private_key(unlocked)?.public();
    let note = draft.note.as_deref().map(str::trim).filter(|note| !note.is_empty());
    let owner = draft.owner.as_deref().map(str::trim).filter(|owner| !owner.is_empty());
    let info = PublicInfo::new(draft.title.trim(), note, owner, &public)?;
    Ok(json!({
        "name": seal_label(draft.name.trim(), extras),
        "linkSecret": secret.seal(extras),
        "publicInfo": info.seal(&secret)?,
        "passwordHash": draft.password.filter(|password| !password.is_empty()).map(|password| secret.password_hash(&password)),
        "secret": secret.to_link_part(),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sealed {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    link_secret: Option<String>,
    public_info: String,
}

/// A request as the owner sees it: label, the link's secret, and the public details. What does
/// not open (a label from before the extras key was reset) is null.
pub fn open(unlocked: &Unlocked, request: &str) -> Result<Value> {
    let request: Sealed = serde_json::from_str(request)?;
    let extras = unlocked.extras.as_ref();
    let name = match (&request.name, extras) {
        (Some(name), Some(key)) => open_label(name, key).ok().map(|name| name.to_string()),
        _ => None,
    };
    let secret = match (&request.link_secret, extras) {
        (Some(secret), Some(key)) => LinkSecret::open(secret, key).ok(),
        _ => None,
    };
    let info = secret.as_ref().and_then(|secret| PublicInfo::open(&request.public_info, secret).ok());
    Ok(json!({
        "name": name,
        "secret": secret.as_ref().map(LinkSecret::to_link_part),
        "title": info.as_ref().map(|info| info.title.clone()),
        "note": info.as_ref().and_then(|info| info.note.clone()),
        "owner": info.as_ref().and_then(|info| info.owner.clone()),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Submission {
    wrapped_key: String,
    #[serde(default)]
    sender: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    files: Vec<SubmittedFile>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmittedFile {
    id: String,
    file_name: String,
    key: String,
    #[serde(default)]
    size: u64,
}

fn submission_key(unlocked: &Unlocked, submission: &Submission) -> Result<SubmissionKey> {
    let private = crate::keys::private_key(unlocked)?;
    Ok(SubmissionKey::open(&submission.wrapped_key, &private)?)
}

fn file_of<'a>(submission: &'a Submission, id: &str) -> Result<&'a SubmittedFile> {
    submission
        .files
        .iter()
        .find(|file| file.id == id)
        .ok_or_else(|| Failure::new("not-found", "This file isn't in the submission."))
}

fn opened_file(key: &SubmissionKey, file: &SubmittedFile) -> Result<(String, FileKey)> {
    let sealed = SealedFile { file_name: file.file_name.clone(), key: file.key.clone() };
    let (name, key) = key.open_file(&sealed)?;
    Ok((name.to_string(), key))
}

/// What arrived, readable: the message, who the uploader said they are (unchecked), the files.
pub fn open_submission(unlocked: &Unlocked, submission: &str) -> Result<Value> {
    let submission: Submission = serde_json::from_str(submission)?;
    let key = submission_key(unlocked, &submission)?;
    let text = match submission.text.as_deref().filter(|text| !text.is_empty()) {
        Some(text) => Some(key.open_text(text)?.to_string()),
        None => None,
    };
    let sender: Option<Sender> = match submission.sender.as_deref().filter(|sender| !sender.is_empty()) {
        Some(sender) => Some(key.open_sender(sender)?),
        None => None,
    };
    let files = submission
        .files
        .iter()
        .map(|file| {
            let (name, _) = opened_file(&key, file)?;
            Ok(json!({ "id": file.id, "name": name, "size": file.size }))
        })
        .collect::<Result<Vec<Value>>>()?;
    Ok(json!({ "text": text, "sender": sender, "files": files }))
}

/// A file of a submission, opened.
pub fn open_file(unlocked: &Unlocked, submission: &str, file_id: &str, data: &[u8]) -> Result<Vec<u8>> {
    let submission: Submission = serde_json::from_str(submission)?;
    let key = submission_key(unlocked, &submission)?;
    let (_, file_key) = opened_file(&key, file_of(&submission, file_id)?)?;
    Ok(file_key.decrypt(data)?.to_vec())
}

/// A file's name and key under an item's key, for `…/attach`: the bytes stay as they are.
pub fn take(unlocked: &Unlocked, submission: &str, file_id: &str, item_id: &str) -> Result<Value> {
    let submission: Submission = serde_json::from_str(submission)?;
    let key = submission_key(unlocked, &submission)?;
    let (name, file_key) = opened_file(&key, file_of(&submission, file_id)?)?;
    let item_key = crate::files::item_key(unlocked, item_id)?;
    Ok(serde_json::to_value(file_key.for_item(&name, item_key))?)
}

// ── The uploader's side ───────────────────────────────────

/// One submission on the page of a link: the request's public details, a key for this
/// submission, and one for each file.
#[wasm_bindgen]
pub struct Upload {
    info: PublicInfo,
    key: SubmissionKey,
    files: Vec<FileKey>,
}

impl Upload {
    fn open(public_info: &str, secret: &str) -> Result<Upload> {
        let secret = LinkSecret::from_link_part(secret)?;
        let info = PublicInfo::open(public_info, &secret)
            .map_err(|_| Failure::new("link", "This link is not complete, or not for this request."))?;
        // The key must read before anything is encrypted for it.
        info.public_key()?;
        Ok(Upload { info, key: SubmissionKey::generate(), files: Vec::new() })
    }

    fn sealed(&mut self, text: &str, name: &str, email: &str, names: &str) -> Result<String> {
        let names: Vec<String> = serde_json::from_str(names)?;
        let public = self.info.public_key()?;
        let text = (!text.trim().is_empty()).then(|| self.key.seal_text(text)).transpose()?;
        let sender = Sender {
            name: Some(name.trim().to_string()).filter(|name| !name.is_empty()),
            email: Some(email.trim().to_string()).filter(|email| !email.is_empty()),
        };
        let sender =
            (sender.name.is_some() || sender.email.is_some()).then(|| self.key.seal_sender(&sender)).transpose()?;
        self.files.clear();
        let mut files = Vec::with_capacity(names.len());
        for name in &names {
            let (key, sealed) = self.key.new_file(name);
            self.files.push(key);
            files.push(sealed);
        }
        let body = json!({
            "wrappedKey": self.key.wrap(&public)?,
            "sender": sender,
            "text": text,
            "files": files,
        });
        Ok(body.to_string())
    }

    fn encrypted(&self, index: usize, data: &[u8]) -> Result<Vec<u8>> {
        let key = self.files.get(index).ok_or_else(|| Failure::new("invalid", "There is no such file."))?;
        Ok(key.encrypt(data))
    }
}

#[wasm_bindgen]
impl Upload {
    /// Opens the request's public details with the secret from the link.
    #[wasm_bindgen(constructor)]
    pub fn new(public_info: &str, secret: &str) -> std::result::Result<Upload, JsValue> {
        Ok(Upload::open(public_info, secret)?)
    }

    /// Title, note and owner, for the page.
    pub fn info(&self) -> String {
        json!({ "title": self.info.title, "note": self.info.note, "owner": self.info.owner }).to_string()
    }

    /// The submission as the server takes it: the key wrapped for the owner, the message and
    /// the sender, and each file's name and key. `names` is a JSON list; the files' contents go
    /// through [`Upload::encrypt_file`] in the same order.
    pub fn seal(&mut self, text: &str, name: &str, email: &str, names: &str) -> std::result::Result<String, JsValue> {
        Ok(self.sealed(text, name, email, names)?)
    }

    /// The `index`th file's contents, encrypted: an EncArrayBuffer, whose length is its `size`.
    #[wasm_bindgen(js_name = encryptFile)]
    pub fn encrypt_file(&self, index: usize, data: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
        Ok(self.encrypted(index, data)?)
    }
}

/// What the uploader's page makes of the password before it goes to the server.
pub fn password_hash(password: &str, secret: &str) -> Result<String> {
    Ok(LinkSecret::from_link_part(secret)?.password_hash(password))
}

/// The link to hand out: on the main host, or on a send domain.
pub fn link(base: &str, access_id: &str, secret: &str, send_domain: bool) -> Result<String> {
    Ok(file_request::link(base, access_id, &LinkSecret::from_link_part(secret)?, send_domain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uwulock_core::crypto::{EncString, PrivateKey, SymmetricKey};

    fn unlocked(private: &PrivateKey) -> Unlocked {
        let user_key = SymmetricKey::generate();
        Unlocked {
            email: "nyu@example.com".into(),
            kdf: uwulock_core::crypto::Kdf::Pbkdf2 { iterations: 600_000 },
            protected_key: String::new(),
            private_key: Some(EncString::encrypt(&private.to_der().unwrap(), &user_key).to_string()),
            user_key,
            vault: Default::default(),
            reprompt_ok: Default::default(),
            attachments: Default::default(),
            sends: Vec::new(),
            send_auth: Default::default(),
            report: Vec::new(),
            extras: None,
        }
    }

    #[test]
    fn a_request_is_made_filled_and_opened() {
        let private = PrivateKey::generate().unwrap();
        let mut owner = unlocked(&private);
        let made = extras(&mut owner, r#"{"extrasKey":null,"lost":false}"#).unwrap();
        assert_eq!(made["action"], "create");
        let draft = serde_json::from_value(json!({
            "name": "Passport for the bank",
            "title": "Passport scan",
            "note": "Both pages, please.",
            "owner": "Nyu",
            "password": "cats",
        }))
        .unwrap();
        let sealed = seal(&owner, draft).unwrap();
        let secret = sealed["secret"].as_str().unwrap().to_string();
        assert_eq!(password_hash("cats", &secret).unwrap(), sealed["passwordHash"].as_str().unwrap());

        let shown = open(&owner, &sealed.to_string()).unwrap();
        assert_eq!(
            (shown["name"].as_str(), shown["title"].as_str()),
            (Some("Passport for the bank"), Some("Passport scan"))
        );
        assert_eq!(shown["secret"].as_str(), Some(secret.as_str()));

        // The uploader, with nothing but the link.
        let mut upload = Upload::open(sealed["publicInfo"].as_str().unwrap(), &secret).unwrap();
        assert!(upload.info().contains("Both pages"));
        let body: Value =
            serde_json::from_str(&upload.sealed("Here you go", "Mika", "", r#"["front.jpg"]"#).unwrap()).unwrap();
        let encrypted = upload.encrypted(0, b"the front page").unwrap();

        let submission = json!({
            "wrappedKey": body["wrappedKey"],
            "sender": body["sender"],
            "text": body["text"],
            "files": [ { "id": "f1", "fileName": body["files"][0]["fileName"], "key": body["files"][0]["key"], "size": encrypted.len() } ],
        })
        .to_string();
        let opened = open_submission(&owner, &submission).unwrap();
        assert_eq!(opened["text"], "Here you go");
        assert_eq!(opened["sender"]["name"], "Mika");
        assert_eq!(opened["files"][0]["name"], "front.jpg");
        assert_eq!(open_file(&owner, &submission, "f1", &encrypted).unwrap(), b"the front page");
        assert!(Upload::open(sealed["publicInfo"].as_str().unwrap(), &LinkSecret::generate().to_link_part()).is_err());
    }
}
