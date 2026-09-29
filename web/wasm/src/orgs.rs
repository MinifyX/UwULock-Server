//! Families (docs/uwu-api.md §16): what the web vault encrypts for them. A new family's keys,
//! collection names under the family key, the family key wrapped for a member being confirmed,
//! and an item moved into a family — encrypted anew under the family key, its attachments'
//! keys with it.
//!
//! The family key comes from the sync: the profile carries it wrapped for the account's public
//! key, and `Vault::open` opens it with the private key.

use crate::files::item_key;
use crate::keys::{private_key, public_key};
use crate::view::find;
use crate::{Failure, Result, Unlocked};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};
use uwulock_core::crypto::{self, EncString, PrivateKey, SymmetricKey};

fn family_key<'a>(unlocked: &'a Unlocked, org_id: &str) -> Result<&'a SymmetricKey> {
    Ok(unlocked.vault.outer_key(Some(org_id), &unlocked.user_key)?)
}

/// The body of `POST /api/organizations` for a new family: its key wrapped for the account's own
/// public key (as Bitwarden's clients send it), its key pair, the first collection's name.
pub fn new_family(unlocked: &Unlocked, name: &str, collection: &str) -> Result<Value> {
    let own = private_key(unlocked)?;
    let key = SymmetricKey::generate();
    let pair = PrivateKey::generate()?;
    Ok(json!({
        "name": name.trim(),
        "billingEmail": unlocked.email,
        "planType": 22,
        "key": crypto::wrap_for(&own.public(), &key)?.to_string(),
        "keys": {
            "publicKey": STANDARD.encode(pair.public().to_der()?),
            "encryptedPrivateKey": EncString::encrypt(&pair.to_der()?, &key).to_string(),
        },
        "collectionName": EncString::encrypt(collection.trim().as_bytes(), &key).to_string(),
    }))
}

/// Text under a family's key: a collection's name.
pub fn encrypt(unlocked: &Unlocked, org_id: &str, text: &str) -> Result<String> {
    Ok(EncString::encrypt(text.as_bytes(), family_key(unlocked, org_id)?).to_string())
}

pub fn decrypt(unlocked: &Unlocked, org_id: &str, text: &str) -> Result<String> {
    Ok(text.parse::<EncString>()?.decrypt_string(family_key(unlocked, org_id)?)?.to_string())
}

/// The family key, wrapped for a member's public key (base64 SPKI): what confirming hands over.
pub fn wrap_for_member(unlocked: &Unlocked, org_id: &str, public: &str) -> Result<String> {
    let (_, key) = public_key(public)?;
    Ok(crypto::wrap_for(&key, family_key(unlocked, org_id)?)?.to_string())
}

/// The body of `PUT /api/ciphers/<id>/share`: a personal item encrypted anew for the family.
///
/// An item with a key of its own keeps it, wrapped under the family key now; its attachments
/// stay under it. One without gets a key of its own first, and its attachments' keys and names
/// move under that — an attachment from before attachments had keys cannot move along.
pub fn share(unlocked: &Unlocked, id: &str, org_id: &str, collection_ids: Vec<String>) -> Result<Value> {
    let mut item = find(unlocked, id)?.clone();
    if item.organization_id.is_some() {
        return Err(Failure::new("refused", "This item belongs to a family already."));
    }
    if item.reprompt && !unlocked.reprompt_ok.contains(id) {
        return Err(Failure::new("refused", "Enter your master password to open this item first."));
    }
    item.can_save()?;
    let org_key = family_key(unlocked, org_id)?.clone();
    let mut attachments = Map::new();
    if item.key.is_none() {
        let old = item_key(unlocked, id)?.clone();
        let new = SymmetricKey::generate();
        for attachment in unlocked.attachments.get(id).into_iter().flatten() {
            let Some(wrapped) = &attachment.key else {
                return Err(Failure::new(
                    "unsupported",
                    "An attachment of this item is too old to move along. Download it, delete it and attach it again first.",
                ));
            };
            let file_key = wrapped.parse::<EncString>()?.decrypt_key(&old)?;
            let name = match &attachment.file_name {
                Some(name) if !name.is_empty() => name.parse::<EncString>()?.decrypt(&old)?.to_vec(),
                _ => Vec::new(),
            };
            attachments.insert(
                attachment.id.clone(),
                json!({
                    "fileName": EncString::encrypt(&name, &new).to_string(),
                    "key": EncString::encrypt(&file_key.to_bytes(), &new).to_string(),
                }),
            );
        }
        item.key = Some(new);
    }
    let own = item.key.as_ref().expect("set above");
    item.wrapped_key = Some(EncString::encrypt(&own.to_bytes(), &org_key).to_string());
    item.organization_id = Some(org_id.to_string());
    item.collection_ids = collection_ids.clone();
    let mut cipher = serde_json::to_value(item.seal(&org_key)?)?;
    if !attachments.is_empty() {
        cipher["attachments2"] = Value::Object(attachments);
    }
    Ok(json!({ "cipher": cipher, "collectionIds": collection_ids }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uwulock_core::vault::{Item, ItemKind, Vault};
    use uwulock_core::wire;

    /// An unlocked account with a key pair and a family whose key the profile carries.
    fn unlocked() -> (Unlocked, SymmetricKey) {
        let user_key = SymmetricKey::generate();
        let private = PrivateKey::generate().unwrap();
        let family = SymmetricKey::generate();
        let wrapped_private = EncString::encrypt(&private.to_der().unwrap(), &user_key).to_string();
        let sync: wire::Sync = serde_json::from_value(wire::lowercase_keys(json!({
            "profile": {
                "email": "nyu@example.com",
                "privateKey": wrapped_private,
                "organizations": [{ "id": "org", "name": "Katzen", "key": crypto::wrap_for(&private.public(), &family).unwrap().to_string() }],
            },
            "collections": [],
            "ciphers": [],
        })))
        .unwrap();
        let vault = Vault::open(&sync, &user_key).unwrap();
        let mut unlocked = Unlocked {
            email: "nyu@example.com".into(),
            kdf: uwulock_core::crypto::Kdf::Pbkdf2 { iterations: 600_000 },
            protected_key: String::new(),
            user_key,
            private_key: Some(wrapped_private),
            vault,
            reprompt_ok: Default::default(),
            attachments: Default::default(),
            sends: Vec::new(),
            report: Vec::new(),
            extras: None,
        };
        let mut item = Item::new(ItemKind::Note);
        item.id = "note".into();
        item.name = zeroize::Zeroizing::new("Geheim".into());
        unlocked.vault.items.push(item);
        (unlocked, family)
    }

    #[test]
    fn a_new_family_s_key_opens_with_the_account_s_private_key() {
        let (unlocked, _) = unlocked();
        let body = new_family(&unlocked, "Mäuse", "Allgemein").unwrap();
        let own = private_key(&unlocked).unwrap();
        let key: EncString = body["key"].as_str().unwrap().parse().unwrap();
        let key = key.decrypt_key_rsa(&own).unwrap();
        let name: EncString = body["collectionName"].as_str().unwrap().parse().unwrap();
        assert_eq!(name.decrypt_string(&key).unwrap().as_str(), "Allgemein");
        let pair: EncString = body["keys"]["encryptedPrivateKey"].as_str().unwrap().parse().unwrap();
        assert!(PrivateKey::from_der(&pair.decrypt(&key).unwrap()).is_ok());
    }

    #[test]
    fn a_shared_item_opens_with_the_family_key_alone() {
        let (unlocked, family) = unlocked();
        assert_eq!(decrypt(&unlocked, "org", &encrypt(&unlocked, "org", "Streaming").unwrap()).unwrap(), "Streaming");
        let body = share(&unlocked, "note", "org", vec!["c".into()]).unwrap();
        assert_eq!(body["collectionIds"], json!(["c"]));
        let cipher = &body["cipher"];
        assert_eq!(cipher["organizationId"], "org");
        let item_key: EncString = cipher["key"].as_str().unwrap().parse().unwrap();
        let item_key = item_key.decrypt_key(&family).unwrap();
        let name: EncString = cipher["name"].as_str().unwrap().parse().unwrap();
        assert_eq!(name.decrypt_string(&item_key).unwrap().as_str(), "Geheim");
        assert!(share(&unlocked, "note", "nope", Vec::new()).is_err(), "no key for that family");
    }

    #[test]
    fn a_member_gets_the_family_key_for_their_public_key() {
        let (unlocked, family) = unlocked();
        let member = PrivateKey::generate().unwrap();
        let public = STANDARD.encode(member.public().to_der().unwrap());
        let wrapped: EncString = wrap_for_member(&unlocked, "org", &public).unwrap().parse().unwrap();
        assert_eq!(wrapped.decrypt_key_rsa(&member).unwrap().to_bytes().as_slice(), family.to_bytes().as_slice());
    }
}
