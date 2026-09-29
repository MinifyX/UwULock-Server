//! Own icons, entry versions and UwULock's key rotation (docs/uwu-api.md §3, §7.3 and §8): the
//! web vault's side of them. Icons are sealed under the extras key (a personal item) or the
//! organisation's key; versions are opened with the key their item is under, and re-encrypted
//! when the user key changes.

use crate::view::{find, text};
use crate::{Failure, Result, Unlocked};
use serde_json::{Value, json};
use uwulock_core::crypto::SymmetricKey;
use uwulock_core::extras;
use uwulock_core::vault::{FieldKind, Item};
use uwulock_core::wire;

/// The key an item's own icon is under, and what the server calls it.
fn icon_key<'a>(unlocked: &'a Unlocked, item_id: &str) -> Result<(&'a SymmetricKey, &'static str)> {
    let item = find(unlocked, item_id)?;
    match item.organization_id.as_deref() {
        Some(org) => Ok((unlocked.vault.outer_key(Some(org), &unlocked.user_key)?, "organization")),
        None => Ok((
            unlocked
                .extras
                .as_ref()
                .ok_or_else(|| Failure::new("extras", "UwULock's own key of this account is not open yet."))?,
            "extras",
        )),
    }
}

/// An own icon for `PUT /uwu/v1/icons/own/{id}`: `{ data, keyType }`. `png` is at most 128 × 128
/// pixels already.
pub fn seal_icon(unlocked: &Unlocked, item_id: &str, png: &[u8]) -> Result<Value> {
    let (key, key_type) = icon_key(unlocked, item_id)?;
    Ok(json!({ "data": extras::seal_icon(png, key)?, "keyType": key_type }))
}

/// An own icon's PNG.
pub fn open_icon(unlocked: &Unlocked, item_id: &str, data: &str) -> Result<Vec<u8>> {
    let (key, _) = icon_key(unlocked, item_id)?;
    Ok(extras::open_icon(data, key)?.to_vec())
}

fn plain(value: &Option<uwulock_core::vault::Secret>) -> Value {
    text(value).map_or(Value::Null, Value::String)
}

/// Everything of an item that a version shows, secrets included: the person asked for this one
/// version, of an item they may see.
fn values(item: &Item) -> Value {
    let login = item.login.as_ref().map(|login| {
        json!({
            "username": plain(&login.username),
            "password": plain(&login.password),
            "totp": plain(&login.totp),
            "uris": login.uris.iter().map(|uri| uri.uri.to_string()).collect::<Vec<_>>(),
        })
    });
    let card = item.card.as_ref().map(|card| {
        json!({
            "cardholderName": plain(&card.cardholder_name),
            "brand": plain(&card.brand),
            "number": plain(&card.number),
            "expMonth": plain(&card.exp_month),
            "expYear": plain(&card.exp_year),
            "code": plain(&card.code),
        })
    });
    let identity = item.identity.as_ref().map(|_| {
        let mut out = serde_json::Map::new();
        for (name, _) in crate::view::IDENTITY_FIELDS {
            if let Some(value) = crate::view::identity_value(item, name).filter(|value| !value.is_empty()) {
                out.insert((*name).to_string(), Value::String(value.to_string()));
            }
        }
        Value::Object(out)
    });
    let ssh_key = item.ssh_key.as_ref().map(|key| {
        json!({
            "privateKey": plain(&key.private_key),
            "publicKey": plain(&key.public_key),
            "fingerprint": plain(&key.fingerprint),
        })
    });
    let fields: Vec<Value> = item
        .fields
        .iter()
        .filter(|field| !matches!(field.kind, FieldKind::Linked))
        .map(|field| {
            json!({
                "name": plain(&field.name),
                "value": plain(&field.value),
                "hidden": matches!(field.kind, FieldKind::Hidden),
            })
        })
        .collect();
    json!({
        "name": item.name.to_string(),
        "notes": plain(&item.notes),
        "login": login,
        "card": card,
        "identity": identity,
        "sshKey": ssh_key,
        "fields": fields,
        "broken": item.broken,
    })
}

/// One `cipherVersion` of the item `item_id`, opened. Refused while the item's master password
/// re-prompt is unanswered, like its details.
pub fn open_version(unlocked: &Unlocked, item_id: &str, version: &str) -> Result<Value> {
    let current = find(unlocked, item_id)?;
    if current.reprompt && !unlocked.reprompt_ok.contains(item_id) {
        return Err(Failure::new("reprompt", "Enter the master password to see this item first."));
    }
    let version: Value = serde_json::from_str(version)?;
    let mut cipher = version.get("cipher").cloned().unwrap_or(Value::Null);
    cipher["id"] = Value::String(item_id.to_string());
    cipher["organizationId"] = current.organization_id.clone().map_or(Value::Null, Value::String);
    let wire: wire::Cipher = serde_json::from_value(wire::lowercase_keys(cipher))?;
    let item = unlocked
        .vault
        .open_cipher(&wire, &unlocked.user_key)?
        .ok_or_else(|| Failure::new("unsupported", "UwULock does not know this kind of item."))?;
    Ok(values(&item))
}

/// A rotation by UwULock (`POST /uwu/v1/accounts/rotate-keys`): Bitwarden's body, the extras key
/// wrapped for the new user key, and every personal version (`versions`, the list of
/// `GET /uwu/v1/versions`) re-encrypted for it.
pub fn rotate(
    unlocked: &Unlocked,
    password: &str,
    public_key: &str,
    holders: crate::account::Holders,
    versions: &str,
) -> Result<Value> {
    let (body, new_key) = crate::account::rotate_with_key(unlocked, password, public_key, holders)?;
    let list: Value = serde_json::from_str(versions)?;
    let mut again = Vec::new();
    for version in list.get("data").and_then(Value::as_array).into_iter().flatten() {
        let id = version.get("id").and_then(Value::as_str).unwrap_or_default();
        let cipher = version.get("cipher").cloned().unwrap_or(Value::Null);
        let cipher = extras::reencrypt_version(&cipher, &unlocked.user_key, &new_key).map_err(|error| {
            Failure::new("refused", format!("An earlier version of an item does not open ({error}); delete it first."))
        })?;
        again.push(json!({ "id": id, "cipher": cipher }));
    }
    let extras_key = match &unlocked.extras {
        Some(key) => {
            let (_, public) = crate::keys::public_key(public_key)?;
            Some(extras::wrap(key, &new_key, &public)?)
        }
        None => None,
    };
    Ok(json!({
        "rotation": body,
        "extrasKey": extras_key,
        "versions": again,
        "dropVersions": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uwulock_core::crypto::{EncString, PrivateKey};
    use uwulock_core::vault::{ItemKind, Login, Vault};
    use zeroize::Zeroizing;

    /// An account with one login, its password "old", under a fresh user key.
    fn unlocked() -> Unlocked {
        let user_key = SymmetricKey::generate();
        let mut item = Item::new(ItemKind::Login);
        item.name = Zeroizing::new("Bank".into());
        item.login = Some(Login { password: Some(Zeroizing::new("old".into())), ..Login::default() });
        let mut cipher = serde_json::to_value(item.seal(&user_key).unwrap()).unwrap();
        cipher["id"] = json!("c1");
        let sync = json!({
            "profile": { "id": "u1", "email": "nyu@example.com", "organizations": [] },
            "folders": [], "collections": [], "ciphers": [cipher],
        });
        let sync: wire::Sync = serde_json::from_value(wire::lowercase_keys(sync)).unwrap();
        let private = PrivateKey::generate().unwrap();
        Unlocked {
            email: "nyu@example.com".into(),
            kdf: uwulock_core::crypto::Kdf::Pbkdf2 { iterations: 5000 },
            protected_key: String::new(),
            private_key: Some(EncString::encrypt(&private.to_der().unwrap(), &user_key).to_string()),
            vault: Vault::open(&sync, &user_key).unwrap(),
            user_key,
            reprompt_ok: Default::default(),
            attachments: Default::default(),
            sends: Vec::new(),
            report: Vec::new(),
            extras: Some(SymmetricKey::generate()),
        }
    }

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x10\0\0\0\x10\x08\x06\0\0\0";

    #[test]
    fn an_icon_is_sealed_under_the_extras_key_and_opens_again() {
        let unlocked = unlocked();
        let sealed = seal_icon(&unlocked, "c1", PNG).unwrap();
        assert_eq!(sealed["keyType"], "extras");
        let data = sealed["data"].as_str().unwrap();
        assert_eq!(open_icon(&unlocked, "c1", data).unwrap(), PNG);
        assert!(seal_icon(&unlocked, "nope", PNG).is_err());
    }

    #[test]
    fn a_version_opens_with_the_key_of_its_item() {
        let unlocked = unlocked();
        let mut item = unlocked.vault.item("c1").unwrap().clone();
        item.login.as_mut().unwrap().password = Some(Zeroizing::new("older".into()));
        let cipher = serde_json::to_value(item.seal(&unlocked.user_key).unwrap()).unwrap();
        let version = json!({ "id": "v1", "cipherId": "c1", "cipher": cipher }).to_string();
        let opened = open_version(&unlocked, "c1", &version).unwrap();
        assert_eq!((opened["name"].as_str(), opened["login"]["password"].as_str()), (Some("Bank"), Some("older")));
    }
}
