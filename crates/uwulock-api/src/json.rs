//! What goes out, spelled the way Bitwarden's clients read it — and what comes in, tidied up
//! once, before it is stored.
//!
//! An item's JSON is written by hand into a string: the stored parts of it (the login, the
//! fields, the password history) are JSON already, tidied when they were saved, and go out as
//! they are, without being parsed again. A sync of a few thousand items is mostly copying.

use crate::errors::{ApiError, ApiResult};
use serde_json::{Map, Value, json};
use uwulock_store::{Cipher, Device, Folder, User, clock};

/// The key of an item's type object in Bitwarden's JSON, by type number.
pub const TYPE_KEYS: [(i64, &str); 8] = [
    (1, "login"),
    (2, "secureNote"),
    (3, "card"),
    (4, "identity"),
    (5, "sshKey"),
    (6, "bankAccount"),
    (7, "driversLicense"),
    (8, "passport"),
];

pub fn type_key(kind: i64) -> Option<&'static str> {
    TYPE_KEYS.iter().find(|(number, _)| *number == kind).map(|(_, key)| *key)
}

/// The encrypted texts of an item are at most this long. Bitwarden's limit for notes.
pub const MAX_NOTE: usize = 10_000;

fn push_str(out: &mut String, value: &str) {
    // Writing into a String cannot fail, and escaping a &str cannot either.
    out.push_str(&serde_json::to_string(value).expect("a string serializes"));
}

fn push_opt(out: &mut String, value: Option<&str>) {
    match value {
        Some(value) => push_str(out, value),
        None => out.push_str("null"),
    }
}

/// An item, as `cipherDetails`.
pub fn write_cipher(out: &mut String, cipher: &Cipher) {
    out.push_str("{\"object\":\"cipherDetails\",\"id\":");
    push_str(out, &cipher.id);
    out.push_str(",\"type\":");
    out.push_str(&cipher.kind.to_string());
    out.push_str(",\"creationDate\":");
    push_str(out, &cipher.created);
    out.push_str(",\"revisionDate\":");
    push_str(out, &cipher.revision);
    out.push_str(",\"deletedDate\":");
    push_opt(out, cipher.deleted.as_deref());
    out.push_str(",\"archivedDate\":");
    push_opt(out, cipher.archived.as_deref());
    out.push_str(",\"reprompt\":");
    out.push_str(if cipher.reprompt == 1 { "1" } else { "0" });
    out.push_str(",\"organizationId\":null,\"key\":");
    push_opt(out, cipher.key.as_deref());
    out.push_str(",\"attachments\":null,\"organizationUseTotp\":true,\"collectionIds\":[],\"name\":");
    push_str(out, &cipher.name);
    out.push_str(",\"notes\":");
    push_opt(out, cipher.notes.as_deref());
    out.push_str(",\"fields\":");
    out.push_str(cipher.fields.as_deref().unwrap_or("[]"));
    out.push_str(",\"passwordHistory\":");
    out.push_str(cipher.password_history.as_deref().unwrap_or("[]"));
    for (kind, key) in TYPE_KEYS {
        out.push_str(",\"");
        out.push_str(key);
        out.push_str("\":");
        out.push_str(if kind == cipher.kind { &cipher.data } else { "null" });
    }
    out.push_str(",\"folderId\":");
    push_opt(out, cipher.folder_id.as_deref());
    out.push_str(",\"favorite\":");
    out.push_str(if cipher.favorite { "true" } else { "false" });
    out.push_str(",\"edit\":true,\"viewPassword\":true,\"permissions\":{\"delete\":true,\"restore\":true}}");
}

pub fn cipher(cipher: &Cipher) -> String {
    let mut out = String::with_capacity(1024);
    write_cipher(&mut out, cipher);
    out
}

/// `{"data": [...], "object": "list", "continuationToken": null}` around items.
pub fn cipher_list<'a>(ciphers: impl IntoIterator<Item = &'a Cipher>) -> String {
    let mut out = String::from("{\"object\":\"list\",\"continuationToken\":null,\"data\":[");
    for (index, item) in ciphers.into_iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_cipher(&mut out, item);
    }
    out.push_str("]}");
    out
}

pub fn folder(folder: &Folder) -> Value {
    json!({ "id": folder.id, "name": folder.name, "revisionDate": folder.revision, "object": "folder" })
}

pub fn list(data: Vec<Value>) -> Value {
    json!({ "data": data, "object": "list", "continuationToken": null })
}

/// The account, as `profile`.
pub fn profile(user: &User, two_factor: bool) -> Value {
    json!({
        "_status": 0,
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "emailVerified": true,
        "premium": true,
        "premiumFromOrganization": false,
        "culture": if user.language == "de" { "de-DE" } else { "en-US" },
        "twoFactorEnabled": two_factor,
        "key": user.user_key,
        "privateKey": user.private_key,
        "accountKeys": account_keys(user),
        "securityStamp": user.security_stamp,
        "organizations": [],
        "organizationsNew": [],
        "providers": [],
        "providerOrganizations": [],
        "forcePasswordReset": false,
        "avatarColor": user.avatar_color,
        "usesKeyConnector": false,
        "creationDate": user.created,
        "object": "profile",
    })
}

fn account_keys(user: &User) -> Value {
    match &user.private_key {
        Some(private) => json!({
            "publicKeyEncryptionKeyPair": {
                "wrappedPrivateKey": private,
                "publicKey": user.public_key,
                "signedPublicKey": null,
                "object": "publicKeyEncryptionKeyPair",
            },
            "securityState": null,
            "signatureKeyPair": null,
            "object": "privateKeys",
        }),
        None => Value::Null,
    }
}

/// The KDF, in the shape of `userDecryption` in a sync.
pub fn kdf(user: &User) -> Value {
    json!({
        "kdfType": user.kdf.kind,
        "iterations": user.kdf.iterations,
        "memory": user.kdf.memory,
        "parallelism": user.kdf.parallelism,
    })
}

pub fn device(device: &Device) -> Value {
    json!({
        "id": device.id,
        "name": device.name,
        "type": device.kind,
        "identifier": device.id,
        "creationDate": device.created,
        "devicePendingAuthRequest": null,
        "isTrusted": false,
        "encryptedPublicKey": null,
        "encryptedUserKey": null,
        "object": "device",
    })
}

// ── What comes in ─────────────────────────────────────────

/// `Name` becomes `name`, all the way down: some older clients write their keys in PascalCase.
/// Only the first letter, so `credentialId` stays `credentialId`.
fn lower_first(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(key, _)| key != "response" && key != "Response")
                .map(|(key, value)| {
                    let mut chars = key.chars();
                    let key = match chars.next() {
                        _ if key.eq_ignore_ascii_case("ssn") => "ssn".to_string(),
                        Some(first) => first.to_lowercase().chain(chars).collect(),
                        None => key,
                    };
                    (key, lower_first(value))
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(lower_first).collect()),
        other => other,
    }
}

/// A time a client sent, in the database's format; the epoch for one that is not a time.
fn tidy_date(value: &Value) -> Value {
    match value {
        Value::String(text) => {
            Value::String(clock::parse(text).map_or_else(|| "1970-01-01T00:00:00.000000Z".to_string(), clock::format))
        }
        Value::Null => Value::Null,
        other => other.clone(),
    }
}

/// The object of an item's type, as it will be stored. Refused if it is missing.
pub fn type_data(kind: i64, value: Option<Value>) -> ApiResult<String> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Err(ApiError::bad("Data missing"));
    };
    let mut data = match lower_first(value) {
        Value::Object(map) => map,
        _ => return Err(ApiError::bad("Data missing")),
    };
    match kind {
        1 => {
            if let Some(Value::Array(uris)) = data.get_mut("uris") {
                for uri in uris.iter_mut() {
                    if let Some(Value::String(text)) = uri.get("match") {
                        let number = text.parse::<u8>().map(Value::from).unwrap_or(Value::Null);
                        uri["match"] = number;
                    }
                }
            }
            let first = data
                .get("uris")
                .and_then(Value::as_array)
                .and_then(|uris| uris.first())
                .and_then(|uri| uri.get("uri"))
                .cloned()
                .unwrap_or(Value::Null);
            data.insert("uri".into(), first);
            if let Some(date) = data.get("passwordRevisionDate") {
                let date = tidy_date(date);
                data.insert("passwordRevisionDate".into(), date);
            }
        }
        2 if !data.get("type").is_some_and(Value::is_number) => {
            data = Map::from_iter([("type".to_string(), Value::from(0))]);
        }
        _ => {}
    }
    Ok(Value::Object(data).to_string())
}

/// Custom fields as they will be stored: `type` always a number.
pub fn fields(value: Option<Value>) -> Option<String> {
    let Value::Array(items) = lower_first(value?) else { return None };
    let items: Vec<Value> = items
        .into_iter()
        .filter_map(|item| {
            let Value::Object(mut map) = item else { return None };
            let kind = match map.get("type") {
                Some(Value::Number(number)) => number.as_i64().unwrap_or(1),
                Some(Value::String(text)) => text.parse().unwrap_or(1),
                _ => 1,
            };
            map.insert("type".into(), Value::from(kind));
            Some(Value::Object(map))
        })
        .collect();
    Some(Value::Array(items).to_string())
}

/// The password history as it will be stored: entries with a password, each with a date.
pub fn password_history(value: Option<Value>) -> Option<String> {
    let Value::Array(items) = lower_first(value?) else { return None };
    let items: Vec<Value> = items
        .into_iter()
        .filter_map(|item| {
            let Value::Object(mut map) = item else { return None };
            if !map.get("password").is_some_and(Value::is_string) {
                return None;
            }
            let date = map.get("lastUsedDate").map_or(Value::String("1970-01-01T00:00:00.000000Z".into()), tidy_date);
            map.insert("lastUsedDate".into(), date);
            Some(Value::Object(map))
        })
        .collect();
    Some(Value::Array(items).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(kind: i64, data: &str) -> Cipher {
        Cipher {
            id: "c1".into(),
            user_id: "u1".into(),
            folder_id: None,
            kind,
            name: "2.n|n|n".into(),
            notes: None,
            key: None,
            data: data.into(),
            fields: None,
            password_history: None,
            favorite: true,
            reprompt: 0,
            created: "2026-09-25T10:00:00.000000Z".into(),
            revision: "2026-09-25T10:00:01.000000Z".into(),
            deleted: None,
            archived: None,
        }
    }

    #[test]
    fn an_item_has_every_key_the_clients_look_for() {
        let data = type_data(
            1,
            Some(json!({"Uris": [{"Uri": "2.u|u|u", "Match": "3", "response": null}], "Username": "2.a|a|a"})),
        )
        .unwrap();
        let value: Value = serde_json::from_str(&cipher(&stored(1, &data))).unwrap();
        assert_eq!(value["object"], "cipherDetails");
        assert_eq!(value["login"]["uri"], "2.u|u|u", "the first address, mirrored");
        assert_eq!(value["login"]["uris"][0]["match"], 3);
        assert!(value["login"]["uris"][0].get("response").is_none());
        assert_eq!(value["login"]["username"], "2.a|a|a");
        for key in ["secureNote", "card", "identity", "sshKey", "bankAccount", "driversLicense", "passport"] {
            assert!(value[key].is_null(), "{key}");
        }
        assert_eq!(value["fields"], json!([]));
        assert_eq!(value["passwordHistory"], json!([]));
        assert!(value["attachments"].is_null());
        assert_eq!(value["collectionIds"], json!([]));
        assert_eq!(value["favorite"], true);
        assert_eq!(value["reprompt"], 0);
        assert_eq!(value["permissions"]["delete"], true);
    }

    #[test]
    fn a_note_always_has_its_type() {
        assert_eq!(type_data(2, Some(json!({}))).unwrap(), r#"{"type":0}"#);
        assert_eq!(type_data(2, Some(json!({"type": 0}))).unwrap(), r#"{"type":0}"#);
        assert!(type_data(2, None).is_err());
        assert!(type_data(2, Some(Value::Null)).is_err());
    }

    #[test]
    fn fields_and_history_are_tidied() {
        let fields =
            fields(Some(json!([{"Name": "2.a", "Value": "2.b", "Type": "2"}, {"name": "x", "type": "odd"}]))).unwrap();
        let fields: Value = serde_json::from_str(&fields).unwrap();
        assert_eq!(fields[0], json!({"name": "2.a", "value": "2.b", "type": 2}));
        assert_eq!(fields[1]["type"], 1, "hidden, when unclear");

        let history = password_history(Some(json!([
            {"Password": "2.p", "LastUsedDate": "2026-09-25T12:00:00Z"},
            {"password": null, "lastUsedDate": "2026-09-25T12:00:00Z"},
            {"password": "2.q"},
        ])))
        .unwrap();
        let history: Value = serde_json::from_str(&history).unwrap();
        assert_eq!(history.as_array().unwrap().len(), 2, "no entry without a password");
        assert_eq!(history[0]["lastUsedDate"], "2026-09-25T12:00:00.000000Z");
        assert_eq!(history[1]["lastUsedDate"], "1970-01-01T00:00:00.000000Z");
    }

    #[test]
    fn a_passkey_keeps_its_spelling() {
        let data =
            type_data(1, Some(json!({"fido2Credentials": [{"credentialId": "c", "rpId": "example.com"}]}))).unwrap();
        let value: Value = serde_json::from_str(&data).unwrap();
        assert_eq!(value["fido2Credentials"][0]["credentialId"], "c");
        assert_eq!(value["fido2Credentials"][0]["rpId"], "example.com");
    }

    #[test]
    fn a_list_of_items_is_valid_json() {
        let a = stored(1, &type_data(1, Some(json!({"uris": []}))).unwrap());
        let b = stored(2, r#"{"type":0}"#);
        let value: Value = serde_json::from_str(&cipher_list([&a, &b])).unwrap();
        assert_eq!(value["data"].as_array().unwrap().len(), 2);
        assert_eq!(value["data"][1]["secureNote"]["type"], 0);
    }
}
