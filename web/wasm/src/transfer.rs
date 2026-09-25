//! Import and export, in Bitwarden's formats: its unencrypted JSON export — everything, fields,
//! history and all — and its CSV, which knows logins and notes. What comes in is encrypted here,
//! before it goes to the server.

use crate::view::{IDENTITY_FIELDS, identity_value, text};
use crate::{Failure, Result, Unlocked};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use uwulock_core::crypto::EncString;
use uwulock_core::vault::{Field, FieldKind, Item, ItemKind, LoginUri, PasswordHistory, Secret};
use uwulock_core::wire::CipherRequest;
use zeroize::Zeroizing;

// ── Export ────────────────────────────────────────────────

pub fn export(unlocked: &Unlocked, format: &str) -> Result<String> {
    // The trash stays behind, as at Bitwarden.
    let items: Vec<&Item> = unlocked.vault.items.iter().filter(|item| !item.deleted && item.organization_id.is_none()).collect();
    if let Some(broken) = items.iter().find(|item| item.broken) {
        return Err(Failure::new(
            "refused",
            format!("The item “{}” does not open completely, so it cannot be exported.", broken.name.as_str()),
        ));
    }
    match format {
        "json" => export_json(unlocked, &items),
        "csv" => Ok(export_csv(unlocked, &items)),
        other => Err(Failure::new("invalid", format!("unknown export format {other}"))),
    }
}

fn secret(value: &Option<Secret>) -> Value {
    value.as_ref().map_or(Value::Null, |v| Value::String(v.to_string()))
}

fn export_json(unlocked: &Unlocked, items: &[&Item]) -> Result<String> {
    let folders: Vec<Value> = unlocked.vault.folders.iter().map(|f| json!({ "id": f.id, "name": f.name })).collect();
    let items: Vec<Value> = items
        .iter()
        .map(|item| {
            let mut out = json!({
                "id": item.id,
                "organizationId": null,
                "folderId": item.folder_id,
                "type": item.kind.to_wire(),
                "reprompt": u8::from(item.reprompt),
                "name": item.name.as_str(),
                "notes": secret(&item.notes),
                "favorite": item.favorite,
                "fields": item.fields.iter().map(|f| json!({
                    "name": secret(&f.name),
                    "value": secret(&f.value),
                    "type": f.kind.to_wire(),
                    "linkedId": f.linked_id,
                })).collect::<Vec<_>>(),
                "passwordHistory": if item.password_history.is_empty() { Value::Null } else {
                    Value::Array(item.password_history.iter().map(|h| json!({
                        "lastUsedDate": h.last_used,
                        "password": h.password.as_str(),
                    })).collect())
                },
                "revisionDate": item.revision_date,
                "creationDate": item.creation_date,
                "deletedDate": null,
                "collectionIds": null,
            });
            match item.kind {
                ItemKind::Login => {
                    let login = item.login.as_ref();
                    out["login"] = json!({
                        "fido2Credentials": login.and_then(|l| l.passkeys.clone()).unwrap_or_default(),
                        "uris": login.map(|l| l.uris.iter().map(|u| json!({ "match": u.match_kind, "uri": u.uri.as_str() })).collect::<Vec<_>>()).unwrap_or_default(),
                        "username": login.map_or(Value::Null, |l| secret(&l.username)),
                        "password": login.map_or(Value::Null, |l| secret(&l.password)),
                        "totp": login.map_or(Value::Null, |l| secret(&l.totp)),
                    });
                }
                ItemKind::Note => out["secureNote"] = json!({ "type": item.note_kind.unwrap_or(0) }),
                ItemKind::Card => {
                    let c = item.card.as_ref();
                    out["card"] = json!({
                        "cardholderName": c.map_or(Value::Null, |c| secret(&c.cardholder_name)),
                        "brand": c.map_or(Value::Null, |c| secret(&c.brand)),
                        "number": c.map_or(Value::Null, |c| secret(&c.number)),
                        "expMonth": c.map_or(Value::Null, |c| secret(&c.exp_month)),
                        "expYear": c.map_or(Value::Null, |c| secret(&c.exp_year)),
                        "code": c.map_or(Value::Null, |c| secret(&c.code)),
                    });
                }
                ItemKind::Identity => {
                    let mut identity = Map::new();
                    for (name, _) in IDENTITY_FIELDS {
                        identity.insert((*name).into(), identity_value(item, name).map_or(Value::Null, |v| Value::String(v.to_string())));
                    }
                    out["identity"] = Value::Object(identity);
                }
                ItemKind::SshKey => {
                    let s = item.ssh_key.as_ref();
                    out["sshKey"] = json!({
                        "privateKey": s.map_or(Value::Null, |s| secret(&s.private_key)),
                        "publicKey": s.map_or(Value::Null, |s| secret(&s.public_key)),
                        "keyFingerprint": s.map_or(Value::Null, |s| secret(&s.fingerprint)),
                    });
                }
            }
            out
        })
        .collect();
    Ok(serde_json::to_string_pretty(&json!({ "encrypted": false, "folders": folders, "items": items }))?)
}

fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) { format!("\"{}\"", value.replace('"', "\"\"")) } else { value.to_string() }
}

/// Bitwarden's CSV: logins and notes only, what the format has room for.
fn export_csv(unlocked: &Unlocked, items: &[&Item]) -> String {
    let folder_name: HashMap<&str, &str> = unlocked.vault.folders.iter().map(|f| (f.id.as_str(), f.name.as_str())).collect();
    let mut out = String::from("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n");
    for item in items.iter().filter(|item| matches!(item.kind, ItemKind::Login | ItemKind::Note)) {
        let login = item.login.as_ref();
        let fields = item
            .fields
            .iter()
            .map(|f| format!("{}: {}", text(&f.name).unwrap_or_default(), text(&f.value).unwrap_or_default()))
            .collect::<Vec<_>>()
            .join("\n");
        let cells = [
            item.folder_id.as_deref().and_then(|id| folder_name.get(id)).copied().unwrap_or_default().to_string(),
            if item.favorite { "1".into() } else { String::new() },
            if item.kind == ItemKind::Login { "login".into() } else { "note".into() },
            item.name.to_string(),
            text(&item.notes).unwrap_or_default(),
            fields,
            u8::from(item.reprompt).to_string(),
            login.map(|l| l.uris.iter().map(|u| u.uri.to_string()).collect::<Vec<_>>().join(",")).unwrap_or_default(),
            login.and_then(|l| text(&l.username)).unwrap_or_default(),
            login.and_then(|l| text(&l.password)).unwrap_or_default(),
            login.and_then(|l| text(&l.totp)).unwrap_or_default(),
        ];
        out.push_str(&cells.iter().map(|cell| csv_cell(cell)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

// ── Import ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Import {
    ciphers: Vec<CipherRequest>,
    folders: Vec<Value>,
    folder_relationships: Vec<Value>,
    /// How many items, for the page to say.
    count: usize,
}

fn some_text(value: Option<&Value>) -> Option<Secret> {
    match value? {
        Value::String(text) if !text.is_empty() => Some(Zeroizing::new(text.clone())),
        Value::Number(number) => Some(Zeroizing::new(number.to_string())),
        Value::Bool(flag) => Some(Zeroizing::new(flag.to_string())),
        _ => None,
    }
}

fn field_kind(value: Option<&Value>) -> FieldKind {
    match value.and_then(Value::as_u64) {
        Some(1) => FieldKind::Hidden,
        Some(2) => FieldKind::Boolean,
        Some(3) => FieldKind::Linked,
        _ => FieldKind::Text,
    }
}

pub fn import(unlocked: &Unlocked, format: &str, text: &str, now: &str) -> Result<Import> {
    let (items, folder_names, in_folder) = match format {
        "json" => read_json(text, now)?,
        "csv" => read_csv(text)?,
        other => return Err(Failure::new("invalid", format!("unknown import format {other}"))),
    };
    let key = &unlocked.user_key;
    let mut ciphers = Vec::with_capacity(items.len());
    for item in &items {
        item.can_save().map_err(|error| Failure::new("invalid", format!("“{}”: {error}", item.name.as_str())))?;
        ciphers.push(item.seal(key)?);
    }
    let folders = folder_names.iter().map(|name| json!({ "name": EncString::encrypt(name.as_bytes(), key).to_string() })).collect();
    let folder_relationships = in_folder.iter().map(|(item, folder)| json!({ "key": item, "value": folder })).collect();
    Ok(Import { count: ciphers.len(), ciphers, folders, folder_relationships })
}

type Read = (Vec<Item>, Vec<String>, Vec<(usize, usize)>);

fn read_json(text: &str, now: &str) -> Result<Read> {
    let value: Value = serde_json::from_str(text).map_err(|_| Failure::new("invalid", "This is not a Bitwarden JSON export."))?;
    if value.get("encrypted").and_then(Value::as_bool) == Some(true) {
        return Err(Failure::new("invalid", "This export is encrypted. Export again without a password (unencrypted JSON)."));
    }
    let folders: Vec<(String, String)> = value
        .get("folders")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|f| Some((f.get("id")?.as_str()?.to_string(), f.get("name")?.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let list = value.get("items").and_then(Value::as_array).ok_or_else(|| Failure::new("invalid", "This is not a Bitwarden JSON export."))?;
    let mut items = Vec::new();
    let mut in_folder = Vec::new();
    for entry in list {
        let kind = match entry.get("type").and_then(Value::as_u64) {
            Some(1) => ItemKind::Login,
            Some(2) => ItemKind::Note,
            Some(3) => ItemKind::Card,
            Some(4) => ItemKind::Identity,
            Some(5) => ItemKind::SshKey,
            _ => continue,
        };
        let mut item = Item::new(kind);
        item.name = some_text(entry.get("name")).unwrap_or_else(|| Zeroizing::new("?".into()));
        item.notes = some_text(entry.get("notes"));
        item.favorite = entry.get("favorite").and_then(Value::as_bool).unwrap_or(false);
        item.reprompt = entry.get("reprompt").and_then(Value::as_u64) == Some(1);
        if let Some(login) = entry.get("login").filter(|_| kind == ItemKind::Login) {
            let current = item.login.as_mut().expect("a login has one");
            current.username = some_text(login.get("username"));
            current.password = some_text(login.get("password"));
            current.totp = some_text(login.get("totp"));
            current.password_revision_date = login.get("passwordRevisionDate").and_then(Value::as_str).map(str::to_string);
            current.uris = login
                .get("uris")
                .and_then(Value::as_array)
                .map(|uris| {
                    uris.iter()
                        .filter_map(|u| {
                            Some(LoginUri {
                                uri: some_text(u.get("uri"))?,
                                match_kind: u.get("match").and_then(Value::as_u64).map(|m| m as u32).filter(|m| *m <= 5),
                                checksum: None,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            current.passkeys = login.get("fido2Credentials").and_then(Value::as_array).filter(|keys| !keys.is_empty()).cloned();
        }
        if let Some(card) = entry.get("card").filter(|_| kind == ItemKind::Card) {
            let current = item.card.as_mut().expect("a card has one");
            current.cardholder_name = some_text(card.get("cardholderName"));
            current.brand = some_text(card.get("brand"));
            current.number = some_text(card.get("number"));
            current.exp_month = some_text(card.get("expMonth"));
            current.exp_year = some_text(card.get("expYear"));
            current.code = some_text(card.get("code"));
        }
        if let Some(identity) = entry.get("identity").filter(|_| kind == ItemKind::Identity) {
            let current = item.identity.as_mut().expect("an identity has one");
            let get = |name: &str| some_text(identity.get(name));
            current.title = get("title");
            current.first_name = get("firstName");
            current.middle_name = get("middleName");
            current.last_name = get("lastName");
            current.username = get("username");
            current.company = get("company");
            current.email = get("email");
            current.phone = get("phone");
            current.address1 = get("address1");
            current.address2 = get("address2");
            current.address3 = get("address3");
            current.postal_code = get("postalCode");
            current.city = get("city");
            current.state = get("state");
            current.country = get("country");
            current.ssn = get("ssn");
            current.passport_number = get("passportNumber");
            current.license_number = get("licenseNumber");
        }
        if let Some(ssh) = entry.get("sshKey").filter(|_| kind == ItemKind::SshKey) {
            let current = item.ssh_key.as_mut().expect("an SSH key has one");
            current.private_key = some_text(ssh.get("privateKey"));
            current.public_key = some_text(ssh.get("publicKey"));
            current.fingerprint = some_text(ssh.get("keyFingerprint"));
        }
        item.fields = entry
            .get("fields")
            .and_then(Value::as_array)
            .map(|fields| {
                fields
                    .iter()
                    .map(|f| Field {
                        name: some_text(f.get("name")),
                        value: some_text(f.get("value")),
                        kind: field_kind(f.get("type")),
                        linked_id: f.get("linkedId").and_then(Value::as_u64).map(|n| n as u32),
                    })
                    .collect()
            })
            .unwrap_or_default();
        item.password_history = entry
            .get("passwordHistory")
            .and_then(Value::as_array)
            .map(|history| {
                history
                    .iter()
                    .filter_map(|h| {
                        Some(PasswordHistory {
                            password: some_text(h.get("password"))?,
                            last_used: Some(h.get("lastUsedDate").and_then(Value::as_str).unwrap_or(now).to_string()),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        if let Some(folder) = entry.get("folderId").and_then(Value::as_str)
            && let Some(index) = folders.iter().position(|(id, _)| id == folder)
        {
            in_folder.push((items.len(), index));
        }
        items.push(item);
    }
    Ok((items, folders.into_iter().map(|(_, name)| name).collect(), in_folder))
}

/// Rows of a CSV: quoted cells, doubled quotes, line breaks inside quotes.
fn csv_rows(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut cell = String::new();
    let mut quoted = false;
    let mut chars = text.trim_start_matches('\u{feff}').chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cell.push('"');
                chars.next();
            }
            ('"', true) => quoted = false,
            ('"', false) if cell.is_empty() => quoted = true,
            (',', false) => row.push(std::mem::take(&mut cell)),
            ('\r', false) => {}
            ('\n', false) => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            (c, _) => cell.push(c),
        }
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(cell);
        rows.push(row);
    }
    rows.retain(|row| row.iter().any(|cell| !cell.trim().is_empty()));
    rows
}

fn read_csv(text: &str) -> Result<Read> {
    let mut rows = csv_rows(text).into_iter();
    let header = rows.next().ok_or_else(|| Failure::new("invalid", "The file is empty."))?;
    let column = |name: &str| header.iter().position(|h| h.trim().eq_ignore_ascii_case(name));
    let name_column = column("name").ok_or_else(|| Failure::new("invalid", "This is not a Bitwarden CSV export (no name column)."))?;
    let get = |row: &[String], name: &str| column(name).and_then(|index| row.get(index)).map(|cell| cell.trim()).filter(|cell| !cell.is_empty()).map(str::to_string);
    let mut items = Vec::new();
    let mut folders: Vec<String> = Vec::new();
    let mut in_folder = Vec::new();
    for row in rows {
        let kind = match get(&row, "type").as_deref() {
            Some("note") => ItemKind::Note,
            _ => ItemKind::Login,
        };
        let mut item = Item::new(kind);
        item.name = Zeroizing::new(row.get(name_column).cloned().filter(|n| !n.trim().is_empty()).unwrap_or_else(|| "?".into()));
        item.notes = get(&row, "notes").map(Zeroizing::new);
        item.favorite = get(&row, "favorite").as_deref() == Some("1");
        item.reprompt = get(&row, "reprompt").as_deref() == Some("1");
        if let Some(login) = item.login.as_mut() {
            login.username = get(&row, "login_username").map(Zeroizing::new);
            login.password = get(&row, "login_password").map(Zeroizing::new);
            login.totp = get(&row, "login_totp").map(Zeroizing::new);
            login.uris = get(&row, "login_uri")
                .map(|uris| {
                    uris.split(',')
                        .map(str::trim)
                        .filter(|uri| !uri.is_empty())
                        .map(|uri| LoginUri { uri: Zeroizing::new(uri.to_string()), match_kind: None, checksum: None })
                        .collect()
                })
                .unwrap_or_default();
        }
        item.fields = get(&row, "fields")
            .map(|fields| {
                fields
                    .lines()
                    .filter_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        Some(Field {
                            name: Some(Zeroizing::new(name.trim().to_string())),
                            value: Some(Zeroizing::new(value.trim().to_string())).filter(|v| !v.is_empty()),
                            kind: FieldKind::Text,
                            linked_id: None,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        if let Some(folder) = get(&row, "folder") {
            let index = match folders.iter().position(|name| *name == folder) {
                Some(index) => index,
                None => {
                    folders.push(folder);
                    folders.len() - 1
                }
            };
            in_folder.push((items.len(), index));
        }
        items.push(item);
    }
    Ok((items, folders, in_folder))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_cells_with_commas_quotes_and_lines() {
        let rows = csv_rows("a,b,c\n\"one, two\",\"say \"\"hi\"\"\",\"line\nbreak\"\r\n");
        assert_eq!(rows, vec![vec!["a", "b", "c"], vec!["one, two", "say \"hi\"", "line\nbreak"]]);
        assert_eq!(csv_cell("say \"hi\", ok"), "\"say \"\"hi\"\", ok\"");
    }

    #[test]
    fn a_bitwarden_csv_reads() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   Arbeit,1,login,Router,,\"pin: 1234\",0,\"https://a.example.com,https://b.example.com\",admin,hunter2,\n\
                   ,,note,Notiz,geheim,,0,,,,\n";
        let (items, folders, in_folder) = read_csv(csv).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(folders, ["Arbeit"]);
        assert_eq!(in_folder, [(0, 0)]);
        let router = &items[0];
        assert!(router.favorite);
        assert_eq!(router.login.as_ref().unwrap().uris.len(), 2);
        assert_eq!(router.fields[0].value.as_ref().unwrap().as_str(), "1234");
        assert_eq!(items[1].kind, ItemKind::Note);
    }

    #[test]
    fn a_bitwarden_json_reads() {
        let json = r#"{"encrypted": false, "folders": [{"id": "f1", "name": "Privat"}], "items": [
            {"type": 1, "name": "Mail", "folderId": "f1", "favorite": true,
             "login": {"username": "nyu", "password": "pw", "uris": [{"uri": "https://mail.example.com", "match": 3}]},
             "fields": [{"name": "pin", "value": "42", "type": 1}],
             "passwordHistory": [{"password": "old", "lastUsedDate": "2026-01-01T00:00:00.000Z"}]},
            {"type": 3, "name": "Karte", "card": {"number": "4111111111111111", "code": "123"}},
            {"type": 9, "name": "Unknown"}]}"#;
        let (items, folders, in_folder) = read_json(json, "2026-09-25T00:00:00.000Z").unwrap();
        assert_eq!(items.len(), 2, "an unknown type is left out");
        assert_eq!(folders, ["Privat"]);
        assert_eq!(in_folder, [(0, 0)]);
        assert_eq!(items[0].login.as_ref().unwrap().uris[0].match_kind, Some(3));
        assert_eq!(items[0].fields[0].kind, FieldKind::Hidden);
        assert_eq!(items[0].password_history[0].password.as_str(), "old");
        assert_eq!(items[1].card.as_ref().unwrap().code.as_ref().unwrap().as_str(), "123");
        assert!(read_json(r#"{"encrypted": true, "items": []}"#, "").is_err());
    }
}
