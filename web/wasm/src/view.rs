//! What the page sees of the vault: a summary per item for the list, an item's details without
//! its secrets, and a secret on its own when somebody asks for it. The same shapes the desktop
//! app's page gets.

use crate::{Failure, Result, Unlocked};
use serde::Serialize;
use serde_json::{Value, json};
use uwulock_core::totp::Totp;
use uwulock_core::vault::{FieldKind, Item, ItemKind, Secret};
use zeroize::Zeroizing;

pub fn text(value: &Option<Secret>) -> Option<String> {
    value.as_ref().map(|s| s.to_string()).filter(|s| !s.trim().is_empty())
}

/// The host of an address, for the list: `github.com` from `https://github.com/login`.
pub fn host_of(uri: &str) -> Option<String> {
    let with_scheme = if uri.contains("://") { uri.to_string() } else { format!("https://{uri}") };
    url::Url::parse(&with_scheme).ok()?.host_str().map(|host| host.trim_start_matches("www.").to_string())
}

fn last_four(number: &str) -> String {
    let digits: String = number.chars().filter(char::is_ascii_digit).collect();
    digits[digits.len().saturating_sub(4)..].to_string()
}

/// The marker field of UwULock's own item types, stored as custom fields of a secure note so
/// that Bitwarden's apps show a note with fields (docs/wifi.md): `uwulock:type` = `wifi`.
pub const TYPE_MARKER: &str = "uwulock:type";

/// The value of a custom field with exactly this name, the first one.
fn field_text<'a>(item: &'a Item, name: &str) -> Option<&'a Secret> {
    item.fields.iter().find(|f| f.name.as_ref().is_some_and(|n| n.as_str() == name)).and_then(|f| f.value.as_ref())
}

/// Whether the item is a Wi-Fi network: a secure note with the marker field.
pub fn is_wifi(item: &Item) -> bool {
    item.kind == ItemKind::Note
        && item.fields.iter().any(|f| {
            f.kind == FieldKind::Text
                && f.name.as_ref().is_some_and(|n| n.as_str() == TYPE_MARKER)
                && f.value.as_ref().is_some_and(|v| v.trim().eq_ignore_ascii_case("wifi"))
        })
}

fn subtitle(item: &Item) -> Option<String> {
    if is_wifi(item) {
        return field_text(item, "SSID").map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    }
    match item.kind {
        ItemKind::Login => {
            item.login.as_ref().and_then(|l| text(&l.username).or_else(|| l.uris.first().and_then(|u| host_of(&u.uri))))
        }
        ItemKind::Card => item.card.as_ref().map(|c| {
            let brand = text(&c.brand).unwrap_or_default();
            match c.number.as_ref() {
                Some(n) if !n.is_empty() => format!("{brand} *{}", last_four(n)).trim().to_string(),
                _ => brand,
            }
        }),
        ItemKind::Identity => item.identity.as_ref().and_then(|i| {
            let name = [text(&i.first_name), text(&i.last_name)].into_iter().flatten().collect::<Vec<_>>().join(" ");
            (!name.is_empty()).then_some(name).or_else(|| text(&i.email))
        }),
        ItemKind::SshKey => item.ssh_key.as_ref().and_then(|s| text(&s.fingerprint)),
        ItemKind::Note => None,
    }
    .filter(|s| !s.is_empty())
}

/// The kind the page shows: one of the vault's, or one of UwULock's own on top of a note.
#[derive(Debug, Serialize, PartialEq)]
#[serde(untagged)]
pub enum ShownKind {
    Vault(ItemKind),
    Own(&'static str),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    id: String,
    kind: ShownKind,
    name: String,
    subtitle: Option<String>,
    host: Option<String>,
    favorite: bool,
    folder_id: Option<String>,
    organization_id: Option<String>,
    collection_ids: Vec<String>,
    deleted: bool,
    archived: bool,
    reprompt: bool,
    has_totp: bool,
    has_password: bool,
    has_username: bool,
    broken: bool,
    revision_date: Option<String>,
}

pub fn summary(item: &Item) -> ItemSummary {
    let login = item.login.as_ref();
    ItemSummary {
        id: item.id.clone(),
        kind: if is_wifi(item) { ShownKind::Own("wifi") } else { ShownKind::Vault(item.kind) },
        name: item.name.to_string(),
        subtitle: subtitle(item),
        host: login.and_then(|l| l.uris.iter().find_map(|u| host_of(&u.uri))),
        favorite: item.favorite,
        folder_id: item.folder_id.clone(),
        organization_id: item.organization_id.clone(),
        collection_ids: item.collection_ids.clone(),
        deleted: item.deleted,
        archived: item.archived_date.is_some(),
        reprompt: item.reprompt,
        has_totp: login.is_some_and(|l| l.totp.as_ref().is_some_and(|t| !t.is_empty())),
        has_password: login.is_some_and(|l| l.password.as_ref().is_some_and(|p| !p.is_empty())),
        has_username: login.is_some_and(|l| l.username.as_ref().is_some_and(|u| !u.is_empty())),
        broken: item.broken,
        revision_date: item.revision_date.clone(),
    }
}

pub fn find<'a>(unlocked: &'a Unlocked, id: &str) -> Result<&'a Item> {
    unlocked.vault.item(id).ok_or_else(|| Failure::new("not-found", "This item isn't in the vault any more."))
}

/// The identity fields, in the order they're shown, and whether each is sensitive.
pub const IDENTITY_FIELDS: &[(&str, bool)] = &[
    ("title", false),
    ("firstName", false),
    ("middleName", false),
    ("lastName", false),
    ("username", false),
    ("company", false),
    ("email", false),
    ("phone", false),
    ("address1", false),
    ("address2", false),
    ("address3", false),
    ("postalCode", false),
    ("city", false),
    ("state", false),
    ("country", false),
    ("ssn", true),
    ("passportNumber", true),
    ("licenseNumber", true),
];

pub fn identity_value<'a>(item: &'a Item, name: &str) -> Option<&'a Secret> {
    let i = item.identity.as_ref()?;
    match name {
        "title" => i.title.as_ref(),
        "firstName" => i.first_name.as_ref(),
        "middleName" => i.middle_name.as_ref(),
        "lastName" => i.last_name.as_ref(),
        "username" => i.username.as_ref(),
        "company" => i.company.as_ref(),
        "email" => i.email.as_ref(),
        "phone" => i.phone.as_ref(),
        "address1" => i.address1.as_ref(),
        "address2" => i.address2.as_ref(),
        "address3" => i.address3.as_ref(),
        "postalCode" => i.postal_code.as_ref(),
        "city" => i.city.as_ref(),
        "state" => i.state.as_ref(),
        "country" => i.country.as_ref(),
        "ssn" => i.ssn.as_ref(),
        "passportNumber" => i.passport_number.as_ref(),
        "licenseNumber" => i.license_number.as_ref(),
        _ => None,
    }
}

fn present(value: &Option<Secret>) -> bool {
    value.as_ref().is_some_and(|v| !v.is_empty())
}

/// An item's details, secrets left out: they come one by one through [`value_of`]. An item with
/// a master password re-prompt only says so until the prompt was answered.
pub fn detail(unlocked: &Unlocked, id: &str) -> Result<Value> {
    let item = find(unlocked, id)?;
    let summary = summary(item);
    if item.reprompt && !unlocked.reprompt_ok.contains(id) {
        return Ok(json!({ "summary": summary, "locked": true }));
    }
    let login = item.login.as_ref().map(|l| {
        json!({
            "username": text(&l.username),
            "hasPassword": present(&l.password),
            "hasTotp": present(&l.totp),
            "passwordRevisionDate": l.password_revision_date,
            "uris": l.uris.iter().map(|u| json!({
                "uri": u.uri.to_string(),
                "match": u.match_kind,
                "host": host_of(&u.uri),
                "openable": u.uri.starts_with("http://") || u.uri.starts_with("https://"),
            })).collect::<Vec<_>>(),
            "passkeys": l.passkey_count(),
            // Their details (site, user, created) for the item's passkey card; nothing secret.
            "passkeyList": unlocked
                .vault
                .item_key(item, &unlocked.user_key)
                .map(|key| uwulock_core::passkey::list(item, key))
                .unwrap_or_default(),
        })
    });
    let card = item.card.as_ref().map(|c| {
        json!({
            "cardholderName": text(&c.cardholder_name),
            "brand": text(&c.brand),
            "numberEnding": c.number.as_ref().filter(|n| !n.is_empty()).map(|n| last_four(n)),
            "expMonth": text(&c.exp_month),
            "expYear": text(&c.exp_year),
            "hasCode": present(&c.code),
        })
    });
    let identity = item.identity.as_ref().map(|_| {
        IDENTITY_FIELDS
            .iter()
            .filter_map(|(name, sensitive)| {
                let value = identity_value(item, name).filter(|v| !v.is_empty())?;
                Some(json!({
                    "name": name,
                    "sensitive": sensitive,
                    "value": if *sensitive { None } else { Some(value.to_string()) },
                }))
            })
            .collect::<Vec<_>>()
    });
    let ssh = item.ssh_key.as_ref().map(|s| {
        json!({
            "publicKey": text(&s.public_key),
            "fingerprint": text(&s.fingerprint),
            "hasPrivateKey": present(&s.private_key),
        })
    });
    let fields = item
        .fields
        .iter()
        .enumerate()
        .map(|(index, f)| {
            json!({
                "index": index,
                "name": text(&f.name),
                "kind": f.kind,
                "value": match f.kind {
                    FieldKind::Text | FieldKind::Boolean => text(&f.value),
                    _ => None,
                },
                "hasValue": present(&f.value),
            })
        })
        .collect::<Vec<_>>();
    let history = item
        .password_history
        .iter()
        .enumerate()
        .map(|(index, h)| json!({ "index": index, "lastUsed": h.last_used }))
        .collect::<Vec<_>>();
    Ok(json!({
        "summary": summary,
        "locked": false,
        "notes": text(&item.notes),
        "login": login,
        "card": card,
        "identity": identity,
        "sshKey": ssh,
        "fields": fields,
        "passwordHistory": history,
        "attachments": item.attachments,
        "creationDate": item.creation_date,
    }))
}

/// A single value of an item, by name: `password`, `username`, `notes`, `uri:<n>`,
/// `card-number`, `card-code`, `card-name`, `card-expiry`, `identity:<name>`, `ssh-private`,
/// `ssh-public`, `ssh-fingerprint`, `field:<n>`, `history:<n>`, `totp` (the current code),
/// `totp-next` (the code of the next period, shown in the last seconds of the current one).
pub fn value_of(unlocked: &Unlocked, id: &str, field: &str, now: u64) -> Result<Zeroizing<String>> {
    let item = find(unlocked, id)?;
    if item.reprompt && !unlocked.reprompt_ok.contains(id) {
        return Err(Failure::new("reprompt", "This item asks for the master password first."));
    }
    let missing = || Failure::new("not-found", "This item has no such value.");
    let clone = |v: Option<&Secret>| v.filter(|v| !v.is_empty()).cloned().ok_or_else(missing);
    let index =
        |prefix: &str| -> Result<usize> { field.strip_prefix(prefix).and_then(|n| n.parse().ok()).ok_or_else(missing) };
    let login = item.login.as_ref();
    let card = item.card.as_ref();
    let ssh = item.ssh_key.as_ref();
    match field {
        "username" => clone(login.and_then(|l| l.username.as_ref())),
        "password" => clone(login.and_then(|l| l.password.as_ref())),
        "totp" => {
            let secret = clone(login.and_then(|l| l.totp.as_ref()))?;
            Ok(Totp::parse(&secret)?.code_at(now).0)
        }
        "totp-next" => {
            let secret = clone(login.and_then(|l| l.totp.as_ref()))?;
            Ok(Totp::parse(&secret)?.next_code_at(now))
        }
        "notes" => clone(item.notes.as_ref()),
        "card-number" => clone(card.and_then(|c| c.number.as_ref())),
        "card-code" => clone(card.and_then(|c| c.code.as_ref())),
        "card-name" => clone(card.and_then(|c| c.cardholder_name.as_ref())),
        "card-expiry" => {
            let c = card.ok_or_else(missing)?;
            let month = text(&c.exp_month).unwrap_or_default();
            let year = text(&c.exp_year).unwrap_or_default();
            if month.is_empty() && year.is_empty() {
                return Err(missing());
            }
            Ok(Zeroizing::new(format!("{month:0>2}/{year}")))
        }
        "ssh-private" => clone(ssh.and_then(|s| s.private_key.as_ref())),
        "ssh-public" => clone(ssh.and_then(|s| s.public_key.as_ref())),
        "ssh-fingerprint" => clone(ssh.and_then(|s| s.fingerprint.as_ref())),
        _ if field.starts_with("uri:") => clone(login.and_then(|l| l.uris.get(index("uri:").ok()?)).map(|u| &u.uri)),
        _ if field.starts_with("field:") => clone(item.fields.get(index("field:")?).and_then(|f| f.value.as_ref())),
        _ if field.starts_with("history:") => clone(item.password_history.get(index("history:")?).map(|h| &h.password)),
        _ if field.starts_with("identity:") => clone(identity_value(item, field.trim_start_matches("identity:"))),
        _ => Err(missing()),
    }
}

/// The codes at one moment: `{code, remaining, period, next, showNext}`. `next` is the code of
/// the following period; `showNext` is true in its last
/// [`uwulock_core::totp::NEXT_CODE_WINDOW`] seconds, when the page shows it below ("Nächster").
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    code: String,
    remaining: u64,
    period: u64,
    next: String,
    show_next: bool,
}

impl From<uwulock_core::totp::Codes> for TotpCode {
    fn from(codes: uwulock_core::totp::Codes) -> Self {
        TotpCode {
            show_next: codes.show_next(),
            code: codes.code.to_string(),
            next: codes.next.to_string(),
            remaining: codes.remaining,
            period: codes.period,
        }
    }
}

/// The codes of an authenticator key that is no item's: the one in an entry Send, for the Send
/// page. Needs no unlocked vault.
pub fn totp_codes(secret: &str, now: u64) -> Result<TotpCode> {
    Ok(Totp::parse(secret)?.codes_at(now).into())
}

pub fn totp(unlocked: &Unlocked, id: &str, now: u64) -> Result<TotpCode> {
    let item = find(unlocked, id)?;
    if item.reprompt && !unlocked.reprompt_ok.contains(id) {
        return Err(Failure::new("reprompt", "This item asks for the master password first."));
    }
    let secret = item
        .login
        .as_ref()
        .and_then(|l| l.totp.as_ref())
        .ok_or_else(|| Failure::new("not-found", "No authenticator key."))?;
    Ok(Totp::parse(secret)?.codes_at(now).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uwulock_core::vault::Field;
    use zeroize::Zeroizing;

    fn field(name: &str, value: &str, kind: FieldKind) -> Field {
        Field {
            name: Some(Zeroizing::new(name.into())),
            value: Some(Zeroizing::new(value.into())),
            kind,
            linked_id: None,
        }
    }

    fn wifi() -> Item {
        let mut item = Item::new(ItemKind::Note);
        item.name = Zeroizing::new("Home".into());
        item.fields = vec![
            field(TYPE_MARKER, "wifi", FieldKind::Text),
            field("SSID", "uwu-net", FieldKind::Text),
            field("Password", "correct horse", FieldKind::Hidden),
            field("Security", "WPA2", FieldKind::Text),
        ];
        item
    }

    #[test]
    fn a_note_with_the_marker_is_a_wifi_network() {
        let item = wifi();
        let summary = serde_json::to_value(summary(&item)).unwrap();
        assert_eq!(summary["kind"], "wifi");
        assert_eq!(summary["subtitle"], "uwu-net");
        assert_eq!(summary["hasPassword"], false, "the list's password is a login's");
    }

    #[test]
    fn without_the_marker_or_as_another_kind_it_stays_what_it_is() {
        let mut note = wifi();
        note.fields.remove(0);
        assert_eq!(serde_json::to_value(summary(&note)).unwrap()["kind"], "note");

        let mut hidden_marker = wifi();
        hidden_marker.fields[0].kind = FieldKind::Hidden;
        assert!(!is_wifi(&hidden_marker), "the marker is a text field");

        let mut other = wifi();
        other.fields[0].value = Some(Zeroizing::new("router".into()));
        assert!(!is_wifi(&other));

        let mut login = Item::new(ItemKind::Login);
        login.fields = wifi().fields;
        assert_eq!(serde_json::to_value(summary(&login)).unwrap()["kind"], "login");
    }
}
