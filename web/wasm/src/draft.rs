//! Saving: what the editor sends back, laid over the item, and encrypted.
//!
//! A value the editor never had — a password nobody looked at, a card number, a hidden field —
//! comes as `null`, and then the one already there is kept; `""` clears it. So editing a name
//! does not need the password to pass through the page. (The same rules as the desktop app.)

use crate::view::{IDENTITY_FIELDS, find};
use crate::{Failure, Result, Unlocked};
use serde::Deserialize;
use uwulock_core::vault::{Field, FieldKind, Item, ItemKind, LoginUri, Secret};
use uwulock_core::wire::CipherRequest;
use zeroize::Zeroizing;

/// A value the editor may have left alone.
type Keep = Option<String>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Draft {
    kind: ItemKind,
    name: String,
    #[serde(default)]
    notes: Keep,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    reprompt: bool,
    #[serde(default)]
    folder_id: Option<String>,
    #[serde(default)]
    login: Option<LoginDraft>,
    #[serde(default)]
    card: Option<CardDraft>,
    /// The identity's fields by name; a name that isn't in here keeps its value.
    #[serde(default)]
    identity: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    ssh_key: Option<SshKeyDraft>,
    #[serde(default)]
    fields: Vec<FieldDraft>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginDraft {
    #[serde(default)]
    username: Keep,
    #[serde(default)]
    password: Keep,
    #[serde(default)]
    totp: Keep,
    #[serde(default)]
    uris: Vec<UriDraft>,
}

#[derive(Debug, Deserialize)]
struct UriDraft {
    uri: String,
    #[serde(default, rename = "match")]
    match_kind: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CardDraft {
    #[serde(default)]
    cardholder_name: Keep,
    #[serde(default)]
    brand: Keep,
    #[serde(default)]
    number: Keep,
    #[serde(default)]
    exp_month: Keep,
    #[serde(default)]
    exp_year: Keep,
    #[serde(default)]
    code: Keep,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshKeyDraft {
    #[serde(default)]
    private_key: Keep,
    #[serde(default)]
    public_key: Keep,
    #[serde(default)]
    fingerprint: Keep,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FieldDraft {
    #[serde(default)]
    name: Option<String>,
    kind: FieldKind,
    #[serde(default)]
    value: Keep,
    /// Which field of the item this one was before. Carries the value the editor never saw, and
    /// where a linked field points.
    #[serde(default)]
    from: Option<usize>,
}

fn secret_of(value: String) -> Option<Secret> {
    (!value.is_empty()).then(|| Zeroizing::new(value))
}

/// `null` keeps what is there, a value replaces it, `""` clears it.
fn apply_keep(field: &mut Option<Secret>, value: Keep) {
    if let Some(value) = value {
        *field = secret_of(value);
    }
}

fn apply(item: &mut Item, draft: Draft, now: &str) -> Result<()> {
    item.name = Zeroizing::new(draft.name.trim().to_string());
    apply_keep(&mut item.notes, draft.notes);
    item.favorite = draft.favorite;
    item.reprompt = draft.reprompt;
    item.folder_id = draft.folder_id.filter(|id| !id.is_empty());

    if let Some(login) = draft.login {
        let old_uris = item.login.as_ref().map(|l| l.uris.clone()).unwrap_or_default();
        let current = item.login.as_mut().ok_or_else(|| Failure::new("invalid", "This item isn't a login."))?;
        apply_keep(&mut current.username, login.username);
        apply_keep(&mut current.totp, login.totp);
        current.uris = login
            .uris
            .into_iter()
            .filter(|u| !u.uri.trim().is_empty())
            .map(|u| {
                let uri = u.uri.trim().to_string();
                LoginUri {
                    // An address that didn't change keeps the checksum the server made for it; a
                    // changed one has none any more.
                    checksum: old_uris.iter().find(|old| old.uri.as_str() == uri).and_then(|old| old.checksum.clone()),
                    uri: Zeroizing::new(uri),
                    match_kind: u.match_kind.filter(|m| *m <= 5),
                }
            })
            .collect();
        // Last, because it writes the history.
        if let Some(password) = login.password {
            item.set_password(Zeroizing::new(password), now);
        }
    }

    if let Some(card) = draft.card {
        let current = item.card.as_mut().ok_or_else(|| Failure::new("invalid", "This item isn't a card."))?;
        apply_keep(&mut current.cardholder_name, card.cardholder_name);
        apply_keep(&mut current.brand, card.brand);
        apply_keep(&mut current.number, card.number);
        apply_keep(&mut current.exp_month, card.exp_month);
        apply_keep(&mut current.exp_year, card.exp_year);
        apply_keep(&mut current.code, card.code);
    }

    if let Some(values) = draft.identity {
        let identity = item.identity.as_mut().ok_or_else(|| Failure::new("invalid", "This item isn't an identity."))?;
        for (name, _) in IDENTITY_FIELDS {
            let Some(value) = values.get(*name) else { continue };
            let value = secret_of(value.trim().to_string());
            match *name {
                "title" => identity.title = value,
                "firstName" => identity.first_name = value,
                "middleName" => identity.middle_name = value,
                "lastName" => identity.last_name = value,
                "username" => identity.username = value,
                "company" => identity.company = value,
                "email" => identity.email = value,
                "phone" => identity.phone = value,
                "address1" => identity.address1 = value,
                "address2" => identity.address2 = value,
                "address3" => identity.address3 = value,
                "postalCode" => identity.postal_code = value,
                "city" => identity.city = value,
                "state" => identity.state = value,
                "country" => identity.country = value,
                "ssn" => identity.ssn = value,
                "passportNumber" => identity.passport_number = value,
                "licenseNumber" => identity.license_number = value,
                _ => {}
            }
        }
    }

    if let Some(ssh) = draft.ssh_key {
        let current = item.ssh_key.as_mut().ok_or_else(|| Failure::new("invalid", "This item isn't an SSH key."))?;
        apply_keep(&mut current.private_key, ssh.private_key);
        apply_keep(&mut current.public_key, ssh.public_key);
        apply_keep(&mut current.fingerprint, ssh.fingerprint);
    }

    let old_fields = item.fields.clone();
    item.fields = draft
        .fields
        .into_iter()
        .map(|field| {
            let old = field.from.and_then(|index| old_fields.get(index));
            Field {
                name: field.name.and_then(secret_of),
                value: match field.value {
                    Some(value) => secret_of(value),
                    None => old.and_then(|old| old.value.clone()),
                },
                kind: field.kind,
                linked_id: old.filter(|_| field.kind == FieldKind::Linked).and_then(|old| old.linked_id),
            }
        })
        .collect();
    Ok(())
}

/// The draft over the item `id` (or a new one), encrypted for the server.
pub fn seal(unlocked: &Unlocked, id: &str, draft: Draft, now: &str) -> Result<CipherRequest> {
    let mut item = if id.is_empty() { Item::new(draft.kind) } else { find(unlocked, id)?.clone() };
    // An item behind the master password re-prompt is not changed before the prompt is answered:
    // the editor never had its values, and a save would turn the prompt off and keep them.
    if !id.is_empty() && item.reprompt && !unlocked.reprompt_ok.contains(id) {
        return Err(Failure::new("refused", "Enter your master password to open this item first."));
    }
    if item.kind != draft.kind {
        return Err(Failure::new("invalid", "An item keeps its kind."));
    }
    apply(&mut item, draft, now)?;
    item.can_save()?;
    let outer = unlocked.vault.outer_key(item.organization_id.as_deref(), &unlocked.user_key)?;
    Ok(item.seal(outer)?)
}
