//! An item's passkeys, as the item's details show them: which site, which user, since when — and
//! deleting one. Using them is the browser extension's job; the web vault only manages them.

use crate::view::find;
use crate::{Failure, Result, Unlocked};
use uwulock_core::passkey::{self, PasskeyInfo};
use uwulock_core::wire::CipherRequest;

fn unprompted(unlocked: &Unlocked, id: &str) -> Result<()> {
    let item = find(unlocked, id)?;
    if item.reprompt && !unlocked.reprompt_ok.contains(id) {
        return Err(Failure::new("reprompt", "This item asks for the master password first."));
    }
    Ok(())
}

pub fn list(unlocked: &Unlocked, id: &str) -> Result<Vec<PasskeyInfo>> {
    unprompted(unlocked, id)?;
    let item = find(unlocked, id)?;
    let key = unlocked.vault.item_key(item, &unlocked.user_key)?;
    Ok(passkey::list(item, key))
}

/// The item without the passkey at `index`, sealed for the server — only if that index still is
/// the passkey `name` (its credential id, or its fingerprint for one that can't be read): else a
/// `conflict`, and the page looks again.
pub fn delete(unlocked: &Unlocked, id: &str, index: usize, name: &str) -> Result<CipherRequest> {
    unprompted(unlocked, id)?;
    let mut item = find(unlocked, id)?.clone();
    let key = unlocked.vault.item_key(&item, &unlocked.user_key)?.clone();
    passkey::remove(&mut item, &key, index, Some(name)).map_err(|error| match error {
        uwulock_core::Error::Conflict => Failure::new("conflict", "This passkey changed in the meantime. Look again."),
        uwulock_core::Error::Refused(_) => Failure::new("not-found", "This item has no such passkey."),
        other => other.into(),
    })?;
    item.can_save()?;
    let outer = unlocked.vault.outer_key(item.organization_id.as_deref(), &unlocked.user_key)?;
    Ok(item.seal(outer)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uwulock_core::crypto::{Kdf, SymmetricKey};
    use uwulock_core::passkey::Passkey;
    use uwulock_core::vault::{Item, ItemKind, Login, Vault};
    use uwulock_core::wire;
    use zeroize::Zeroizing;

    fn passkey(rp: &str, user: &str) -> Passkey {
        Passkey::generate(
            rp,
            Some("Example"),
            Some(b"user-1"),
            Some(user),
            Some("Nyu"),
            true,
            "2026-09-28T12:00:00.000Z",
        )
        .unwrap()
    }

    /// An unlocked account with a login that has two passkeys under the user key.
    fn unlocked() -> (Unlocked, Vec<String>) {
        let user_key = SymmetricKey::generate();
        let sync: wire::Sync = serde_json::from_value(wire::lowercase_keys(json!({
            "profile": { "email": "nyu@example.com", "organizations": [] },
            "collections": [],
            "ciphers": [],
        })))
        .unwrap();
        let vault = Vault::open(&sync, &user_key).unwrap();
        let keys = [passkey("example.com", "nyu@example.com"), passkey("example.org", "nyu")];
        let mut item = Item::new(ItemKind::Login);
        item.id = "site".into();
        item.name = Zeroizing::new("Site".into());
        item.login =
            Some(Login { passkeys: Some(keys.iter().map(|k| k.seal(&user_key)).collect()), ..Login::default() });
        let mut unlocked = Unlocked {
            email: "nyu@example.com".into(),
            kdf: Kdf::Pbkdf2 { iterations: 600_000 },
            protected_key: String::new(),
            user_key,
            private_key: None,
            vault,
            reprompt_ok: Default::default(),
            attachments: Default::default(),
            sends: Vec::new(),
            send_auth: Default::default(),
            report: Vec::new(),
            extras: None,
        };
        unlocked.vault.items.push(item);
        (unlocked, keys.iter().map(|k| k.credential_id.clone()).collect())
    }

    #[test]
    fn passkeys_are_listed_and_deleted_one_by_one() {
        let (mut unlocked, ids) = unlocked();
        let listed = list(&unlocked, "site").unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[1].rp_id, "example.org");
        assert_eq!(listed[0].user_name.as_deref(), Some("nyu@example.com"));
        let detail = crate::view::detail(&unlocked, "site").unwrap();
        assert_eq!(detail["login"]["passkeyList"][1]["rpId"], "example.org");

        // A passkey that moved in the meantime is not deleted.
        assert_eq!(delete(&unlocked, "site", 0, &ids[1]).unwrap_err().kind, "conflict");
        assert_eq!(delete(&unlocked, "site", 5, &ids[0]).unwrap_err().kind, "not-found");
        // The fingerprint names one too: what an unreadable passkey is deleted by.
        let by_fingerprint = delete(&unlocked, "site", 1, &listed[1].fingerprint).unwrap();
        let rest = serde_json::to_value(by_fingerprint).unwrap();
        assert_eq!(rest["login"]["fido2Credentials"].as_array().unwrap().len(), 1);
        let sealed = serde_json::to_value(delete(&unlocked, "site", 0, &ids[0]).unwrap()).unwrap();
        let left = sealed["login"]["fido2Credentials"].as_array().unwrap();
        assert_eq!(left.len(), 1);

        unlocked.vault.items[0].reprompt = true;
        assert_eq!(list(&unlocked, "site").unwrap_err().kind, "reprompt");
    }

    #[test]
    fn a_duplicate_keeps_the_passkeys() {
        let (unlocked, _) = unlocked();
        let draft = serde_json::from_value(json!({ "kind": "login", "name": "Site (Kopie)", "fields": [] })).unwrap();
        let sealed = serde_json::to_value(
            crate::draft::seal_clone(&unlocked, "site", draft, "2026-10-02T12:00:00.000Z").unwrap(),
        )
        .unwrap();
        assert_eq!(sealed["login"]["fido2Credentials"].as_array().unwrap().len(), 2);
        assert!(sealed.get("id").is_none_or(|id| id.is_null() || id == ""));
    }
}
