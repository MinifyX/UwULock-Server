//! The password check: which logins have a weak password, one that is used for more than one,
//! one that was in a breach, or an address without https.
//!
//! Everything is worked out in here. For the breaches, the page only gets the first five
//! characters of each password's SHA-1 to ask Have I Been Pwned about, and the first ten of its
//! Keccak-512 to ask XposedOrNot about (both through the server), and hands the answers back in;
//! which hash belongs to which item stays in here.

use crate::{Failure, Unlocked};
use serde::Serialize;
use sha1::{Digest, Sha1};
use sha3::Keccak512;
use std::collections::HashMap;
use uwulock_core::vault::ItemKind;

/// Below this many bits a password counts as weak: a random one of ten letters and digits has
/// about 60.
const WEAK_BITS: u32 = 50;

/// What the check keeps per item, between asking for the prefixes and hearing the answers.
pub struct Checked {
    id: String,
    prefix: String,
    suffix: String,
    /// The first ten hex digits of the password's Keccak-512, lower case: XposedOrNot's prefix.
    xon: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    id: String,
    name: String,
    subtitle: Option<String>,
    bits: u32,
    weak: bool,
    /// How many other items have the same password.
    reused: usize,
    unsecured: bool,
    /// The login's website (without `www.`), for the lists of breached sites and the
    /// change-password page.
    host: Option<String>,
    /// The first address of the login, to open when the site has no change-password page.
    uri: Option<String>,
    /// When the password was last changed: Bitwarden's `passwordRevisionDate`, else when the
    /// item was made.
    password_changed: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    findings: Vec<Finding>,
    /// Checked for breaches, by prefix: the page asks for each once.
    prefixes: Vec<String>,
    /// The same for XposedOrNot.
    xon_prefixes: Vec<String>,
    checked: usize,
}

pub fn report(unlocked: &mut Unlocked) -> Report {
    let mut by_password: HashMap<String, usize> = HashMap::new();
    let logins: Vec<_> = unlocked
        .vault
        .items
        .iter()
        .filter(|item| item.kind == ItemKind::Login && !item.deleted && item.archived_date.is_none())
        .filter_map(|item| {
            let password = item.login.as_ref()?.password.as_ref()?.to_string();
            (!password.is_empty()).then_some((item, password))
        })
        .collect();
    for (_, password) in &logins {
        *by_password.entry(password.clone()).or_default() += 1;
    }
    let mut checked = Vec::with_capacity(logins.len());
    let mut findings = Vec::new();
    for (item, password) in &logins {
        let bits = uwulock_core::generator::entropy_bits(password);
        let reused = by_password.get(password).copied().unwrap_or(1) - 1;
        let unsecured = item
            .login
            .as_ref()
            .is_some_and(|login| login.uris.iter().any(|uri| uri.uri.to_ascii_lowercase().starts_with("http://")));
        let hash: String = Sha1::digest(password.as_bytes()).iter().map(|byte| format!("{byte:02X}")).collect();
        let keccak: String =
            Keccak512::digest(password.as_bytes()).iter().take(5).map(|byte| format!("{byte:02x}")).collect();
        checked.push(Checked {
            id: item.id.clone(),
            prefix: hash[..5].to_string(),
            suffix: hash[5..].to_string(),
            xon: keccak,
        });
        let login = item.login.as_ref();
        findings.push(Finding {
            id: item.id.clone(),
            name: item.name.to_string(),
            subtitle: item.login.as_ref().and_then(|login| crate::view::text(&login.username)),
            bits,
            weak: bits < WEAK_BITS,
            reused,
            unsecured,
            host: login.and_then(|login| login.uris.iter().find_map(|uri| crate::view::host_of(&uri.uri))),
            uri: login
                .and_then(|login| {
                    login.uris.iter().map(|uri| uri.uri.trim()).find(|uri| {
                        let lower = uri.to_ascii_lowercase();
                        lower.starts_with("https://") || lower.starts_with("http://")
                    })
                })
                .map(str::to_string),
            password_changed: login
                .and_then(|login| login.password_revision_date.clone())
                .or_else(|| item.creation_date.clone()),
        });
    }
    let mut prefixes: Vec<String> = checked.iter().map(|checked| checked.prefix.clone()).collect();
    prefixes.sort();
    prefixes.dedup();
    let mut xon_prefixes: Vec<String> = checked.iter().map(|checked| checked.xon.clone()).collect();
    xon_prefixes.sort();
    xon_prefixes.dedup();
    let count = checked.len();
    unlocked.report = checked;
    Report { findings, prefixes, xon_prefixes, checked: count }
}

/// The items whose password XposedOrNot saw `count` times, by `prefix` (its answer for it).
pub fn xon_breaches(unlocked: &Unlocked, prefix: &str, count: u64) -> Vec<(String, u64)> {
    if count == 0 {
        return Vec::new();
    }
    unlocked
        .report
        .iter()
        .filter(|checked| checked.xon.eq_ignore_ascii_case(prefix))
        .map(|checked| (checked.id.clone(), count))
        .collect()
}

/// How often each item's password was in a breach, from HIBP's answer for `prefix`.
pub fn breaches(unlocked: &Unlocked, prefix: &str, range: &str) -> Vec<(String, u64)> {
    let counts: HashMap<&str, u64> = range
        .lines()
        .filter_map(|line| {
            let (suffix, count) = line.trim().split_once(':')?;
            Some((suffix, count.trim().parse().ok()?))
        })
        .collect();
    unlocked
        .report
        .iter()
        .filter(|checked| checked.prefix.eq_ignore_ascii_case(prefix))
        .filter_map(|checked| {
            let count = counts.get(checked.suffix.as_str()).copied().unwrap_or(0);
            (count > 0).then(|| (checked.id.clone(), count))
        })
        .collect()
}

/// The last report as the server keeps it (docs/uwu-api.md §15): its JSON under the extras key,
/// so it survives an official client's key rotation. The extras key has to be open.
pub fn seal(unlocked: &Unlocked, report: &str) -> crate::Result<String> {
    let key = crate::requests::extras_key(unlocked)?;
    Ok(uwulock_core::crypto::EncString::encrypt(report.as_bytes(), key).to_string())
}

/// A report [`seal`] made, as its JSON again.
pub fn open(unlocked: &Unlocked, data: &str) -> crate::Result<String> {
    let key = crate::requests::extras_key(unlocked)?;
    let sealed: uwulock_core::crypto::EncString = data.parse()?;
    let bytes = sealed.decrypt(key)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| Failure::new("report", "The saved report is not text."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uwulock_core::crypto::SymmetricKey;
    use uwulock_core::vault::{Item, Login, LoginUri, Vault};
    use uwulock_core::wire;
    use zeroize::Zeroizing;

    /// An account with two logins that share the password "password".
    fn unlocked() -> Unlocked {
        let user_key = SymmetricKey::generate();
        let ciphers: Vec<_> = ["c1", "c2"]
            .iter()
            .map(|id| {
                let mut item = Item::new(ItemKind::Login);
                item.name = Zeroizing::new(format!("Shop {id}"));
                item.login = Some(Login {
                    username: Some(Zeroizing::new("nyu@example.com".into())),
                    password: Some(Zeroizing::new("password".into())),
                    uris: vec![LoginUri {
                        uri: Zeroizing::new("https://www.shop.example.com/login".into()),
                        match_kind: None,
                        checksum: None,
                    }],
                    password_revision_date: Some("2024-01-01T00:00:00Z".into()),
                    ..Login::default()
                });
                let mut cipher = serde_json::to_value(item.seal(&user_key).unwrap()).unwrap();
                cipher["id"] = json!(id);
                cipher
            })
            .collect();
        let sync = json!({
            "profile": { "id": "u1", "email": "nyu@example.com", "organizations": [] },
            "folders": [], "collections": [], "ciphers": ciphers,
        });
        let sync: wire::Sync = serde_json::from_value(wire::lowercase_keys(sync)).unwrap();
        Unlocked {
            email: "nyu@example.com".into(),
            kdf: uwulock_core::crypto::Kdf::Pbkdf2 { iterations: 5000 },
            protected_key: String::new(),
            private_key: None,
            vault: Vault::open(&sync, &user_key).unwrap(),
            user_key,
            reprompt_ok: Default::default(),
            attachments: Default::default(),
            sends: Vec::new(),
            send_auth: Default::default(),
            report: Vec::new(),
            extras: Some(SymmetricKey::generate()),
        }
    }

    #[test]
    fn the_report_carries_what_the_breach_sources_need() {
        let mut unlocked = unlocked();
        let report = serde_json::to_value(report(&mut unlocked)).unwrap();
        // XposedOrNot's own example: "password" is a6818b8188… in the original Keccak-512.
        assert_eq!(report["xonPrefixes"], json!(["a6818b8188"]));
        assert_eq!(report["prefixes"], json!(["5BAA6"]));
        let finding = &report["findings"][0];
        assert_eq!(finding["host"], "shop.example.com");
        assert_eq!(finding["uri"], "https://www.shop.example.com/login");
        assert_eq!(finding["passwordChanged"], "2024-01-01T00:00:00Z");
        assert_eq!(finding["reused"], 1);
        let mut hits = xon_breaches(&unlocked, "A6818B8188", 7);
        hits.sort();
        assert_eq!(hits, vec![("c1".to_string(), 7), ("c2".to_string(), 7)]);
        assert!(xon_breaches(&unlocked, "a6818b8188", 0).is_empty());
        assert!(xon_breaches(&unlocked, "0000000000", 7).is_empty());
    }

    #[test]
    fn a_new_password_keeps_the_old_one_in_the_history() {
        let unlocked = unlocked();
        let sealed =
            crate::draft::seal_password(&unlocked, "c1", "n3w-Pa55word".into(), "2026-10-01T00:00:00Z").unwrap();
        let sealed = serde_json::to_value(sealed).unwrap();
        assert_eq!(sealed["passwordHistory"].as_array().map(Vec::len), Some(1), "{sealed}");
        assert_eq!(sealed["login"]["passwordRevisionDate"], "2026-10-01T00:00:00Z");
        assert!(crate::draft::seal_password(&unlocked, "c1", String::new(), "now").is_err());
        assert!(crate::draft::seal_password(&unlocked, "nope", "x".into(), "now").is_err());
    }
}
