//! The password check: which logins have a weak password, one that is used for more than one,
//! one that was in a breach, or an address without https.
//!
//! Everything is worked out in here. For the breaches, the page only gets the first five
//! characters of each password's SHA-1 to ask Have I Been Pwned about (through the server), and
//! hands the answers back in; which suffix belongs to which item stays in here.

use crate::{Failure, Unlocked};
use serde::Serialize;
use sha1::{Digest, Sha1};
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
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    findings: Vec<Finding>,
    /// Checked for breaches, by prefix: the page asks for each once.
    prefixes: Vec<String>,
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
        checked.push(Checked { id: item.id.clone(), prefix: hash[..5].to_string(), suffix: hash[5..].to_string() });
        findings.push(Finding {
            id: item.id.clone(),
            name: item.name.to_string(),
            subtitle: item.login.as_ref().and_then(|login| crate::view::text(&login.username)),
            bits,
            weak: bits < WEAK_BITS,
            reused,
            unsecured,
        });
    }
    let mut prefixes: Vec<String> = checked.iter().map(|checked| checked.prefix.clone()).collect();
    prefixes.sort();
    prefixes.dedup();
    let count = checked.len();
    unlocked.report = checked;
    Report { findings, prefixes, checked: count }
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
