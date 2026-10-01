//! The suite vault (docs/uwu-api.md §6): UwUSSH's and UwURDP's records, opened and written by the
//! web vault.
//!
//! The spaces' keys and the records as the server sent them stay in here. The page gets each
//! record's JSON (every field it has, also those it doesn't know), never a secret unless it asks
//! for that one (`suiteSecret`), and hands back the edited JSON to be sealed. Sealing follows the
//! apps' rules through `uwulock_core::suite`: a clock after the record's and not before the wall
//! clock, `baseSeq` = the record's `seq`, a fresh nonce, tombstones with an empty payload, and
//! `manifest` records never written. Records of kinds this build doesn't know are kept as they
//! came and never shown.

use crate::{Failure, Result, Unlocked};
use serde::Serialize;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use uwulock_core::suite::{self, Envelope, Hlc, KIND_MANIFEST, KIND_SECRET, Payload, SpaceVault, SuiteSpace, openssh};
use uwulock_core::suite::{Pushed, Space};

/// One space, open: its key and every record the server sent, by id.
struct Opened {
    vault: SpaceVault,
    records: BTreeMap<String, Envelope>,
}

thread_local! {
    static SPACES: RefCell<HashMap<Space, Opened>> = RefCell::new(HashMap::new());
}

/// Forget every space: the vault was locked or another account unlocked.
pub fn forget_all() {
    SPACES.with(|cell| cell.borrow_mut().clear());
}

fn space_of(name: &str) -> Result<Space> {
    name.parse::<Space>().map_err(Failure::from)
}

fn with_space<T>(space: Space, work: impl FnOnce(&mut Opened) -> Result<T>) -> Result<T> {
    SPACES.with(|cell| match cell.borrow_mut().get_mut(&space) {
        Some(opened) => work(opened),
        None => Err(Failure::new("suite-closed", format!("The space {space} is not open."))),
    })
}

/// A space as `GET /uwu/v1/suite/spaces` lists it, opened with the extras key. The records
/// already read stay when it is the same space (same id); after a rekey they go.
pub fn open_space(unlocked: &Unlocked, found: &str) -> Result<Value> {
    let found: SuiteSpace = serde_json::from_str(found)?;
    let extras = crate::requests::extras_key(unlocked)?;
    let vault = SpaceVault::open_space(&found, extras)?;
    let (space, id) = (vault.space, vault.id);
    SPACES.with(|cell| {
        let mut spaces = cell.borrow_mut();
        let keep = spaces.get(&space).is_some_and(|opened| opened.vault.id == id);
        if keep {
            spaces.get_mut(&space).expect("checked").vault = vault;
        } else {
            spaces.insert(space, Opened { vault, records: BTreeMap::new() });
        }
    });
    Ok(json!({ "space": space.as_str(), "id": id.to_string() }))
}

/// A new space: a fresh id and key, kept open here, and the body of
/// `PUT /uwu/v1/suite/spaces/{space}`.
pub fn create_space(unlocked: &Unlocked, space: &str) -> Result<Value> {
    let space = space_of(space)?;
    let extras = crate::requests::extras_key(unlocked)?;
    let (vault, request) = SpaceVault::create(space, extras);
    SPACES.with(|cell| cell.borrow_mut().insert(space, Opened { vault, records: BTreeMap::new() }));
    Ok(serde_json::to_value(request)?)
}

/// Drop what was read of a space, to pull it again from 0 (`reset`, or after a rekey).
pub fn forget_records(space: &str) -> Result<()> {
    with_space(space_of(space)?, |opened| {
        opened.records.clear();
        Ok(())
    })
}

/// Take records from a pull (or a push's conflicts): the server's copy wins over an older one.
pub fn merge(space: &str, envelopes: &str) -> Result<()> {
    let envelopes: Vec<Envelope> = serde_json::from_str(envelopes)?;
    with_space(space_of(space)?, |opened| {
        for envelope in envelopes {
            take(&mut opened.records, envelope);
        }
        Ok(())
    })
}

fn take(records: &mut BTreeMap<String, Envelope>, envelope: Envelope) {
    // Ids as the server writes them (lower case, hyphens). Another spelling of a UUID opens
    // with the same AAD, so a server could otherwise show one record twice, under an id that
    // goes into a link to the app, and make pointers at the record miss it.
    if !envelope.head().is_ok_and(|head| head.id.hyphenated().to_string() == envelope.id) {
        return;
    }
    let newer = match records.get(&envelope.id) {
        Some(known) => envelope.seq.unwrap_or(0) > known.seq.unwrap_or(0),
        None => true,
    };
    if newer {
        records.insert(envelope.id.clone(), envelope);
    }
}

/// What a push did: the accepted records are kept with their new `seq`, the server's copies of
/// the conflicting ones replace ours. Answers the ids that conflicted.
pub fn apply_push(space: &str, pushed: &str, answer: &str) -> Result<Vec<String>> {
    let pushed: Vec<Envelope> = serde_json::from_str(pushed)?;
    let answer: Pushed = serde_json::from_str(answer)?;
    with_space(space_of(space)?, |opened| {
        let seqs: HashMap<&str, u64> = answer.accepted.iter().map(|a| (a.id.as_str(), a.seq)).collect();
        for mut envelope in pushed {
            if let Some(seq) = seqs.get(envelope.id.as_str()) {
                envelope.seq = Some(*seq);
                take(&mut opened.records, envelope);
            }
        }
        let conflicts = answer.conflicts.iter().map(|c| c.id.clone()).collect();
        for envelope in answer.conflicts {
            take(&mut opened.records, envelope);
        }
        Ok(conflicts)
    })
}

/// A record as the page sees it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Shown {
    id: String,
    kind: String,
    seq: u64,
    updated_at: Hlc,
    /// The JSON with every field; `None` for a secret, which the page asks for on its own.
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<Value>,
}

/// The records of a space the page shows: no tombstones, no manifests, no kinds this build
/// doesn't know (they stay as they came). `unreadable` counts those that don't open.
pub fn records(space: &str) -> Result<Value> {
    with_space(space_of(space)?, |opened| {
        let mut shown = Vec::new();
        let mut unreadable = 0;
        for envelope in opened.records.values() {
            if envelope.deleted
                || envelope.kind == KIND_MANIFEST
                || opened.vault.space.kind_discriminant(&envelope.kind).is_none()
            {
                continue;
            }
            let Ok(record) = opened.vault.open_record(envelope) else {
                unreadable += 1;
                continue;
            };
            let payload = match record.payload {
                _ if envelope.kind == KIND_SECRET => None,
                Some(Payload::Json(value)) if value.is_object() => Some(value),
                _ => {
                    unreadable += 1;
                    continue;
                }
            };
            shown.push(Shown {
                id: envelope.id.clone(),
                kind: envelope.kind.clone(),
                seq: envelope.seq.unwrap_or(0),
                updated_at: envelope.updated_at,
                payload,
            });
        }
        Ok(json!({ "records": shown, "unreadable": unreadable }))
    })
}

/// One `secret`'s content: `{"text": …}`, or `{"bytes": <base64>}` when it isn't UTF-8.
pub fn secret(space: &str, id: &str) -> Result<Value> {
    with_space(space_of(space)?, |opened| {
        let envelope = opened
            .records
            .get(id)
            .filter(|e| e.kind == KIND_SECRET && !e.deleted)
            .ok_or_else(|| Failure::new("not-found", "There is no such secret."))?;
        let record = opened.vault.open_record(envelope)?;
        Ok(serde_json::to_value(record.payload)?)
    })
}

/// `{"json": {...}}` for every kind but `secret`, `{"text": "…"}` for a secret.
fn payload(text: &str) -> Result<Payload> {
    Ok(serde_json::from_str(text)?)
}

/// A new record of `kind`.
pub fn seal_new(space: &str, kind: &str, payload_json: &str, now_ms: u64, device: u32) -> Result<Envelope> {
    let payload = payload(payload_json)?;
    with_space(space_of(space)?, |opened| Ok(opened.vault.seal_new(kind, &payload, now_ms, device)?))
}

/// An edit of the record `id` as it was read last.
pub fn seal_edit(space: &str, id: &str, payload_json: &str, now_ms: u64, device: u32) -> Result<Envelope> {
    let payload = payload(payload_json)?;
    with_space(space_of(space)?, |opened| {
        let head = known(opened, id)?.head()?;
        Ok(opened.vault.seal_edit(&head, &payload, now_ms, device)?)
    })
}

/// The tombstone of the record `id`.
pub fn seal_tombstone(space: &str, id: &str, now_ms: u64, device: u32) -> Result<Envelope> {
    with_space(space_of(space)?, |opened| {
        let head = known(opened, id)?.head()?;
        Ok(opened.vault.seal_tombstone(&head, now_ms, device)?)
    })
}

/// The record `id`, checked against the space key first: an edit or tombstone takes its clock and
/// `seq` from it, so a record the server made up or changed must never be the base of one we seal
/// (a forged clock near the end would otherwise be signed with the real key and spread).
fn known<'a>(opened: &'a Opened, id: &str) -> Result<&'a Envelope> {
    let envelope = opened.records.get(id).ok_or_else(|| Failure::new("not-found", "There is no such record."))?;
    if opened.vault.open(envelope).is_err() {
        return Err(Failure::new("broken", "This record can't be opened, so it can't be changed or deleted here."));
    }
    Ok(envelope)
}

/// The body of a push of `envelopes`, for the space as it is open.
pub fn push_request(space: &str, envelopes: &str) -> Result<Value> {
    let envelopes: Vec<Envelope> = serde_json::from_str(envelopes)?;
    if envelopes.len() > suite::PAGE {
        return Err(Failure::new("refused", format!("At most {} records go in one push.", suite::PAGE)));
    }
    with_space(space_of(space)?, |opened| Ok(serde_json::to_value(opened.vault.push_request(envelopes))?))
}

// ── SSH keys ──────────────────────────────────────────────

pub fn generate_key(comment: &str, passphrase: &str) -> Result<Value> {
    let key = openssh::generate_ed25519(comment, Some(passphrase))?;
    Ok(serde_json::to_value(&key)?)
}

pub fn inspect_private_key(text: &str) -> Result<Value> {
    Ok(serde_json::to_value(openssh::inspect_private_key(text)?)?)
}

pub fn inspect_public_key(line: &str) -> Result<Value> {
    Ok(serde_json::to_value(openssh::inspect_public_key(line)?)?)
}

pub fn passphrase_opens(text: &str, passphrase: &str) -> Result<bool> {
    Ok(openssh::passphrase_opens(text, passphrase)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uwulock_core::crypto::SymmetricKey;
    use uwulock_core::suite::{RecordHead, SuiteSpace};

    fn unlocked() -> Unlocked {
        let user_key = SymmetricKey::generate();
        Unlocked {
            email: "nyu@example.com".into(),
            kdf: uwulock_core::crypto::Kdf::Pbkdf2 { iterations: 5000 },
            protected_key: String::new(),
            private_key: None,
            vault: Default::default(),
            user_key,
            reprompt_ok: Default::default(),
            attachments: Default::default(),
            sends: Vec::new(),
            send_auth: Default::default(),
            report: Vec::new(),
            extras: Some(SymmetricKey::generate()),
        }
    }

    /// The server's side of a push: every record taken, with the next seq.
    fn accept(envelopes: &[Envelope], seq: &mut u64) -> (String, String) {
        let accepted: Vec<Value> = envelopes
            .iter()
            .map(|e| {
                *seq += 1;
                json!({ "id": e.id, "seq": *seq })
            })
            .collect();
        (
            serde_json::to_string(envelopes).unwrap(),
            json!({ "object": "suitePush", "accepted": accepted, "conflicts": [], "cursor": *seq }).to_string(),
        )
    }

    #[test]
    fn a_space_is_made_written_and_read_back_by_the_core() {
        forget_all();
        let unlocked = unlocked();
        let request = create_space(&unlocked, "ssh").unwrap();
        let space_id = request["id"].as_str().unwrap().to_string();
        let mut seq = 0;

        let secret = seal_new("ssh", "secret", r#"{"text":"hunter2"}"#, 1_790_000_000_000, 7).unwrap();
        let identity = json!({ "json": {
            "label": "Nyu", "username": "nyu", "auth_type": "password", "key_id": null,
            "password_secret_id": secret.id, "future_field": [1, 2]
        }});
        let identity = seal_new("ssh", "identity", &identity.to_string(), 1_790_000_000_000, 7).unwrap();
        assert_eq!(identity.base_seq, 0);
        let pushed = vec![secret.clone(), identity.clone()];
        let body = push_request("ssh", &serde_json::to_string(&pushed).unwrap()).unwrap();
        assert_eq!((body["schema"].as_u64(), body["spaceId"].as_str()), (Some(2), Some(space_id.as_str())));
        let (pushed, answer) = accept(&pushed, &mut seq);
        assert!(apply_push("ssh", &pushed, &answer).unwrap().is_empty());

        let shown = records("ssh").unwrap();
        let list = shown["records"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        let secret_shown = list.iter().find(|r| r["kind"] == "secret").unwrap();
        assert!(secret_shown.get("payload").is_none(), "a secret only when asked for");
        assert_eq!(super::secret("ssh", &secret.id).unwrap(), json!({ "text": "hunter2" }));

        // An edit keeps the field this build doesn't know; its clock is after the record's.
        let shown_identity = list.iter().find(|r| r["kind"] == "identity").unwrap();
        let mut edited = shown_identity["payload"].clone();
        edited["username"] = json!("nyu2");
        let edit =
            seal_edit("ssh", &identity.id, &json!({ "json": edited }).to_string(), 1_789_000_000_000, 9).unwrap();
        assert_eq!(edit.base_seq, 2);
        assert!(edit.updated_at > identity.updated_at, "never before the record, even with a clock behind");
        assert_eq!(edit.updated_at.device, 9);

        // The core opens it with the space's key as the apps would.
        let extras = unlocked.extras.as_ref().unwrap();
        let listed = SuiteSpace {
            space: "ssh".into(),
            id: space_id.clone(),
            key: request["key"].as_str().unwrap().into(),
            ..Default::default()
        };
        let core = SpaceVault::open_space(&listed, extras).unwrap();
        let opened = core.open_record(&edit).unwrap();
        let Some(Payload::Json(value)) = opened.payload else { panic!("JSON") };
        assert_eq!(value["username"], "nyu2");
        assert_eq!(value["future_field"], json!([1, 2]));

        // A tombstone: deleted, nothing inside.
        let (pushed, answer) = accept(&[edit], &mut seq);
        apply_push("ssh", &pushed, &answer).unwrap();
        let gone = seal_tombstone("ssh", &identity.id, 1_790_000_000_000, 9).unwrap();
        assert!(gone.deleted);
        assert_eq!(gone.base_seq, 3);
        assert!(core.open(&gone).unwrap().is_empty());
        let (pushed, answer) = accept(&[gone], &mut seq);
        apply_push("ssh", &pushed, &answer).unwrap();
        assert_eq!(records("ssh").unwrap()["records"].as_array().unwrap().len(), 1);

        // Manifests are the apps' own.
        assert!(seal_new("ssh", "manifest", r#"{"bytes":""}"#, 1, 1).is_err());
        assert!(seal_new("ssh", "host", r#"{"text":"not json"}"#, 1, 1).is_err());
    }

    #[test]
    fn records_of_the_apps_and_unknown_kinds_pass_through() {
        forget_all();
        let unlocked = unlocked();
        let request = create_space(&unlocked, "rdp").unwrap();
        let extras = unlocked.extras.as_ref().unwrap();
        let listed = SuiteSpace {
            space: "rdp".into(),
            id: request["id"].as_str().unwrap().into(),
            key: request["key"].as_str().unwrap().into(),
            ..Default::default()
        };
        // What UwURDP wrote, sealed by the core as the app does.
        let app = SpaceVault::open_space(&listed, extras).unwrap();
        let host = json!({ "name": "Desk", "address": "198.51.100.7", "port": 3389, "workspace": "private",
            "position": 0, "group_id": null, "identity_id": null, "rdp": { "display": "fit", "newer": true } });
        let mut host = app.seal_new("host", &Payload::Json(host), 1_790_000_000_000, 3).unwrap();
        host.seq = Some(5);
        let mut manifest = app
            .seal_new("secret", &Payload::Text("x".into()), 1_790_000_000_000, 3)
            .map(|mut e| {
                e.kind = "manifest".into();
                e
            })
            .unwrap();
        manifest.seq = Some(6);
        let mut unknown = host.clone();
        unknown.id = "9b2d0c1e-0000-4000-8000-000000000077".into();
        unknown.kind = "hologram".into();
        unknown.seq = Some(7);
        let mut broken = host.clone();
        broken.id = "9b2d0c1e-0000-4000-8000-000000000078".into();
        broken.seq = Some(8);
        merge("rdp", &serde_json::to_string(&[host.clone(), manifest, unknown, broken]).unwrap()).unwrap();

        let shown = records("rdp").unwrap();
        assert_eq!(shown["unreadable"], 1, "sealed for another id");
        let list = shown["records"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["payload"]["rdp"]["newer"], true);

        // A record that doesn't open is never the base of something sealed with the real key: its
        // clock and seq could be the server's.
        let broken_id = "9b2d0c1e-0000-4000-8000-000000000078";
        assert!(seal_edit("rdp", broken_id, r#"{"json":{"name":"x"}}"#, 1_790_000_000_001, 4).is_err());
        assert!(seal_tombstone("rdp", broken_id, 1_790_000_000_001, 4).is_err());

        // Another spelling of a known id is not taken: one record, one id.
        for spelled in [
            host.id.to_uppercase(),
            host.id.replace('-', ""),
            format!("{{{}}}", host.id),
            format!("urn:uuid:{}", host.id),
        ] {
            let mut twin = host.clone();
            twin.id = spelled;
            twin.seq = Some(50);
            merge("rdp", &serde_json::to_string(&[twin]).unwrap()).unwrap();
        }
        assert_eq!(records("rdp").unwrap()["records"].as_array().unwrap().len(), 1);
        assert_eq!(records("rdp").unwrap()["records"][0]["id"], host.id.as_str());

        // An older copy doesn't replace a newer one.
        let mut older = host.clone();
        older.seq = Some(1);
        older.blob = "AAAA".into();
        merge("rdp", &serde_json::to_string(&[older]).unwrap()).unwrap();
        assert_eq!(records("rdp").unwrap()["unreadable"], 1);

        // A conflict: the server's copy comes in.
        let edit = seal_edit("rdp", &host.id, r#"{"json":{"name":"Mine"}}"#, 1_790_000_000_001, 4).unwrap();
        let mut theirs = app
            .seal_edit(
                &RecordHead { id: host.id.parse().unwrap(), kind: "host".into(), updated_at: host.updated_at, seq: 5 },
                &Payload::Json(json!({ "name": "Theirs" })),
                1_790_000_000_002,
                3,
            )
            .unwrap();
        theirs.seq = Some(9);
        let answer = json!({ "accepted": [], "conflicts": [theirs], "cursor": 9 }).to_string();
        let conflicts = apply_push("rdp", &serde_json::to_string(&[edit]).unwrap(), &answer).unwrap();
        assert_eq!(conflicts, vec![host.id.clone()]);
        assert_eq!(records("rdp").unwrap()["records"][0]["payload"]["name"], "Theirs");

        // The same space listed again keeps what was read; another id (a rekey) drops it.
        open_space(&unlocked, &serde_json::to_string(&listed).unwrap()).unwrap();
        assert_eq!(records("rdp").unwrap()["records"].as_array().unwrap().len(), 1);
        forget_records("rdp").unwrap();
        assert!(records("rdp").unwrap()["records"].as_array().unwrap().is_empty());
        assert!(records("mail").is_err(), "not open");
    }

    #[test]
    fn a_key_made_here_reads_back() {
        let key = generate_key("nyu@example.com", "").unwrap();
        let private = key["privateKey"].as_str().unwrap();
        assert!(private.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        let info = inspect_private_key(private).unwrap();
        assert_eq!(info["publicKey"], key["publicKey"]);
        assert_eq!(info["encrypted"], false);
        assert_eq!(inspect_public_key(key["publicKey"].as_str().unwrap()).unwrap()["keyType"], "ssh-ed25519");
        assert!(passphrase_opens(private, "anything").unwrap());
        assert!(inspect_private_key("no key").is_err());
    }
}
