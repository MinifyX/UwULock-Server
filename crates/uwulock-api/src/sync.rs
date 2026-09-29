//! `GET /uwu/v1/sync` (docs/uwu-api.md §4.4): the vault as `/api/sync` gives it, plus UwULock's
//! own and the suite spaces, and after the first time only what changed since the cursor.
//!
//! The change numbers are the store's ([`uwulock_store::sync`]); here they become a cursor and
//! the answer. A cursor is base64url JSON the clients never read: the server epoch, the account's
//! sync epoch, the areas it was made for, the account's number, one number per organisation and
//! the key epoch of every suite space it saw. When any of that no longer fits, the answer is a
//! full sync with `reset: true`.

use crate::AppState;
use crate::auth::AnySession;
use crate::ciphers::{json_text, knows_ssh_keys, vault_parts};
use crate::errors::{ApiError, ApiResult};
use crate::json::{self as out, View};
use axum::Router;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use uwulock_store::{Counters, Delta, DeltaRequest};

/// Changed objects in one delta when the client does not say.
const DEFAULT_LIMIT: usize = 500;
const MAX_LIMIT: usize = 1000;
/// A cursor is at most this long (§4.2).
const MAX_CURSOR: usize = 4096;
const VERSION: u8 = 1;

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/sync", get(sync))
}

/// What a sync covers: the areas, and for a suite app's token its one space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Areas {
    pub vault: bool,
    pub suite: bool,
    pub uwu: bool,
    /// The spaces a suite answer covers: the token's own, or every one (`None`).
    pub space: Option<&'static str>,
}

impl Areas {
    /// `include` as the client wrote it, for this session.
    pub(crate) fn parse(include: Option<&str>, space: Option<&'static str>) -> ApiResult<Areas> {
        let include = include.map(str::trim).filter(|text| !text.is_empty());
        let include = include.unwrap_or(if space.is_some() { "suite" } else { "vault,uwu" });
        let mut areas = Areas { vault: false, suite: false, uwu: false, space };
        for area in include.split(',').map(str::trim) {
            match area {
                "vault" => areas.vault = true,
                "suite" => areas.suite = true,
                "uwu" => areas.uwu = true,
                _ => {
                    return Err(ApiError::bad(format!("There is no area “{area}”: vault, suite, uwu.")).code("invalid"));
                }
            }
        }
        if space.is_some() && (areas.vault || areas.uwu) {
            return Err(crate::suite::scope_error());
        }
        Ok(areas)
    }

    /// What goes into the cursor: another set is another cursor.
    fn key(&self) -> String {
        let mut key: Vec<&str> = Vec::new();
        if self.vault {
            key.push("vault");
        }
        if self.suite {
            key.push("suite");
        }
        if self.uwu {
            key.push("uwu");
        }
        let mut key = key.join(",");
        if let Some(space) = self.space {
            key.push(':');
            key.push_str(space);
        }
        key
    }

    /// The realtime areas this is about.
    pub(crate) fn names(&self) -> Vec<&'static str> {
        [("vault", self.vault), ("uwu", self.uwu), ("suite", self.suite)]
            .into_iter()
            .filter_map(|(name, on)| on.then_some(name))
            .collect()
    }
}

/// What a cursor says.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Cursor {
    v: u8,
    /// The server epoch.
    s: String,
    /// The account's sync epoch.
    e: i64,
    /// The areas.
    i: String,
    /// The account's number.
    u: i64,
    /// Each organisation's number.
    #[serde(default)]
    o: BTreeMap<String, i64>,
    /// Each suite space's key epoch.
    #[serde(default)]
    p: BTreeMap<String, i64>,
}

impl Cursor {
    pub(crate) fn encode(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).unwrap_or_default())
    }

    /// A cursor the client sent back; nothing when it cannot be read.
    pub(crate) fn decode(text: &str) -> Option<Cursor> {
        if text.len() > MAX_CURSOR {
            return None;
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text.trim().trim_end_matches('=')).ok()?;
        serde_json::from_slice::<Cursor>(&bytes).ok().filter(|cursor| cursor.v == VERSION)
    }

    /// The areas it was made for, as it wrote them.
    pub(crate) fn areas(&self) -> &str {
        &self.i
    }

    /// The cursor after everything up to the counters as they are now.
    fn at(counters: &Counters, areas: &Areas) -> Cursor {
        Cursor {
            v: VERSION,
            s: counters.server_epoch.clone(),
            e: counters.epoch,
            i: areas.key(),
            u: counters.seq,
            o: counters.orgs.iter().map(|org| (org.id.clone(), org.seq)).collect(),
            p: spaces_of(counters, areas),
        }
    }

    /// Whether a delta from this cursor still tells the whole story: same epochs, same areas,
    /// nothing forgotten since, and the spaces' keys unchanged.
    pub(crate) fn fits(&self, counters: &Counters, areas: &Areas) -> bool {
        if self.s != counters.server_epoch || self.e != counters.epoch || self.i != areas.key() {
            return false;
        }
        if self.u > counters.seq || self.u < counters.pruned {
            return false;
        }
        for org in &counters.orgs {
            if let Some(&seq) = self.o.get(&org.id)
                && (seq > org.seq || seq < org.pruned)
            {
                return false;
            }
        }
        let now = spaces_of(counters, areas);
        self.p.iter().all(|(space, epoch)| now.get(space) == Some(epoch))
    }

    /// Whether the account changed since, for these areas: a cheap check for the realtime
    /// channel's resume (it may say yes when only another area changed).
    pub(crate) fn behind(&self, counters: &Counters, areas: &Areas) -> bool {
        !self.fits(counters, areas)
            || self.u < counters.seq
            || counters.orgs.iter().any(|org| self.o.get(&org.id).is_none_or(|&seq| seq < org.seq))
    }
}

/// The key epochs of the spaces an answer for `areas` covers.
fn spaces_of(counters: &Counters, areas: &Areas) -> BTreeMap<String, i64> {
    if !areas.suite {
        return BTreeMap::new();
    }
    counters
        .spaces
        .iter()
        .filter(|(space, _)| areas.space.is_none_or(|own| own == space))
        .map(|(space, epoch)| (space.clone(), *epoch))
        .collect()
}

#[derive(Deserialize)]
struct SyncQuery {
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    include: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn sync(
    State(state): State<AppState>,
    AnySession(session): AnySession,
    headers: HeaderMap,
    Query(query): Query<SyncQuery>,
) -> ApiResult<Response> {
    let mut areas = Areas::parse(query.include.as_deref(), session.space)?;
    if areas.suite && !state.settings().suite.enabled {
        if session.is_suite() {
            crate::suite::enabled(&state)?;
        }
        // An account's client that asks for the suite of a server without one gets none.
        areas.suite = false;
    }
    let since = match query.since.as_deref().map(str::trim).filter(|text| !text.is_empty()) {
        Some(text) => Some(
            Cursor::decode(text)
                .ok_or_else(|| ApiError::bad("The cursor cannot be read; sync without one.").code("invalid"))?,
        ),
        None => None,
    };
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let user = &session.user;
    let ssh = knows_ssh_keys(&headers);
    let started = std::time::Instant::now();

    if let Some(cursor) = since {
        let request = DeltaRequest {
            user_id: user.id.clone(),
            since: cursor.u,
            orgs: cursor.o.iter().map(|(org, seq)| (org.clone(), *seq)).collect(),
            vault: areas.vault,
            uwu: areas.uwu,
            spaces: areas.suite.then(|| suite_spaces(&areas)),
            limit,
        };
        let (delta, counters) = state.store.delta(request).await?.ok_or_else(ApiError::unauthorized)?;
        if cursor.fits(&counters, &areas) {
            let answer = delta_answer(&state, &session, &areas, ssh, delta, &counters).await?;
            state.metrics.sync("delta", started.elapsed().as_secs_f64());
            return Ok(answer);
        }
    }
    let answer = full_answer(&state, &session, &areas, &headers).await?;
    state.metrics.sync("full", started.elapsed().as_secs_f64());
    Ok(answer)
}

/// The spaces a suite answer covers.
fn suite_spaces(areas: &Areas) -> Vec<String> {
    match areas.space {
        Some(space) => vec![space.to_string()],
        None => crate::suite::SPACES.iter().map(|space| space.to_string()).collect(),
    }
}

/// Everything, and a cursor that points after it.
async fn full_answer(
    state: &AppState,
    session: &crate::auth::Session,
    areas: &Areas,
    headers: &HeaderMap,
) -> ApiResult<Response> {
    let user = &session.user;
    // The counters first: what changes while the rest is read comes again in the next delta.
    let counters = state.store.sync_counters(&user.id).await?.ok_or_else(ApiError::unauthorized)?;
    let cursor = Cursor::at(&counters, areas);
    let mut body = String::with_capacity(4096);
    body.push_str("{\"object\":\"uwuSync\",\"reset\":true,\"cursor\":");
    body.push_str(&Value::String(cursor.encode()).to_string());
    body.push_str(",\"hasMore\":false,\"vault\":");
    // The items' ids, for their own icons below.
    let mut cipher_ids = None;
    if areas.vault {
        let mut parts = vault_parts(state, user, headers, false).await?;
        cipher_ids = Some(std::mem::take(&mut parts.cipher_ids));
        body.reserve(parts.ciphers.len());
        body.push_str("{\"profile\":");
        body.push_str(&parts.profile);
        body.push_str(",\"folders\":");
        body.push_str(&parts.folders);
        body.push_str(",\"collections\":");
        body.push_str(&parts.collections);
        body.push_str(",\"ciphers\":");
        body.push_str(&parts.ciphers);
        body.push_str(",\"sends\":");
        body.push_str(&parts.sends);
        body.push_str(",\"policies\":");
        body.push_str(&parts.policies);
        body.push_str(",\"domains\":");
        body.push_str(&parts.domains);
        body.push_str(",\"userDecryption\":");
        body.push_str(&parts.user_decryption);
        body.push_str(",\"deleted\":");
        body.push_str(&no_deletions().to_string());
        body.push('}');
    } else {
        body.push_str("null");
    }
    body.push_str(",\"suite\":");
    if areas.suite {
        let mut spaces = Vec::new();
        let mut records = Vec::new();
        for space in state.store.suite_spaces(&user.id).await? {
            if areas.space.is_some_and(|own| own != space.space) {
                continue;
            }
            if let Some(pull) = state.store.suite_pull(&user.id, &space.space, 0, usize::MAX, usize::MAX).await? {
                records.extend(pull.records.iter().filter(|record| !record.deleted).map(crate::suite::record_json));
            }
            spaces.push(crate::suite::space_json(&space));
        }
        body.push_str(&json!({ "records": records, "spaces": spaces }).to_string());
    } else {
        body.push_str("null");
    }
    body.push_str(",\"uwu\":");
    if areas.uwu {
        let ids = match cipher_ids {
            Some(ids) => ids,
            None => {
                let (own, orgs) = tokio::try_join!(state.store.ciphers(&user.id), state.store.org_vault(&user.id))?;
                own.into_iter()
                    .map(|cipher| cipher.id)
                    .chain(orgs.ciphers.into_iter().map(|item| item.cipher.id))
                    .collect()
            }
        };
        let (key, icons) = tokio::try_join!(state.store.extras_key(&user.id), state.store.own_icons(ids, false))?;
        let uwu = json!({
            "extrasKey": crate::keys::view(key),
            "icons": icons.iter().map(icon_json).collect::<Vec<_>>(),
            "iconsDeleted": [],
            "reminders": crate::reminders::list_json(state, &user.id).await?,
            "travel": crate::travel::travel_json(state, &user.id).await?,
            "sendDomains": {},
            "maskedLinks": null,
            "unseen": unseen(state, &user.id).await?,
        });
        body.push_str(&uwu.to_string());
    } else {
        body.push_str("null");
    }
    body.push('}');
    Ok(json_text(body))
}

fn no_deletions() -> Value {
    json!({ "folders": [], "collections": [], "ciphers": [], "sends": [] })
}

fn icon_json(icon: &uwulock_store::OwnIcon) -> Value {
    json!({ "cipherId": icon.cipher_id, "revisionDate": icon.revision, "keyType": icon.key_type })
}

async fn unseen(state: &AppState, user_id: &str) -> ApiResult<Value> {
    let (notices, submissions) =
        tokio::try_join!(state.store.unseen_notices(user_id), state.store.unseen_submissions(user_id))?;
    Ok(json!({ "securityNotices": notices, "fileRequestSubmissions": submissions }))
}

/// One page of changes, and the cursor after it.
async fn delta_answer(
    state: &AppState,
    session: &crate::auth::Session,
    areas: &Areas,
    ssh: bool,
    delta: Delta,
    counters: &Counters,
) -> ApiResult<Response> {
    let user = &session.user;
    let mut cursor = Cursor::at(counters, areas);
    cursor.u = delta.until;
    for (org, seq) in &delta.org_until {
        cursor.o.insert(org.clone(), *seq);
    }
    let mut body = String::with_capacity(2048);
    body.push_str("{\"object\":\"uwuSync\",\"reset\":false,\"cursor\":");
    body.push_str(&Value::String(cursor.encode()).to_string());
    body.push_str(",\"hasMore\":");
    body.push_str(if delta.has_more { "true" } else { "false" });
    body.push_str(",\"vault\":");
    if areas.vault {
        let (profile, domains, user_decryption) = if delta.profile {
            let memberships = state.store.memberships_of(&user.id).await?;
            (
                crate::ciphers::profile_json(state, user, &memberships).await?,
                crate::meta::domains(user, false),
                crate::ciphers::user_decryption(user),
            )
        } else {
            (Value::Null, Value::Null, Value::Null)
        };
        let policies = if delta.policies {
            let policies = state.store.policies_of(&user.id).await?;
            Value::Array(policies.iter().map(crate::organizations::policy_json).collect())
        } else {
            Value::Null
        };
        let ids: Vec<String> = delta
            .ciphers
            .iter()
            .map(|cipher| cipher.id.clone())
            .chain(delta.org_ciphers.iter().map(|item| item.cipher.id.clone()))
            .collect();
        let mut grouped: HashMap<String, Vec<uwulock_store::Attachment>> = HashMap::new();
        if !ids.is_empty() {
            for attachment in state.store.attachments_of(ids).await? {
                grouped.entry(attachment.cipher_id.clone()).or_default().push(attachment);
            }
        }
        let attachments: HashMap<String, String> = grouped
            .into_iter()
            .map(|(id, list)| {
                (id, crate::attachments::render(state, &list, crate::files::SYNC_LINK_SECONDS).to_string())
            })
            .collect();
        let mut ciphers = String::from("[");
        let mut first = true;
        for cipher in delta.ciphers.iter().filter(|cipher| ssh || cipher.kind != 5) {
            if !first {
                ciphers.push(',');
            }
            first = false;
            out::write_cipher(&mut ciphers, cipher, &View::own(attachments.get(&cipher.id).map(String::as_str)));
        }
        for item in delta.org_ciphers.iter().filter(|item| ssh || item.cipher.kind != 5) {
            if !first {
                ciphers.push(',');
            }
            first = false;
            let view = View {
                attachments: attachments.get(&item.cipher.id).map(String::as_str),
                collection_ids: &item.collection_ids,
                access: item.access,
            };
            out::write_cipher(&mut ciphers, &item.cipher, &view);
        }
        ciphers.push(']');
        body.push_str("{\"profile\":");
        body.push_str(&profile.to_string());
        body.push_str(",\"folders\":");
        body.push_str(&Value::Array(delta.folders.iter().map(out::folder).collect()).to_string());
        body.push_str(",\"collections\":");
        let collections: Vec<Value> = delta
            .collections
            .iter()
            .map(|(collection, access)| crate::organizations::collection_json(collection, access))
            .collect();
        body.push_str(&Value::Array(collections).to_string());
        body.push_str(",\"ciphers\":");
        body.push_str(&ciphers);
        body.push_str(",\"sends\":");
        body.push_str(&Value::Array(delta.sends.iter().map(crate::sends::render).collect()).to_string());
        body.push_str(",\"policies\":");
        body.push_str(&policies.to_string());
        body.push_str(",\"domains\":");
        body.push_str(&domains.to_string());
        body.push_str(",\"userDecryption\":");
        body.push_str(&user_decryption.to_string());
        body.push_str(",\"deleted\":");
        let deleted = json!({
            "folders": delta.deleted_folders,
            "collections": delta.deleted_collections,
            "ciphers": delta.deleted_ciphers,
            "sends": delta.deleted_sends,
        });
        body.push_str(&deleted.to_string());
        body.push('}');
    } else {
        body.push_str("null");
    }
    body.push_str(",\"suite\":");
    if areas.suite {
        let suite = json!({
            "records": delta.records.iter().map(crate::suite::record_json).collect::<Vec<_>>(),
            "spaces": delta.spaces.iter().map(crate::suite::space_json).collect::<Vec<_>>(),
        });
        body.push_str(&suite.to_string());
    } else {
        body.push_str("null");
    }
    body.push_str(",\"uwu\":");
    if areas.uwu {
        let reminders = if delta.reminders { crate::reminders::list_json(state, &user.id).await? } else { Value::Null };
        // Which folders travel mode hides is a folder's change; switching it is an epoch.
        let travel = if !delta.folders.is_empty() || !delta.deleted_folders.is_empty() {
            crate::travel::travel_json(state, &user.id).await?
        } else {
            Value::Null
        };
        let uwu = json!({
            "extrasKey": delta.extras_key.map(|key| crate::keys::view(Some(key))),
            "icons": delta.icons.iter().map(icon_json).collect::<Vec<_>>(),
            "iconsDeleted": delta.icons_deleted,
            "reminders": reminders,
            "travel": travel,
            "sendDomains": {},
            "maskedLinks": null,
            "unseen": unseen(state, &user.id).await?,
        });
        body.push_str(&uwu.to_string());
    } else {
        body.push_str("null");
    }
    body.push('}');
    Ok(json_text(body))
}

#[cfg(test)]
mod tests;
