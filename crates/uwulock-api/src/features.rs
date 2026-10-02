//! Feature switches: the extras an admin turns on or off (docs/features.md).
//!
//! The vault and everything Bitwarden's own clients know — Sends, attachments, two-step login,
//! emergency access, organisations, local backups — is always there; so are the automatic
//! website icons, which keep their own switch. What UwULock adds on top is listed here, one
//! switch each. A feature that is off is gone as far as anyone outside can tell: its endpoints
//! answer 404 like a route that never existed, what it does by itself stops, `/uwu/v1/info`
//! leaves it out (and says so in `switches`), and the web vault and admin portal hide it.
//! Turning one off never deletes anything; turning it on again brings it all back.
//!
//! The switches are kept as JSON under `features` in the `server` table, apart from the other
//! settings: the portal saves those as a whole, and a switch should never ride along with them.
//! A server that never had them (a new one) starts with `UWULOCK_FEATURES`, by default none of
//! them; migration 0017 wrote them for a server that was running before they existed, on for
//! every feature that was in use.
//!
//! While `UWULOCK_FEATURES` counts, what it says is kept too, under `features.start`: the
//! environment is not in a backup, the database is, and a server restored on a machine without
//! that line keeps the switches it had (docs/features.md, "New and updated servers").

use crate::AppState;
use crate::admin::record;
use crate::auth::Admin;
use crate::errors::{ApiError, ApiResult};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use uwulock_store::Store;

const KEY: &str = "features";
/// What `UWULOCK_FEATURES` said when this server last ran with it, until somebody switches.
const START_KEY: &str = "features.start";

/// One extra that can be switched off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    // Sharing
    Families,
    FileRequests,
    SendDomains,
    MaskedAddresses,
    // The vault
    Versions,
    Reminders,
    TravelMode,
    EmergencySheet,
    OwnIcons,
    IconLibrary,
    TwofaDirectory,
    // Logging in
    Sso,
    Scim,
    // Running the server
    OffsiteBackups,
    AdminNotifications,
    // The UwU apps
    Suite,
}

/// Where a feature is listed in the admin portal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Sharing,
    Vault,
    SignIn,
    Operations,
    Apps,
}

impl Group {
    pub fn id(self) -> &'static str {
        match self {
            Group::Sharing => "sharing",
            Group::Vault => "vault",
            Group::SignIn => "sign-in",
            Group::Operations => "operations",
            Group::Apps => "apps",
        }
    }
}

impl Feature {
    /// Every switch, in the order the portal lists them.
    pub const ALL: [Feature; 16] = [
        Feature::Families,
        Feature::FileRequests,
        Feature::SendDomains,
        Feature::MaskedAddresses,
        Feature::Versions,
        Feature::Reminders,
        Feature::TravelMode,
        Feature::EmergencySheet,
        Feature::OwnIcons,
        Feature::IconLibrary,
        Feature::TwofaDirectory,
        Feature::Sso,
        Feature::Scim,
        Feature::OffsiteBackups,
        Feature::AdminNotifications,
        Feature::Suite,
    ];

    /// Its name on the wire: in `/uwu/v1/info` (both `features` and `switches`), the admin API,
    /// `UWULOCK_FEATURES` and the database.
    pub fn id(self) -> &'static str {
        match self {
            Feature::Families => "families",
            Feature::FileRequests => "file-requests",
            Feature::SendDomains => "send-domains",
            Feature::MaskedAddresses => "masked-addresses",
            Feature::Versions => "versions",
            Feature::Reminders => "reminders",
            Feature::TravelMode => "travel-mode",
            Feature::EmergencySheet => "emergency-sheet",
            Feature::OwnIcons => "own-icons",
            Feature::IconLibrary => "icon-library",
            Feature::TwofaDirectory => "twofa-directory",
            Feature::Sso => "sso",
            Feature::Scim => "scim",
            Feature::OffsiteBackups => "offsite-backups",
            Feature::AdminNotifications => "admin-notifications",
            Feature::Suite => "suite",
        }
    }

    pub fn from_id(id: &str) -> Option<Feature> {
        Feature::ALL.into_iter().find(|feature| feature.id() == id)
    }

    pub fn group(self) -> Group {
        match self {
            Feature::Families | Feature::FileRequests | Feature::SendDomains | Feature::MaskedAddresses => {
                Group::Sharing
            }
            Feature::Versions
            | Feature::Reminders
            | Feature::TravelMode
            | Feature::EmergencySheet
            | Feature::OwnIcons
            | Feature::IconLibrary
            | Feature::TwofaDirectory => Group::Vault,
            Feature::Sso | Feature::Scim => Group::SignIn,
            Feature::OffsiteBackups | Feature::AdminNotifications => Group::Operations,
            Feature::Suite => Group::Apps,
        }
    }

    /// What has to be on too for this one to work: a library icon is kept as an own icon, and
    /// SCIM's accounts log in through the provider (its settings are SSO's too).
    pub fn requires(self) -> Option<Feature> {
        match self {
            Feature::IconLibrary => Some(Feature::OwnIcons),
            Feature::Scim => Some(Feature::Sso),
            _ => None,
        }
    }
}

/// Which features are on. Missing means off.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Features {
    on: BTreeSet<Feature>,
}

impl Features {
    /// None of them: a new server.
    pub fn none() -> Self {
        Features::default()
    }

    /// All of them: for tests of the features themselves.
    pub fn all() -> Self {
        Features { on: Feature::ALL.into_iter().collect() }
    }

    /// Whether `feature` is on, and what it needs is too.
    pub fn on(&self, feature: Feature) -> bool {
        self.on.contains(&feature) && feature.requires().is_none_or(|needed| self.on.contains(&needed))
    }

    /// Whether the switch itself is on, whatever the ones it needs say.
    pub fn switched_on(&self, feature: Feature) -> bool {
        self.on.contains(&feature)
    }

    pub fn set(&mut self, feature: Feature, on: bool) {
        if on {
            self.on.insert(feature);
        } else {
            self.on.remove(&feature);
        }
    }

    pub fn with(mut self, feature: Feature, on: bool) -> Self {
        self.set(feature, on);
        self
    }

    /// `UWULOCK_FEATURES`: `all`, `none`, or names like `families,file-requests`.
    pub fn parse_list(text: &str) -> Result<Features, String> {
        let mut features = Features::none();
        for word in text.split([',', ' ']).map(str::trim).filter(|word| !word.is_empty()) {
            match word.to_ascii_lowercase().as_str() {
                "all" => features = Features::all(),
                "none" => features = Features::none(),
                name => {
                    let feature = Feature::from_id(name).ok_or_else(|| {
                        let known: Vec<&str> = Feature::ALL.iter().map(|feature| feature.id()).collect();
                        format!("{name} is no feature this server knows; it knows {}", known.join(", "))
                    })?;
                    features.set(feature, true);
                }
            }
        }
        Ok(features)
    }

    /// As kept: every switch by name, `true` or `false`.
    pub fn to_json(&self) -> Value {
        self.json_by(Features::switched_on)
    }

    /// As `/uwu/v1/info` says it: whether each one works, what it needs included.
    pub fn working_json(&self) -> Value {
        self.json_by(Features::on)
    }

    fn json_by(&self, on: fn(&Features, Feature) -> bool) -> Value {
        let map: Map<String, Value> =
            Feature::ALL.into_iter().map(|feature| (feature.id().to_string(), on(self, feature).into())).collect();
        Value::Object(map)
    }

    /// The switches as the database or the admin API has them; names this build does not know
    /// are left alone, missing ones are off.
    pub fn from_json(value: &Value) -> Features {
        let mut features = Features::none();
        if let Some(map) = value.as_object() {
            for (name, on) in map {
                if let (Some(feature), Some(true)) = (Feature::from_id(name), on.as_bool()) {
                    features.set(feature, true);
                }
            }
        }
        features
    }

    /// What the switches are: those an admin switched (in the database); else what
    /// `UWULOCK_FEATURES` says (`start`); else what it said when this server, or the one it was
    /// restored from, last ran with it; else none, a new server.
    pub async fn load(store: &Store, start: Option<&Features>) -> Result<Features, String> {
        if let Some(switched) = Features::read(store, KEY).await? {
            return Ok(switched);
        }
        if let Some(start) = start {
            return Ok(start.clone());
        }
        Ok(Features::read(store, START_KEY).await?.unwrap_or_default())
    }

    /// Keeps what `UWULOCK_FEATURES` says in the database while it counts (nobody switched), so
    /// a backup carries the switches as they are. Without it, or once switched, nothing changes.
    pub async fn remember_start(store: &Store, start: Option<&Features>) -> Result<(), String> {
        let Some(start) = start else {
            return Ok(());
        };
        if store.setting(KEY).await.map_err(|error| error.to_string())?.is_some() {
            return Ok(());
        }
        if Features::read(store, START_KEY).await?.as_ref() != Some(start) {
            store.set_setting(START_KEY, &start.to_json().to_string()).await.map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    async fn read(store: &Store, key: &str) -> Result<Option<Features>, String> {
        match store.setting(key).await.map_err(|error| error.to_string())? {
            Some(json) => serde_json::from_str::<Value>(&json)
                .map(|value| Some(Features::from_json(&value)))
                .map_err(|error| format!("the feature switches in the database: {error}")),
            None => Ok(None),
        }
    }

    pub async fn save(&self, store: &Store) -> Result<(), uwulock_store::StoreError> {
        store.set_setting(KEY, &self.to_json().to_string()).await
    }

    /// The names of those on, for logs and the event log.
    pub fn names(&self) -> Vec<&'static str> {
        Feature::ALL.into_iter().filter(|feature| self.on(*feature)).map(Feature::id).collect()
    }
}

// ── The guard ─────────────────────────────────────────────

/// `routes`, answered only while `feature` is on: 404 otherwise, as for a route that does not
/// exist, with the code `feature_off` of the contract (docs/uwu-api.md §1.3) so UwULock's own
/// clients can say why.
pub(crate) fn only_with(routes: Router<AppState>, state: &AppState, feature: Feature) -> Router<AppState> {
    routes.route_layer(axum::middleware::from_fn_with_state((state.clone(), feature), guard))
}

async fn guard(State((state, feature)): State<(AppState, Feature)>, request: Request, next: Next) -> Response {
    if !state.feature(feature) {
        return ApiError::not_found("This is switched off on this server.").code("feature_off").into_response();
    }
    next.run(request).await
}

// ── The admin portal ──────────────────────────────────────

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/admin/features", get(list).put(change))
}

/// Every switch: on or off, its group, what it needs, and whether something of it is kept.
async fn list(State(state): State<AppState>, _admin: Admin) -> ApiResult<Json<Value>> {
    Ok(Json(view(&state).await?))
}

async fn view(state: &AppState) -> ApiResult<Value> {
    let features = state.features();
    let settings = state.settings();
    let used = in_use(state, &settings).await?;
    let list: Vec<Value> = Feature::ALL
        .into_iter()
        .map(|feature| {
            json!({
                "id": feature.id(),
                "group": feature.group().id(),
                "on": features.switched_on(feature),
                "works": features.on(feature),
                "requires": feature.requires().map(Feature::id),
                "inUse": used.contains(&feature),
            })
        })
        .collect();
    Ok(json!({ "object": "features", "features": list }))
}

/// `{"families": true, "sso": false}`: those named are switched, the others stay as they are.
async fn change(State(state): State<AppState>, admin: Admin, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let Some(map) = body.as_object() else {
        return Err(ApiError::bad("Send the switches as an object, like {\"families\": true}."));
    };
    let before = state.features();
    let mut after = before.clone();
    for (name, on) in map {
        let feature = Feature::from_id(name).ok_or_else(|| ApiError::bad(format!("{name} is no feature.")))?;
        let on = on.as_bool().ok_or_else(|| ApiError::bad(format!("{name}: true or false.")))?;
        after.set(feature, on);
    }
    if before.on(Feature::TravelMode) && !after.on(Feature::TravelMode) {
        let travelling = state.store.travelling_count().await?;
        if travelling > 0 {
            return Err(ApiError::bad(format!(
                "{travelling} account(s) are travelling right now: their hidden folders would show up again. \
                 Travel mode can be switched off once nobody is travelling."
            ))
            .code("travelling"));
        }
    }
    if after != before {
        after.save(&state.store).await?;
        state.apply_features(after.clone());
        crate::send_domains::reload(&state).await;
        let changed: Vec<String> = Feature::ALL
            .into_iter()
            .filter(|feature| before.switched_on(*feature) != after.switched_on(*feature))
            .map(|feature| format!("{} {}", feature.id(), if after.switched_on(feature) { "on" } else { "off" }))
            .collect();
        record(&state, &admin, format!("switched features: {}", changed.join(", "))).await;
    }
    Ok(Json(view(&state).await?))
}

/// The features something is kept for, or set up: what migration 0017 looked at, as it is now.
pub async fn in_use(state: &AppState, settings: &crate::Settings) -> ApiResult<BTreeSet<Feature>> {
    let mut used: BTreeSet<Feature> =
        state.store.features_with_data().await?.iter().filter_map(|name| Feature::from_id(name)).collect();
    if !settings.masked.servers.is_empty() {
        used.insert(Feature::MaskedAddresses);
    }
    if settings.sso.enabled || !settings.sso.issuer.trim().is_empty() {
        used.insert(Feature::Sso);
    }
    if settings.scim.token_hash.is_some() {
        used.insert(Feature::Scim);
    }
    if state.offsite.settings().await.is_ok_and(|offsite| offsite.target.is_some()) {
        used.insert(Feature::OffsiteBackups);
    }
    Ok(used)
}

#[cfg(test)]
mod tests;
