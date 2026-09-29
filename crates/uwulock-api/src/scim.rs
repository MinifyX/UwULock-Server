//! SCIM 2.0 (RFC 7643, RFC 7644) at `/scim/v2`: how UwUAuth — or another provider — tells this
//! server who may use it (docs/uwu-api.md §19.4).
//!
//! - **People.** Somebody without an account becomes a provisioned entry: an address that may
//!   sign up through SSO, even while sign-ups need an invitation. An account is found by its
//!   address (a `POST` for it is 409, and the provider then finds it by filter). `active: false`
//!   disables the account and ends its sessions; `DELETE` disables or deletes it, as the admin
//!   chose. The address itself never changes this way: it is the salt of the account's keys, so
//!   its owner changes it in the vault.
//! - **Groups** are kept only to know who is in the admin group between logins: whoever leaves
//!   it loses the admin right at once.
//!
//! The token is the one from the pairing, or made in the admin portal; only its SHA-256 is kept,
//! compared in constant time, and refused tokens are counted per address.

use crate::AppState;
use crate::auth;
use axum::body::Bytes;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use uwulock_store::{Event, ScimGroup, ScimUser, StoreError, User, clock, normalize_email};

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
/// The most one page lists.
const MAX_RESULTS: usize = 200;
/// The most members a group may have here.
const MAX_MEMBERS: usize = 10_000;

/// What a `DELETE` of a person with an account does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnDelete {
    #[default]
    Disable,
    Delete,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScimSettings {
    pub on_delete: OnDelete,
    /// Hex SHA-256 of the bearer token; `tokenSet` in the portal.
    pub token_hash: Option<String>,
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/scim/v2/ServiceProviderConfig", get(service_provider_config))
        .route("/scim/v2/ResourceTypes", get(resource_types))
        .route("/scim/v2/Schemas", get(schemas))
        .route("/scim/v2/Users", get(list_users).post(create_user))
        .route("/scim/v2/Users/{id}", get(get_user).put(put_user).patch(patch_user).delete(delete_user))
        .route("/scim/v2/Groups", get(list_groups).post(create_group))
        .route("/scim/v2/Groups/{id}", get(get_group).put(put_group).patch(patch_group).delete(delete_group))
}

// ── Answers ───────────────────────────────────────────────

/// A SCIM error: status, `scimType` and a detail.
#[derive(Debug)]
pub(crate) struct ScimError {
    status: StatusCode,
    kind: Option<&'static str>,
    detail: String,
}

impl ScimError {
    fn new(status: StatusCode, kind: Option<&'static str>, detail: impl Into<String>) -> Self {
        ScimError { status, kind, detail: detail.into() }
    }

    fn bad(kind: &'static str, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Some(kind), detail)
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, None, "No such resource.")
    }

    fn conflict(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, Some("uniqueness"), detail)
    }
}

impl From<StoreError> for ScimError {
    fn from(error: StoreError) -> Self {
        tracing::error!(%error, "a SCIM request failed");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, None, "Something went wrong on the server.")
    }
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let mut body = json!({
            "schemas": [ERROR_SCHEMA],
            "status": self.status.as_u16().to_string(),
            "detail": self.detail,
        });
        if let Some(kind) = self.kind {
            body["scimType"] = kind.into();
        }
        scim(self.status, body)
    }
}

type ScimResult<T> = Result<T, ScimError>;

fn scim(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/scim+json"));
    response
}

fn list(resources: Vec<Value>, total: usize, start: usize) -> Response {
    scim(
        StatusCode::OK,
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }),
    )
}

fn body_json(body: &Bytes) -> ScimResult<Value> {
    serde_json::from_slice(body).map_err(|_| ScimError::bad("invalidSyntax", "The body is not JSON."))
}

// ── The token ─────────────────────────────────────────────

/// A request with the SCIM token.
pub(crate) struct Scim;

impl FromRequestParts<AppState> for Scim {
    type Rejection = ScimError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let ip = auth::client_ip(parts, state.config.trust_forwarded);
        let key = crate::limits::network_of(ip);
        if !state.limits.scim_refused.allows(&key) {
            return Err(ScimError::new(StatusCode::TOO_MANY_REQUESTS, None, "Too many refused tokens. Wait a while."));
        }
        let stored = state.settings.read().scim.token_hash.clone();
        let presented = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer ")))
            .map(str::trim)
            .unwrap_or_default();
        let right = stored.as_deref().is_some_and(|stored| {
            !presented.is_empty()
                && auth::constant_time_eq(
                    crate::metrics::hex(&auth::sha256(presented.as_bytes())).as_bytes(),
                    stored.as_bytes(),
                )
        });
        if !right {
            state.limits.scim_refused.take(key);
            tracing::info!(%ip, "a SCIM request with a wrong token");
            return Err(ScimError::new(StatusCode::UNAUTHORIZED, None, "The SCIM token is missing or wrong."));
        }
        Ok(Scim)
    }
}

// ── What the server can do ────────────────────────────────

async fn service_provider_config(State(state): State<AppState>, _scim: Scim) -> Response {
    scim(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": MAX_RESULTS },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "The SCIM token from the pairing with UwUAuth, or made in UwULock's admin portal",
                "primary": true,
            }],
            "meta": {
                "resourceType": "ServiceProviderConfig",
                "location": format!("{}/scim/v2/ServiceProviderConfig", state.config.public),
            },
        }),
    )
}

async fn resource_types(State(state): State<AppState>, _scim: Scim) -> Response {
    let public = &state.config.public;
    let kind = |name: &str, endpoint: &str, schema: &str| {
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": name,
            "name": name,
            "endpoint": endpoint,
            "schema": schema,
            "meta": { "resourceType": "ResourceType", "location": format!("{public}/scim/v2/ResourceTypes/{name}") },
        })
    };
    let types = vec![kind("User", "/Users", USER_SCHEMA), kind("Group", "/Groups", GROUP_SCHEMA)];
    list(types, 2, 1)
}

async fn schemas(_scim: Scim) -> Response {
    let attribute = |name: &str, kind: &str, mutability: &str, required: bool| {
        json!({
            "name": name, "type": kind, "multiValued": false, "required": required,
            "caseExact": false, "mutability": mutability, "returned": "default", "uniqueness": "none",
        })
    };
    let user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": USER_SCHEMA,
        "name": "User",
        "attributes": [
            attribute("userName", "string", "immutable", true),
            attribute("displayName", "string", "readWrite", false),
            attribute("active", "boolean", "readWrite", false),
            attribute("externalId", "string", "readWrite", false),
        ],
    });
    let group = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": GROUP_SCHEMA,
        "name": "Group",
        "attributes": [
            attribute("displayName", "string", "readWrite", true),
            attribute("externalId", "string", "readWrite", false),
            { "name": "members", "type": "complex", "multiValued": true, "required": false, "mutability": "readWrite" },
        ],
    });
    list(vec![user, group], 2, 1)
}

// ── Filters and pages ─────────────────────────────────────

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ListQuery {
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    start_index: Option<usize>,
    #[serde(default)]
    count: Option<usize>,
}

/// `attribute eq "value"`, the one kind of filter the providers send for a lookup. The
/// attribute in lower case.
fn parse_filter(filter: &str) -> ScimResult<(String, String)> {
    let invalid = || ScimError::bad("invalidFilter", "Only filters like userName eq \"a@example.com\" are supported.");
    let filter = filter.trim();
    let (attribute, rest) = filter.split_once(char::is_whitespace).ok_or_else(invalid)?;
    let rest = rest.trim_start();
    let (operator, value) = rest.split_once(char::is_whitespace).ok_or_else(invalid)?;
    if !operator.eq_ignore_ascii_case("eq") {
        return Err(invalid());
    }
    let value: String = serde_json::from_str(value.trim()).map_err(|_| invalid())?;
    Ok((attribute.to_ascii_lowercase(), value))
}

fn page(resources: Vec<Value>, query: &ListQuery) -> Response {
    let total = resources.len();
    let start = query.start_index.unwrap_or(1).max(1);
    let count = query.count.unwrap_or(MAX_RESULTS).min(MAX_RESULTS);
    let shown = resources.into_iter().skip(start - 1).take(count).collect();
    list(shown, total, start)
}

// ── People ────────────────────────────────────────────────

/// Who an id stands for.
enum Person {
    /// An account, with its SCIM entry if it has one.
    Account(Box<User>, Option<ScimUser>),
    /// An address without an account.
    Provisioned(ScimUser),
}

impl Person {
    fn id(&self) -> &str {
        match self {
            Person::Account(user, entry) => entry.as_ref().map_or(&user.id, |entry| &entry.id),
            Person::Provisioned(entry) => &entry.id,
        }
    }

    fn email(&self) -> &str {
        match self {
            Person::Account(user, _) => &user.email,
            Person::Provisioned(entry) => &entry.email,
        }
    }

    fn json(&self, public: &str) -> Value {
        let (id, email, external, active, name, created, updated) = match self {
            Person::Account(user, entry) => (
                self.id(),
                &user.email,
                entry.as_ref().and_then(|entry| entry.external_id.as_deref()),
                !user.disabled,
                user.name.as_deref(),
                &user.created,
                &user.updated,
            ),
            Person::Provisioned(entry) => (
                entry.id.as_str(),
                &entry.email,
                entry.external_id.as_deref(),
                entry.active,
                entry.display_name.as_deref(),
                &entry.created,
                &entry.updated,
            ),
        };
        json!({
            "schemas": [USER_SCHEMA],
            "id": id,
            "externalId": external,
            "userName": email,
            "displayName": name,
            "active": active,
            "emails": [{ "value": email, "primary": true, "type": "work" }],
            "meta": {
                "resourceType": "User",
                "created": created,
                "lastModified": updated,
                "location": format!("{public}/scim/v2/Users/{id}"),
            },
        })
    }
}

/// The person with this SCIM id: an entry, or an account's own id.
async fn person(state: &AppState, id: &str) -> ScimResult<Option<Person>> {
    if let Some(entry) = state.store.scim_user(id).await? {
        return Ok(Some(entry_person(state, entry).await?));
    }
    let Some(user) = state.store.user(id).await? else { return Ok(None) };
    let entry = state.store.scim_user_of(&user.id).await?;
    Ok(Some(Person::Account(Box::new(user), entry)))
}

/// An entry as the person it is now: an account that was made for its address since (by
/// invitation, or through SSO) takes it over.
async fn entry_person(state: &AppState, entry: ScimUser) -> ScimResult<Person> {
    let account = match &entry.user_id {
        Some(user_id) => state.store.user(user_id).await?,
        None => {
            let found = state.store.user_by_email(&entry.email).await?;
            if let Some(user) = &found {
                state.store.claim_scim_user(&entry.email, &user.id).await?;
            }
            found
        }
    };
    Ok(match account {
        Some(user) => {
            let entry = state.store.scim_user_of(&user.id).await?.or(Some(entry));
            Person::Account(Box::new(user), entry)
        }
        None => Person::Provisioned(entry),
    })
}

async fn person_by_email(state: &AppState, email: &str) -> ScimResult<Option<Person>> {
    if let Some(user) = state.store.user_by_email(email).await? {
        let entry = state.store.scim_user_of(&user.id).await?;
        return Ok(Some(Person::Account(Box::new(user), entry)));
    }
    Ok(state.store.scim_provisioned(email).await?.map(Person::Provisioned))
}

async fn list_users(
    State(state): State<AppState>,
    _scim: Scim,
    Query(query): Query<ListQuery>,
) -> ScimResult<Response> {
    let public = &state.config.public;
    let people: Vec<Person> = match query.filter.as_deref().filter(|filter| !filter.trim().is_empty()) {
        Some(filter) => match parse_filter(filter)? {
            (attribute, value) if matches!(attribute.as_str(), "username" | "emails" | "emails.value") => {
                person_by_email(&state, &value).await?.into_iter().collect()
            }
            (attribute, value) if attribute == "externalid" => {
                let mut found = Vec::new();
                for entry in state.store.scim_users_by_external(&value).await? {
                    found.push(entry_person(&state, entry).await?);
                }
                found
            }
            (attribute, value) if attribute == "id" => person(&state, &value).await?.into_iter().collect(),
            _ => return Err(ScimError::bad("invalidFilter", "Users are filtered by userName, externalId or id.")),
        },
        None => {
            let mut all: Vec<Person> = Vec::new();
            let mut entries: HashMap<String, ScimUser> = HashMap::new();
            for entry in state.store.scim_users().await? {
                match &entry.user_id {
                    Some(user_id) => {
                        entries.insert(user_id.clone(), entry);
                    }
                    None => all.push(Person::Provisioned(entry)),
                }
            }
            for overview in state.store.users().await? {
                let entry = entries.remove(&overview.user.id);
                all.push(Person::Account(Box::new(overview.user), entry));
            }
            all
        }
    };
    Ok(page(people.iter().map(|person| person.json(public)).collect(), &query))
}

async fn get_user(State(state): State<AppState>, _scim: Scim, Path(id): Path<String>) -> ScimResult<Response> {
    let person = person(&state, &id).await?.ok_or_else(ScimError::not_found)?;
    Ok(scim(StatusCode::OK, person.json(&state.config.public)))
}

/// The address a user resource names: `userName`, or its primary (or first) email.
fn user_name(body: &Value) -> Option<String> {
    let name = body["userName"].as_str().map(str::to_string).or_else(|| {
        let emails = body["emails"].as_array()?;
        let primary = emails.iter().find(|email| email["primary"] == true).or_else(|| emails.first())?;
        primary["value"].as_str().map(str::to_string)
    })?;
    Some(normalize_email(&name))
}

/// `true`, `false`, or the strings some providers send for them.
fn boolean(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(flag) => Some(*flag),
        Value::String(text) if text.eq_ignore_ascii_case("true") => Some(true),
        Value::String(text) if text.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

/// A name for the account from a user resource: `displayName`, else `name.formatted`.
fn display_name(body: &Value) -> Option<String> {
    body["displayName"].as_str().or_else(|| body["name"]["formatted"].as_str()).map(clean_name)
}

fn clean_name(name: &str) -> String {
    name.trim().chars().take(50).collect()
}

fn text(value: &Value, most: usize) -> Option<String> {
    value.as_str().map(|text| text.trim().chars().take(most).collect::<String>()).filter(|text| !text.is_empty())
}

async fn create_user(State(state): State<AppState>, _scim: Scim, body: Bytes) -> ScimResult<Response> {
    let body = body_json(&body)?;
    let email = user_name(&body)
        .filter(|email| email.contains('@') && email.len() <= crate::identity::MAX_EMAIL)
        .ok_or_else(|| ScimError::bad("invalidValue", "userName has to be an email address."))?;
    if person_by_email(&state, &email).await?.is_some() {
        return Err(ScimError::conflict("There is somebody with this userName already."));
    }
    let now = clock::now();
    let entry = ScimUser {
        id: uuid::Uuid::new_v4().to_string(),
        email,
        user_id: None,
        external_id: text(&body["externalId"], 255),
        display_name: display_name(&body).filter(|name| !name.is_empty()),
        active: boolean(&body["active"]).unwrap_or(true),
        created: now.clone(),
        updated: now,
    };
    match state.store.put_scim_user(entry.clone()).await {
        Ok(()) => {}
        Err(StoreError::Exists) => return Err(ScimError::conflict("There is somebody with this userName already.")),
        Err(error) => return Err(error.into()),
    }
    tracing::info!(email = %entry.email, "SCIM: somebody may sign up through SSO");
    let person = Person::Provisioned(entry);
    let mut response = scim(StatusCode::CREATED, person.json(&state.config.public));
    if let Ok(location) = HeaderValue::from_str(&format!("{}/scim/v2/Users/{}", state.config.public, person.id())) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    Ok(response)
}

/// What a `PATCH` or `PUT` changes of a person. `None`: left as it is.
#[derive(Default)]
struct PersonChange {
    active: Option<bool>,
    display_name: Option<Option<String>>,
    external_id: Option<Option<String>>,
}

/// The address named in a change, which may not be another one.
fn same_address(person: &Person, value: &Value) -> ScimResult<()> {
    let named = match value {
        Value::String(name) => Some(normalize_email(name)),
        Value::Array(_) => user_name(&json!({ "emails": value })),
        _ => None,
    };
    match named {
        Some(named) if named != person.email() => Err(ScimError::bad(
            "mutability",
            "The address cannot change here: it is the salt of the account's keys. Its owner changes it in the vault.",
        )),
        _ => Ok(()),
    }
}

fn change_of(person: &Person, change: &mut PersonChange, path: &str, value: &Value, remove: bool) -> ScimResult<()> {
    match path.to_ascii_lowercase().as_str() {
        "active" => {
            if !remove {
                change.active =
                    Some(boolean(value).ok_or_else(|| ScimError::bad("invalidValue", "active is true or false."))?);
            }
        }
        "displayname" | "name.formatted" => {
            change.display_name = Some(if remove { None } else { value.as_str().map(clean_name) })
        }
        "externalid" => change.external_id = Some(if remove { None } else { text(value, 255) }),
        "username" | "emails" | "emails.value" if !remove => same_address(person, value)?,
        "username" | "emails" => {
            return Err(ScimError::bad("mutability", "The address cannot be removed."));
        }
        // Everything else a provider may send is not kept here.
        _ => {}
    }
    Ok(())
}

async fn patch_user(
    State(state): State<AppState>,
    _scim: Scim,
    Path(id): Path<String>,
    body: Bytes,
) -> ScimResult<Response> {
    let body = body_json(&body)?;
    let person = person(&state, &id).await?.ok_or_else(ScimError::not_found)?;
    let operations = body["Operations"]
        .as_array()
        .or_else(|| body["operations"].as_array())
        .ok_or_else(|| ScimError::bad("invalidSyntax", "A PATCH needs Operations."))?;
    let mut change = PersonChange::default();
    for operation in operations {
        let op = operation["op"].as_str().unwrap_or_default().to_ascii_lowercase();
        let remove = match op.as_str() {
            "add" | "replace" => false,
            "remove" => true,
            _ => return Err(ScimError::bad("invalidSyntax", "An operation is add, replace or remove.")),
        };
        match operation["path"].as_str().filter(|path| !path.is_empty()) {
            Some(path) => change_of(&person, &mut change, path, &operation["value"], remove)?,
            None => {
                let object = operation["value"]
                    .as_object()
                    .ok_or_else(|| ScimError::bad("invalidValue", "Without a path, the value is an object."))?;
                for (path, value) in object {
                    change_of(&person, &mut change, path, value, remove)?;
                }
            }
        }
    }
    let person = apply(&state, person, change).await?;
    Ok(scim(StatusCode::OK, person.json(&state.config.public)))
}

async fn put_user(
    State(state): State<AppState>,
    _scim: Scim,
    Path(id): Path<String>,
    body: Bytes,
) -> ScimResult<Response> {
    let body = body_json(&body)?;
    let person = person(&state, &id).await?.ok_or_else(ScimError::not_found)?;
    if let Some(name) = user_name(&body)
        && name != person.email()
    {
        return Err(ScimError::bad(
            "mutability",
            "The address cannot change here: it is the salt of the account's keys. Its owner changes it in the vault.",
        ));
    }
    let change = PersonChange {
        active: Some(boolean(&body["active"]).unwrap_or(true)),
        display_name: Some(display_name(&body).filter(|name| !name.is_empty())),
        external_id: Some(text(&body["externalId"], 255)),
    };
    let person = apply(&state, person, change).await?;
    Ok(scim(StatusCode::OK, person.json(&state.config.public)))
}

/// The last admin stays: disabled or deleted by the provider, nobody could reach the portal.
async fn keep_last_admin(state: &AppState, user: &User) -> ScimResult<()> {
    if user.admin && !user.disabled && state.store.admin_count().await? <= 1 {
        return Err(ScimError::new(
            StatusCode::CONFLICT,
            Some("mutability"),
            "This is the last admin of UwULock: make somebody else an admin there first.",
        ));
    }
    Ok(())
}

async fn log(state: &AppState, user: Option<&User>, email: &str, detail: String) {
    let event = Event {
        kind: "scim".into(),
        user_id: user.map(|user| user.id.clone()),
        email: Some(email.to_string()),
        detail: Some(detail.clone()),
        ..Event::default()
    };
    let _ = state.store.log_event(event).await;
    tracing::info!(%email, "SCIM: {detail}");
}

/// Disable an account: every session ends now.
async fn disable(state: &AppState, user: &User) -> ScimResult<()> {
    state
        .store
        .update_user(&user.id, |user| {
            user.disabled = true;
            user.security_stamp = uuid::Uuid::new_v4().to_string();
        })
        .await?;
    crate::notify::user(state, &user.id, None, uwulock_notify::Kind::LogOut);
    log(state, Some(user), &user.email, "disabled the account".into()).await;
    Ok(())
}

async fn apply(state: &AppState, person: Person, change: PersonChange) -> ScimResult<Person> {
    let now = clock::now();
    match person {
        Person::Provisioned(mut entry) => {
            if let Some(active) = change.active {
                entry.active = active;
            }
            if let Some(name) = change.display_name {
                entry.display_name = name.filter(|name| !name.is_empty());
            }
            if let Some(external) = change.external_id {
                entry.external_id = external;
            }
            entry.updated = now;
            state.store.put_scim_user(entry.clone()).await?;
            Ok(Person::Provisioned(entry))
        }
        Person::Account(user, entry) => {
            match change.active {
                Some(false) if !user.disabled => {
                    keep_last_admin(state, &user).await?;
                    disable(state, &user).await?;
                }
                Some(true) if user.disabled => {
                    state.store.update_user(&user.id, |user| user.disabled = false).await?;
                    log(state, Some(&user), &user.email, "enabled the account".into()).await;
                }
                _ => {}
            }
            if let Some(name) = change.display_name
                && name.as_deref().filter(|name| !name.is_empty()) != user.name.as_deref()
            {
                let name = name.filter(|name| !name.is_empty());
                state.store.update_user(&user.id, move |user| user.name = name).await?;
            }
            let mut entry = entry;
            if let Some(external) = change.external_id {
                let mut kept = entry.unwrap_or_else(|| ScimUser {
                    // The id the provider knows the account by stays the account's own.
                    id: user.id.clone(),
                    email: user.email.clone(),
                    user_id: Some(user.id.clone()),
                    active: true,
                    created: now.clone(),
                    ..ScimUser::default()
                });
                kept.external_id = external;
                kept.updated = now;
                state.store.put_scim_user(kept.clone()).await?;
                entry = Some(kept);
            }
            let user = state.store.user(&user.id).await?.ok_or_else(ScimError::not_found)?;
            Ok(Person::Account(Box::new(user), entry))
        }
    }
}

async fn delete_user(State(state): State<AppState>, _scim: Scim, Path(id): Path<String>) -> ScimResult<Response> {
    let person = person(&state, &id).await?.ok_or_else(ScimError::not_found)?;
    match person {
        Person::Provisioned(entry) => {
            state.store.delete_scim_user(&entry.id).await?;
            log(&state, None, &entry.email, "removed an address that could sign up".into()).await;
        }
        Person::Account(user, _) => {
            keep_last_admin(&state, &user).await?;
            match state.settings().scim.on_delete {
                OnDelete::Disable => {
                    if !user.disabled {
                        disable(&state, &user).await?;
                    }
                }
                OnDelete::Delete => {
                    crate::notify::user(&state, &user.id, None, uwulock_notify::Kind::LogOut);
                    crate::masked::account_going(&state, &user.id).await;
                    state.store.delete_user(&user.id).await?;
                    log(&state, None, &user.email, "deleted the account and its vault".into()).await;
                }
            }
        }
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ── Groups ────────────────────────────────────────────────

fn group_json(group: &ScimGroup, public: &str) -> Value {
    json!({
        "schemas": [GROUP_SCHEMA],
        "id": group.id,
        "displayName": group.display_name,
        "externalId": group.external_id,
        "members": group.members.iter().map(|id| json!({ "value": id })).collect::<Vec<_>>(),
        "meta": {
            "resourceType": "Group",
            "created": group.created,
            "lastModified": group.updated,
            "location": format!("{public}/scim/v2/Groups/{}", group.id),
        },
    })
}

/// The member ids of a `members` value.
fn member_ids(value: &Value) -> ScimResult<Vec<String>> {
    let list = match value {
        Value::Array(list) => list.clone(),
        Value::Object(_) => vec![value.clone()],
        Value::Null => Vec::new(),
        _ => return Err(ScimError::bad("invalidValue", "members is a list of { value }.")),
    };
    let mut ids: Vec<String> = list
        .iter()
        .filter_map(|member| member["value"].as_str().or_else(|| member.as_str()))
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty() && id.len() <= 255)
        .collect();
    ids.sort();
    ids.dedup();
    if ids.len() > MAX_MEMBERS {
        return Err(ScimError::bad("tooMany", "A group has at most 10000 members here."));
    }
    Ok(ids)
}

fn group_name(value: &Value) -> ScimResult<String> {
    text(value, 200).ok_or_else(|| ScimError::bad("invalidValue", "A group needs a displayName."))
}

async fn list_groups(
    State(state): State<AppState>,
    _scim: Scim,
    Query(query): Query<ListQuery>,
) -> ScimResult<Response> {
    let groups = match query.filter.as_deref().filter(|filter| !filter.trim().is_empty()) {
        Some(filter) => match parse_filter(filter)? {
            (attribute, value) if attribute == "displayname" => {
                state.store.scim_group_named(&value).await?.into_iter().collect()
            }
            (attribute, value) if attribute == "externalid" => state
                .store
                .scim_groups()
                .await?
                .into_iter()
                .filter(|group| group.external_id.as_deref() == Some(&value))
                .collect(),
            (attribute, value) if attribute == "id" => state.store.scim_group(&value).await?.into_iter().collect(),
            _ => return Err(ScimError::bad("invalidFilter", "Groups are filtered by displayName, externalId or id.")),
        },
        None => state.store.scim_groups().await?,
    };
    let public = &state.config.public;
    Ok(page(groups.iter().map(|group| group_json(group, public)).collect(), &query))
}

async fn get_group(State(state): State<AppState>, _scim: Scim, Path(id): Path<String>) -> ScimResult<Response> {
    let group = state.store.scim_group(&id).await?.ok_or_else(ScimError::not_found)?;
    Ok(scim(StatusCode::OK, group_json(&group, &state.config.public)))
}

/// Keep the group as it is now, and take the admin right from whoever left the admin group.
async fn save_group(state: &AppState, before: Option<&ScimGroup>, after: ScimGroup) -> ScimResult<ScimGroup> {
    match state.store.put_scim_group(after.clone()).await {
        Ok(()) => {}
        Err(StoreError::Exists) => return Err(ScimError::conflict("There is a group with this displayName already.")),
        Err(error) => return Err(error.into()),
    }
    left_admin_group(state, before, Some(&after)).await?;
    Ok(after)
}

/// Whoever was in the admin group before and is not now loses the admin right (§19.4) — unless
/// they are the last admin.
async fn left_admin_group(state: &AppState, before: Option<&ScimGroup>, after: Option<&ScimGroup>) -> ScimResult<()> {
    let admin_group = {
        let settings = state.settings.read();
        if settings.sso.roles_claim.is_some() {
            return Ok(());
        }
        match &settings.sso.admin_group {
            Some(group) => group.trim().trim_start_matches('/').to_string(),
            None => return Ok(()),
        }
    };
    let named = |group: &ScimGroup| group.display_name.eq_ignore_ascii_case(&admin_group);
    let Some(before) = before.filter(|group| named(group)) else { return Ok(()) };
    let still: Vec<&String> =
        after.filter(|group| named(group)).map(|group| group.members.iter().collect()).unwrap_or_default();
    for id in before.members.iter().filter(|id| !still.contains(id)) {
        let Some(Person::Account(user, _)) = person(state, id).await? else { continue };
        if !user.admin {
            continue;
        }
        if state.store.admin_count().await? <= 1 {
            tracing::warn!(email = %user.email, "SCIM: left the admin group, but is the last admin: stays one");
            continue;
        }
        state.store.update_user(&user.id, |user| user.admin = false).await?;
        log(state, Some(&user), &user.email, format!("took the admin right: no longer in {admin_group}")).await;
    }
    Ok(())
}

async fn create_group(State(state): State<AppState>, _scim: Scim, body: Bytes) -> ScimResult<Response> {
    let body = body_json(&body)?;
    let now = clock::now();
    let group = ScimGroup {
        id: uuid::Uuid::new_v4().to_string(),
        display_name: group_name(&body["displayName"])?,
        external_id: text(&body["externalId"], 255),
        members: member_ids(&body["members"])?,
        created: now.clone(),
        updated: now,
    };
    let group = save_group(&state, None, group).await?;
    let mut response = scim(StatusCode::CREATED, group_json(&group, &state.config.public));
    if let Ok(location) = HeaderValue::from_str(&format!("{}/scim/v2/Groups/{}", state.config.public, group.id)) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    Ok(response)
}

async fn put_group(
    State(state): State<AppState>,
    _scim: Scim,
    Path(id): Path<String>,
    body: Bytes,
) -> ScimResult<Response> {
    let body = body_json(&body)?;
    let before = state.store.scim_group(&id).await?.ok_or_else(ScimError::not_found)?;
    let after = ScimGroup {
        display_name: group_name(&body["displayName"])?,
        external_id: text(&body["externalId"], 255),
        members: member_ids(&body["members"])?,
        updated: clock::now(),
        ..before.clone()
    };
    let group = save_group(&state, Some(&before), after).await?;
    Ok(scim(StatusCode::OK, group_json(&group, &state.config.public)))
}

/// `members[value eq "…"]`: the member a `remove` means.
fn member_in_path(path: &str) -> Option<String> {
    let inner = path.strip_prefix("members[")?.strip_suffix(']')?;
    parse_filter(inner).ok().filter(|(attribute, _)| attribute == "value").map(|(_, value)| value)
}

async fn patch_group(
    State(state): State<AppState>,
    _scim: Scim,
    Path(id): Path<String>,
    body: Bytes,
) -> ScimResult<Response> {
    let body = body_json(&body)?;
    let before = state.store.scim_group(&id).await?.ok_or_else(ScimError::not_found)?;
    let operations = body["Operations"]
        .as_array()
        .or_else(|| body["operations"].as_array())
        .ok_or_else(|| ScimError::bad("invalidSyntax", "A PATCH needs Operations."))?;
    let mut after = before.clone();
    for operation in operations {
        let op = operation["op"].as_str().unwrap_or_default().to_ascii_lowercase();
        let value = &operation["value"];
        let path = operation["path"].as_str().unwrap_or_default().trim().to_string();
        let lower = path.to_ascii_lowercase();
        match (op.as_str(), lower.as_str()) {
            ("replace" | "add", "displayname") => after.display_name = group_name(value)?,
            ("replace" | "add", "externalid") => after.external_id = text(value, 255),
            ("remove", "externalid") => after.external_id = None,
            ("replace", "members") => after.members = member_ids(value)?,
            ("add", "members") => {
                after.members.extend(member_ids(value)?);
                after.members.sort();
                after.members.dedup();
            }
            ("remove", "members") => {
                if value.is_null() {
                    after.members.clear();
                } else {
                    let gone = member_ids(value)?;
                    after.members.retain(|id| !gone.contains(id));
                }
            }
            ("remove", _) if lower.starts_with("members[") => {
                let gone = member_in_path(&path)
                    .ok_or_else(|| ScimError::bad("invalidPath", "Only members[value eq \"…\"] is supported."))?;
                after.members.retain(|id| *id != gone);
            }
            ("replace" | "add", "") => {
                let object = value
                    .as_object()
                    .ok_or_else(|| ScimError::bad("invalidValue", "Without a path, the value is an object."))?;
                if let Some(name) = object.get("displayName") {
                    after.display_name = group_name(name)?;
                }
                if let Some(external) = object.get("externalId") {
                    after.external_id = text(external, 255);
                }
                if let Some(members) = object.get("members") {
                    let ids = member_ids(members)?;
                    if op == "add" {
                        after.members.extend(ids);
                        after.members.sort();
                        after.members.dedup();
                    } else {
                        after.members = ids;
                    }
                }
            }
            ("add" | "replace" | "remove", _) => {}
            _ => return Err(ScimError::bad("invalidSyntax", "An operation is add, replace or remove.")),
        }
    }
    if after.members.len() > MAX_MEMBERS {
        return Err(ScimError::bad("tooMany", "A group has at most 10000 members here."));
    }
    after.updated = clock::now();
    let group = save_group(&state, Some(&before), after).await?;
    Ok(scim(StatusCode::OK, group_json(&group, &state.config.public)))
}

async fn delete_group(State(state): State<AppState>, _scim: Scim, Path(id): Path<String>) -> ScimResult<Response> {
    let group = state.store.delete_scim_group(&id).await?.ok_or_else(ScimError::not_found)?;
    left_admin_group(&state, Some(&group), None).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests;
