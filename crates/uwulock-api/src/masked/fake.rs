//! A UwUMail server on this machine, for the tests: the OAuth side of UwUMail-Server's
//! `maskedemail` scope (discovery, registration of public clients, PKCE, rotating refresh tokens
//! that end the grant when an old one comes back, revocation) and JMAP `MaskedEmail`. Only what
//! the Lock server uses, with switches for what can go wrong.

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Default)]
pub(crate) struct Inner {
    pub base: String,
    pub clients: HashSet<String>,
    pub registrations: u32,
    /// code → (client, redirect uri, challenge)
    codes: HashMap<String, (String, String, String)>,
    /// refresh token → grant, for the one each grant has now.
    refresh: HashMap<String, u32>,
    /// Refresh tokens used already, and their grant.
    pub used: HashMap<String, u32>,
    /// access token → grant
    access: HashMap<String, u32>,
    pub dead_grants: HashSet<u32>,
    next: u32,
    pub refreshes: u32,
    pub revoked: Vec<String>,
    pub addresses: Vec<Value>,
    /// The token endpoint answers 429.
    pub token_busy: bool,
    /// The JMAP API answers 429.
    pub jmap_busy: bool,
    /// The discovery document leaves the scope out.
    pub no_scope: bool,
    pub domains: Vec<String>,
    /// How many addresses the account may have (UwUMail's 5000).
    pub limit: usize,
}

impl Inner {
    fn id(&mut self, prefix: &str) -> String {
        self.next += 1;
        format!("{prefix}{}", self.next)
    }

    fn grant_of(&self, headers: &HeaderMap) -> Option<u32> {
        let token = headers.get("authorization")?.to_str().ok()?.strip_prefix("Bearer ")?;
        let grant = *self.access.get(token)?;
        (!self.dead_grants.contains(&grant)).then_some(grant)
    }

    fn tokens(&mut self, grant: u32) -> Value {
        let access = self.id("access-");
        let refresh = self.id("refresh-");
        self.access.insert(access.clone(), grant);
        self.refresh.insert(refresh.clone(), grant);
        json!({ "access_token": access, "token_type": "Bearer", "expires_in": 3600, "refresh_token": refresh, "scope": "maskedemail" })
    }
}

#[derive(Clone)]
pub(crate) struct Fake {
    pub url: String,
    pub inner: Arc<Mutex<Inner>>,
}

fn oauth_error(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({ "error": error, "error_description": error }))).into_response()
}

impl Fake {
    pub(crate) async fn start() -> Fake {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let inner = Arc::new(Mutex::new(Inner {
            base: url.clone(),
            domains: vec!["example.com".into(), "masked.example.com".into()],
            limit: 100,
            ..Inner::default()
        }));
        let app = Router::new()
            .route("/.well-known/oauth-authorization-server", get(discovery))
            .route("/oauth/register", post(register))
            .route("/oauth/token", post(token))
            .route("/oauth/revoke", post(revoke))
            .route("/jmap/session", get(session))
            .route("/jmap/api", post(api))
            .with_state(inner.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Fake { url, inner }
    }

    /// The person agrees at UwUMail: the code the browser is sent back with, for the
    /// `authorizeUrl` the Lock server made. Panics where UwUMail would refuse.
    pub(crate) fn approve(&self, authorize_url: &str) -> String {
        let url = reqwest::Url::parse(authorize_url).unwrap();
        assert!(authorize_url.starts_with(&format!("{}/oauth/authorize?", self.url)), "{authorize_url}");
        let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["scope"], "maskedemail");
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(query["prompt"], "consent");
        let mut inner = self.inner.lock();
        assert!(inner.clients.contains(&query["client_id"]), "a registered client");
        let code = inner.id("code-");
        inner.codes.insert(
            code.clone(),
            (query["client_id"].clone(), query["redirect_uri"].clone(), query["code_challenge"].clone()),
        );
        code
    }

    /// UwUMail forgets every client, as it does unused ones after seven days.
    pub(crate) fn forget_clients(&self) {
        self.inner.lock().clients.clear();
    }

    /// Every access token runs out now.
    pub(crate) fn expire_access(&self) {
        self.inner.lock().access.clear();
    }
}

async fn discovery(State(inner): State<Arc<Mutex<Inner>>>) -> Json<Value> {
    let inner = inner.lock();
    let base = &inner.base;
    let scopes = if inner.no_scope { json!(["openid", "mail"]) } else { json!(["openid", "mail", "maskedemail"]) };
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "revocation_endpoint": format!("{base}/oauth/revoke"),
        "scopes_supported": scopes,
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "authorization_response_iss_parameter_supported": true,
    }))
}

async fn register(State(inner): State<Arc<Mutex<Inner>>>, Json(body): Json<Value>) -> Response {
    assert!(body["client_name"].as_str().unwrap().starts_with("UwULock ("));
    assert_eq!(body["redirect_uris"].as_array().unwrap().len(), 1);
    let mut inner = inner.lock();
    inner.registrations += 1;
    let id = inner.id("client-");
    inner.clients.insert(id.clone());
    (StatusCode::CREATED, Json(json!({ "client_id": id, "token_endpoint_auth_method": "none" }))).into_response()
}

async fn token(State(inner): State<Arc<Mutex<Inner>>>, Form(form): Form<HashMap<String, String>>) -> Response {
    let mut inner = inner.lock();
    if inner.token_busy {
        return oauth_error(StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable");
    }
    let client = form.get("client_id").cloned().unwrap_or_default();
    if !inner.clients.contains(&client) {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let Some((code_client, redirect, challenge)) = inner.codes.remove(&form["code"]) else {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
            };
            let verifier = form.get("code_verifier").cloned().unwrap_or_default();
            let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()));
            if code_client != client || redirect != form["redirect_uri"] || computed != challenge {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            inner.next += 1;
            let grant = inner.next;
            Json(inner.tokens(grant)).into_response()
        }
        Some("refresh_token") => {
            let presented = form.get("refresh_token").cloned().unwrap_or_default();
            if let Some(grant) = inner.used.get(&presented).copied() {
                // An old refresh token again: somebody has a copy. The grant ends.
                inner.dead_grants.insert(grant);
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            let Some(grant) = inner.refresh.remove(&presented) else {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
            };
            if inner.dead_grants.contains(&grant) {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            inner.used.insert(presented, grant);
            inner.refreshes += 1;
            Json(inner.tokens(grant)).into_response()
        }
        _ => oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    }
}

async fn revoke(State(inner): State<Arc<Mutex<Inner>>>, Form(form): Form<HashMap<String, String>>) -> StatusCode {
    let mut inner = inner.lock();
    let token = form.get("token").cloned().unwrap_or_default();
    if let Some(grant) = inner.refresh.get(&token).copied() {
        inner.dead_grants.insert(grant);
    }
    inner.revoked.push(token);
    StatusCode::OK
}

async fn session(State(inner): State<Arc<Mutex<Inner>>>, headers: HeaderMap) -> Response {
    let inner = inner.lock();
    if inner.grant_of(&headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let capability = super::uwumail::CAPABILITY;
    Json(json!({
        "capabilities": { "urn:ietf:params:jmap:core": {}, capability: {} },
        "accounts": { "a1": { "name": "nyu@example.com", "accountCapabilities": {
            capability: { "domains": inner.domains, "defaultDomain": "masked.example.com" }
        } } },
        "primaryAccounts": { capability: "a1" },
        "username": "nyu@example.com",
        "apiUrl": format!("{}/jmap/api", inner.base),
        "state": "s1",
    }))
    .into_response()
}

async fn api(State(inner): State<Arc<Mutex<Inner>>>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let mut inner = inner.lock();
    if inner.jmap_busy {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    if inner.grant_of(&headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let call = &body["methodCalls"][0];
    let (method, arguments) = (call[0].as_str().unwrap_or_default(), &call[1]);
    assert_eq!(arguments["accountId"], "a1");
    let answer = match method {
        "MaskedEmail/get" => {
            let list: Vec<Value> = match arguments["ids"].as_array() {
                None => inner.addresses.iter().rev().cloned().collect(),
                Some(ids) => inner.addresses.iter().filter(|address| ids.contains(&address["id"])).cloned().collect(),
            };
            json!({ "accountId": "a1", "list": list, "notFound": [] })
        }
        "MaskedEmail/set" => {
            let mut answer = json!({ "accountId": "a1" });
            for (key, create) in arguments["create"].as_object().cloned().unwrap_or_default() {
                if inner.addresses.len() >= inner.limit {
                    answer["notCreated"][&key] =
                        json!({ "type": "forbidden", "description": "An account has at most 5000 masked addresses." });
                    continue;
                }
                let domain = create["domain"].as_str().unwrap_or("masked.example.com").to_string();
                let id = inner.id("x");
                let address = json!({
                    "id": id,
                    "email": format!("quiet.otter{}@{domain}", inner.next),
                    "state": create["state"].as_str().unwrap_or("pending"),
                    "forDomain": create["forDomain"].as_str().unwrap_or_default(),
                    "description": create["description"].as_str().unwrap_or_default(),
                    "url": create["url"],
                    "createdAt": "2026-09-28T12:00:00Z",
                    "lastMessageAt": null,
                    "createdBy": "OAuth:UwULock (vault.example.com)",
                });
                answer["created"][&key] = json!({
                    "id": address["id"], "email": address["email"], "state": address["state"],
                    "createdAt": address["createdAt"], "createdBy": address["createdBy"], "lastMessageAt": null,
                });
                inner.addresses.push(address);
            }
            for (id, patch) in arguments["update"].as_object().cloned().unwrap_or_default() {
                match inner.addresses.iter_mut().find(|address| address["id"] == id.as_str()) {
                    Some(address) => {
                        for (key, value) in patch.as_object().cloned().unwrap_or_default() {
                            address[key] = value;
                        }
                        answer["updated"][&id] = Value::Null;
                    }
                    None => answer["notUpdated"][&id] = json!({ "type": "notFound" }),
                }
            }
            answer
        }
        _ => return Json(json!({ "methodResponses": [["error", { "type": "forbidden" }, "0"]] })).into_response(),
    };
    Json(json!({ "methodResponses": [[method, answer, "0"]], "sessionState": "s1" })).into_response()
}
