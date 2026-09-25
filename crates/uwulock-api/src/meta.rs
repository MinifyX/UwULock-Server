//! The rest of what the official clients ask: the server's configuration and version,
//! equivalent domains — and empty answers for what this server does not have yet (sends,
//! emergency access, organisations, passkey login), so a client that looks finds nothing
//! instead of an error.

use crate::auth::Session;
use crate::errors::ApiResult;
use crate::{AppState, json as out};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::LazyLock;
use uwulock_store::User;

/// The Bitwarden server version this one answers like. The clients turn features on and off by
/// it, so it has to be one whose features this server has — the same Vaultwarden gives.
const BITWARDEN_VERSION: &str = "2026.6.0";

/// Groups of domains that belong together, like `google.com` and `youtube.com`: Bitwarden's own
/// list (from its server, by way of Vaultwarden), so a login fills in on each of them.
static GLOBAL_DOMAINS: LazyLock<Vec<Value>> =
    LazyLock::new(|| serde_json::from_str(include_str!("global_domains.json")).expect("the domain list parses"));

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/config", get(config))
        .route("/api/version", get(version))
        .route("/api/settings/domains", get(get_domains).post(set_domains).put(set_domains))
        .route("/api/webauthn", get(empty_list))
        .route("/api/emergency-access/trusted", get(empty_list))
        .route("/api/emergency-access/granted", get(empty_list))
        .route("/api/sends", get(empty_list))
        .route("/api/collections", get(empty_list))
        .route("/api/auth-requests", get(empty_list))
        .route("/api/auth-requests/pending", get(empty_list))
        .route("/api/organizations", get(empty_list))
        .route("/api/policies", get(empty_list))
        .route("/api/tasks", get(tasks))
        .route("/events/collect", post(nothing))
        .route("/app-id.json", get(app_id))
        .route("/.well-known/apple-app-site-association", get(apple_association))
}

async fn config(State(state): State<AppState>) -> Json<Value> {
    let public = &state.config.public;
    Json(json!({
        "version": BITWARDEN_VERSION,
        "gitHash": null,
        "server": { "name": "UwULock Server", "url": "https://github.com/MinifyX/UwULock-Server" },
        "settings": { "disableUserRegistration": true, "suppressOnboardingInterstitials": false },
        "environment": {
            "vault": public,
            "api": format!("{public}/api"),
            "identity": format!("{public}/identity"),
            "notifications": format!("{public}/notifications"),
            "sso": "",
            "cloudRegion": null,
        },
        "push": { "pushTechnology": 0, "vapidPublicKey": null },
        "featureStates": { "pm-19148-innovation-archive": true },
        "communication": null,
        "object": "config",
    }))
}

async fn version(State(state): State<AppState>) -> Json<&'static str> {
    Json(state.version)
}

/// The user's own groups, and Bitwarden's — flagged when the user turned one off, or left out
/// entirely for a sync.
pub(crate) fn domains(user: &User, flag_excluded: bool) -> Value {
    let own: Value = serde_json::from_str(&user.equivalent_domains).unwrap_or_else(|_| json!([]));
    let excluded: Vec<i64> = serde_json::from_str(&user.excluded_globals).unwrap_or_default();
    let global: Vec<Value> = GLOBAL_DOMAINS
        .iter()
        .filter_map(|group| {
            let off = group["type"].as_i64().is_some_and(|kind| excluded.contains(&kind));
            if off && !flag_excluded {
                return None;
            }
            let mut group = group.clone();
            group["excluded"] = off.into();
            Some(group)
        })
        .collect();
    json!({ "equivalentDomains": own, "globalEquivalentDomains": global, "object": "domains" })
}

async fn get_domains(session: Session) -> Json<Value> {
    Json(domains(&session.user, true))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DomainsData {
    #[serde(default)]
    excluded_global_equivalent_domains: Option<Vec<i64>>,
    #[serde(default)]
    equivalent_domains: Option<Vec<Vec<String>>>,
}

async fn set_domains(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<DomainsData>,
) -> ApiResult<Json<Value>> {
    let excluded =
        serde_json::to_string(&data.excluded_global_equivalent_domains.unwrap_or_default()).expect("numbers serialize");
    let own = serde_json::to_string(&data.equivalent_domains.unwrap_or_default()).expect("strings serialize");
    state
        .store
        .update_user(&session.user.id, move |user| {
            user.excluded_globals = excluded;
            user.equivalent_domains = own;
            user.revision = uwulock_store::clock::now();
        })
        .await?;
    Ok(Json(json!({})))
}

async fn empty_list(_session: Session) -> Json<Value> {
    Json(out::list(Vec::new()))
}

async fn tasks() -> Json<Value> {
    Json(json!({ "data": [], "object": "list" }))
}

async fn nothing() -> StatusCode {
    StatusCode::OK
}

/// For security keys: which apps may use this server's name.
async fn app_id(State(state): State<AppState>) -> impl axum::response::IntoResponse {
    let body = json!({
        "trustedFacets": [{
            "version": { "major": 1, "minor": 0 },
            "ids": [state.config.public, "ios:bundle-id:com.8bit.bitwarden", "android:apk-key-hash:dUGFzUzf3lmHSLBDBIv+WaFyZMI"],
        }],
    });
    ([(axum::http::header::CONTENT_TYPE, "application/fido.trusted-apps+json")], body.to_string())
}

/// Lets the Bitwarden app on iOS fill in passwords for this server's own pages.
async fn apple_association() -> Json<Value> {
    Json(
        json!({ "webcredentials": { "apps": ["LTZ2PFU5D6.com.8bit.bitwarden", "LTZ2PFU5D6.com.8bit.bitwarden.beta"] } }),
    )
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use serde_json::json;

    #[tokio::test]
    async fn the_config_points_the_clients_here() {
        let server = TestServer::new().await;
        let config = json(server.get("/api/config").await).await;
        assert_eq!(config["environment"]["api"], "https://vault.example.com/api");
        assert_eq!(config["featureStates"]["pm-19148-innovation-archive"], true);
        assert_eq!(config["object"], "config");
    }

    #[tokio::test]
    async fn equivalent_domains_are_the_user_s_and_bitwarden_s() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let body =
            json!({"equivalentDomains": [["example.com", "example.net"]], "excludedGlobalEquivalentDomains": [2]});
        server.call("POST", "/api/settings/domains", Some(&account.token), body).await;
        let domains = json(server.get_as(&account.token, "/api/settings/domains").await).await;
        assert_eq!(domains["equivalentDomains"], json!([["example.com", "example.net"]]));
        let two = domains["globalEquivalentDomains"].as_array().unwrap().iter().find(|g| g["type"] == 2).unwrap();
        assert_eq!(two["excluded"], true);
        let request = axum::http::Request::get("/api/sync")
            .header("authorization", format!("Bearer {}", account.token))
            .body(axum::body::Body::empty())
            .unwrap();
        let sync = json(server.send(request).await).await;
        assert!(
            sync["domains"]["globalEquivalentDomains"].as_array().unwrap().iter().all(|g| g["type"] != 2),
            "left out in a sync"
        );
    }

    #[tokio::test]
    async fn what_is_not_here_yet_is_empty() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        for path in ["/api/sends", "/api/emergency-access/trusted", "/api/auth-requests", "/api/webauthn"] {
            let body = json(server.get_as(&account.token, path).await).await;
            assert_eq!(body["data"], json!([]), "{path}");
        }
    }
}
