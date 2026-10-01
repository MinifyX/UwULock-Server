//! Addresses that may not log in (docs/failed-logins.md): an admin blocks an address or a
//! network from the failed-logins page, for some hours or until lifted.
//!
//! A blocked client gets 403 `ip_blocked` from every endpoint that logs in or leads to a login
//! ([`is_login_path`]): the token endpoint with all its grants (password, refresh, API key,
//! passkey, SSO code, Send access), the prelogin, registering, the password hint, the mail with
//! a second-step code, the passkey login's options, the SSO start, and "log in with a device".
//! The web vault and the admin portal log in through the same endpoints. Everything else, like
//! the vault of an account that is logged in already, is not affected. The address is the one
//! the rest of the server believes (behind a trusted proxy, what it forwarded).

use crate::AppState;
use crate::auth::{Admin, ClientIp, client_ip, now_seconds};
use crate::errors::{ApiError, ApiResult};
use crate::networks::IpNetwork;
use axum::extract::{Path, Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use parking_lot::RwLock;
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use uwulock_store::{IpBlock, clock};

/// How long a block may be: a year. Longer is "until lifted".
const MOST_HOURS: i64 = 366 * 24;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/admin/ip-blocks", get(list).post(create))
        .route("/uwu/v1/admin/ip-blocks/{id}", delete(remove))
}

/// The blocks in force, as the guard checks them: read from the database at the start, after
/// every change, and again every minute (the command line changes the database, not the
/// running server).
#[derive(Default)]
pub struct Blocks {
    list: RwLock<Vec<(IpNetwork, Option<i64>)>>,
    loaded: AtomicI64,
}

impl Blocks {
    pub async fn reload(&self, store: &uwulock_store::Store) {
        match store.ip_blocks().await {
            Ok(blocks) => {
                let parsed = blocks
                    .iter()
                    .filter_map(|block| {
                        let network = IpNetwork::parse(&block.network).ok()?;
                        Some((network, block.expires.as_deref().and_then(clock::parse).map(|t| t.unix_timestamp())))
                    })
                    .collect();
                *self.list.write() = parsed;
                self.loaded.store(now_seconds(), Ordering::Relaxed);
            }
            Err(error) => tracing::warn!(%error, "the blocked addresses could not be read"),
        }
    }

    /// Whether `ip` is blocked right now.
    pub fn blocks(&self, ip: IpAddr) -> bool {
        let now = now_seconds();
        self.list.read().iter().any(|(network, expires)| expires.is_none_or(|end| end > now) && network.contains(ip))
    }

    /// Read again when the last read is older than `seconds`; whether it was.
    async fn reload_after(&self, store: &uwulock_store::Store, seconds: i64) -> bool {
        let (now, last) = (now_seconds(), self.loaded.load(Ordering::Relaxed));
        if now - last < seconds
            || self.loaded.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_err()
        {
            return false;
        }
        self.reload(store).await;
        true
    }
}

/// Whether a request logs in, or is a step towards a login. See the module's documentation.
pub fn is_login_path(method: &Method, path: &str) -> bool {
    let path = path.trim_end_matches('/');
    path.starts_with("/identity/")
        || matches!(path, "/api/accounts/prelogin" | "/api/accounts/password-hint" | "/api/two-factor/send-email-login")
        || (path == "/api/auth-requests" && method == Method::POST)
        || (path.starts_with("/api/auth-requests/") && path.ends_with("/response"))
}

/// The middleware: 403 for a blocked address at the login endpoints.
pub(crate) async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if !is_login_path(request.method(), request.uri().path()) {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let ip = client_ip(&parts, state.config.trust_forwarded);
    state.blocks.reload_after(&state.store, 60).await;
    // A block lifted on the command line counts within seconds.
    if state.blocks.blocks(ip) && !(state.blocks.reload_after(&state.store, 5).await && !state.blocks.blocks(ip)) {
        tracing::info!(%ip, path = parts.uri.path(), "a login from a blocked address was refused");
        return ApiError::forbidden("Logins from your address are blocked on this server for now.")
            .code("ip_blocked")
            .into_response();
    }
    next.run(Request::from_parts(parts, body)).await
}

fn block_json(state: &AppState, block: &IpBlock, language: &str) -> Value {
    let place = IpNetwork::parse(&block.network)
        .ok()
        .filter(|network| network.prefix() == 32 || network.prefix() == 128)
        .and_then(|_| block.network.parse::<IpAddr>().ok())
        .and_then(|ip| crate::failed_logins::place(state, ip, language));
    json!({
        "id": block.id,
        "network": block.network,
        "reason": block.reason,
        "created": block.created,
        "expires": block.expires,
        "createdBy": block.created_by,
        "place": place,
    })
}

async fn list(State(state): State<AppState>, admin: Admin, ClientIp(ip): ClientIp) -> ApiResult<Json<Value>> {
    let language = admin.0.user.language.clone();
    let blocks: Vec<Value> =
        state.store.ip_blocks().await?.iter().map(|block| block_json(&state, block, &language)).collect();
    Ok(Json(json!({ "object": "ipBlocks", "blocks": blocks, "yourAddress": ip.to_string() })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewBlock {
    network: String,
    #[serde(default)]
    reason: String,
    /// None: until lifted.
    #[serde(default)]
    hours: Option<i64>,
}

async fn create(
    State(state): State<AppState>,
    admin: Admin,
    ClientIp(ip): ClientIp,
    Json(body): Json<NewBlock>,
) -> ApiResult<Json<Value>> {
    let network = IpNetwork::parse(&body.network).map_err(ApiError::bad)?;
    let v4 = body.network.contains('.') && !body.network.contains(':');
    if network.prefix() < if v4 { 8 } else { 16 } {
        return Err(ApiError::bad("That network is too large to block; at most a /8 (IPv4) or a /16 (IPv6)."));
    }
    if network.contains(ip) {
        return Err(ApiError::bad("This is your own address: you would shut yourself out.").code("would_lock_out"));
    }
    let hours = body.hours.filter(|hours| *hours > 0);
    if hours.is_some_and(|hours| hours > MOST_HOURS) {
        return Err(ApiError::bad("A block lasts at most a year; leave the time out for one until lifted."));
    }
    let reason: String = body.reason.chars().filter(|char| !char.is_control()).take(200).collect();
    let block = state
        .store
        .block_ip(
            &network.to_string(),
            reason.trim(),
            hours.map(|hours| clock::in_seconds(hours * 3600)),
            Some(admin.0.user.email.clone()),
        )
        .await?;
    state.blocks.reload(&state.store).await;
    let until = hours.map_or("until lifted".to_string(), |hours| format!("for {hours} hours"));
    crate::admin::record(&state, &admin, format!("blocked {} {until}", block.network)).await;
    Ok(Json(block_json(&state, &block, &admin.0.user.language)))
}

async fn remove(State(state): State<AppState>, admin: Admin, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let block = state.store.unblock_ip(id).await?.ok_or_else(|| ApiError::not_found("There is no such block."))?;
    state.blocks.reload(&state.store).await;
    crate::admin::record(&state, &admin, format!("lifted the block of {}", block.network)).await;
    Ok(Json(json!({ "object": "ipBlock", "id": id })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::json;

    /// A request to `path` from `ip`, behind the trusted proxy.
    fn from(ip: &str, method: &str, path: &str, body: Body, form: bool) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("x-forwarded-for", ip)
            .header("content-type", if form { "application/x-www-form-urlencoded" } else { "application/json" })
            .body(body)
            .unwrap()
    }

    fn login_body(email: &str) -> Body {
        let fields = login_form(email, "d1");
        let text: Vec<String> = fields.iter().map(|(key, value)| format!("{key}={}", urlencode(value))).collect();
        Body::from(text.join("&"))
    }

    #[test]
    fn a_block_that_ran_out_blocks_nothing() {
        let blocks = Blocks::default();
        let network = IpNetwork::parse("203.0.113.0/24").unwrap();
        *blocks.list.write() = vec![(network, Some(now_seconds() - 1))];
        assert!(!blocks.blocks("203.0.113.1".parse().unwrap()));
        *blocks.list.write() =
            vec![(network, Some(now_seconds() + 60)), (IpNetwork::parse("198.51.100.1").unwrap(), None)];
        assert!(blocks.blocks("203.0.113.1".parse().unwrap()) && blocks.blocks("198.51.100.1".parse().unwrap()));
        assert!(!blocks.blocks("198.51.100.2".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_blocked_address_logs_in_nowhere_until_the_block_runs_out_or_is_lifted() {
        let server = TestServer::new().await.behind_proxy();
        let admin = server.admin().await;
        server.account("nyu@example.com").await;
        let (bad, lan) = ("203.0.113.66", "192.0.2.10");

        let own = server
            .call_from(lan, "POST", "/uwu/v1/admin/ip-blocks", &admin.token, json!({"network": "192.0.2.0/24"}))
            .await;
        assert_eq!(own.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(own).await["code"], "would_lock_out");
        let huge = server
            .call_from(lan, "POST", "/uwu/v1/admin/ip-blocks", &admin.token, json!({"network": "0.0.0.0/0"}))
            .await;
        assert_eq!(huge.status(), StatusCode::BAD_REQUEST);

        let blocked = server
            .call_from(
                lan,
                "POST",
                "/uwu/v1/admin/ip-blocks",
                &admin.token,
                json!({"network": " 203.0.113.66 ", "reason": "tries passwords", "hours": 2}),
            )
            .await;
        assert_eq!(blocked.status(), StatusCode::OK);
        let block = json(blocked).await;
        assert_eq!(block["network"], "203.0.113.66");
        assert!(block["expires"].is_string());

        // Every login endpoint refuses the address.
        let requests = [
            from(bad, "POST", "/identity/connect/token", login_body("nyu@example.com"), true),
            from(bad, "POST", "/identity/accounts/prelogin", Body::from(r#"{"email":"nyu@example.com"}"#), false),
            from(bad, "POST", "/api/accounts/prelogin", Body::from(r#"{"email":"nyu@example.com"}"#), false),
            from(
                bad,
                "POST",
                "/identity/accounts/prelogin/password",
                Body::from(r#"{"email":"a@example.com"}"#),
                false,
            ),
            from(bad, "GET", "/identity/accounts/webauthn/assertion-options", Body::empty(), false),
            from(bad, "POST", "/api/two-factor/send-email-login", Body::from(r#"{"email":"nyu@example.com"}"#), false),
            from(bad, "POST", "/api/accounts/password-hint", Body::from(r#"{"email":"nyu@example.com"}"#), false),
            from(bad, "POST", "/api/auth-requests", Body::from("{}"), false),
            from(bad, "GET", "/api/auth-requests/x/response?code=y", Body::empty(), false),
            from(bad, "POST", "/identity/accounts/register/finish", Body::from("{}"), false),
        ];
        for request in requests {
            let path = request.uri().to_string();
            let response = server.send(request).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
            assert_eq!(json(response).await["code"], "ip_blocked", "{path}");
        }
        // Others log in, and the blocked address still reaches what is not a login.
        let other =
            server.send(from(lan, "POST", "/identity/connect/token", login_body("nyu@example.com"), true)).await;
        assert_eq!(other.status(), StatusCode::OK);
        assert_eq!(server.send(from(bad, "GET", "/uwu/v1/info", Body::empty(), false)).await.status(), StatusCode::OK);

        // A block that ran out lets the address in again, without anybody lifting it.
        server.state.store.block_ip("203.0.113.66", "", Some(clock::in_seconds(-1)), None).await.unwrap();
        server.state.blocks.reload(&server.state.store).await;
        let again =
            server.send(from(bad, "POST", "/identity/connect/token", login_body("nyu@example.com"), true)).await;
        assert_eq!(again.status(), StatusCode::OK, "the block ran out");
        assert!(json(server.call_from(lan, "GET", "/uwu/v1/admin/ip-blocks", &admin.token, json!({})).await).await
            ["blocks"]
            .as_array()
            .unwrap()
            .is_empty());

        // A network until lifted, and lifted.
        let net = json(
            server
                .call_from(lan, "POST", "/uwu/v1/admin/ip-blocks", &admin.token, json!({"network": "2001:db8::5/64"}))
                .await,
        )
        .await;
        assert_eq!((net["network"].clone(), net["expires"].clone()), (json!("2001:db8::/64"), Value::Null));
        let v6 = "2001:db8::abcd";
        let refused =
            server.send(from(v6, "POST", "/identity/connect/token", login_body("nyu@example.com"), true)).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let listed = json(server.call_from(lan, "GET", "/uwu/v1/admin/ip-blocks", &admin.token, json!({})).await).await;
        assert_eq!(listed["yourAddress"], lan);
        assert_eq!(listed["blocks"][0]["createdBy"], "admin@example.com");
        let path = format!("/uwu/v1/admin/ip-blocks/{}", net["id"]);
        assert_eq!(server.call_from(lan, "DELETE", &path, &admin.token, json!({})).await.status(), StatusCode::OK);
        assert_eq!(
            server.call_from(lan, "DELETE", &path, &admin.token, json!({})).await.status(),
            StatusCode::NOT_FOUND
        );
        let back = server.send(from(v6, "POST", "/identity/connect/token", login_body("nyu@example.com"), true)).await;
        assert_eq!(back.status(), StatusCode::OK, "lifted");
        let events = server.state.store.events(Some("admin".into()), None, 10).await.unwrap();
        let details: Vec<_> = events.iter().filter_map(|event| event.detail.clone()).collect();
        assert!(details.contains(&"blocked 203.0.113.66 for 2 hours".to_string()), "{details:?}");
        assert!(details.contains(&"lifted the block of 2001:db8::/64".to_string()), "{details:?}");
    }

    #[tokio::test]
    async fn a_block_lifted_on_the_command_line_counts_within_seconds() {
        let server = TestServer::new().await.behind_proxy();
        server.account("nyu@example.com").await;
        server.state.store.block_ip("198.51.100.9", "", None, None).await.unwrap();
        server.state.blocks.reload(&server.state.store).await;
        let request = || from("198.51.100.9", "POST", "/identity/connect/token", login_body("nyu@example.com"), true);
        assert_eq!(server.send(request()).await.status(), StatusCode::FORBIDDEN);
        assert!(server.state.store.unblock_network("198.51.100.9").await.unwrap());
        server.state.blocks.loaded.store(0, Ordering::Relaxed);
        assert_eq!(server.send(request()).await.status(), StatusCode::OK);
    }

    #[test]
    fn login_paths_are_known() {
        for (method, path) in [
            (Method::POST, "/identity/connect/token"),
            (Method::GET, "/identity/sso/prevalidate"),
            (Method::GET, "/identity/connect/authorize"),
            (Method::POST, "/api/accounts/prelogin"),
            (Method::POST, "/api/auth-requests"),
            (Method::GET, "/api/auth-requests/abc/response"),
        ] {
            assert!(is_login_path(&method, path), "{path}");
        }
        for (method, path) in [
            (Method::GET, "/api/auth-requests"),
            (Method::PUT, "/api/auth-requests/abc"),
            (Method::GET, "/api/sync"),
            (Method::GET, "/uwu/v1/admin/users"),
            (Method::GET, "/identityx"),
        ] {
            assert!(!is_login_path(&method, path), "{path}");
        }
    }
}
