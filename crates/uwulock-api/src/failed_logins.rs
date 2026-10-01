//! `/uwu/v1/admin/failed-logins`: the admin portal's page of refused logins
//! (docs/failed-logins.md) — each attempt with where it came from (GeoIP, on this server), the
//! client and device, the account it was for; the same grouped by address; the history of one
//! address; and the GeoIP databases' state.

use crate::AppState;
use crate::auth::{Admin, device_type_name};
use crate::errors::{ApiError, ApiResult};
use crate::geoip::Place;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::IpAddr;
use uwulock_store::{EVENT_DAYS, Event, LoginFilter, clock};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/admin/failed-logins", get(attempts))
        .route("/uwu/v1/admin/failed-logins/by-ip", get(by_ip))
        .route("/uwu/v1/admin/geoip", get(geoip_status))
        .route("/uwu/v1/admin/geoip/update", post(geoip_update))
}

/// Where `ip` is, while GeoIP is on and its databases are there.
pub(crate) fn place(state: &AppState, ip: IpAddr, language: &str) -> Option<Place> {
    if !state.settings().geoip {
        return None;
    }
    state.geoip.lookup(ip, language)
}

const REASONS: [&str; 5] = ["password", "unknown-account", "disabled", "api-key", "two-factor"];

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct FilterQuery {
    /// The last so many hours; all 90 days the events are kept when left out.
    #[serde(default)]
    hours: Option<i64>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    /// The logins that worked too (the history of an address).
    #[serde(default)]
    all: bool,
    #[serde(default)]
    before: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

impl FilterQuery {
    fn filter(&self) -> ApiResult<LoginFilter> {
        let reason = self.reason.clone().filter(|reason| !reason.is_empty());
        if reason.as_deref().is_some_and(|reason| !REASONS.contains(&reason)) {
            return Err(ApiError::bad("Unknown reason."));
        }
        let hours = self.hours.filter(|hours| *hours > 0).map(|hours| hours.min(EVENT_DAYS * 24));
        let clip = |text: &Option<String>| text.as_ref().map(|text| text.trim().chars().take(254).collect::<String>());
        Ok(LoginFilter {
            since: hours.map(|hours| clock::in_seconds(-hours * 3600)),
            user: clip(&self.user),
            ip: clip(&self.ip),
            reason,
            all: self.all,
        })
    }
}

/// Places of many addresses, each looked up once.
struct Places<'a> {
    state: &'a AppState,
    language: String,
    seen: HashMap<String, Option<Place>>,
}

impl Places<'_> {
    fn of(&mut self, ip: Option<&str>) -> Option<Place> {
        let ip = ip?;
        if let Some(known) = self.seen.get(ip) {
            return known.clone();
        }
        let found = ip.parse().ok().and_then(|address| place(self.state, address, &self.language));
        self.seen.insert(ip.to_string(), found.clone());
        found
    }
}

async fn attempts(
    State(state): State<AppState>,
    admin: Admin,
    Query(query): Query<FilterQuery>,
) -> ApiResult<Json<Value>> {
    let filter = query.filter()?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let events = state.store.login_events(filter, query.before, limit).await?;
    // The accounts that are there still, for the links to them.
    let mut accounts: HashMap<String, Option<String>> = HashMap::new();
    for id in events.iter().filter_map(|event| event.user_id.as_ref()) {
        if !accounts.contains_key(id) {
            let user = state.store.user(id).await?;
            accounts.insert(id.clone(), user.map(|user| user.email));
        }
    }
    let mut places = Places { state: &state, language: admin.0.user.language.clone(), seen: HashMap::new() };
    let list: Vec<Value> =
        events.iter().map(|event| attempt_json(event, &accounts, places.of(event.ip.as_deref()))).collect();
    Ok(Json(json!({
        "object": "failedLogins",
        "attempts": list,
        "more": list.len() as i64 == limit,
        "geoip": state.settings().geoip && state.geoip.ready(),
    })))
}

fn attempt_json(event: &Event, accounts: &HashMap<String, Option<String>>, place: Option<Place>) -> Value {
    let account = event.user_id.as_ref().and_then(|id| Some(json!({ "id": id, "email": accounts.get(id)?.clone()? })));
    json!({
        "id": event.id,
        "time": event.time,
        "kind": event.kind,
        "reason": event.reason,
        "email": event.email,
        "account": account,
        "ip": event.ip,
        "place": place,
        "deviceType": event.device_type.map(device_type_name),
        "deviceName": event.device_name.as_deref().or(if event.kind == "login" { event.detail.as_deref() } else { None }),
        "userAgent": event.user_agent,
        "clientName": event.client_name,
        "clientVersion": event.client_version,
        "detail": event.detail,
    })
}

async fn by_ip(
    State(state): State<AppState>,
    admin: Admin,
    Query(query): Query<FilterQuery>,
) -> ApiResult<Json<Value>> {
    let filter = query.filter()?;
    let groups = state.store.failed_by_ip(filter, query.limit.unwrap_or(100).clamp(1, 500)).await?;
    let mut places = Places { state: &state, language: admin.0.user.language.clone(), seen: HashMap::new() };
    let list: Vec<Value> = groups
        .iter()
        .map(|group| {
            let blocked = group.ip.parse().is_ok_and(|ip| state.blocks.blocks(ip));
            json!({
                "ip": group.ip,
                "attempts": group.attempts,
                "first": group.first,
                "last": group.last,
                "targets": group.targets,
                "unknown": group.unknown,
                "emails": group.emails,
                "logins": group.logins,
                "place": places.of(Some(&group.ip)),
                "blocked": blocked,
            })
        })
        .collect();
    Ok(Json(json!({ "object": "failedLoginsByIp", "groups": list })))
}

async fn geoip_status(State(state): State<AppState>, _admin: Admin) -> Json<Value> {
    let status = state.geoip.status();
    Json(json!({
        "object": "geoip",
        "enabled": state.settings().geoip,
        "ready": state.geoip.ready(),
        "month": status.month,
        "cityBytes": status.city_bytes,
        "asnBytes": status.asn_bytes,
        "attempted": status.attempted,
        "error": status.error,
        "updating": state.geoip.updating(),
        "source": { "name": "DB-IP", "url": "https://db-ip.com", "license": "CC BY 4.0",
                    "licenseUrl": "https://creativecommons.org/licenses/by/4.0/",
                    "attribution": "IP Geolocation by DB-IP" },
    }))
}

/// Download the databases now, beside the request: the city file takes a while.
async fn geoip_update(State(state): State<AppState>, admin: Admin) -> ApiResult<(StatusCode, Json<Value>)> {
    if !state.settings().geoip {
        return Err(ApiError::bad("GeoIP is switched off."));
    }
    crate::admin::record(&state, &admin, "asked for the GeoIP databases".into()).await;
    let background = state.clone();
    tokio::spawn(async move {
        let _ = crate::geoip::update_now(&background).await;
    });
    Ok((StatusCode::ACCEPTED, Json(json!({ "object": "geoip", "updating": true }))))
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::json;

    #[tokio::test]
    async fn failed_logins_show_where_from_with_what_and_for_whom() {
        let server = TestServer::new().await.behind_proxy();
        let (city, asn) = crate::geoip::tests::fixtures();
        server.state.geoip.install(&city, &asn);
        let admin = server.admin().await;
        let nyu = server.account("nyu@example.com").await;
        let lan = "192.0.2.10";
        let attempt = |email: &str, ip: &str| {
            let mut fields = login_form(email, "phone-1");
            fields[2].1 = "wrong";
            fields[7].1 = "Pixel 9";
            let body: Vec<String> = fields.iter().map(|(key, value)| format!("{key}={}", urlencode(value))).collect();
            Request::post("/identity/connect/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("x-forwarded-for", ip)
                .header("user-agent", "Bitwarden_Mobile/2026.9.0 (Android 16)")
                .header("bitwarden-client-name", "mobile")
                .header("bitwarden-client-version", "2026.9.0")
                .body(Body::from(body.join("&")))
                .unwrap()
        };
        for (email, ip) in [
            ("nyu@example.com", "203.0.113.5"),
            ("nyu@example.com", "203.0.113.5"),
            ("ghost@example.com", "203.0.113.5"),
            ("nyu@example.com", "2001:db8::9"),
        ] {
            assert_eq!(server.send(attempt(email, ip)).await.status(), StatusCode::BAD_REQUEST);
        }

        let page =
            json(server.call_from(lan, "GET", "/uwu/v1/admin/failed-logins?hours=24", &admin.token, json!({})).await)
                .await;
        assert_eq!(page["geoip"], true);
        let list = page["attempts"].as_array().unwrap();
        assert_eq!(list.len(), 4);
        let newest = &list[0];
        assert_eq!(newest["ip"], "2001:db8::9");
        assert_eq!(newest["place"]["city"], "Wien", "in the admin's language");
        assert_eq!(newest["reason"], "password");
        assert_eq!(newest["account"], json!({ "id": nyu.id, "email": "nyu@example.com" }));
        assert_eq!(newest["deviceName"], "Pixel 9");
        assert_eq!(newest["clientName"], "mobile");
        assert_eq!(newest["clientVersion"], "2026.9.0");
        assert_eq!(newest["userAgent"], "Bitwarden_Mobile/2026.9.0 (Android 16)");
        assert_eq!(newest["deviceType"], "Firefox Extension");
        let ghost = &list[1];
        assert_eq!((ghost["reason"].clone(), ghost["account"].clone()), (json!("unknown-account"), json!(null)));
        assert_eq!(ghost["place"]["network"], "Example Net");
        assert_eq!(ghost["place"]["asn"], 64496);

        let filtered = json(
            server
                .call_from(lan, "GET", "/uwu/v1/admin/failed-logins?reason=unknown-account", &admin.token, json!({}))
                .await,
        )
        .await;
        assert_eq!(filtered["attempts"].as_array().unwrap().len(), 1);
        let bad =
            server.call_from(lan, "GET", "/uwu/v1/admin/failed-logins?reason=nope", &admin.token, json!({})).await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

        let groups =
            json(server.call_from(lan, "GET", "/uwu/v1/admin/failed-logins/by-ip", &admin.token, json!({})).await)
                .await;
        let first = &groups["groups"][0];
        assert_eq!((first["ip"].clone(), first["attempts"].clone()), (json!("203.0.113.5"), json!(3)));
        assert_eq!((first["targets"].clone(), first["unknown"].clone()), (json!(2), json!(1)));
        assert_eq!(first["place"]["country"], "DE");
        assert_eq!(first["blocked"], false);

        // The history of an address: the logins that worked from it too.
        server
            .send(
                Request::post("/identity/connect/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("x-forwarded-for", "203.0.113.5")
                    .body(Body::from(
                        login_form("nyu@example.com", "d7")
                            .iter()
                            .map(|(key, value)| format!("{key}={}", urlencode(value)))
                            .collect::<Vec<_>>()
                            .join("&"),
                    ))
                    .unwrap(),
            )
            .await;
        let history = json(
            server
                .call_from(lan, "GET", "/uwu/v1/admin/failed-logins?ip=203.0.113.5&all=true", &admin.token, json!({}))
                .await,
        )
        .await;
        let history = history["attempts"].as_array().unwrap();
        assert_eq!(history.len(), 4);
        assert_eq!((history[0]["kind"].clone(), history[0]["deviceName"].clone()), (json!("login"), json!("firefox")));

        // Switched off, nothing is looked up.
        let mut settings =
            json(server.call_from(lan, "GET", "/uwu/v1/admin/settings", &admin.token, json!({})).await).await;
        settings["geoip"] = json!(false);
        assert_eq!(
            server.call_from(lan, "PUT", "/uwu/v1/admin/settings", &admin.token, settings).await.status(),
            StatusCode::OK
        );
        let off =
            json(server.call_from(lan, "GET", "/uwu/v1/admin/failed-logins", &admin.token, json!({})).await).await;
        assert_eq!(off["geoip"], false);
        assert!(off["attempts"][0]["place"].is_null());
        let status = json(server.call_from(lan, "GET", "/uwu/v1/admin/geoip", &admin.token, json!({})).await).await;
        assert_eq!((status["enabled"].clone(), status["month"].clone()), (json!(false), json!("2026-10")));
        let update = server.call_from(lan, "POST", "/uwu/v1/admin/geoip/update", &admin.token, json!({})).await;
        assert_eq!(update.status(), StatusCode::BAD_REQUEST);

        let user = server.call_from(lan, "GET", "/uwu/v1/admin/failed-logins", &nyu.token, json!({})).await;
        assert_eq!(user.status(), StatusCode::FORBIDDEN, "only for admins");
    }
}
