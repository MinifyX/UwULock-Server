//! "Log in with a device": a new device asks with its public key and a code it made; a device
//! that is logged in shows the request with its fingerprint phrase and, if the person says yes,
//! answers with the user key wrapped for that public key. The new device then logs in once with
//! its code instead of the master password — no second step, the approval is one.
//!
//! Whoever asks without being logged in learns nothing from the answer about which addresses
//! have an account: an unknown one gets a request too, which nobody will ever answer.

use crate::auth::{self, ClientIp, Session, device_type_name};
use crate::errors::{ApiError, ApiResult};
use crate::{AppState, json as out};
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_store::{AuthRequest, Event, clock};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth-requests", get(list).post(create))
        .route("/api/auth-requests/pending", get(pending))
        .route("/api/auth-requests/{id}", get(one).put(answer))
        .route("/api/auth-requests/{id}/response", get(response))
}

fn render(state: &AppState, request: &AuthRequest) -> Value {
    json!({
        "id": request.id,
        "publicKey": request.public_key,
        "requestDeviceType": device_type_name(request.device_type),
        "requestDeviceTypeValue": request.device_type,
        "requestDeviceIdentifier": request.device_id,
        "requestIpAddress": request.ip,
        "requestCountryName": null,
        "key": request.key,
        "masterPasswordHash": request.master_password_hash,
        "creationDate": request.created,
        "responseDate": request.responded,
        "requestApproved": request.approved,
        "origin": state.config.public,
        "object": "auth-request",
    })
}

fn device_type(headers: &HeaderMap) -> i64 {
    headers
        .get("device-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(14)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ask {
    email: String,
    public_key: String,
    device_identifier: String,
    access_code: String,
    #[serde(default, rename = "type")]
    kind: Option<Value>,
}

async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(data): Json<Ask>,
) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let kind = match &data.kind {
        None => 0,
        Some(Value::Number(number)) => number.as_i64().unwrap_or(-1),
        Some(Value::String(text)) => text.parse().unwrap_or(-1),
        Some(_) => -1,
    };
    if !(0..=1).contains(&kind) {
        return Err(ApiError::bad("Only logging in with a device is available on this server."));
    }
    if data.public_key.is_empty()
        || data.public_key.len() > 2048
        || data.access_code.len() < 16
        || data.access_code.len() > 64
        || data.device_identifier.is_empty()
        || data.device_identifier.len() > 256
        || data.email.len() > crate::identity::MAX_EMAIL
    {
        return Err(ApiError::bad("The request is not complete."));
    }
    let request = AuthRequest {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: String::new(),
        kind,
        device_id: data.device_identifier,
        device_type: device_type(&headers),
        ip: ip.to_string(),
        public_key: data.public_key,
        access_code_hash: auth::sha256(data.access_code.as_bytes()),
        key: None,
        master_password_hash: None,
        approved: None,
        response_device_id: None,
        created: clock::now(),
        responded: None,
        used: None,
    };
    let rendered = render(&state, &request);
    let Some(user) = state.store.user_by_email(&data.email).await?.filter(|user| !user.disabled) else {
        return Ok(Json(rendered));
    };
    // Each request lands on every device of the account; nobody gets to pile them up.
    if !state.limits.password.take(format!("auth-request:{}", user.id)) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let request = AuthRequest { user_id: user.id.clone(), ..request };
    state.store.add_auth_request(request.clone()).await?;
    crate::notify::auth_request(&state, &user.id, &request.id);
    let event = Event {
        kind: "auth-request".into(),
        user_id: Some(user.id.clone()),
        email: Some(user.email.clone()),
        ip: Some(ip.to_string()),
        device_type: Some(request.device_type),
        ..Event::default()
    };
    let _ = state.store.log_event(event).await;
    Ok(Json(rendered))
}

async fn list(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let requests = state.store.auth_requests(&session.user.id).await?;
    Ok(Json(out::list(requests.iter().map(|request| render(&state, request)).collect())))
}

/// Requests nobody answered yet: what a logged-in device shows.
async fn pending(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let requests = state.store.auth_requests(&session.user.id).await?;
    Ok(Json(out::list(
        requests.iter().filter(|request| request.approved.is_none()).map(|request| render(&state, request)).collect(),
    )))
}

async fn one(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let request = state
        .store
        .auth_request(&id)
        .await?
        .filter(|request| request.user_id == session.user.id)
        .ok_or_else(|| ApiError::bad("AuthRequest doesn't exist"))?;
    Ok(Json(render(&state, &request)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Answer {
    device_identifier: String,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    master_password_hash: Option<String>,
    request_approved: bool,
}

async fn answer(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(data): Json<Answer>,
) -> ApiResult<Json<Value>> {
    if data.device_identifier != session.device {
        return Err(ApiError::bad("AuthRequest doesn't exist"));
    }
    if data.request_approved && data.key.as_ref().is_none_or(|key| key.is_empty() || key.len() > out::MAX_NOTE) {
        return Err(ApiError::bad("An approval needs the key."));
    }
    let request = state
        .store
        .answer_auth_request(
            &session.user.id,
            &id,
            data.request_approved,
            data.key,
            data.master_password_hash,
            &session.device,
        )
        .await?
        .ok_or_else(|| ApiError::bad("This request was answered already, or it is too old."))?;
    crate::notify::auth_response(&state, &session, &request.id);
    Ok(Json(render(&state, &request)))
}

#[derive(Deserialize)]
struct Code {
    #[serde(default)]
    code: String,
}

/// The new device asks whether it was let in, with the code only it knows.
async fn response(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Query(code): Query<Code>,
) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let request = state
        .store
        .auth_request(&id)
        .await?
        .filter(|request| auth::constant_time_eq(&request.access_code_hash, &auth::sha256(code.code.as_bytes())));
    Ok(Json(match request {
        Some(request) => render(&state, &request),
        // A request for an address without an account, or a wrong code: it just never gets an
        // answer, like a request nobody looks at.
        None => json!({
            "id": id,
            "key": null,
            "masterPasswordHash": null,
            "responseDate": null,
            "requestApproved": null,
            "origin": state.config.public,
            "object": "auth-request",
        }),
    }))
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::{Value, json};

    const CODE: &str = "an-access-code-of-25-chars";

    async fn ask(server: &TestServer, email: &str, device: &str) -> Value {
        let body =
            json!({"email": email, "publicKey": "MIIBpub", "deviceIdentifier": device, "accessCode": CODE, "type": 0});
        let request = Request::post("/api/auth-requests")
            .header("content-type", "application/json")
            .header("device-type", "9")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = server.send(request).await;
        assert_eq!(response.status(), StatusCode::OK);
        json(response).await
    }

    fn login(email: &str, device: &str, request: &str, code: &str) -> Vec<(&'static str, String)> {
        vec![
            ("grant_type", "password".into()),
            ("username", email.into()),
            ("password", code.into()),
            ("authRequest", request.into()),
            ("scope", "api offline_access".into()),
            ("client_id", "web".into()),
            ("deviceType", "9".into()),
            ("deviceIdentifier", device.into()),
            ("deviceName", "chrome".into()),
        ]
    }

    #[tokio::test]
    async fn a_new_device_is_let_in_by_one_that_is_logged_in() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        server.state.store.set_two_factor(&account.id, 0, "JBSWY3DPEHPK3PXP".into(), "RECOVER".into()).await.unwrap();
        let asked = ask(&server, "nyu@example.com", "new-device").await;
        let id = asked["id"].as_str().unwrap().to_string();
        assert_eq!(asked["requestDeviceType"], "Chrome");

        let pending = json(server.get_as(&account.token, "/api/auth-requests/pending").await).await;
        assert_eq!(pending["data"][0]["id"], id.as_str());
        assert_eq!(pending["data"][0]["publicKey"], "MIIBpub");

        let fields = login("nyu@example.com", "new-device", &id, CODE);
        let form: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(server.form("/identity/connect/token", &form).await.status(), StatusCode::BAD_REQUEST, "not yet");

        let wrong_device = json!({"deviceIdentifier": "not-mine", "key": "4.k", "requestApproved": true});
        let response =
            server.call("PUT", &format!("/api/auth-requests/{id}"), Some(&account.token), wrong_device).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let yes = json!({"deviceIdentifier": account.device, "key": "4.wrapped", "requestApproved": true});
        let answered =
            json(server.call("PUT", &format!("/api/auth-requests/{id}"), Some(&account.token), yes).await).await;
        assert_eq!(answered["requestApproved"], true);

        let response = json(server.get(&format!("/api/auth-requests/{id}/response?code={CODE}")).await).await;
        assert_eq!(response["key"], "4.wrapped");
        let guess = json(server.get(&format!("/api/auth-requests/{id}/response?code=guess")).await).await;
        assert!(guess["key"].is_null(), "a wrong code sees nothing");

        let response = server.form("/identity/connect/token", &form).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        assert!(json(response).await["access_token"].is_string(), "no second step: the approval is one");
        assert_eq!(server.form("/identity/connect/token", &form).await.status(), StatusCode::BAD_REQUEST, "once");
    }

    #[tokio::test]
    async fn an_unknown_address_looks_like_any_other() {
        let server = TestServer::new().await;
        let asked = ask(&server, "nobody@example.com", "d").await;
        assert!(asked["id"].is_string());
        let id = asked["id"].as_str().unwrap();
        let response = server.get(&format!("/api/auth-requests/{id}/response?code={CODE}")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(json(response).await["requestApproved"].is_null(), "waits for ever, like one nobody answers");
    }
}
