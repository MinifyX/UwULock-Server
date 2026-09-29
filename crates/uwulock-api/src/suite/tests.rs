//! The suite vault as UwUSSH and UwURDP use it (docs/uwu-api.md §6): the login of a suite app,
//! what its token opens and what not, and records pushed and pulled with UwUSync's rules.

use crate::test_support::*;
use axum::http::StatusCode;
use base64::Engine as _;
use serde_json::{Value, json};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The password grant as UwUSSH sends it (`crates/uwussh-sync/src/lock/api.rs`).
fn suite_form<'a>(email: &'a str, device: &'a str, client_id: &'a str) -> Vec<(&'static str, &'a str)> {
    vec![
        ("grant_type", "password"),
        ("username", email),
        ("password", Box::leak(password_hash(email).into_boxed_str())),
        ("scope", "uwu.suite offline_access"),
        ("client_id", client_id),
        ("deviceType", "8"),
        ("deviceIdentifier", device),
        ("deviceName", "UwUSSH"),
    ]
}

/// A suite app's login: its access and refresh token.
async fn suite_login(server: &TestServer, email: &str, device: &str) -> (String, String) {
    let response = server.form("/identity/connect/token", &suite_form(email, device, "uwussh")).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    let body = json(response).await;
    assert_eq!(body["scope"], "uwu.suite offline_access");
    (body["access_token"].as_str().unwrap().into(), body["refresh_token"].as_str().unwrap().into())
}

fn record(id: &str, base: i64, blob: &[u8]) -> Value {
    json!({
        "id": id,
        "kind": "host",
        "updatedAt": { "wallMs": 1_790_000_000_000u64, "counter": 0, "device": 305_419_896u32 },
        "baseSeq": base,
        "deleted": false,
        "nonce": b64(&[7; 24]),
        "blob": b64(blob),
    })
}

const R1: &str = "9b2d0c1e-0000-4000-8000-000000000001";
const R2: &str = "9b2d0c1e-0000-4000-8000-000000000002";
const R3: &str = "9b2d0c1e-0000-4000-8000-000000000003";
const SPACE_ID: &str = "3f0e0c1e-0000-4000-8000-00000000000a";

async fn make_space(server: &TestServer, token: &str, space: &str, id: &str) -> Value {
    let response = server
        .call("PUT", &format!("/uwu/v1/suite/spaces/{space}"), Some(token), json!({ "id": id, "key": type2() }))
        .await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    json(response).await
}

async fn push(server: &TestServer, token: &str, records: Vec<Value>) -> axum::http::Response<axum::body::Body> {
    let body = json!({ "schema": 2, "records": records });
    server.call("POST", "/uwu/v1/suite/spaces/ssh/records", Some(token), body).await
}

async fn pull(server: &TestServer, token: &str, query: &str) -> Value {
    let response = server.get_as(token, &format!("/uwu/v1/suite/spaces/ssh/records?{query}")).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    json(response).await
}

async fn code_of(response: axum::http::Response<axum::body::Body>) -> (StatusCode, Value) {
    let status = response.status();
    (status, json(response).await)
}

#[tokio::test]
async fn a_suite_app_logs_in_with_its_own_scope_and_reaches_only_its_space() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let (token, refresh) = suite_login(&server, "nyu@example.com", "5a0e9c1e-0000-4000-8000-0000000000ss").await;

    // Nothing of Bitwarden's, nothing of the account's own.
    for path in ["/api/sync", "/api/ciphers", "/uwu/v1/account", "/uwu/v1/devices", "/uwu/v1/reminders"] {
        let (status, body) = code_of(server.get_as(&token, path).await).await;
        assert_eq!((status, body["code"].as_str()), (StatusCode::FORBIDDEN, Some("scope")), "{path}");
    }
    let (status, body) = code_of(
        server.call("PUT", "/uwu/v1/suite/spaces/rdp", Some(&token), json!({ "id": SPACE_ID, "key": type2() })).await,
    )
    .await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::FORBIDDEN, Some("scope")), "another app's space");
    let (status, body) = code_of(server.get_as(&token, "/uwu/v1/sync?include=vault,suite").await).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::FORBIDDEN, Some("scope")));

    // What it may: the keys, its space, its sync.
    let keys = json!({ "userKeyWrapped": type2(), "privateKeyWrapped": type2() });
    let response = server.call("POST", "/uwu/v1/keys", Some(&token), keys).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    let space = make_space(&server, &token, "ssh", SPACE_ID).await;
    assert_eq!(
        (space["object"].as_str(), space["space"].as_str(), space["id"].as_str()),
        (Some("suiteSpace"), Some("ssh"), Some(SPACE_ID))
    );
    let sync = json(server.get_as(&token, "/uwu/v1/sync").await).await;
    assert_eq!(sync["suite"]["spaces"][0]["id"], SPACE_ID);
    assert!(sync["vault"].is_null() && sync["uwu"].is_null());
    let listed = json(server.get_as(&token, "/uwu/v1/suite/spaces").await).await;
    assert_eq!(listed["data"].as_array().unwrap().len(), 1);

    // Deleting the space is for the account itself, with its master password.
    let secret = json!({ "masterPasswordHash": password_hash("nyu@example.com") });
    let (status, body) =
        code_of(server.call("DELETE", "/uwu/v1/suite/spaces/ssh", Some(&token), secret.clone()).await).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::FORBIDDEN, Some("scope")));

    // The account sees the device as the app's, and a notice of its login.
    let devices = json(server.get_as(&nyu.token, "/uwu/v1/devices").await).await;
    let apps: Vec<Value> = devices.as_array().unwrap().iter().map(|device| device["app"].clone()).collect();
    assert!(apps.contains(&json!("uwussh")) && apps.contains(&Value::Null), "{devices}");
    let notices = json(server.get_as(&nyu.token, "/uwu/v1/security/notices").await).await;
    let kinds: Vec<&str> = notices["data"].as_array().unwrap().iter().filter_map(|n| n["kind"].as_str()).collect();
    assert!(kinds.contains(&"suiteLogin") && kinds.contains(&"extrasKeyCreated"), "{kinds:?}");

    // A refresh keeps the scope, and works for this app alone.
    let response = server
        .form(
            "/identity/connect/token",
            &[("grant_type", "refresh_token"), ("client_id", "browser"), ("refresh_token", &refresh)],
        )
        .await;
    assert_eq!(json(response).await["error"], "invalid_grant");
    let response = server
        .form(
            "/identity/connect/token",
            &[("grant_type", "refresh_token"), ("client_id", "uwussh"), ("refresh_token", &refresh)],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json(response).await["scope"], "uwu.suite offline_access");
    // The account's own refresh token does not turn into a suite app's.
    let response = server
        .form(
            "/identity/connect/token",
            &[("grant_type", "refresh_token"), ("client_id", "uwussh"), ("refresh_token", &nyu.refresh)],
        )
        .await;
    assert_eq!(json(response).await["error"], "invalid_grant");

    // The scope and the client go together.
    let mut form = suite_form("nyu@example.com", "d-3", "browser");
    let response = server.form("/identity/connect/token", &form).await;
    assert_eq!(json(response).await["error"], "invalid_client");
    form = suite_form("nyu@example.com", "d-3", "uwussh");
    form[3].1 = "api offline_access";
    let response = server.form("/identity/connect/token", &form).await;
    assert_eq!(json(response).await["error"], "invalid_scope");

    // Now the account deletes it.
    let response = server.call("DELETE", "/uwu/v1/suite/spaces/ssh", Some(&nyu.token), secret).await;
    assert_eq!(response.status(), StatusCode::OK);
    let listed = json(server.get_as(&nyu.token, "/uwu/v1/suite/spaces").await).await;
    assert!(listed["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_suite_app_goes_through_two_step_login_like_every_client() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let now = crate::auth::now_seconds();
    let secret = json!({ "masterPasswordHash": password_hash(&nyu.email) });
    let got = json(server.call("POST", "/api/two-factor/get-authenticator", Some(&nyu.token), secret).await).await;
    let key = got["key"].as_str().unwrap().to_string();
    let seed = crate::totp::base32_decode(&key).unwrap();
    let body = json!({ "key": key, "token": crate::totp::code(&seed, now / 30), "masterPasswordHash": password_hash(&nyu.email) });
    assert_eq!(
        server.call("PUT", "/api/two-factor/authenticator", Some(&nyu.token), body).await.status(),
        StatusCode::OK
    );

    let device = "5a0e9c1e-0000-4000-8000-0000000000tf";
    let response = server.form("/identity/connect/token", &suite_form(&nyu.email, device, "uwussh")).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json(response).await;
    assert_eq!(body["TwoFactorProviders"], json!(["0"]));
    assert!(body["TwoFactorProviders2"].as_object().unwrap().contains_key("0"));

    let next = crate::totp::code(&seed, now / 30 + 1);
    let mut form = suite_form(&nyu.email, device, "uwussh");
    form.extend([("twoFactorToken", next.as_str()), ("twoFactorProvider", "0"), ("twoFactorRemember", "1")]);
    let response = server.form("/identity/connect/token", &form).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    let body = json(response).await;
    assert_eq!(body["scope"], "uwu.suite offline_access");
    let remember = body["TwoFactorToken"].as_str().unwrap().to_string();

    let mut form = suite_form(&nyu.email, device, "uwussh");
    form.extend([("twoFactorToken", remember.as_str()), ("twoFactorProvider", "5")]);
    let response = server.form("/identity/connect/token", &form).await;
    assert_eq!(response.status(), StatusCode::OK, "the remembered device: {}", text(response).await);
}

#[tokio::test]
async fn records_are_pushed_and_pulled_with_uwusyncs_rules() {
    let server = TestServer::new().await;
    server.account("nyu@example.com").await;
    let (token, _) = suite_login(&server, "nyu@example.com", "ssh-1").await;

    let (status, _) = code_of(push(&server, &token, vec![record(R1, 0, b"a")]).await).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no space yet");
    make_space(&server, &token, "ssh", SPACE_ID).await;
    let (status, body) = code_of(make_space_raw(&server, &token).await).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::CONFLICT, Some("exists")), "the loser of a race");

    // What is not UwUSync's record model.
    let body = json!({ "schema": 1, "records": [record(R1, 0, b"a")] });
    let (status, body) =
        code_of(server.call("POST", "/uwu/v1/suite/spaces/ssh/records", Some(&token), body).await).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::BAD_REQUEST, Some("schema")));
    let mut odd = record(R1, 0, b"a");
    odd["kind"] = json!("hologram");
    assert_eq!(code_of(push(&server, &token, vec![odd]).await).await.1["code"], "invalid");
    let mut odd = record(R1, 0, b"a");
    odd["nonce"] = json!(b64(&[1; 12]));
    assert_eq!(code_of(push(&server, &token, vec![odd]).await).await.1["code"], "invalid");
    let mut odd = record(R1, 0, b"a");
    odd["id"] = json!("not-a-uuid");
    assert_eq!(code_of(push(&server, &token, vec![odd]).await).await.1["code"], "invalid");
    let big = record(R1, 0, &vec![0; 256 * 1024 + 1]);
    assert_eq!(code_of(push(&server, &token, vec![big]).await).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    let many = (0..501).map(|n| record(&format!("9b2d0c1e-0000-4000-8000-{n:012}"), 0, b"x")).collect();
    assert_eq!(code_of(push(&server, &token, many).await).await.0, StatusCode::PAYLOAD_TOO_LARGE);

    // Two new records, in the apps' own base64 (URL-safe, unpadded taken too).
    let mut second = record(R2, 0, b"b");
    second["blob"] = json!("Yg");
    let (status, answer) = code_of(push(&server, &token, vec![record(R1, 0, b"a"), second]).await).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["object"], "suitePush");
    let accepted = answer["accepted"].as_array().unwrap();
    assert_eq!(accepted.len(), 2);
    let r1 = accepted[0]["seq"].as_i64().unwrap();
    assert!(answer["conflicts"].as_array().unwrap().is_empty());
    assert_eq!(answer["cursor"], accepted[1]["seq"]);

    let page = pull(&server, &token, "since=0").await;
    assert_eq!(
        (page["object"].as_str(), page["reset"].as_bool(), page["hasMore"].as_bool()),
        (Some("suitePull"), Some(false), Some(false))
    );
    let records = page["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["id"], R1);
    assert_eq!(records[0]["seq"], r1);
    assert_eq!(records[1]["blob"], b64(b"b"), "written the standard way");
    assert_eq!(records[0]["updatedAt"]["device"], 305_419_896u32);
    let cursor = page["cursor"].as_i64().unwrap();

    // Based on something older: the record comes back as it is here.
    let (_, answer) = code_of(push(&server, &token, vec![record(R1, r1 - 1, b"stale")]).await).await;
    assert!(answer["accepted"].as_array().unwrap().is_empty());
    assert_eq!(answer["conflicts"][0]["blob"], b64(b"a"));
    assert_eq!(answer["conflicts"][0]["seq"], r1);
    let (_, answer) = code_of(push(&server, &token, vec![record(R1, r1, b"merged")]).await).await;
    assert_eq!(answer["accepted"][0]["id"], R1);

    let page = pull(&server, &token, &format!("since={cursor}")).await;
    assert_eq!(page["records"].as_array().unwrap().len(), 1);
    assert_eq!(page["records"][0]["blob"], b64(b"merged"));
    let page = pull(&server, &token, "since=0&limit=1").await;
    assert_eq!((page["records"].as_array().unwrap().len(), page["hasMore"].as_bool()), (1, Some(true)));
    let (status, _) = code_of(server.get_as(&token, "/uwu/v1/suite/spaces/ssh/records?since=soon").await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A record id of another account is not to be had.
    server.account("other@example.com").await;
    let (theirs, _) = suite_login(&server, "other@example.com", "ssh-2").await;
    make_space(&server, &theirs, "ssh", "3f0e0c1e-0000-4000-8000-00000000000b").await;
    let (status, body) = code_of(push(&server, &theirs, vec![record(R1, 0, b"mine now")]).await).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::CONFLICT, Some("exists")));
    let (status, _) = code_of(make_space_with(&server, &theirs, "3f0e0c1e-0000-4000-8000-00000000000b").await).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

async fn make_space_raw(server: &TestServer, token: &str) -> axum::http::Response<axum::body::Body> {
    make_space_with(server, token, "3f0e0c1e-0000-4000-8000-00000000000c").await
}

async fn make_space_with(server: &TestServer, token: &str, id: &str) -> axum::http::Response<axum::body::Body> {
    server.call("PUT", "/uwu/v1/suite/spaces/ssh", Some(token), json!({ "id": id, "key": type2() })).await
}

#[tokio::test]
async fn a_full_suite_vault_takes_nothing_more() {
    let mut settings = crate::Settings::default();
    settings.suite.max_records = 2;
    let server = TestServer::with_settings(settings).await;
    server.account("nyu@example.com").await;
    let (token, _) = suite_login(&server, "nyu@example.com", "ssh-1").await;
    make_space(&server, &token, "ssh", SPACE_ID).await;
    let (status, _) = code_of(push(&server, &token, vec![record(R1, 0, b"a"), record(R2, 0, b"b")]).await).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = code_of(push(&server, &token, vec![record(R3, 0, b"c")]).await).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("quota")));
    assert_eq!(pull(&server, &token, "since=0").await["records"].as_array().unwrap().len(), 2, "nothing of it");
}

#[tokio::test]
async fn a_new_key_makes_a_new_space_id_and_older_pulls_start_over() {
    let server = TestServer::new().await;
    server.account("nyu@example.com").await;
    let (token, _) = suite_login(&server, "nyu@example.com", "ssh-1").await;
    make_space(&server, &token, "ssh", SPACE_ID).await;
    let (_, answer) = code_of(push(&server, &token, vec![record(R1, 0, b"a"), record(R2, 0, b"b")]).await).await;
    let (r1, r2) = (answer["accepted"][0]["seq"].as_i64().unwrap(), answer["accepted"][1]["seq"].as_i64().unwrap());
    let new_id = "3f0e0c1e-0000-4000-8000-0000000000ff";

    let only_one = json!({ "id": new_id, "key": type2(), "records": [record(R1, r1, b"A")] });
    let (status, body) =
        code_of(server.call("POST", "/uwu/v1/suite/spaces/ssh/rekey", Some(&token), only_one).await).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::CONFLICT, Some("conflict")));
    let all = json!({ "id": new_id, "key": type2(), "records": [record(R1, r1, b"A"), record(R2, r2, b"B")] });
    let (status, space) = code_of(server.call("POST", "/uwu/v1/suite/spaces/ssh/rekey", Some(&token), all).await).await;
    assert_eq!(status, StatusCode::OK, "{space}");
    assert_eq!((space["id"].as_str(), space["records"].as_i64()), (Some(new_id), Some(2)));

    let old = pull(&server, &token, &format!("since={r2}")).await;
    assert_eq!((old["reset"].as_bool(), old["records"].as_array().unwrap().len()), (Some(true), 0));
    let fresh = pull(&server, &token, "since=0").await;
    let blobs: Vec<&str> = fresh["records"].as_array().unwrap().iter().filter_map(|r| r["blob"].as_str()).collect();
    assert_eq!(blobs, vec![b64(b"A"), b64(b"B")]);
    let listed = json(server.get_as(&token, "/uwu/v1/suite/spaces").await).await;
    assert_eq!(listed["data"][0]["id"], new_id);

    // A device that still has the old space pushes records sealed for it: refused whole (SV-L10).
    let fresh_r1 = fresh["records"][0]["baseSeq"].as_i64().unwrap();
    let stale =
        json!({ "schema": 2, "spaceId": SPACE_ID, "records": [record(R1, fresh_r1, b"old"), record(R3, 0, b"x")] });
    let (status, body) =
        code_of(server.call("POST", "/uwu/v1/suite/spaces/ssh/records", Some(&token), stale).await).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::CONFLICT, Some("space_changed")));
    assert_eq!(pull(&server, &token, "since=0").await["records"].as_array().unwrap().len(), 2, "nothing written");
    let current = json!({ "schema": 2, "spaceId": new_id, "records": [record(R3, 0, b"c")] });
    let (status, _) =
        code_of(server.call("POST", "/uwu/v1/suite/spaces/ssh/records", Some(&token), current).await).await;
    assert_eq!(status, StatusCode::OK, "the space's own id");
    let (status, _) =
        code_of(push(&server, &token, vec![record(R2, fresh["records"][1]["baseSeq"].as_i64().unwrap(), b"d")]).await)
            .await;
    assert_eq!(status, StatusCode::OK, "without spaceId, as older apps push");
}

#[tokio::test]
async fn a_server_without_the_suite_says_so() {
    let server = TestServer::new().await;
    server.switch(crate::Feature::Suite, false);
    let nyu = server.account("nyu@example.com").await;
    let response = server.form("/identity/connect/token", &suite_form("nyu@example.com", "ssh-1", "uwussh")).await;
    assert_eq!(json(response).await["error"], "invalid_client");
    let (status, body) = code_of(server.get_as(&nyu.token, "/uwu/v1/suite/spaces").await).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::NOT_FOUND, Some("feature_off")));
    let info = json(server.get("/uwu/v1/info").await).await;
    let features = info["features"].as_array().unwrap();
    assert!(!features.contains(&json!("suite")) && features.contains(&json!("delta-sync")));
    // An account's sync that asks for the suite gets none, and no error.
    let sync = json(server.get_as(&nyu.token, "/uwu/v1/sync?include=vault,suite").await).await;
    assert!(sync["suite"].is_null() && sync["vault"].is_object());
}
