//! The realtime channel on a real socket (docs/uwu-api.md §5): the handshake, `auth` first and
//! again later, what an account's devices hear and what a suite app hears, the session checked at
//! every heartbeat, and the close codes.

use crate::test_support::*;
use axum::http::StatusCode;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn listen(server: &TestServer) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = server.router.clone().into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    address
}

/// A connection that offered the subprotocol, before `auth`.
async fn open(address: SocketAddr) -> Socket {
    let mut request = format!("ws://{address}/uwu/v1/realtime").into_client_request().unwrap();
    request.headers_mut().insert("Sec-WebSocket-Protocol", "uwu.realtime.v1".parse().unwrap());
    let (socket, response) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert_eq!(response.headers()["sec-websocket-protocol"], "uwu.realtime.v1");
    socket
}

async fn say(socket: &mut Socket, message: Value) {
    socket.send(Message::text(message.to_string())).await.unwrap();
}

/// The next JSON message, or the close code as `{"close": code}`.
async fn next(socket: &mut Socket) -> Value {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next()).await.expect("a message in time");
        match message {
            Some(Ok(Message::Text(text))) => return serde_json::from_str(text.as_str()).unwrap(),
            Some(Ok(Message::Close(frame))) => return json!({ "close": frame.map(|f| u16::from(f.code)) }),
            Some(Ok(_)) => continue,
            other => panic!("the connection ended without a close: {other:?}"),
        }
    }
}

/// Connected and signed in: the `ready` message.
async fn connect(address: SocketAddr, token: &str, cursor: Option<&str>) -> (Socket, Value) {
    let mut socket = open(address).await;
    say(&mut socket, json!({ "type": "auth", "token": token, "cursor": cursor })).await;
    let ready = next(&mut socket).await;
    assert_eq!(ready["type"], "ready", "{ready}");
    (socket, ready)
}

async fn suite_token(server: &TestServer, email: &str, device: &str) -> String {
    let form = [
        ("grant_type", "password"),
        ("username", email),
        ("password", &password_hash(email)),
        ("scope", "uwu.suite offline_access"),
        ("client_id", "uwussh"),
        ("deviceType", "8"),
        ("deviceIdentifier", device),
        ("deviceName", "UwUSSH"),
    ];
    let response = server.form("/identity/connect/token", &form).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    json(response).await["access_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn the_channel_wants_its_protocol_and_auth_first() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let address = listen(&server).await;

    let refused = tokio_tungstenite::connect_async(format!("ws://{address}/uwu/v1/realtime")).await;
    assert!(refused.is_err(), "not without the subprotocol");

    let mut socket = open(address).await;
    assert_eq!(next(&mut socket).await["close"], 4408, "no auth in time");
    let mut socket = open(address).await;
    say(&mut socket, json!({ "type": "ping" })).await;
    assert_eq!(next(&mut socket).await["close"], 4401, "the first message is auth");
    let mut socket = open(address).await;
    say(&mut socket, json!({ "type": "auth", "token": "nonsense" })).await;
    assert_eq!(next(&mut socket).await["close"], 4401);

    let (mut socket, ready) = connect(address, &nyu.token, None).await;
    assert!(ready["connectionId"].as_str().is_some_and(|id| !id.is_empty()));
    assert!(ready["expires"].as_i64().unwrap() > crate::auth::now_seconds());
    assert!(ready["heartbeat"].as_u64().unwrap() >= 1);
    say(&mut socket, json!({ "type": "ping" })).await;
    assert_eq!(next(&mut socket).await, json!({ "type": "pong" }));
    say(&mut socket, json!({ "type": "subscribe" })).await;
    assert_eq!(next(&mut socket).await["close"], 4400, "a message it does not know");
}

#[tokio::test]
async fn the_account_s_devices_hear_what_changed_but_not_what_they_did_themselves() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let phone = server.login("nyu@example.com", "device-2").await;
    let other = server.account("other@example.com").await;
    let address = listen(&server).await;
    let (mut socket, _) = connect(address, &nyu.token, None).await;

    // Its own change and somebody else's are not heard; the other device's is.
    server.call("POST", "/api/folders", Some(&nyu.token), json!({ "name": type2() })).await;
    server.call("POST", "/api/folders", Some(&other.token), json!({ "name": type2() })).await;
    server.call("POST", "/api/folders", Some(&phone.token), json!({ "name": type2() })).await;
    assert_eq!(next(&mut socket).await, json!({ "type": "changed", "areas": ["vault"] }));

    // UwULock's own: the extras key, a notice.
    let keys = json!({ "userKeyWrapped": type2(), "privateKeyWrapped": type2() });
    assert_eq!(server.call("POST", "/uwu/v1/keys", Some(&phone.token), keys).await.status(), StatusCode::OK);
    let mut heard = [next(&mut socket).await, next(&mut socket).await];
    heard.sort_by_key(|message| message["type"].as_str().unwrap_or_default().to_string());
    assert_eq!(heard[0], json!({ "type": "changed", "areas": ["uwu"] }));
    assert_eq!((heard[1]["type"].as_str(), heard[1]["kind"].as_str()), (Some("notice"), Some("securityNotice")));
    assert!(heard[1]["id"].is_i64(), "a notice's id is a number");

    // A reminder that became due, and the server's settings.
    let item = json(
        server
            .call(
                "POST",
                "/api/ciphers",
                Some(&phone.token),
                json!({
                    "type": 2, "name": type2(), "secureNote": { "type": 0 }
                }),
            )
            .await,
    )
    .await;
    assert_eq!(next(&mut socket).await["areas"], json!(["vault"]));
    let path = format!("/uwu/v1/reminders/{}", item["id"].as_str().unwrap());
    server.call("PUT", &path, Some(&phone.token), json!({ "due": "2020-01-01" })).await;
    assert_eq!(next(&mut socket).await["areas"], json!(["uwu"]));
    crate::reminders::tend(&server.state).await;
    assert_eq!(next(&mut socket).await, json!({ "type": "notice", "kind": "reminderDue" }));
    server.state.apply_settings(server.state.settings());
    assert_eq!(next(&mut socket).await, json!({ "type": "info" }));

    // Another device removed: only that one hears it.
    let (mut phone_socket, _) = connect(address, &phone.token, None).await;
    let path = format!("/uwu/v1/devices/{}", phone.device);
    assert_eq!(server.call("DELETE", &path, Some(&nyu.token), json!({})).await.status(), StatusCode::OK);
    assert_eq!(next(&mut phone_socket).await, json!({ "type": "logout", "reason": "deviceRemoved" }));
    assert_eq!(next(&mut phone_socket).await["close"], 4401);
}

#[tokio::test]
async fn the_session_is_checked_at_every_heartbeat() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let address = listen(&server).await;
    let (mut socket, _) = connect(address, &nyu.token, None).await;
    // Changed behind the channel's back, without a word to it: the next heartbeat finds out.
    server.state.store.update_user(&nyu.id, |user| user.security_stamp = "new".into()).await.unwrap();
    assert_eq!(next(&mut socket).await, json!({ "type": "logout", "reason": "securityStamp" }));
    assert_eq!(next(&mut socket).await["close"], 4401);
}

#[tokio::test]
async fn a_suite_app_hears_its_space_and_nothing_else() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let token = suite_token(&server, "nyu@example.com", "ssh-1").await;
    let address = listen(&server).await;
    let (mut socket, _) = connect(address, &token, None).await;

    for space in ["ssh", "rdp"] {
        let body = json!({ "id": uuid::Uuid::new_v4().to_string(), "key": type2() });
        let path = format!("/uwu/v1/suite/spaces/{space}");
        assert_eq!(server.call("PUT", &path, Some(&nyu.token), body).await.status(), StatusCode::OK);
    }
    server.call("POST", "/api/folders", Some(&nyu.token), json!({ "name": type2() })).await;
    let body = json!({ "schema": 2, "records": [{
        "id": "9b2d0c1e-0000-4000-8000-000000000001", "kind": "host",
        "updatedAt": { "wallMs": 1, "counter": 0, "device": 1 }, "baseSeq": 0, "deleted": false,
        "nonce": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB", "blob": "eA==" }] });
    let response = server.call("POST", "/uwu/v1/suite/spaces/rdp/records", Some(&nyu.token), body).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    // The ssh space made, the rdp push and the folder are not heard; the first message is the
    // making of its own space.
    assert_eq!(next(&mut socket).await, json!({ "type": "changed", "areas": ["suite"], "spaces": ["ssh"] }));
    server.state.apply_settings(server.state.settings());
    assert_eq!(next(&mut socket).await, json!({ "type": "info" }));

    // Another account's token on the same connection: no.
    say(&mut socket, json!({ "type": "auth", "token": nyu.token })).await;
    assert_eq!(next(&mut socket).await["close"], 4400);

    // The account's password changes: the app is logged out.
    let (mut socket, _) = connect(address, &token, None).await;
    let body = json!({
        "masterPasswordHash": password_hash("nyu@example.com"), "newMasterPasswordHash": password_hash("nyu@example.com"),
        "key": "2.new|new|new", "masterPasswordHint": null,
    });
    let response = server.call("POST", "/api/accounts/password", Some(&nyu.token), body).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    assert_eq!(next(&mut socket).await, json!({ "type": "logout", "reason": "securityStamp" }));
    assert_eq!(next(&mut socket).await["close"], 4401);
}

#[tokio::test]
async fn a_device_that_comes_back_hears_if_it_missed_something_and_renews_its_token() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let phone = server.login("nyu@example.com", "device-2").await;
    let address = listen(&server).await;
    let cursor = json(server.get_as(&nyu.token, "/uwu/v1/sync").await).await["cursor"].as_str().unwrap().to_string();

    let (mut socket, _) = connect(address, &nyu.token, Some(&cursor)).await;
    say(&mut socket, json!({ "type": "ping" })).await;
    assert_eq!(next(&mut socket).await["type"], "pong", "nothing missed");
    drop(socket);

    server.call("POST", "/api/folders", Some(&phone.token), json!({ "name": type2() })).await;
    let (mut socket, _) = connect(address, &nyu.token, Some(&cursor)).await;
    assert_eq!(next(&mut socket).await, json!({ "type": "changed", "areas": ["vault", "uwu"] }));

    // A fresh token on the same connection: `ready` again, and the resume with it.
    let fresh = server.login("nyu@example.com", "device-1").await;
    say(&mut socket, json!({ "type": "auth", "token": fresh.token, "cursor": cursor })).await;
    assert_eq!(next(&mut socket).await["type"], "ready");
    assert_eq!(next(&mut socket).await["type"], "changed");
}

#[tokio::test]
async fn too_many_connections_or_messages_are_refused() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let address = listen(&server).await;
    let mut held = Vec::new();
    for _ in 0..uwulock_notify::realtime::PER_ACCOUNT {
        held.push(connect(address, &nyu.token, None).await.0);
    }
    let mut one_more = open(address).await;
    say(&mut one_more, json!({ "type": "auth", "token": nyu.token })).await;
    assert_eq!(next(&mut one_more).await["close"], 4429);
    held.clear();

    let (mut socket, _) = connect(address, &nyu.token, None).await;
    for _ in 0..12 {
        let _ = socket.send(Message::text(json!({ "type": "ping" }).to_string())).await;
    }
    loop {
        let message = next(&mut socket).await;
        if message["type"] == "pong" {
            continue;
        }
        assert_eq!(message["close"], 4429);
        break;
    }
}
