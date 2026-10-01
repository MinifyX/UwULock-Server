//! UwUSSH's and UwURDP's way through UwULock (docs/uwu-api.md §3, §5, §6), against the real
//! server on a free port, with the crypto of uwulock-core that the apps use. The scenarios are
//! the ones UwUSSH's own tests run against its fake server (`crates/uwussh-sync/src/lock/tests.rs`,
//! branch sync-uwulock): the first sign-in makes the keys and the space and the next takes them,
//! two-step login, the extras key after an official rotation, two devices in step through the
//! space, a session that ended, a pull told to start over, a space with a new key, the move from
//! UwUSync, and the realtime channel. The requests are made the way the apps make them.

use crate::client::{EMAIL, PASSWORD, Running, client, hash, login, register, start};
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use uwulock_bitwarden::LoginOutcome;
use uwulock_core::crypto::{self, EncString, Kdf, PrivateKey, SymmetricKey};
use uwulock_core::extras::{self, Keys, Resolved, SpaceKey};
use uwulock_core::wire;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// An account with a key pair, as a client leaves it after registering.
async fn account(server: &Running, token: &str) {
    register(&server.url, token).await;
    let desktop = client(&server.url, "5a0e9c1e-7d3b-4d0c-9a8e-0000000000d1");
    let (master, hash) = hash(&desktop).await;
    let LoginOutcome::LoggedIn(session) = desktop.login(login(&hash)).await.unwrap() else { panic!("a login") };
    let user_key =
        crypto::decrypt_user_key(&master, &session.protected_user_key.clone().unwrap().parse().unwrap()).unwrap();
    let private = PrivateKey::generate().unwrap();
    let keys = json!({
        "publicKey": b64(&private.public().to_der().unwrap()),
        "encryptedPrivateKey": EncString::encrypt(&private.to_der().unwrap(), &user_key).to_string(),
    });
    let response = reqwest::Client::new()
        .post(format!("{}/api/accounts/keys", server.url))
        .bearer_auth(session.access_token.as_str())
        .json(&keys)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
}

/// One install of a suite app, as `uwussh-sync`'s `Lock` talks to the server.
struct App {
    url: String,
    http: reqwest::Client,
    client_id: &'static str,
    space: &'static str,
    device: String,
    access: String,
    refresh: String,
}

/// What a sign-in ends with: the app, and the space it syncs.
struct SignedIn {
    app: App,
    space_id: String,
    space_key: SpaceKey,
    made_space: bool,
    remember: Option<String>,
}

/// Why a sign-in did not get through: the status and the token endpoint's answer.
#[derive(Debug)]
struct Refused(u16, Value);

/// §6.5: prelogin, the password grant as a suite app, the user key and the private key, the
/// extras key (opened, wrapped again, or made), the space (taken or made).
async fn sign_in(
    url: &str,
    device: &str,
    (client_id, space): (&'static str, &'static str),
    two_factor: Option<(&str, u8, bool)>,
    password: &str,
) -> Result<SignedIn, Refused> {
    let http = reqwest::Client::new();
    let email = crypto::normalize_email(EMAIL);
    let prelogin: Value = http
        .post(format!("{url}/identity/accounts/prelogin"))
        .json(&json!({ "email": email }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let prelogin: wire::Prelogin = serde_json::from_value(wire::lowercase_keys(prelogin)).unwrap();
    let kdf = Kdf::Pbkdf2 { iterations: prelogin.kdf_iterations.unwrap() };
    let master = crypto::master_key(password, &email, kdf).unwrap();
    let hash = crypto::master_password_hash(&master, password);

    let mut form = vec![
        ("grant_type", "password".to_string()),
        ("username", email.clone()),
        ("password", hash),
        ("scope", "uwu.suite offline_access".into()),
        ("client_id", client_id.into()),
        ("deviceType", "8".into()),
        ("deviceIdentifier", device.into()),
        ("deviceName", if client_id == "uwussh" { "UwUSSH" } else { "UwURDP" }.into()),
    ];
    if let Some((code, provider, remember)) = two_factor {
        form.push(("twoFactorToken", code.into()));
        form.push(("twoFactorProvider", provider.to_string()));
        form.push(("twoFactorRemember", u8::from(remember).to_string()));
    }
    let response = http
        .post(format!("{url}/identity/connect/token"))
        .header("Auth-Email", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(email.as_bytes()))
        .header("Device-Type", "8")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form_body(form.iter().map(|(k, v)| (*k, v.as_str()))))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body: Value = response.json().await.unwrap();
    if status != 200 {
        return Err(Refused(status, body));
    }
    assert_eq!(body["scope"], "uwu.suite offline_access");
    let token: wire::Token = serde_json::from_value(wire::lowercase_keys(body)).unwrap();
    let user_key = crypto::decrypt_user_key(&master, &token.key.unwrap().parse().unwrap()).unwrap();
    let private = token.private_key.map(|wrapped| {
        let der = wrapped.parse::<EncString>().unwrap().decrypt(&user_key).unwrap();
        PrivateKey::from_der(&der).unwrap()
    });
    let app = App {
        url: url.to_string(),
        http,
        client_id,
        space,
        device: device.to_string(),
        access: token.access_token,
        refresh: token.refresh_token.unwrap(),
    };
    let extras = app.extras_key(&user_key, private.as_ref()).await;
    let (space_id, space_key, made_space) = app.space(&extras).await;
    Ok(SignedIn { app, space_id, space_key, made_space, remember: token.two_factor_token })
}

const SSH: (&str, &str) = ("uwussh", "ssh");

impl App {
    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut request = self.http.request(method, format!("{}{path}", self.url)).bearer_auth(&self.access);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn ok(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Value {
        let (status, answer) = self.call(method, path, body).await;
        assert_eq!(status, 200, "{path}: {answer}");
        answer
    }

    async fn extras_key(&self, user_key: &SymmetricKey, private: Option<&PrivateKey>) -> SymmetricKey {
        for _ in 0..2 {
            let keys: Keys = serde_json::from_value(self.ok(reqwest::Method::GET, "/uwu/v1/keys", None).await).unwrap();
            match extras::resolve(&keys, user_key, private).unwrap() {
                Resolved::Open { key, rewrap, private_wrap } => {
                    if let Some(rewrap) = rewrap {
                        self.ok(
                            reqwest::Method::PUT,
                            "/uwu/v1/keys/user-wrap",
                            Some(serde_json::to_value(&rewrap).unwrap()),
                        )
                        .await;
                    }
                    if let Some(private_wrap) = private_wrap {
                        self.ok(
                            reqwest::Method::PUT,
                            "/uwu/v1/keys/private-wrap",
                            Some(serde_json::to_value(&private_wrap).unwrap()),
                        )
                        .await;
                    }
                    return key;
                }
                Resolved::Create(new) => {
                    let (status, answer) = self
                        .call(reqwest::Method::POST, "/uwu/v1/keys", Some(serde_json::to_value(&new.request).unwrap()))
                        .await;
                    match status {
                        200 => return new.key,
                        409 if answer["code"] == "exists" => continue,
                        _ => panic!("the extras key: {status} {answer}"),
                    }
                }
                Resolved::Lost => panic!("the extras key is lost"),
            }
        }
        panic!("the extras key keeps changing")
    }

    async fn spaces(&self) -> Vec<Value> {
        let list = self.ok(reqwest::Method::GET, "/uwu/v1/suite/spaces", None).await;
        list["data"].as_array().unwrap().clone()
    }

    async fn space(&self, extras: &SymmetricKey) -> (String, SpaceKey, bool) {
        for _ in 0..2 {
            if let Some(existing) = self.spaces().await.into_iter().find(|space| space["space"] == self.space) {
                let key = SpaceKey::unwrap(existing["key"].as_str().unwrap(), extras).unwrap();
                return (existing["id"].as_str().unwrap().to_string(), key, false);
            }
            let key = SpaceKey::generate();
            let id = uuid();
            let body = json!({ "id": id, "key": key.wrap(extras) });
            let (status, answer) =
                self.call(reqwest::Method::PUT, &format!("/uwu/v1/suite/spaces/{}", self.space), Some(body)).await;
            match status {
                200 => return (id, key, true),
                409 if answer["code"] == "exists" => continue,
                _ => panic!("the space: {status} {answer}"),
            }
        }
        panic!("the space keeps changing")
    }

    fn records(&self) -> String {
        format!("/uwu/v1/suite/spaces/{}/records", self.space)
    }

    async fn push(&self, records: Vec<Value>) -> Value {
        self.ok(reqwest::Method::POST, &self.records(), Some(json!({ "schema": 2, "records": records }))).await
    }

    async fn pull(&self, since: u64) -> Value {
        self.ok(reqwest::Method::GET, &format!("{}?since={since}&limit=500", self.records()), None).await
    }

    /// Everything from `since`, page by page: the records and the cursor after them.
    async fn pull_all(&self, mut since: u64) -> (Vec<Value>, u64) {
        let mut all = Vec::new();
        loop {
            let page = self.pull(since).await;
            assert_eq!(page["reset"], false);
            all.extend(page["records"].as_array().unwrap().iter().cloned());
            since = page["cursor"].as_u64().unwrap();
            if !page["hasMore"].as_bool().unwrap() {
                return (all, since);
            }
        }
    }

    /// `grant_type=refresh_token` with this app's `client_id`: the new tokens, or the refusal.
    async fn refresh(&mut self) -> Result<(), Refused> {
        let form = [("grant_type", "refresh_token"), ("client_id", self.client_id), ("refresh_token", &self.refresh)];
        let response = self
            .http
            .post(format!("{}/identity/connect/token", self.url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form_body(form))
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body: Value = response.json().await.unwrap();
        if status != 200 {
            return Err(Refused(status, body));
        }
        assert_eq!(body["scope"], "uwu.suite offline_access");
        self.access = body["access_token"].as_str().unwrap().to_string();
        if let Some(refresh) = body["refresh_token"].as_str() {
            self.refresh = refresh.to_string();
        }
        Ok(())
    }
}

fn uuid() -> String {
    let bytes: [u8; 16] = rand_bytes();
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{}-{}-4{}-8{}-{}", &hex[0..8], &hex[8..12], &hex[13..16], &hex[17..20], &hex[20..32])
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let key = SymmetricKey::generate();
    let bytes = key.to_bytes();
    let mut out = [0; N];
    out.copy_from_slice(&bytes[..N]);
    out
}

/// A record as the apps seal it: the server sees only a nonce and bytes.
fn record(id: &str, base: u64, wall_ms: u64, blob: &[u8]) -> Value {
    json!({
        "id": id,
        "kind": "host",
        "updatedAt": { "wallMs": wall_ms, "counter": 0, "device": 305_419_896u32 },
        "baseSeq": base,
        "deleted": false,
        "nonce": b64(&rand_bytes::<24>()),
        "blob": b64(blob),
    })
}

#[tokio::test]
async fn the_first_sign_in_makes_the_keys_and_the_space_and_the_next_one_takes_them() {
    let (server, token) = start().await;
    account(&server, &token).await;

    let first = sign_in(&server.url, "5a0e9c1e-0000-4000-8000-00000000a001", SSH, None, PASSWORD).await.unwrap();
    assert!(first.made_space);
    let second = sign_in(&server.url, "5a0e9c1e-0000-4000-8000-00000000a002", SSH, None, PASSWORD).await.unwrap();
    assert!(!second.made_space);
    assert_eq!(second.space_id, first.space_id);
    assert_eq!(second.space_key.as_bytes(), first.space_key.as_bytes(), "the same key, opened with the extras key");

    // UwURDP has a space of its own, under the same extras key.
    let rdp =
        sign_in(&server.url, "5a0e9c1e-0000-4000-8000-00000000a003", ("uwurdp", "rdp"), None, PASSWORD).await.unwrap();
    assert!(rdp.made_space && rdp.space_id != first.space_id);
    let (status, answer) = rdp.app.call(reqwest::Method::GET, "/uwu/v1/suite/spaces/ssh/records?since=0", None).await;
    assert_eq!((status, answer["code"].as_str()), (403, Some("scope")), "not UwUSSH's space");
    let (status, _) = first.app.call(reqwest::Method::GET, "/api/sync", None).await;
    assert_eq!(status, 403, "and nothing of the vault");

    // A wrong password, in the server's words.
    let Err(Refused(status, body)) =
        sign_in(&server.url, "5a0e9c1e-0000-4000-8000-00000000a004", SSH, None, "wrong horse").await
    else {
        panic!("refused")
    };
    // As Vaultwarden answers it; the apps show `errorModel.message`.
    assert_eq!(status, 400);
    assert!(body["errorModel"]["message"].as_str().is_some_and(|message| !message.is_empty()), "{body}");
}

#[tokio::test]
async fn two_step_login_asks_for_a_code_and_can_remember_this_device() {
    let (server, token) = start().await;
    account(&server, &token).await;
    let desktop = client(&server.url, "5a0e9c1e-7d3b-4d0c-9a8e-0000000000d2");
    let (_, hash) = hash(&desktop).await;
    let LoginOutcome::LoggedIn(session) = desktop.login(login(&hash)).await.unwrap() else { panic!("a login") };
    let http = reqwest::Client::new();
    let api = |path: &str| format!("{}/api/two-factor/{path}", server.url);
    let secret: Value = http
        .post(api("get-authenticator"))
        .bearer_auth(session.access_token.as_str())
        .json(&json!({ "masterPasswordHash": hash }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key = secret["key"].as_str().unwrap().to_string();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let code = |at: u64| uwulock_bitwarden::totp::Totp::parse(&key).unwrap().code_at(at).0.to_string();
    let response = http
        .put(api("authenticator"))
        .bearer_auth(session.access_token.as_str())
        .json(&json!({ "key": key, "token": code(now), "masterPasswordHash": hash }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    let device = "5a0e9c1e-0000-4000-8000-00000000b001";
    let Err(Refused(400, body)) = sign_in(&server.url, device, SSH, None, PASSWORD).await else { panic!("a code") };
    let providers = wire::lowercase_keys(body);
    assert!(providers["twofactorproviders2"].get("0").is_some(), "{providers}");

    let next = code(now + 30);
    let signed = sign_in(&server.url, device, SSH, Some((&next, 0, true)), PASSWORD).await.unwrap();
    let remember = signed.remember.expect("a token to remember the device");
    let again = sign_in(&server.url, device, SSH, Some((&remember, 5, false)), PASSWORD).await;
    assert!(again.is_ok(), "the remembered device skips the code");
    let elsewhere =
        sign_in(&server.url, "5a0e9c1e-0000-4000-8000-00000000b002", SSH, Some((&remember, 5, false)), PASSWORD).await;
    assert!(matches!(elsewhere, Err(Refused(400, _))), "but only that device");
}

#[tokio::test]
async fn after_an_official_rotation_the_key_opens_with_the_private_key_and_is_wrapped_again() {
    let (server, token) = start().await;
    account(&server, &token).await;
    let first = sign_in(&server.url, "5a0e9c1e-0000-4000-8000-00000000c001", SSH, None, PASSWORD).await.unwrap();
    let user = server.store.user_by_email(EMAIL).await.unwrap().unwrap();
    // What an official client's rotation leaves behind.
    server.store.drop_extras_user_wrap(&user.id).await.unwrap();
    let keys = first.app.ok(reqwest::Method::GET, "/uwu/v1/keys", None).await;
    assert!(keys["extrasKey"]["userKeyWrapped"].is_null());

    let second = sign_in(&server.url, "5a0e9c1e-0000-4000-8000-00000000c002", SSH, None, PASSWORD).await.unwrap();
    assert_eq!(second.space_key.as_bytes(), first.space_key.as_bytes());
    let keys = second.app.ok(reqwest::Method::GET, "/uwu/v1/keys", None).await;
    assert!(keys["extrasKey"]["userKeyWrapped"].is_string(), "wrapped again for the user key");
}

#[tokio::test]
async fn two_devices_keep_each_other_in_step_through_the_space() {
    let (server, token) = start().await;
    account(&server, &token).await;
    let laptop = sign_in(&server.url, "5a0e9c1e-0000-4000-8000-00000000d001", SSH, None, PASSWORD).await.unwrap().app;
    let desk = sign_in(&server.url, "5a0e9c1e-0000-4000-8000-00000000d002", SSH, None, PASSWORD).await.unwrap().app;
    let (a, b) = (uuid(), uuid());

    let pushed = laptop.push(vec![record(&a, 0, 1, b"a1"), record(&b, 0, 1, b"b1")]).await;
    assert_eq!(pushed["accepted"].as_array().unwrap().len(), 2);
    let (seen, desk_cursor) = desk.pull_all(0).await;
    assert_eq!(seen.len(), 2);
    let a_seq = seen.iter().find(|r| r["id"] == a.as_str()).unwrap()["seq"].as_u64().unwrap();

    // The desk changes a; the laptop, which did not pull, changes it too and hears of the conflict.
    let changed = desk.push(vec![record(&a, a_seq, 2, b"a2 desk")]).await;
    let a_now = changed["accepted"][0]["seq"].as_u64().unwrap();
    let stale = laptop.push(vec![record(&a, a_seq, 3, b"a3 laptop")]).await;
    assert!(stale["accepted"].as_array().unwrap().is_empty());
    assert_eq!(stale["conflicts"][0]["blob"], b64(b"a2 desk"), "as the server holds it");
    assert_eq!(stale["conflicts"][0]["updatedAt"]["wallMs"], 2);
    // Merged (the later clock wins), and pushed on what the server holds.
    let merged = laptop.push(vec![record(&a, a_now, 3, b"a3 laptop")]).await;
    assert_eq!(merged["accepted"][0]["id"], a.as_str());

    let (news, _) = desk.pull_all(desk_cursor).await;
    let blobs: Vec<&str> = news.iter().filter_map(|r| r["blob"].as_str()).collect();
    assert_eq!(blobs, vec![b64(b"a3 laptop")], "a record as it is now, once");
}

#[tokio::test]
async fn a_session_that_ended_asks_for_the_master_password() {
    let (server, token) = start().await;
    account(&server, &token).await;
    let mut app = sign_in(&server.url, "5a0e9c1e-0000-4000-8000-00000000e001", SSH, None, PASSWORD).await.unwrap().app;
    // An access token that ran out is renewed, with the scope it had.
    app.refresh().await.unwrap();
    app.ok(reqwest::Method::GET, "/uwu/v1/suite/spaces", None).await;

    // Removed from the account's devices: the refresh token is gone with it.
    let desktop = client(&server.url, "5a0e9c1e-7d3b-4d0c-9a8e-0000000000d3");
    let (_, hash) = hash(&desktop).await;
    let LoginOutcome::LoggedIn(session) = desktop.login(login(&hash)).await.unwrap() else { panic!("a login") };
    let response = reqwest::Client::new()
        .delete(format!("{}/uwu/v1/devices/{}", server.url, app.device))
        .bearer_auth(session.access_token.as_str())
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let Err(Refused(status, body)) = app.refresh().await else { panic!("the session ended") };
    assert_eq!((status, body["error"].as_str()), (400, Some("invalid_grant")));
    let (status, _) = app.call(reqwest::Method::GET, "/uwu/v1/suite/spaces", None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn a_space_with_a_new_key_starts_the_other_devices_over() {
    let (server, token) = start().await;
    account(&server, &token).await;
    let laptop = sign_in(&server.url, "5a0e9c1e-0000-4000-8000-00000000f001", SSH, None, PASSWORD).await.unwrap();
    let desk = sign_in(&server.url, "5a0e9c1e-0000-4000-8000-00000000f002", SSH, None, PASSWORD).await.unwrap();
    let a = uuid();
    laptop.app.push(vec![record(&a, 0, 1, b"a1")]).await;
    let (_, cursor) = desk.app.pull_all(0).await;

    // The laptop gives the space a new key (a device was lost): every record, sealed again.
    let (held, _) = laptop.app.pull_all(0).await;
    let new_id = uuid();
    let resealed: Vec<Value> =
        held.iter().map(|r| record(r["id"].as_str().unwrap(), r["seq"].as_u64().unwrap(), 1, b"a1 resealed")).collect();
    let current = laptop.app.spaces().await[0]["key"].as_str().unwrap().to_string();
    let body = json!({ "id": new_id, "key": current, "records": resealed });
    let space = laptop.app.ok(reqwest::Method::POST, "/uwu/v1/suite/spaces/ssh/rekey", Some(body)).await;
    assert_eq!(space["id"], new_id.as_str());

    // The desk's next pull is told to start over, and the space it knows is gone.
    let page = desk.app.pull(cursor).await;
    assert_eq!((page["reset"].as_bool(), page["records"].as_array().unwrap().len()), (Some(true), 0));
    let spaces = desk.app.spaces().await;
    assert_ne!(spaces[0]["id"].as_str().unwrap(), desk.space_id, "so it asks for the master password");
    let (again, _) = desk.app.pull_all(0).await;
    assert_eq!(again[0]["blob"], b64(b"a1 resealed"));
}

#[tokio::test]
async fn the_move_from_uwusync_copies_everything_and_a_second_run_copies_nothing() {
    let (server, token) = start().await;
    account(&server, &token).await;
    let app = sign_in(&server.url, "5a0e9c1e-0000-4000-8000-0000000a0001", SSH, None, PASSWORD).await.unwrap().app;
    // What was read from UwUSync: more than one page.
    let copied: Vec<Value> = (0..620).map(|n| record(&uuid(), 0, 1_790_000_000_000 + n, b"sealed again")).collect();
    for page in copied.chunks(500) {
        let answer = app.push(page.to_vec()).await;
        assert_eq!(answer["accepted"].as_array().unwrap().len(), page.len());
    }
    // The check: everything there, with its clock.
    let (held, _) = app.pull_all(0).await;
    assert_eq!(held.len(), copied.len());
    for (mine, theirs) in copied.iter().zip(&held) {
        assert_eq!((&mine["id"], &mine["updatedAt"]), (&theirs["id"], &theirs["updatedAt"]));
    }
    // Run again (or on another device): every record is there already, and comes back to merge.
    let again = app.push(copied[..500].to_vec()).await;
    assert!(again["accepted"].as_array().unwrap().is_empty());
    assert_eq!(again["conflicts"].as_array().unwrap().len(), 500);
}

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn next(socket: &mut Socket) -> Value {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), socket.next()).await.expect("a message in time") {
            Some(Ok(Message::Text(text))) => return serde_json::from_str(text.as_str()).unwrap(),
            Some(Ok(Message::Close(frame))) => return json!({ "close": frame.map(|f| u16::from(f.code)) }),
            Some(Ok(_)) => continue,
            other => panic!("the channel ended without a close: {other:?}"),
        }
    }
}

#[tokio::test]
async fn the_channel_signs_in_passes_on_changes_to_this_space_renews_its_token_and_ends_on_logout() {
    let (server, token) = start().await;
    account(&server, &token).await;
    let laptop = sign_in(&server.url, "5a0e9c1e-0000-4000-8000-0000000b0001", SSH, None, PASSWORD).await.unwrap().app;
    let mut desk = sign_in(&server.url, "5a0e9c1e-0000-4000-8000-0000000b0002", SSH, None, PASSWORD).await.unwrap().app;

    let url = server.url.replacen("http://", "ws://", 1);
    let mut request = format!("{url}/uwu/v1/realtime").into_client_request().unwrap();
    request.headers_mut().insert("Sec-WebSocket-Protocol", "uwu.realtime.v1".parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let auth = |token: &str| Message::text(json!({ "type": "auth", "token": token, "cursor": null }).to_string());
    socket.send(auth(&desk.access)).await.unwrap();
    let ready = next(&mut socket).await;
    assert_eq!(ready["type"], "ready");
    assert!(ready["expires"].as_u64().unwrap() > 0 && ready["heartbeat"].as_u64().unwrap() >= 1);

    laptop.push(vec![record(&uuid(), 0, 1, b"new host")]).await;
    assert_eq!(next(&mut socket).await, json!({ "type": "changed", "areas": ["suite"], "spaces": ["ssh"] }));

    // Before the token runs out, a new one on the same connection.
    desk.refresh().await.unwrap();
    socket.send(auth(&desk.access)).await.unwrap();
    assert_eq!(next(&mut socket).await["type"], "ready");

    // The account logs out everywhere: the app hears why, then the close.
    let desktop = client(&server.url, "5a0e9c1e-7d3b-4d0c-9a8e-0000000000d4");
    let (_, hash) = hash(&desktop).await;
    let LoginOutcome::LoggedIn(session) = desktop.login(login(&hash)).await.unwrap() else { panic!("a login") };
    let response = reqwest::Client::new()
        .post(format!("{}/api/accounts/security-stamp", server.url))
        .bearer_auth(session.access_token.as_str())
        .json(&json!({ "masterPasswordHash": hash }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(next(&mut socket).await, json!({ "type": "logout", "reason": "securityStamp" }));
    assert_eq!(next(&mut socket).await["close"], 4401);
}

/// `application/x-www-form-urlencoded`, as the apps send the token request.
fn form_body<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    fn encode(text: &str) -> String {
        text.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => (b as char).to_string(),
                b' ' => "+".into(),
                _ => format!("%{b:02X}"),
            })
            .collect()
    }
    pairs.into_iter().map(|(k, v)| format!("{}={}", encode(k), encode(v))).collect::<Vec<_>>().join("&")
}

/// The web vault's way (docs/uwu-api.md §6, "the web vault edits suite records"): logged in as
/// the account, it makes the space and writes records with `uwulock_core::suite`, the calls its
/// WebAssembly module makes; UwUSSH signs in afterwards, takes that space and opens them. Then
/// the app writes, and the web vault edits on top of it, keeping every field it doesn't know and
/// the assistant's records it never shows.
#[tokio::test]
async fn the_web_vault_makes_the_space_and_writes_records_the_app_opens() {
    use uwulock_core::suite::{Envelope, Payload, Space, SpaceVault, SuiteSpace};

    let (server, token) = start().await;
    account(&server, &token).await;
    let browser = client(&server.url, "5a0e9c1e-0000-4000-8000-00000000f001");
    let (master, password_hash) = hash(&browser).await;
    let LoginOutcome::LoggedIn(session) = browser.login(login(&password_hash)).await.unwrap() else {
        panic!("a login")
    };
    let user_key =
        crypto::decrypt_user_key(&master, &session.protected_user_key.clone().unwrap().parse().unwrap()).unwrap();
    let private = session.protected_private_key.as_ref().map(|wrapped| {
        PrivateKey::from_der(&wrapped.parse::<EncString>().unwrap().decrypt(&user_key).unwrap()).unwrap()
    });
    let web = App {
        url: server.url.clone(),
        http: reqwest::Client::new(),
        client_id: "web",
        space: "ssh",
        device: "browser".into(),
        access: session.access_token.to_string(),
        refresh: String::new(),
    };
    let extras = web.extras_key(&user_key, private.as_ref()).await;

    // No space yet: the web vault makes it.
    assert!(web.spaces().await.is_empty());
    let (vault, request) = SpaceVault::create(Space::Ssh, &extras);
    web.ok(reqwest::Method::PUT, "/uwu/v1/suite/spaces/ssh", Some(serde_json::to_value(&request).unwrap())).await;
    let device = 0x5eb_u32;
    let now = 1_790_000_000_000;
    let secret = vault.seal_new("secret", &Payload::Text("hunter2".into()), now, device).unwrap();
    let identity = json!({ "label": "Nyu", "username": "nyu", "auth_type": "password", "key_id": null,
        "password_secret_id": secret.id });
    let identity = vault.seal_new("identity", &Payload::Json(identity), now, device).unwrap();
    let host = json!({ "name": "Router", "address": "192.0.2.1", "port": 2222, "workspace": "private",
        "position": 0, "group_id": null, "identity_id": identity.id });
    let host = vault.seal_new("host", &Payload::Json(host), now, device).unwrap();
    let body = vault.push_request(vec![secret.clone(), identity.clone(), host.clone()]);
    let pushed = web
        .ok(reqwest::Method::POST, "/uwu/v1/suite/spaces/ssh/records", Some(serde_json::to_value(&body).unwrap()))
        .await;
    assert_eq!(pushed["accepted"].as_array().unwrap().len(), 3, "{pushed}");

    // UwUSSH takes the web vault's space and opens what it wrote.
    let ssh = sign_in(&server.url, "5a0e9c1e-0000-4000-8000-00000000f002", SSH, None, PASSWORD).await.unwrap();
    assert!(!ssh.made_space);
    assert_eq!(ssh.space_id, vault.id.to_string());
    let listed = web.spaces().await.remove(0);
    let listed: SuiteSpace = serde_json::from_value(listed).unwrap();
    let app = SpaceVault::open_space(&listed, &extras).unwrap();
    assert_eq!(app.key().as_bytes(), ssh.space_key.as_bytes());
    let (records, _) = ssh.app.pull_all(0).await;
    let records: Vec<Envelope> = records.into_iter().map(|r| serde_json::from_value(r).unwrap()).collect();
    let opened = |id: &str| app.open_record(records.iter().find(|r| r.id == id).unwrap()).unwrap();
    assert_eq!(opened(&secret.id).payload, Some(Payload::Text("hunter2".into())));
    let Some(Payload::Json(read)) = opened(&host.id).payload else { panic!("a host") };
    assert_eq!((read["address"].as_str(), read["port"].as_u64()), (Some("192.0.2.1"), Some(2222)));

    // The app writes a field the web vault doesn't know, and its assistant's settings.
    let host_seq = records.iter().find(|r| r.id == host.id).unwrap().seq.unwrap();
    let mut newer = read.clone();
    newer["tags"] = json!(["lab"]);
    let head = records.iter().find(|r| r.id == host.id).unwrap().head().unwrap();
    let app_edit = app.seal_edit(&head, &Payload::Json(newer), now + 5, 305_419_896).unwrap();
    let assist =
        app.seal_new("assist_config", &Payload::Json(json!({ "provider": "" })), now + 5, 305_419_896).unwrap();
    let answer =
        ssh.app.push(vec![serde_json::to_value(&app_edit).unwrap(), serde_json::to_value(&assist).unwrap()]).await;
    assert_eq!(answer["accepted"].as_array().unwrap().len(), 2, "{answer}");

    // The web vault pulls, edits the host as JSON and writes it back on what the server holds.
    let (records, _) = web.pull_all(0).await;
    let records: Vec<Envelope> = records.into_iter().map(|r| serde_json::from_value(r).unwrap()).collect();
    let current = records.iter().find(|r| r.id == host.id).unwrap();
    assert!(current.seq.unwrap() > host_seq);
    let Some(Payload::Json(mut edited)) = vault.open_record(current).unwrap().payload else { panic!("a host") };
    edited["name"] = json!("Router (Keller)");
    // The browser's clock is behind: the edit still sorts after the app's.
    let web_edit = vault.seal_edit(&current.head().unwrap(), &Payload::Json(edited), now, device).unwrap();
    assert!(web_edit.updated_at > app_edit.updated_at);
    let body = vault.push_request(vec![web_edit.clone()]);
    let pushed = web
        .ok(reqwest::Method::POST, "/uwu/v1/suite/spaces/ssh/records", Some(serde_json::to_value(&body).unwrap()))
        .await;
    assert_eq!(pushed["accepted"][0]["id"], host.id.as_str());

    let (records, _) = ssh.app.pull_all(0).await;
    let records: Vec<Envelope> = records.into_iter().map(|r| serde_json::from_value(r).unwrap()).collect();
    let Some(Payload::Json(now_read)) = opened_in(&app, &records, &host.id) else { panic!("a host") };
    assert_eq!(now_read["name"], "Router (Keller)");
    assert_eq!(now_read["tags"], json!(["lab"]), "the app's field survived the web vault's edit");
    assert!(records.iter().any(|r| r.kind == "assist_config" && r.id == assist.id), "passed on untouched");

    // Deleting the host in the web vault is a tombstone the app opens as one.
    let current = records.iter().find(|r| r.id == host.id).unwrap();
    let gone = vault.seal_tombstone(&current.head().unwrap(), now, device).unwrap();
    let body = vault.push_request(vec![gone]);
    web.ok(reqwest::Method::POST, "/uwu/v1/suite/spaces/ssh/records", Some(serde_json::to_value(&body).unwrap())).await;
    let (records, _) = ssh.app.pull_all(0).await;
    let records: Vec<Envelope> = records.into_iter().map(|r| serde_json::from_value(r).unwrap()).collect();
    let tombstone = app.open_record(records.iter().find(|r| r.id == host.id).unwrap()).unwrap();
    assert!(tombstone.deleted && tombstone.payload.is_none());
}

fn opened_in(
    vault: &uwulock_core::suite::SpaceVault,
    records: &[uwulock_core::suite::Envelope],
    id: &str,
) -> Option<uwulock_core::suite::Payload> {
    vault.open_record(records.iter().find(|r| r.id == id).unwrap()).unwrap().payload
}
