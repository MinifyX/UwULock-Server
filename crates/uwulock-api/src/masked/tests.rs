use super::fake::Fake;
use crate::Settings;
use crate::settings::{MaskedServer, MaskedSettings};
use crate::test_support::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

/// A server that may talk to `fake`, and an account on it.
async fn server_with(fake: &Fake) -> (TestServer, Account) {
    let settings = Settings {
        masked: MaskedSettings { servers: vec![MaskedServer { url: fake.url.clone(), name: "UwUMail".into() }] },
        ..Settings::default()
    };
    let server = TestServer::with_settings(settings).await;
    let account = server.account("nyu@example.com").await;
    (server, account)
}

/// `/uwu/v1/masked/connect`: the address the browser goes to, and the cookie it gets.
async fn start_connect(server: &TestServer, account: &Account, fake: &Fake) -> (String, String) {
    let response =
        server.call("POST", "/uwu/v1/masked/connect", Some(&account.token), json!({ "server": fake.url })).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(cookie.starts_with("__Host-uwu-masked=") && cookie.contains("HttpOnly") && cookie.contains("Secure"));
    let binding = cookie.split(';').next().unwrap().to_string();
    let body = json(response).await;
    assert_eq!(body["object"], "maskedConnect");
    (body["authorizeUrl"].as_str().unwrap().to_string(), binding)
}

/// Back from UwUMail with `query`, carrying `cookie`: where the browser is sent.
async fn come_back(server: &TestServer, query: &str, cookie: &str) -> String {
    let request =
        Request::get(format!("/uwu/v1/masked/callback?{query}")).header("cookie", cookie).body(Body::empty()).unwrap();
    let response = server.send(request).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    response.headers()["location"].to_str().unwrap().to_string()
}

fn state_of(authorize_url: &str) -> String {
    let url = reqwest::Url::parse(authorize_url).unwrap();
    url.query_pairs().find(|(key, _)| key == "state").unwrap().1.into_owned()
}

/// Connect `account` all the way.
async fn connect(server: &TestServer, account: &Account, fake: &Fake) {
    let (authorize, cookie) = start_connect(server, account, fake).await;
    let code = fake.approve(&authorize);
    let query = format!("code={code}&state={}&iss={}", state_of(&authorize), crate::oidc::form_encode(&fake.url));
    let to = come_back(server, &query, &cookie).await;
    assert_eq!(to, "https://vault.example.com/#/settings/masked?result=connected");
}

async fn item(server: &TestServer, account: &Account) -> String {
    let body = json!({
        "type": 1, "name": "2.n|n|n", "notes": null, "favorite": false, "reprompt": 0, "folderId": null,
        "organizationId": null,
        "login": { "username": "2.u|u|u", "password": "2.p|p|p", "uris": null, "totp": null },
    });
    let response = server.call("POST", "/api/ciphers", Some(&account.token), body).await;
    assert_eq!(response.status(), StatusCode::OK);
    json(response).await["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn connect_make_link_and_switch_off_addresses() {
    let fake = Fake::start().await;
    let (server, account) = server_with(&fake).await;
    let before = json(server.get_as(&account.token, "/uwu/v1/masked/connection").await).await;
    assert_eq!(before["connected"], false);
    assert_eq!(before["allowedServers"][0]["url"], fake.url.as_str());
    let addresses = server.get_as(&account.token, "/uwu/v1/masked/addresses").await;
    assert_eq!(json(addresses).await["code"], "not_connected");

    connect(&server, &account, &fake).await;
    assert_eq!(fake.inner.lock().registrations, 1);
    let now = json(server.get_as(&account.token, "/uwu/v1/masked/connection").await).await;
    assert_eq!((now["connected"].as_bool(), now["status"].as_str()), (Some(true), Some("ok")));
    assert_eq!(now["username"], "nyu@example.com");
    assert_eq!(now["defaultDomain"], "masked.example.com");
    assert_eq!(now["domains"], json!(["example.com", "masked.example.com"]));
    let info = json(server.get("/uwu/v1/info").await).await;
    assert!(info["features"].as_array().unwrap().contains(&json!("masked-addresses")));
    let me = json(server.get_as(&account.token, "/uwu/v1/account").await).await;
    assert_eq!(me["maskedConnected"], true);

    // The token is kept sealed, never as it is.
    let stored = server.state.store.masked_connection(&account.id).await.unwrap().unwrap();
    assert!(stored.refresh_token.starts_with("v1.") && !stored.refresh_token.contains("refresh-"));

    let cipher = item(&server, &account).await;
    let body = json!({ "forDomain": "https://shop.example.com/login", "description": "Shop", "domain": "EXAMPLE.com", "cipherId": cipher });
    let made = server.call("POST", "/uwu/v1/masked/addresses", Some(&account.token), body.clone()).await;
    assert_eq!(made.status(), StatusCode::OK);
    let made = json(made).await;
    assert_eq!(made["object"], "maskedAddress");
    assert_eq!(made["state"], "enabled", "not pending: it must not vanish after a day");
    assert!(made["email"].as_str().unwrap().ends_with("@example.com"));
    assert_eq!(made["forDomain"], "https://shop.example.com");
    assert_eq!(made["cipherId"], cipher.as_str());
    assert_eq!(made["url"], format!("https://vault.example.com/#/vault?itemId={cipher}"));
    let again = server.call("POST", "/uwu/v1/masked/addresses", Some(&account.token), body).await;
    assert_eq!(json(again).await["code"], "exists", "one address per item");
    let wrong_domain = json!({ "forDomain": "", "domain": "elsewhere.example.net" });
    let refused = server.call("POST", "/uwu/v1/masked/addresses", Some(&account.token), wrong_domain).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);

    let links = json(server.get_as(&account.token, "/uwu/v1/masked/links").await).await;
    assert_eq!(links[&cipher]["email"], made["email"]);
    let id = made["id"].as_str().unwrap();
    let off = server
        .call("PATCH", &format!("/uwu/v1/masked/addresses/{id}"), Some(&account.token), json!({ "state": "disabled" }))
        .await;
    assert_eq!(json(off).await["state"], "disabled");
    let links = json(server.get_as(&account.token, "/uwu/v1/masked/links").await).await;
    assert_eq!(links[&cipher]["state"], "disabled", "the link knows the state");

    let unlinked = server
        .call("PATCH", &format!("/uwu/v1/masked/addresses/{id}"), Some(&account.token), json!({ "cipherId": null }))
        .await;
    let unlinked = json(unlinked).await;
    assert_eq!((unlinked["cipherId"].clone(), unlinked["url"].clone()), (Value::Null, Value::Null));
    let list = json(server.get_as(&account.token, "/uwu/v1/masked/addresses").await).await;
    assert_eq!(list["data"].as_array().unwrap().len(), 1);
    let gone = server.call("DELETE", &format!("/uwu/v1/masked/addresses/{id}"), Some(&account.token), json!({})).await;
    assert_eq!(json(gone).await["state"], "deleted");

    // UwUMail's limit of addresses is a quota.
    fake.inner.lock().limit = 1;
    let over = server.call("POST", "/uwu/v1/masked/addresses", Some(&account.token), json!({})).await;
    assert_eq!((over.status(), json(over).await["code"].clone()), (StatusCode::UNPROCESSABLE_ENTITY, json!("quota")));

    let notices = json(server.get_as(&account.token, "/uwu/v1/security/notices").await).await;
    assert!(notices["data"].as_array().unwrap().iter().any(|notice| notice["kind"] == "maskedConnected"));
    let off = server.call("DELETE", "/uwu/v1/masked/connection", Some(&account.token), json!({})).await;
    assert_eq!(off.status(), StatusCode::OK);
    assert!(fake.inner.lock().revoked.len() == 1, "the grant ended at UwUMail");
    let after = json(server.get_as(&account.token, "/uwu/v1/masked/connection").await).await;
    assert_eq!(after["connected"], false);
    let notices = json(server.get_as(&account.token, "/uwu/v1/security/notices").await).await;
    assert!(notices["data"].as_array().unwrap().iter().any(|notice| notice["kind"] == "maskedDisconnected"));
}

#[tokio::test]
async fn refresh_tokens_rotate_one_at_a_time_and_an_old_one_ends_the_grant() {
    let fake = Fake::start().await;
    let (server, account) = server_with(&fake).await;
    connect(&server, &account, &fake).await;

    // Five requests at once with a token that ran out: one refresh, not five.
    fake.expire_access();
    let path = "/uwu/v1/masked/addresses";
    let (a, b, c, d, e) = tokio::join!(
        server.get_as(&account.token, path),
        server.get_as(&account.token, path),
        server.get_as(&account.token, path),
        server.get_as(&account.token, path),
        server.get_as(&account.token, path),
    );
    for response in [a, b, c, d, e] {
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(fake.inner.lock().refreshes, 1);
    fake.expire_access();
    assert_eq!(server.get_as(&account.token, "/uwu/v1/masked/addresses").await.status(), StatusCode::OK);
    assert_eq!(fake.inner.lock().refreshes, 2);
    assert!(fake.inner.lock().dead_grants.is_empty(), "no refresh token came twice");

    // A refresh token that was used already (a database from before, say) ends the grant.
    let mut stored = server.state.store.masked_connection(&account.id).await.unwrap().unwrap();
    let used = fake.inner.lock().used.keys().next().cloned().unwrap();
    stored.refresh_token = server.state.secret.seal(&used, &super::purpose("refresh", &account.id, &fake.url)).unwrap();
    stored.access_token = None;
    server.state.store.set_masked_connection(stored).await.unwrap();
    let refused = server.get_as(&account.token, "/uwu/v1/masked/addresses").await;
    assert_eq!((refused.status(), json(refused).await["code"].clone()), (StatusCode::CONFLICT, json!("revoked")));
    assert_eq!(fake.inner.lock().dead_grants.len(), 1);
    let now = json(server.get_as(&account.token, "/uwu/v1/masked/connection").await).await;
    assert_eq!(now["status"], "revoked");
}

#[tokio::test]
async fn connecting_again_ends_the_grant_it_replaces() {
    let fake = Fake::start().await;
    let (server, account) = server_with(&fake).await;
    connect(&server, &account, &fake).await;
    assert!(fake.inner.lock().revoked.is_empty());
    connect(&server, &account, &fake).await;
    assert_eq!(fake.inner.lock().revoked.len(), 1, "the old grant ended at UwUMail (SV-L14)");
    fake.expire_access();
    let list = server.get_as(&account.token, "/uwu/v1/masked/addresses").await;
    assert_eq!(list.status(), StatusCode::OK, "the new one works");
}

#[tokio::test]
async fn a_forgotten_client_registers_again_and_uwumail_asking_to_wait_is_said() {
    let fake = Fake::start().await;
    let (server, account) = server_with(&fake).await;
    connect(&server, &account, &fake).await;
    let off = server.call("DELETE", "/uwu/v1/masked/connection", Some(&account.token), json!({})).await;
    assert_eq!(off.status(), StatusCode::OK);

    // UwUMail forgets the client between the consent and the code: that try ends with an
    // error, and the next registers anew.
    let (authorize, cookie) = start_connect(&server, &account, &fake).await;
    let code = fake.approve(&authorize);
    fake.forget_clients();
    let query = format!("code={code}&state={}&iss={}", state_of(&authorize), crate::oidc::form_encode(&fake.url));
    let to = come_back(&server, &query, &cookie).await;
    assert!(to.ends_with("?result=error&reason=upstream"), "{to}");
    connect(&server, &account, &fake).await;
    assert_eq!(fake.inner.lock().registrations, 2);

    // UwUMail forgot it while connected: the grant is gone with it, and connecting registers again.
    fake.forget_clients();
    fake.expire_access();
    let refused = server.get_as(&account.token, "/uwu/v1/masked/addresses").await;
    assert_eq!(json(refused).await["code"], "revoked");
    connect(&server, &account, &fake).await;
    assert_eq!(fake.inner.lock().registrations, 3);

    fake.expire_access();
    fake.inner.lock().token_busy = true;
    let busy = server.call("POST", "/uwu/v1/masked/addresses", Some(&account.token), json!({})).await;
    assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
    fake.inner.lock().token_busy = false;
    fake.inner.lock().jmap_busy = true;
    let busy = server.get_as(&account.token, "/uwu/v1/masked/addresses").await;
    assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
    let now = json(server.get_as(&account.token, "/uwu/v1/masked/connection").await).await;
    assert_eq!(now["status"], "ok", "a busy UwUMail is no reason to connect again");
}

/// Review finding R3-5: UwUMail refuses every token request from this server's address after 30
/// refused ones in 15 minutes, so no account may spend them: codes that are no codes are not sent
/// on, few failures per account, a budget per UwUMail server, and nothing while it asks to wait.
#[tokio::test]
async fn refused_codes_cannot_spend_uwumail_s_limit_for_everybody() {
    let fake = Fake::start().await;
    let (server, account) = server_with(&fake).await;
    let limits = crate::Limits {
        masked_codes_account: crate::limits::Limiter::new(3, std::time::Duration::from_secs(3600)),
        masked_codes_server: crate::limits::Limiter::new(4, std::time::Duration::from_secs(3600)),
        ..crate::Limits::generous()
    };
    let server = server.with_limits(limits);
    let other = server.account("other@example.com").await;
    async fn bogus(server: &TestServer, account: &Account, fake: &Fake, code: &str) -> String {
        let (authorize, cookie) = start_connect(server, account, fake).await;
        let iss = crate::oidc::form_encode(&fake.url);
        come_back(server, &format!("code={code}&state={}&iss={iss}", state_of(&authorize)), &cookie).await
    }
    let asked = || fake.inner.lock().token_requests;

    assert!(bogus(&server, &account, &fake, "%3Cscript%3E").await.ends_with("reason=invalid_state"));
    let long = "x".repeat(600);
    assert!(bogus(&server, &account, &fake, &long).await.ends_with("reason=invalid_state"));
    assert_eq!(asked(), 0, "not sent on");
    for _ in 0..3 {
        assert!(bogus(&server, &account, &fake, "not-a-code-at-all").await.ends_with("reason=upstream"));
    }
    assert!(bogus(&server, &account, &fake, "not-a-code-at-all").await.ends_with("reason=busy"), "three per account");
    assert_eq!(asked(), 3);
    assert!(bogus(&server, &other, &fake, "not-a-code-at-all").await.ends_with("reason=upstream"));
    assert!(
        bogus(&server, &other, &fake, "not-a-code-at-all").await.ends_with("reason=busy"),
        "the server's budget is spent"
    );
    assert_eq!(asked(), 4);

    // UwUMail says 429: its token endpoint is left alone for a while, refreshes included.
    let fake = Fake::start().await;
    let (server, account) = server_with(&fake).await;
    connect(&server, &account, &fake).await;
    fake.expire_access();
    fake.inner.lock().token_busy = true;
    let busy = server.get_as(&account.token, "/uwu/v1/masked/addresses").await;
    assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
    let asked = fake.inner.lock().token_requests;
    fake.inner.lock().token_busy = false;
    let still = server.get_as(&account.token, "/uwu/v1/masked/addresses").await;
    assert_eq!(still.status(), StatusCode::TOO_MANY_REQUESTS);
    let again =
        server.call("POST", "/uwu/v1/masked/connect", Some(&account.token), json!({ "server": fake.url })).await;
    assert_eq!(again.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(fake.inner.lock().token_requests, asked, "nothing asked while backing off");
    let now = json(server.get_as(&account.token, "/uwu/v1/masked/connection").await).await;
    assert_eq!(now["status"], "ok", "and nothing is ended for it");
}

#[tokio::test]
async fn the_answer_has_to_come_back_to_the_browser_that_asked() {
    let fake = Fake::start().await;
    let (server, account) = server_with(&fake).await;

    let unlisted = server
        .call("POST", "/uwu/v1/masked/connect", Some(&account.token), json!({ "server": "https://mail.example.net" }))
        .await;
    assert_eq!(json(unlisted).await["code"], "server_not_allowed");

    let iss = crate::oidc::form_encode(&fake.url);
    let (authorize, cookie) = start_connect(&server, &account, &fake).await;
    let code = fake.approve(&authorize);
    let state = state_of(&authorize);
    let wrong_cookie = come_back(&server, &format!("code={code}&state={state}&iss={iss}"), "__Host-uwu-masked=x").await;
    assert!(wrong_cookie.ends_with("reason=invalid_state"), "{wrong_cookie}");
    let again = come_back(&server, &format!("code={code}&state={state}&iss={iss}"), &cookie).await;
    assert!(again.ends_with("reason=invalid_state"), "a state works once: {again}");

    let (authorize, cookie) = start_connect(&server, &account, &fake).await;
    let code = fake.approve(&authorize);
    let other = crate::oidc::form_encode("https://mail.example.net");
    let mixed = come_back(&server, &format!("code={code}&state={}&iss={other}", state_of(&authorize)), &cookie).await;
    assert!(mixed.ends_with("reason=invalid_state"), "another issuer: {mixed}");

    let (authorize, cookie) = start_connect(&server, &account, &fake).await;
    let denied = come_back(&server, &format!("error=access_denied&state={}", state_of(&authorize)), &cookie).await;
    assert!(denied.ends_with("reason=denied"), "{denied}");
    assert!(server.state.store.masked_connection(&account.id).await.unwrap().is_none());

    // Without the scope, UwUMail cannot be used.
    fake.inner.lock().no_scope = true;
    let old = server.call("POST", "/uwu/v1/masked/connect", Some(&account.token), json!({ "server": fake.url })).await;
    assert_eq!(old.status(), StatusCode::BAD_GATEWAY);
    let check =
        server.call("POST", "/uwu/v1/admin/masked/check", Some(&account.token), json!({ "url": fake.url })).await;
    assert_eq!(check.status(), StatusCode::FORBIDDEN, "admins only");
}

#[tokio::test]
async fn without_listed_servers_the_feature_is_off() {
    let server = TestServer::new().await;
    let account = server.account("nyu@example.com").await;
    let off = server.get_as(&account.token, "/uwu/v1/masked/connection").await;
    assert_eq!((off.status(), json(off).await["code"].clone()), (StatusCode::NOT_FOUND, json!("feature_off")));
    let info = json(server.get("/uwu/v1/info").await).await;
    assert!(!info["features"].as_array().unwrap().contains(&json!("masked-addresses")));
}

#[tokio::test]
async fn the_admin_checks_a_server_before_listing_it() {
    let fake = Fake::start().await;
    let server = TestServer::new().await;
    let token = server.invite("admin@example.com", true).await;
    let response = server
        .call("POST", "/identity/accounts/register/finish", None, register_body("admin@example.com", &token))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let admin = server.login("admin@example.com", "device-1").await;
    let check = server.call("POST", "/uwu/v1/admin/masked/check", Some(&admin.token), json!({ "url": fake.url })).await;
    assert_eq!(
        json(check).await,
        json!({ "discovery": true, "maskedScope": true, "registration": true, "error": null })
    );
    fake.inner.lock().no_scope = true;
    let check =
        json(server.call("POST", "/uwu/v1/admin/masked/check", Some(&admin.token), json!({ "url": fake.url })).await)
            .await;
    assert_eq!((check["maskedScope"].as_bool(), check["error"].is_string()), (Some(false), true));

    let settings = json(server.get_as(&admin.token, "/uwu/v1/admin/settings").await).await;
    let mut settings = settings;
    settings["masked"] = json!({ "servers": [{ "url": format!("{}/", fake.url), "name": "" }] });
    let saved = server.call("PUT", "/uwu/v1/admin/settings", Some(&admin.token), settings.clone()).await;
    let saved = json(saved).await;
    assert_eq!(saved["masked"]["servers"][0]["url"], fake.url.as_str(), "kept without the slash");
    assert_eq!(saved["masked"]["servers"][0]["name"], "127.0.0.1");
    settings["masked"] = json!({ "servers": [{ "url": "https://mail.example.com/some/path", "name": "x" }] });
    let refused = server.call("PUT", "/uwu/v1/admin/settings", Some(&admin.token), settings.clone()).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    // Tokens in the clear only inside the local network (SV-L16).
    settings["masked"] = json!({ "servers": [{ "url": "http://mail.example.com", "name": "x" }] });
    let refused = server.call("PUT", "/uwu/v1/admin/settings", Some(&admin.token), settings.clone()).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    for local in ["http://192.0.2.1:8080", "http://uwumail:8080", "http://mail.internal"] {
        settings["masked"] = json!({ "servers": [{ "url": local, "name": "x" }] });
        let saved = server.call("PUT", "/uwu/v1/admin/settings", Some(&admin.token), settings.clone()).await;
        assert_eq!(saved.status(), StatusCode::OK, "{local}");
    }
}

#[test]
fn connecting_needs_the_server_on_https() {
    // SV-L15: the binding cookie is `__Host-` and `Secure` only there.
    for safe in ["https://vault.example.com", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"] {
        assert!(super::public_is_safe(safe), "{safe}");
    }
    for unsafe_ in ["http://vault.example.com", "http://192.0.2.1"] {
        assert!(!super::public_is_safe(unsafe_), "{unsafe_}");
    }
}

// ── The official clients' generators ─────────────────────

async fn api_key(server: &TestServer, account: &Account) -> String {
    let body = json!({ "name": "Firefox", "masterPasswordHash": password_hash(&account.email) });
    let made = server.call("POST", "/uwu/v1/masked/api-keys", Some(&account.token), body).await;
    assert_eq!(made.status(), StatusCode::OK);
    let made = json(made).await;
    let key = made["key"].as_str().unwrap().to_string();
    assert!(key.starts_with("uwulock_ma_"));
    assert_eq!(made["hint"], format!("…{}", &key[key.len() - 4..]));
    key
}

async fn post_with(server: &TestServer, path: &str, header: (&str, &str), body: Value) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("content-type", "application/json")
        .header(header.0, header.1)
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = server.send(request).await;
    let status = response.status();
    (status, json(response).await)
}

#[tokio::test]
async fn addy_io_and_simplelogin_as_bitwarden_s_generators_call_them() {
    let fake = Fake::start().await;
    let (server, account) = server_with(&fake).await;
    let key = api_key(&server, &account).await;
    let bearer = format!("Bearer {key}");
    let description =
        json!({ "domain": "whatever", "description": "Website: shop.example.com. Generated by Bitwarden." });

    let (status, body) =
        post_with(&server, "/uwu/v1/masked/addy/api/v1/aliases", ("authorization", &bearer), description.clone()).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("not_connected")));
    assert!(body["message"].as_str().unwrap().contains("Settings → Masked addresses"));

    connect(&server, &account, &fake).await;
    let (status, body) =
        post_with(&server, "/uwu/v1/masked/addy//api/v1/aliases", ("authorization", &bearer), description).await;
    assert_eq!(status, StatusCode::CREATED);
    let email = body["data"]["email"].as_str().unwrap();
    assert!(email.ends_with("@masked.example.com"), "the default for a domain it does not have: {email}");
    assert_eq!(body["data"]["active"], true);
    assert_eq!(body["data"]["domain"], "masked.example.com");
    let at_uwumail = fake.inner.lock().addresses.last().cloned().unwrap();
    assert_eq!(at_uwumail["forDomain"], "https://shop.example.com");
    assert_eq!(at_uwumail["state"], "enabled");

    let chosen = json!({ "domain": "Example.com", "description": "Website: a.example.org. Generated by Bitwarden." });
    let (_, body) = post_with(&server, "/uwu/v1/masked/addy/api/v1/aliases", ("authorization", &bearer), chosen).await;
    assert!(body["data"]["email"].as_str().unwrap().ends_with("@example.com"));

    let note = json!({ "note": "Website: https://shop.example.net/login. Generated by Bitwarden." });
    let (status, body) = post_with(
        &server,
        "/uwu/v1/masked/simplelogin/api/alias/random/new?hostname=https://login.example.net/x",
        ("authentication", &key),
        note,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["alias"], body["email"]);
    assert_eq!(body["enabled"], true);
    assert!(body["creation_timestamp"].as_i64().unwrap() > 0);
    assert_eq!(fake.inner.lock().addresses.last().unwrap()["forDomain"], "https://login.example.net");

    let (status, body) = post_with(
        &server,
        "/uwu/v1/masked/addy/api/v1/aliases",
        ("authorization", "Bearer uwulock_ma_AAAAAAAAAAAAAAAAAAAAAA_nope"),
        json!({}),
    )
    .await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::UNAUTHORIZED, Some("unauthorized")));
    // Not a login, anywhere else.
    assert_eq!(server.get_as(&key, "/api/sync").await.status(), StatusCode::UNAUTHORIZED);

    // A disabled account's key stops working, and works again once the account is back (SV-L1).
    server.state.store.update_user(&account.id, |user| user.disabled = true).await.unwrap();
    let (status, _) =
        post_with(&server, "/uwu/v1/masked/addy/api/v1/aliases", ("authorization", &bearer), json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a disabled account's key");
    server.state.store.update_user(&account.id, |user| user.disabled = false).await.unwrap();

    let keys = json(server.get_as(&account.token, "/uwu/v1/masked/api-keys").await).await;
    let listed = &keys["data"][0];
    assert!(listed["lastUsedDate"].is_string() && listed.get("key").is_none());
    let id = listed["id"].as_str().unwrap();
    let gone = server.call("DELETE", &format!("/uwu/v1/masked/api-keys/{id}"), Some(&account.token), json!({})).await;
    assert_eq!(gone.status(), StatusCode::OK);
    let (status, _) =
        post_with(&server, "/uwu/v1/masked/addy/api/v1/aliases", ("authorization", &bearer), json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a deleted key is no key");

    let notices = json(server.get_as(&account.token, "/uwu/v1/security/notices").await).await;
    assert!(notices["data"].as_array().unwrap().iter().any(|notice| notice["kind"] == "maskedApiKeyCreated"));
}

#[tokio::test]
async fn keys_need_the_master_password_and_are_limited() {
    let fake = Fake::start().await;
    let (server, account) = server_with(&fake).await;
    let wrong = json!({ "name": "Firefox", "masterPasswordHash": "wrong" });
    let refused = server.call("POST", "/uwu/v1/masked/api-keys", Some(&account.token), wrong).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    for _ in 0..10 {
        api_key(&server, &account).await;
    }
    let body = json!({ "name": "One more", "masterPasswordHash": password_hash(&account.email) });
    let over = server.call("POST", "/uwu/v1/masked/api-keys", Some(&account.token), body).await;
    assert_eq!((over.status(), json(over).await["code"].clone()), (StatusCode::UNPROCESSABLE_ENTITY, json!("quota")));
}

/// Against a real UwUMail Server with the `maskedemail` scope (UwUMail-Server PR #21, branch
/// of `feat(oauth): a masked-only scope`). What the fake above cannot show: that the two
/// really understand each other. Run by hand:
///
/// ```sh
/// # In UwUMail-Server on that branch: a server on https://mail.example.test with an account,
/// # JMAP on for it and a domain its masked-address policy allows (docs/jmap-masked-email.md).
/// # Then get a token with the scope, e.g. through the Lock server's own connect in the web
/// # vault, or any OAuth client (PKCE, scope=maskedemail), and:
/// UWULOCK_TEST_UWUMAIL=https://mail.example.test UWULOCK_TEST_UWUMAIL_TOKEN=<access token> \
///   cargo test -p uwulock-api -- --ignored masked::tests::against_a_real_uwumail
/// ```
///
/// It checks discovery and registration, reads the session, makes an address, switches it off
/// and deletes it.
#[tokio::test]
#[ignore = "needs a running UwUMail Server, see the comment"]
async fn against_a_real_uwumail() {
    use super::uwumail;
    let server = std::env::var("UWULOCK_TEST_UWUMAIL").expect("UWULOCK_TEST_UWUMAIL");
    let token = std::env::var("UWULOCK_TEST_UWUMAIL_TOKEN").expect("UWULOCK_TEST_UWUMAIL_TOKEN");
    let discovery = uwumail::discover(&server).await.expect("discovery with the maskedemail scope");
    let client =
        uwumail::register(&discovery, "UwULock (test.example.com)", "https://test.example.com/uwu/v1/masked/callback")
            .await
            .expect("registration as a public client");
    assert!(!client.is_empty());
    let session = uwumail::session(&server, &token).await.expect("the session with the masked account");
    assert!(!session.domains.is_empty(), "a domain the account may use");
    let create = json!({ "accountId": session.account_id, "create": { "k1": {
        "state": "enabled", "forDomain": "https://shop.example.com", "description": "UwULock test" } } });
    let made = uwumail::call(&session.api_url, &token, "MaskedEmail/set", create).await.expect("MaskedEmail/set");
    let id = made["created"]["k1"]["id"].as_str().expect("an address").to_string();
    assert!(made["created"]["k1"]["createdBy"].as_str().unwrap_or_default().starts_with("OAuth:"));
    for state in ["disabled", "deleted"] {
        let update = json!({ "accountId": session.account_id, "update": { id.clone(): { "state": state } } });
        let changed = uwumail::call(&session.api_url, &token, "MaskedEmail/set", update).await.unwrap();
        assert!(changed["updated"].get(&id).is_some(), "{changed}");
    }
}

#[tokio::test]
async fn a_deleted_account_ends_its_grant_at_uwumail() {
    let fake = Fake::start().await;
    let (server, account) = server_with(&fake).await;
    connect(&server, &account, &fake).await;
    let secret = json!({ "masterPasswordHash": password_hash(&account.email) });
    assert_eq!(server.call("DELETE", "/api/accounts", Some(&account.token), secret).await.status(), StatusCode::OK);
    assert_eq!(fake.inner.lock().revoked.len(), 1, "the grant ended at UwUMail");
    assert!(server.state.store.masked_connection(&account.id).await.unwrap().is_none());
}

async fn uwu_sync(server: &TestServer, account: &Account, query: String) -> Value {
    json(server.get_as(&account.token, &format!("/uwu/v1/sync?include=uwu{query}")).await).await
}

/// Whether `changed uwu` is among what the account's realtime connection heard since last asked.
fn heard_uwu(connection: &mut uwulock_notify::realtime::Connection) -> bool {
    let mut heard = false;
    while let Ok(event) = connection.events.try_recv() {
        heard |= event.live == uwulock_notify::realtime::Live::changed("uwu");
    }
    heard
}

#[tokio::test]
async fn links_come_with_the_delta_sync_and_on_the_realtime_channel() {
    let fake = Fake::start().await;
    let (server, account) = server_with(&fake).await;
    connect(&server, &account, &fake).await;
    let cipher = item(&server, &account).await;
    let full = uwu_sync(&server, &account, String::new()).await;
    assert_eq!(full["uwu"]["maskedLinks"], json!({}), "complete in a full sync, even when empty");
    let mut live = server.state.realtime.join(&account.id).unwrap();

    let body = json!({ "forDomain": "https://shop.example.com", "cipherId": cipher });
    let made = json(server.call("POST", "/uwu/v1/masked/addresses", Some(&account.token), body).await).await;
    assert!(heard_uwu(&mut live));
    let delta = uwu_sync(&server, &account, format!("&since={}", full["cursor"].as_str().unwrap())).await;
    assert_eq!(delta["reset"], false);
    assert_eq!(delta["uwu"]["maskedLinks"][&cipher]["email"], made["email"]);
    assert_eq!(delta["uwu"]["maskedLinks"][&cipher]["id"], made["id"]);
    let quiet = uwu_sync(&server, &account, format!("&since={}", delta["cursor"].as_str().unwrap())).await;
    assert_eq!(quiet["uwu"]["maskedLinks"], Value::Null, "nothing changed");

    // Listing the addresses again with nothing new says nothing; a new state does.
    server.get_as(&account.token, "/uwu/v1/masked/addresses").await;
    assert!(!heard_uwu(&mut live));
    let id = made["id"].as_str().unwrap();
    let path = format!("/uwu/v1/masked/addresses/{id}");
    server.call("PATCH", &path, Some(&account.token), json!({ "state": "disabled" })).await;
    assert!(heard_uwu(&mut live));
    let delta = uwu_sync(&server, &account, format!("&since={}", quiet["cursor"].as_str().unwrap())).await;
    assert_eq!(delta["uwu"]["maskedLinks"][&cipher]["state"], "disabled");

    // An item deleted for good takes its link along.
    let gone = server.call("DELETE", &format!("/api/ciphers/{cipher}"), Some(&account.token), json!({})).await;
    assert_eq!(gone.status(), StatusCode::OK);
    let delta = uwu_sync(&server, &account, format!("&since={}", delta["cursor"].as_str().unwrap())).await;
    assert_eq!(delta["uwu"]["maskedLinks"], json!({}));
}

#[tokio::test]
async fn the_admin_check_is_limited() {
    let fake = Fake::start().await;
    let limits = crate::Limits {
        masked_connect: crate::limits::Limiter::new(2, std::time::Duration::from_secs(3600)),
        ..crate::Limits::generous()
    };
    let server = TestServer::new().await.with_limits(limits);
    let token = server.invite("admin@example.com", true).await;
    server.call("POST", "/identity/accounts/register/finish", None, register_body("admin@example.com", &token)).await;
    let admin = server.login("admin@example.com", "device-1").await;
    let check = || server.call("POST", "/uwu/v1/admin/masked/check", Some(&admin.token), json!({ "url": fake.url }));
    assert_eq!(check().await.status(), StatusCode::OK);
    assert_eq!(check().await.status(), StatusCode::OK);
    assert_eq!(check().await.status(), StatusCode::TOO_MANY_REQUESTS);
}
