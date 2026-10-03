//! SSO against a provider in this process: discovery, keys, a token endpoint that hands out ID
//! tokens it signs itself, userinfo — and UwUAuth's pairing endpoints.

use super::*;
use crate::oidc::tests::Signer;
use crate::test_support::*;
use axum::body::Body;
use axum::http::Request;
use parking_lot::Mutex as PlMutex;
use std::sync::Arc;

const CODE: &str = "7KQ4-M2XD-9HFT";

/// A token request: the `Authorization` header and the form.
type TokenRequest = (Option<String>, HashMap<String, String>);

/// An OpenID Connect provider (and a UwUAuth that pairs) on `127.0.0.1`.
#[derive(Clone)]
pub(crate) struct Provider {
    pub issuer: String,
    signer: Arc<Signer>,
    /// What the ID token for a code says.
    codes: Arc<PlMutex<HashMap<String, Value>>>,
    /// The token requests: the `Authorization` header and the form.
    pub requests: Arc<PlMutex<Vec<TokenRequest>>>,
    pub userinfo: Arc<PlMutex<Value>>,
    pub paired: Arc<PlMutex<Vec<Value>>>,
}

impl Provider {
    pub(crate) async fn start() -> Self {
        use axum::extract::State as S;
        use axum::routing::{get, post};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let provider = Provider {
            issuer: issuer.clone(),
            signer: Arc::new(Signer::es256()),
            codes: Arc::default(),
            requests: Arc::default(),
            userinfo: Arc::new(PlMutex::new(json!({}))),
            paired: Arc::default(),
        };
        let app = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(|S(p): S<Provider>| async move {
                    Json(json!({
                        "issuer": p.issuer,
                        "authorization_endpoint": format!("{}/authorize", p.issuer),
                        "token_endpoint": format!("{}/token", p.issuer),
                        "userinfo_endpoint": format!("{}/userinfo", p.issuer),
                        "jwks_uri": format!("{}/jwks", p.issuer),
                    }))
                }),
            )
            .route("/jwks", get(|S(p): S<Provider>| async move { Json(json!({ "keys": [p.signer.jwk("k1")] })) }))
            .route(
                "/token",
                post(|S(p): S<Provider>, headers: HeaderMap, axum::Form(form): axum::Form<HashMap<String, String>>| async move {
                    let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string);
                    p.requests.lock().push((auth, form.clone()));
                    let claims = p.codes.lock().remove(form.get("code").map(String::as_str).unwrap_or_default());
                    match claims {
                        Some(claims) => Json(json!({
                            "access_token": "provider-access",
                            "token_type": "Bearer",
                            "id_token": p.signer.sign("k1", &claims),
                        }))
                        .into_response(),
                        None => (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant" }))).into_response(),
                    }
                }),
            )
            .route("/userinfo", get(|S(p): S<Provider>| async move { Json(p.userinfo.lock().clone()) }))
            .route(
                "/uwu/v1/server",
                get(|S(p): S<Provider>| async move {
                    Json(json!({ "product": "UwUAuth", "version": "0.4.0", "issuer": p.issuer, "pairing": 1, "scim": true }))
                }),
            )
            .route(
                "/uwu/v1/pair",
                post(|S(p): S<Provider>, Json(body): Json<Value>| async move {
                    let code = body["code"].as_str().unwrap_or_default().to_string();
                    p.paired.lock().push(body);
                    if code != CODE {
                        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_code", "message": "no" })))
                            .into_response();
                    }
                    Json(json!({
                        "issuer": p.issuer,
                        "clientId": "uwulock-vault",
                        "clientSecret": "paired-secret",
                        "tokenEndpointAuthMethod": "client_secret_basic",
                        "scopes": ["openid", "email", "profile", "groups", "roles"],
                        "groupsClaim": "groups",
                        "rolesClaim": "roles",
                        "scimToken": "scim-token-from-uwuauth",
                        "appId": "app-1",
                        "manageUrl": format!("{}/admin#/apps/app-1", p.issuer),
                    }))
                    .into_response()
                }),
            )
            .with_state(provider.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        provider
    }

    /// The ID token the next exchange of `code` gets: `claims` over sensible defaults.
    fn will_answer(&self, code: &str, nonce: &str, claims: Value) {
        let now = auth::now_seconds();
        let mut token = json!({
            "iss": self.issuer, "aud": "vault", "sub": "person-1", "nonce": nonce,
            "exp": now + 300, "iat": now, "email": "mia@example.com", "email_verified": true,
        });
        for (key, value) in claims.as_object().unwrap() {
            if value.is_null() {
                token.as_object_mut().unwrap().remove(key);
            } else {
                token[key] = value.clone();
            }
        }
        self.codes.lock().insert(code.to_string(), token);
    }
}

/// SSO switched on against `provider`, with `change` made to the settings.
async fn server_with(provider: &Provider, change: impl FnOnce(&mut SsoSettings)) -> TestServer {
    let server = TestServer::new().await;
    configure(&server, provider, change);
    server
}

fn configure(server: &TestServer, provider: &Provider, change: impl FnOnce(&mut SsoSettings)) {
    let mut settings = server.state.settings();
    settings.sso = SsoSettings {
        enabled: true,
        issuer: provider.issuer.clone(),
        client_id: "vault".into(),
        client_secret: Some(server.state.secret.seal("s3cret", SECRET_PURPOSE).unwrap()),
        signups: Signups::Group,
        ..SsoSettings::default()
    };
    change(&mut settings.sso);
    server.state.apply_settings(settings);
}

const VERIFIER: &str = "a-client-verifier-that-is-long-enough-for-pkce-0123456789";
const CONNECTOR: &str = "https://vault.example.com/sso-connector.html";

/// A browser's way through: prevalidate, authorize, the provider (answering `claims` for the
/// code), and back to the callback. The callback's answer.
async fn through_provider(
    server: &TestServer,
    provider: &Provider,
    client: &str,
    redirect: &str,
    claims: Value,
) -> Response {
    let (location, cookie) = start(server, client, redirect).await;
    let url = reqwest::Url::parse(&location).unwrap();
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert!(location.starts_with(&format!("{}/authorize?", provider.issuer)), "{location}");
    assert_eq!(query["client_id"], server.state.settings().sso.client_id);
    assert_eq!(query["redirect_uri"], "https://vault.example.com/identity/connect/oidc-signin");
    assert_eq!(query["code_challenge_method"], "S256");
    let code = format!("pc-{}", auth::random_token(6));
    provider.will_answer(&code, &query["nonce"], claims);
    callback(server, &format!("code={code}&state={}", query["state"]), Some(&cookie)).await
}

/// Up to the provider: its address, and the cookie.
async fn start(server: &TestServer, client: &str, redirect: &str) -> (String, String) {
    let token = json(server.get("/identity/sso/prevalidate").await).await["token"].as_str().unwrap().to_string();
    let path = format!(
        "/identity/connect/authorize?client_id={client}&redirect_uri={}&response_type=code&scope=api%20offline_access\
         &state=client-state&code_challenge={}&code_challenge_method=S256&response_mode=query&domain_hint=x&ssoToken={token}",
        oidc::form_encode(redirect),
        pkce_challenge(VERIFIER),
    );
    let response = server.get(&path).await;
    assert_eq!(response.status(), StatusCode::FOUND, "{}", text(response).await);
    let cookie = response.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(cookie.starts_with("__Host-uwu-sso=") && cookie.contains("HttpOnly") && cookie.contains("Secure"));
    assert!(cookie.contains("SameSite=Lax") && cookie.contains("Path=/"));
    let cookie = cookie.split(';').next().unwrap().to_string();
    (response.headers()["location"].to_str().unwrap().to_string(), cookie)
}

async fn callback(server: &TestServer, query: &str, cookie: Option<&str>) -> Response {
    let mut request = Request::get(format!("{CALLBACK}?{query}"));
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    server.send(request.body(Body::empty()).unwrap()).await
}

/// Where the callback sent the browser, as its query.
fn back(response: &Response) -> HashMap<String, String> {
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response.headers()["location"].to_str().unwrap();
    reqwest::Url::parse(location).unwrap().query_pairs().into_owned().collect()
}

async fn redeem(server: &TestServer, code: &str, client: &str, redirect: &str, device: &str) -> Response {
    server
        .form(
            "/identity/connect/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("code_verifier", VERIFIER),
                ("redirect_uri", redirect),
                ("client_id", client),
                ("scope", "api offline_access"),
                ("deviceType", "9"),
                ("deviceIdentifier", device),
                ("deviceName", "chrome"),
            ],
        )
        .await
}

/// A whole SSO login from the web vault: the token answer.
async fn log_in(server: &TestServer, provider: &Provider, claims: Value, device: &str) -> Value {
    let response = through_provider(server, provider, "web", CONNECTOR, claims).await;
    let query = back(&response);
    assert_eq!(query["state"], "client-state");
    let code = query.get("code").unwrap_or_else(|| panic!("refused: {query:?}"));
    let response = redeem(server, code, "web", CONNECTOR, device).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    json(response).await
}

fn claims_of(token: &str) -> Value {
    use base64::Engine as _;
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

#[tokio::test]
async fn a_new_person_signs_up_through_sso_and_sets_the_master_password() {
    let provider = Provider::start().await;
    let server = server_with(&provider, |_| {}).await;
    let body = log_in(&server, &provider, json!({}), "d1").await;
    assert!(body.get("Key").is_none() && body.get("PrivateKey").is_none() && body.get("AccountKeys").is_none());
    assert_eq!(body["UserDecryptionOptions"], json!({ "HasMasterPassword": false, "Object": "userDecryptionOptions" }));
    let token = body["access_token"].as_str().unwrap().to_string();
    assert_eq!(claims_of(&token)["amr"], json!(["Application", "sso"]));

    // The provider got the secret, and the server's own PKCE verifier.
    let (auth_header, form) = provider.requests.lock()[0].clone();
    use base64::Engine as _;
    assert_eq!(
        auth_header.unwrap(),
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("vault:s3cret"))
    );
    assert!(form["code_verifier"].len() >= 43);

    let account = json(server.get_as(&token, "/uwu/v1/account").await).await;
    assert_eq!((account["hasMasterPassword"].clone(), account["sso"].clone()), (json!(false), json!(true)));
    let sync = json(server.get_as(&token, "/api/sync").await).await;
    assert_eq!(sync["profile"]["key"], Value::Null);

    // The password: once, with a KDF the server takes.
    let mut set = json!({
        "masterPasswordHash": password_hash("mia@example.com"),
        "key": type2(),
        "masterPasswordHint": null,
        "orgIdentifier": "uwulock",
        "keys": { "publicKey": "MIIBpublic", "encryptedPrivateKey": type2() },
        "kdf": 0, "kdfIterations": 5000,
    });
    let weak = server.call("POST", "/api/accounts/set-password", Some(&token), set.clone()).await;
    assert_eq!(weak.status(), StatusCode::BAD_REQUEST);
    set["kdfIterations"] = 600_000.into();
    let response = server.call("POST", "/api/accounts/set-password", Some(&token), set.clone()).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    let again = server.call("POST", "/api/accounts/set-password", Some(&token), set).await;
    assert_eq!(again.status(), StatusCode::BAD_REQUEST, "only once");
    assert_eq!(server.get_as(&token, "/api/sync").await.status(), StatusCode::OK, "the session goes on");

    // Now the password works, and SSO answers with the keys.
    server.login("mia@example.com", "d2").await;
    let body = log_in(&server, &provider, json!({}), "d3").await;
    assert_eq!(body["Key"], type2());
    assert_eq!(body["UserDecryptionOptions"]["HasMasterPassword"], true);

    // A refresh keeps saying it came through SSO.
    let refreshed = server
        .form(
            "/identity/connect/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", "web"),
                ("refresh_token", body["refresh_token"].as_str().unwrap()),
            ],
        )
        .await;
    let refreshed = json(refreshed).await;
    assert_eq!(claims_of(refreshed["access_token"].as_str().unwrap())["amr"], json!(["Application", "sso"]));
}

#[tokio::test]
async fn the_new_form_of_setting_the_password_works_too() {
    let provider = Provider::start().await;
    let server = server_with(&provider, |_| {}).await;
    let token = log_in(&server, &provider, json!({}), "d1").await["access_token"].as_str().unwrap().to_string();
    let kdf = json!({ "kdfType": 1, "iterations": 3, "memory": 64, "parallelism": 4 });
    let body = json!({
        "masterPasswordAuthentication": { "kdf": kdf, "salt": "mia@example.com", "masterPasswordAuthenticationHash": password_hash("mia@example.com") },
        "masterPasswordUnlock": { "kdf": kdf, "salt": "mia@example.com", "masterKeyWrappedUserKey": type2() },
        "accountKeys": { "publicKeyEncryptionKeyPair": { "wrappedPrivateKey": type2(), "publicKey": "MIIBpublic" } },
    });
    let mut wrong_salt = body.clone();
    wrong_salt["masterPasswordUnlock"]["salt"] = "other@example.com".into();
    let refused = server.call("POST", "/api/accounts/set-password", Some(&token), wrong_salt).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let response = server.call("POST", "/api/accounts/set-password", Some(&token), body).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    let user = server.state.store.user_by_email("mia@example.com").await.unwrap().unwrap();
    assert_eq!((user.kdf.kind, user.public_key.as_deref()), (1, Some("MIIBpublic")));
}

#[tokio::test]
async fn an_account_is_linked_by_its_verified_address_once() {
    let provider = Provider::start().await;
    let server = server_with(&provider, |_| {}).await;
    let account = server.account("mia@example.com").await;

    // An address the provider does not vouch for finds nothing.
    let refused = through_provider(&server, &provider, "web", CONNECTOR, json!({ "email_verified": false })).await;
    let query = back(&refused);
    assert_eq!(query["error"], "access_denied");
    assert!(query["error_description"].contains("verified"), "{query:?}");

    let body = log_in(&server, &provider, json!({}), "d2").await;
    assert_eq!(body["Key"], "2.userkey|userkey|userkey", "the account there was");
    let notices = server.state.store.notices(&account.id, None, 10).await.unwrap();
    assert!(notices.iter().any(|notice| notice.kind == "ssoLinked" && notice.detail.contains(&provider.issuer)));

    // Another login at the same provider with the same address: not this account.
    let other = through_provider(&server, &provider, "web", CONNECTOR, json!({ "sub": "person-2" })).await;
    assert!(back(&other)["error_description"].contains("another login"));
    // The linked login finds it even with another address now.
    let body = log_in(&server, &provider, json!({ "email": "new@example.com", "email_verified": false }), "d3").await;
    assert_eq!(claims_of(body["access_token"].as_str().unwrap())["sub"], account.id);
}

#[tokio::test]
async fn who_may_sign_up_follows_the_settings() {
    let provider = Provider::start().await;
    let server = server_with(&provider, |sso| sso.signups = Signups::Invitation).await;
    let refused = through_provider(&server, &provider, "web", CONNECTOR, json!({})).await;
    assert!(back(&refused)["error_description"].contains("invitation"));

    // An invitation, or an entry SCIM made, lets the address in.
    server.invite("mia@example.com", false).await;
    log_in(&server, &provider, json!({}), "d1").await;
    let now = clock::now();
    let entry = uwulock_store::ScimUser {
        id: "p-1".into(),
        email: "kai@example.com".into(),
        active: true,
        created: now.clone(),
        updated: now,
        ..Default::default()
    };
    server.state.store.put_scim_user(entry).await.unwrap();
    let kai = json!({ "sub": "person-kai", "email": "kai@example.com" });
    log_in(&server, &provider, kai, "d2").await;
    let kai = server.state.store.user_by_email("kai@example.com").await.unwrap().unwrap();
    assert_eq!(server.state.store.scim_user("p-1").await.unwrap().unwrap().user_id.as_deref(), Some(kai.id.as_str()));

    // A group: only its members (the groups may come from userinfo).
    configure(&server, &provider, |sso| sso.user_group = Some("vault-users".into()));
    let outsider = json!({ "sub": "person-3", "email": "ben@example.com" });
    let refused = through_provider(&server, &provider, "web", CONNECTOR, outsider.clone()).await;
    assert_eq!(back(&refused)["error"], "access_denied");
    *provider.userinfo.lock() = json!({ "sub": "person-3", "groups": ["/vault-users"] });
    log_in(&server, &provider, outsider, "d3").await;

    configure(&server, &provider, |sso| sso.signups = Signups::Off);
    let refused =
        through_provider(&server, &provider, "web", CONNECTOR, json!({ "sub": "p4", "email": "x@example.com" })).await;
    assert_eq!(back(&refused)["error"], "access_denied");
}

#[tokio::test]
async fn the_admin_right_follows_the_group_within_the_admin_networks() {
    let provider = Provider::start().await;
    let server = server_with(&provider, |sso| sso.admin_group = Some("vault-admins".into())).await;
    let first = server.account("first@example.com").await;
    server.state.store.update_user(&first.id, |user| user.admin = true).await.unwrap();

    let admin = json!({ "groups": ["vault-admins"] });
    let body = log_in(&server, &provider, admin.clone(), "d1").await;
    let token = body["access_token"].as_str().unwrap();
    assert_eq!(server.get_as(token, "/uwu/v1/admin/sso").await.status(), StatusCode::OK);
    let mia = server.state.store.user_by_email("mia@example.com").await.unwrap().unwrap();
    assert!(mia.admin);

    // Out of the group: no admin any more.
    log_in(&server, &provider, json!({ "groups": [] }), "d2").await;
    assert!(!server.state.store.user(&mia.id).await.unwrap().unwrap().admin);

    // Outside the admin networks, the group does not make an admin.
    let mut settings = server.state.settings();
    settings.admin_networks = vec!["192.0.2.0/24".into()];
    server.state.apply_settings(settings);
    log_in(&server, &provider, admin, "d3").await;
    assert!(!server.state.store.user(&mia.id).await.unwrap().unwrap().admin);

    // The last admin stays one.
    server.state.apply_settings(crate::Settings { admin_networks: Vec::new(), ..server.state.settings() });
    server.state.store.update_user(&first.id, |user| user.admin = false).await.unwrap();
    server.state.store.update_user(&mia.id, |user| user.admin = true).await.unwrap();
    log_in(&server, &provider, json!({ "groups": [] }), "d4").await;
    assert!(server.state.store.user(&mia.id).await.unwrap().unwrap().admin);
}

#[tokio::test]
async fn admins_only_with_sso_and_sso_only() {
    let provider = Provider::start().await;
    let server = server_with(&provider, |_| {}).await;
    let admin = server.account("mia@example.com").await;
    server.state.store.update_user(&admin.id, |user| user.admin = true).await.unwrap();
    let password_token = server.login("mia@example.com", "d1").await.token;

    // Switching it on from a password login would lock the admin out.
    let mut wanted = serde_json::to_value(server.state.settings().sso).unwrap();
    wanted.as_object_mut().unwrap().remove("clientSecret");
    wanted["adminsOnlyWithSso"] = true.into();
    let response = server.call("PUT", "/uwu/v1/admin/sso", Some(&password_token), wanted.clone()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "would_lock_out");

    let sso_token = log_in(&server, &provider, json!({}), "d2").await["access_token"].as_str().unwrap().to_string();
    let response = server.call("PUT", "/uwu/v1/admin/sso", Some(&sso_token), wanted).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    let refused = server.get_as(&password_token, "/uwu/v1/admin/users").await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(server.get_as(&sso_token, "/uwu/v1/admin/users").await.status(), StatusCode::OK);

    // SSO only: no password login but for admins that may.
    server.account("ben@example.com").await;
    configure(&server, &provider, |sso| sso.only = true);
    let refused = server.form("/identity/connect/token", &login_form("ben@example.com", "d3")).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(refused).await["message"], "Log in with SSO.");
    server.login("mia@example.com", "d4").await;
    let info = json(server.get("/uwu/v1/info").await).await;
    assert_eq!(info["sso"], json!({ "enabled": true, "only": true, "identifier": "uwulock", "label": "SSO" }));
    assert!(info["features"].as_array().unwrap().contains(&json!("sso")));
}

#[tokio::test]
async fn a_login_is_bound_to_its_browser_state_and_verifier() {
    let provider = Provider::start().await;
    let server = server_with(&provider, |_| {}).await;
    let (location, cookie) = start(&server, "web", CONNECTOR).await;
    let query: HashMap<String, String> = reqwest::Url::parse(&location).unwrap().query_pairs().into_owned().collect();
    provider.will_answer("c1", &query["nonce"], json!({}));
    let state = &query["state"];

    // Another browser (or none) cannot finish it; that uses the state up.
    let stolen = callback(&server, &format!("code=c1&state={state}"), Some("__Host-uwu-sso=other")).await;
    assert_eq!(stolen.status(), StatusCode::BAD_REQUEST);
    let again = callback(&server, &format!("code=c1&state={state}"), Some(&cookie)).await;
    assert_eq!(again.status(), StatusCode::BAD_REQUEST, "a state works once");
    assert_eq!(callback(&server, "code=c1&state=made-up", Some(&cookie)).await.status(), StatusCode::BAD_REQUEST);

    // A token for another login (another nonce) is refused.
    let (location, cookie) = start(&server, "web", CONNECTOR).await;
    let query: HashMap<String, String> = reqwest::Url::parse(&location).unwrap().query_pairs().into_owned().collect();
    provider.will_answer("c2", "another-nonce", json!({}));
    let refused = callback(&server, &format!("code=c2&state={}", query["state"]), Some(&cookie)).await;
    assert_eq!(back(&refused)["error"], "access_denied");

    // An answer from another issuer, or the provider's own refusal.
    let (location, cookie) = start(&server, "web", CONNECTOR).await;
    let state: String =
        reqwest::Url::parse(&location).unwrap().query_pairs().find(|(k, _)| k == "state").unwrap().1.into();
    let refused =
        callback(&server, &format!("code=c3&state={state}&iss=https%3A%2F%2Fevil.example.com"), Some(&cookie)).await;
    assert!(back(&refused)["error_description"].contains("another login provider"));
    let (location, cookie) = start(&server, "web", CONNECTOR).await;
    let state: String =
        reqwest::Url::parse(&location).unwrap().query_pairs().find(|(k, _)| k == "state").unwrap().1.into();
    let refused = callback(&server, &format!("error=access_denied&state={state}"), Some(&cookie)).await;
    assert_eq!(back(&refused)["error"], "access_denied");

    // The code goes only to the client it was for, with its verifier, once.
    let response = through_provider(&server, &provider, "web", CONNECTOR, json!({})).await;
    let code = back(&response)["code"].clone();
    let wrong_client = redeem(&server, &code, "browser", CONNECTOR, "d1").await;
    assert_eq!(wrong_client.status(), StatusCode::BAD_REQUEST);
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("code_verifier", "not-the-verifier-not-the-verifier-not-the-verifier"),
        ("redirect_uri", CONNECTOR),
        ("client_id", "web"),
        ("deviceType", "9"),
        ("deviceIdentifier", "d1"),
        ("deviceName", "chrome"),
    ];
    assert_eq!(server.form("/identity/connect/token", &form).await.status(), StatusCode::BAD_REQUEST);
    form[2].1 = VERIFIER;
    assert_eq!(server.form("/identity/connect/token", &form).await.status(), StatusCode::OK);
    assert_eq!(server.form("/identity/connect/token", &form).await.status(), StatusCode::BAD_REQUEST, "once");
}

#[tokio::test]
async fn the_server_s_own_two_step_login_still_applies() {
    let provider = Provider::start().await;
    let server = server_with(&provider, |_| {}).await;
    let account = server.account("mia@example.com").await;
    let key = crate::totp::base32_encode(&auth::random_bytes(20));
    server.state.store.set_two_factor(&account.id, 0, key.clone(), "recovery".into()).await.unwrap();

    let response = through_provider(&server, &provider, "web", CONNECTOR, json!({})).await;
    let code = back(&response)["code"].clone();
    let asked = redeem(&server, &code, "web", CONNECTOR, "d9").await;
    assert_eq!(asked.status(), StatusCode::BAD_REQUEST);
    assert!(json(asked).await["TwoFactorProviders2"].get("0").is_some());
    // The same code, now with the second step.
    let now_code = crate::totp::code(&crate::totp::base32_decode(&key).unwrap(), auth::now_seconds() / 30);
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("code_verifier", VERIFIER),
        ("redirect_uri", CONNECTOR),
        ("client_id", "web"),
        ("deviceType", "9"),
        ("deviceIdentifier", "d9"),
        ("deviceName", "chrome"),
        ("twoFactorProvider", "0"),
        ("twoFactorToken", now_code.as_str()),
    ];
    assert_eq!(server.form("/identity/connect/token", &form).await.status(), StatusCode::OK);
}

#[test]
fn every_client_goes_back_only_where_it_may() {
    let public = "https://vault.example.com";
    assert!(redirect_allowed(public, "web", CONNECTOR, &[]));
    assert!(redirect_allowed(public, "browser", CONNECTOR, &[]));
    assert!(!redirect_allowed(public, "web", "https://evil.example.com/sso-connector.html", &[]));
    assert!(redirect_allowed(public, "mobile", "bitwarden://sso-callback", &[]));
    assert!(redirect_allowed(public, "desktop", "bitwarden://sso-callback", &[]));
    assert!(redirect_allowed(public, "desktop", "http://localhost:8065/", &[]));
    assert!(redirect_allowed(public, "cli", "http://127.0.0.1:8070/callback", &[]));
    assert!(!redirect_allowed(public, "cli", "http://192.0.2.1:8070/", &[]));
    assert!(!redirect_allowed(public, "cli", "https://localhost:8070/", &[]));
    assert!(!redirect_allowed(public, "cli", "http://localhost/", &[]), "a port");
    assert!(redirect_allowed(public, "uwussh", "http://localhost:9000/", &[]));
    // The released extension, and only the others the admin listed (SV-L3).
    let released = "https://e2a48da41bf871b17a40262b242249e7cd857b53.extensions.allizom.org/";
    assert!(redirect_allowed(public, "uwulock-extension", released, &[]));
    let chromium = format!("https://{}.chromiumapp.org/", "a".repeat(32));
    let firefox = format!("https://{}.extensions.allizom.org/", "0f".repeat(20));
    assert!(!redirect_allowed(public, "uwulock-extension", &chromium, &[]), "any extension");
    assert!(!redirect_allowed(public, "uwulock-extension", &firefox, &[]));
    let listed = ["a".repeat(32), "0f".repeat(20)];
    assert!(redirect_allowed(public, "uwulock-extension", &chromium, &listed));
    assert!(redirect_allowed(public, "uwulock-extension", &firefox, &listed));
    let other = format!("https://{}.chromiumapp.org/", "b".repeat(32));
    assert!(!redirect_allowed(public, "uwulock-extension", &other, &listed));
    assert!(!redirect_allowed(public, "uwulock-extension", "https://zz.chromiumapp.org/", &["zz".into()]));
    assert!(!redirect_allowed(public, "made-up", CONNECTOR, &[]));
}

#[tokio::test]
async fn authorize_refuses_what_it_should() {
    let provider = Provider::start().await;
    let server = server_with(&provider, |_| {}).await;
    let token = json(server.get("/identity/sso/prevalidate").await).await["token"].as_str().unwrap().to_string();
    let challenge = pkce_challenge(VERIFIER);
    let base = |client: &str, redirect: &str, method: &str, sso: &str| {
        format!(
            "/identity/connect/authorize?client_id={client}&redirect_uri={}&response_type=code&state=s\
             &code_challenge={challenge}&code_challenge_method={method}&ssoToken={sso}",
            oidc::form_encode(redirect)
        )
    };
    assert_eq!(server.get(&base("web", CONNECTOR, "S256", &token)).await.status(), StatusCode::FOUND);
    for path in [
        base("web", "https://evil.example.com/", "S256", &token),
        base("web", CONNECTOR, "plain", &token),
        base("web", CONNECTOR, "S256", "not-a-token"),
        base("web", CONNECTOR, "S256", &server.state.tokens.file_token("x", 60)),
    ] {
        assert_eq!(server.get(&path).await.status(), StatusCode::BAD_REQUEST, "{path}");
    }
    configure(&server, &provider, |sso| sso.enabled = false);
    assert_eq!(server.get("/identity/sso/prevalidate").await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(server.get(&base("web", CONNECTOR, "S256", &token)).await.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn what_the_clients_ask_before_and_after() {
    let provider = Provider::start().await;
    let server = server_with(&provider, |_| {}).await;
    let found = json(
        server.call("POST", "/api/organizations/domain/sso/verified", None, json!({ "email": "a@Example.com" })).await,
    )
    .await;
    assert_eq!(found["data"][0]["organizationIdentifier"], "uwulock");
    assert_eq!(found["data"][0]["domainName"], "example.com");
    let account = server.account("mia@example.com").await;
    let status = json(server.get_as(&account.token, "/api/organizations/UwULock/auto-enroll-status").await).await;
    assert_eq!(status["resetPasswordEnabled"], false);
    let id = status["id"].as_str().unwrap();
    assert_eq!(id, identifier_id("uwulock"));
    let policy =
        json(server.get_as(&account.token, &format!("/api/organizations/{id}/policies/master-password")).await).await;
    assert_eq!((policy["type"].clone(), policy["data"]["minLength"].clone()), (json!(1), json!(12)));
    let other = server.get_as(&account.token, "/api/organizations/other/auto-enroll-status").await;
    assert_eq!(other.status(), StatusCode::NOT_FOUND);

    configure(&server, &provider, |sso| sso.enabled = false);
    let none = json(
        server.call("POST", "/api/organizations/domain/sso/verified", None, json!({ "email": "a@example.com" })).await,
    )
    .await;
    assert_eq!(none["data"], json!([]));
}

async fn admin(server: &TestServer) -> String {
    let admin = server.account("admin@example.com").await;
    server.state.store.update_user(&admin.id, |user| user.admin = true).await.unwrap();
    server.login("admin@example.com", "admin-device").await.token
}

#[tokio::test]
async fn the_portal_sets_sso_up_by_hand_and_keeps_the_secret_to_itself() {
    let provider = Provider::start().await;
    let server = TestServer::new().await;
    let token = admin(&server).await;
    let settings = json!({
        "enabled": true, "issuer": format!("{}/", provider.issuer), "clientId": "vault", "clientSecret": "s3cret",
        "scopes": ["openid", "email"], "signups": "group", "adminGroup": " vault-admins ", "label": "Firma",
        "identifier": "firma", "groupsClaim": "groups",
    });
    // Another provider wants the master password (R1-3).
    let refused = server.call("PUT", "/uwu/v1/admin/sso", Some(&token), settings.clone()).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(refused).await["code"], "password_required");
    let mut settings = settings;
    settings["masterPasswordHash"] = password_hash("admin@example.com").into();
    let response = server.call("PUT", "/uwu/v1/admin/sso", Some(&token), settings.clone()).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    let shown = json(response).await;
    assert_eq!(shown["clientSecretSet"], true);
    assert!(shown.get("clientSecret").is_none());
    assert_eq!(shown["issuer"], provider.issuer, "without the slash");
    assert_eq!(shown["adminGroup"], "vault-admins");
    assert_eq!(shown["redirectUri"], "https://vault.example.com/identity/connect/oidc-signin");
    let stored = server.state.store.setting("settings").await.unwrap().unwrap();
    assert!(!stored.contains("s3cret"), "encrypted at rest");
    let general = json(server.get_as(&token, "/uwu/v1/admin/settings").await).await;
    assert_eq!(general["sso"]["clientSecretSet"], true);
    assert!(general["sso"].get("clientSecret").is_none());

    // A label is not who logs in as whom: no password needed.
    let mut label = settings.clone();
    label.as_object_mut().unwrap().remove("clientSecret");
    label.as_object_mut().unwrap().remove("masterPasswordHash");
    label["label"] = "Company".into();
    let response = server.call("PUT", "/uwu/v1/admin/sso", Some(&token), label.clone()).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    label["trustUnverifiedEmail"] = true.into();
    let refused = server.call("PUT", "/uwu/v1/admin/sso", Some(&token), label).await;
    assert_eq!(json(refused).await["code"], "password_required");
    // Nor who becomes an admin through SSO: a claim a user sets themselves would do (R5-3).
    let mut base = settings.clone();
    base.as_object_mut().unwrap().remove("clientSecret");
    base.as_object_mut().unwrap().remove("masterPasswordHash");
    for (field, value) in [
        ("adminGroup", json!("someone@example.com")),
        ("adminGroup", Value::Null),
        ("groupsClaim", json!("email")),
        ("rolesClaim", json!("given_name")),
        // Nor who may make an account: `group` without a user group is everybody (R8 I-D).
        ("signups", json!("invitation")),
        ("signups", json!("off")),
        ("userGroup", json!("staff")),
    ] {
        let mut changed = base.clone();
        changed[field] = value.clone();
        let refused = server.call("PUT", "/uwu/v1/admin/sso", Some(&token), changed.clone()).await;
        assert_eq!(json(refused).await["code"], "password_required", "{field} = {value}");
        changed["masterPasswordHash"] = "wrong".into();
        let refused = server.call("PUT", "/uwu/v1/admin/sso", Some(&token), changed).await;
        assert_eq!(json(refused).await["code"], "password_required", "{field} with a wrong password");
    }
    assert_eq!(server.state.settings().sso.admin_group.as_deref(), Some("vault-admins"));
    assert_eq!((server.state.settings().sso.signups, server.state.settings().sso.user_group), (Signups::Group, None));
    let mut spaces = base.clone();
    spaces["userGroup"] = " ".into();
    let response = server.call("PUT", "/uwu/v1/admin/sso", Some(&token), spaces).await;
    assert_eq!(response.status(), StatusCode::OK, "an empty user group is no change: {}", text(response).await);
    let mut roles = base.clone();
    roles["rolesClaim"] = "roles".into();
    roles["masterPasswordHash"] = password_hash("admin@example.com").into();
    let response = server.call("PUT", "/uwu/v1/admin/sso", Some(&token), roles).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    assert_eq!(server.state.settings().sso.roles_claim.as_deref(), Some("roles"));

    // Left out: kept for the same provider and client, gone for another.
    let mut again = settings.clone();
    again.as_object_mut().unwrap().remove("clientSecret");
    let kept = json(server.call("PUT", "/uwu/v1/admin/sso", Some(&token), again.clone()).await).await;
    assert_eq!(kept["clientSecretSet"], true);
    again["clientId"] = "other".into();
    let dropped = json(server.call("PUT", "/uwu/v1/admin/sso", Some(&token), again).await).await;
    assert_eq!(dropped["clientSecretSet"], false);

    // The general settings leave SSO alone.
    let mut general = json(server.get_as(&token, "/uwu/v1/admin/settings").await).await;
    general["sso"]["enabled"] = false.into();
    let response = server.call("PUT", "/uwu/v1/admin/settings", Some(&token), general).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    assert!(server.state.settings().sso.enabled);

    let test = json(server.call("POST", "/uwu/v1/admin/sso/test", Some(&token), json!({})).await).await;
    assert_eq!(test, json!({ "ok": true, "error": null }));
    let broken = json(
        server.call("POST", "/uwu/v1/admin/sso/test", Some(&token), json!({ "issuer": "http://127.0.0.1:9" })).await,
    )
    .await;
    assert_eq!(broken["ok"], false);
    let mut wrong = settings;
    wrong["issuer"] = "http://auth.example.com".into();
    assert_eq!(server.call("PUT", "/uwu/v1/admin/sso", Some(&token), wrong).await.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pairing_with_uwuauth_fills_everything_in() {
    let provider = Provider::start().await;
    let server = TestServer::new().await;
    let token = admin(&server).await;

    let wrong = server
        .call(
            "POST",
            "/uwu/v1/admin/sso/pair",
            Some(&token),
            json!({ "url": provider.issuer, "code": "AAAA-BBBB-CCCC", "masterPasswordHash": password_hash("admin@example.com") }),
        )
        .await;
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(wrong).await["code"], "invalid_code");

    // The whole QR text will do.
    let qr = format!("{}/#pair={CODE}", provider.issuer);
    let refused = server.call("POST", "/uwu/v1/admin/sso/pair", Some(&token), json!({ "code": qr })).await;
    assert_eq!(json(refused).await["code"], "password_required", "pairing sets the provider (R1-3)");
    let hash = password_hash("admin@example.com");
    let response = server
        .call("POST", "/uwu/v1/admin/sso/pair", Some(&token), json!({ "code": qr, "masterPasswordHash": hash }))
        .await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    let shown = json(response).await;
    assert_eq!((shown["enabled"].clone(), shown["clientId"].clone()), (json!(true), json!("uwulock-vault")));
    assert_eq!((shown["rolesClaim"].clone(), shown["signups"].clone()), (json!("roles"), json!("group")));
    assert_eq!(shown["paired"]["appId"], "app-1");
    assert_eq!(shown["scimTokenSet"], true);

    let sent = provider.paired.lock().last().unwrap().clone();
    let app = &sent["app"];
    assert_eq!(sent["code"], CODE);
    assert_eq!(app["redirectUris"], json!(["https://vault.example.com/identity/connect/oidc-signin"]));
    assert_eq!(app["scim"]["baseUrl"], "https://vault.example.com/scim/v2");
    assert_eq!(app["roles"].as_array().unwrap().len(), 2);
    assert!(app["icon"].as_str().unwrap().starts_with("data:image/png;base64,"));
    assert!(app["icon"].as_str().unwrap().len() < 64 * 1024 * 4 / 3 + 30);
    let stored = server.state.store.setting("settings").await.unwrap().unwrap();
    assert!(!stored.contains("paired-secret") && !stored.contains("scim-token-from-uwuauth"));

    // SCIM takes UwUAuth's token now.
    let request =
        Request::get("/scim/v2/Users").header("authorization", "Bearer scim-token-from-uwuauth").body(Body::empty());
    assert_eq!(server.send(request.unwrap()).await.status(), StatusCode::OK);

    // Roles decide: `admin` makes an admin, `user` may sign up.
    let body = log_in(&server, &provider, json!({ "aud": "uwulock-vault", "roles": ["user", "admin"] }), "d1").await;
    assert!(body["access_token"].is_string());
    assert!(server.state.store.user_by_email("mia@example.com").await.unwrap().unwrap().admin);
    let (header, _) = provider.requests.lock().last().unwrap().clone();
    use base64::Engine as _;
    assert_eq!(
        header.unwrap(),
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("uwulock-vault:paired-secret"))
    );

    let gone = json(server.call("DELETE", "/uwu/v1/admin/sso/pairing", Some(&token), json!({})).await).await;
    assert_eq!(
        (gone["enabled"].clone(), gone["paired"].clone(), gone["scimTokenSet"].clone()),
        (json!(false), Value::Null, json!(false))
    );
    let not_uwuauth = server
        .call(
            "POST",
            "/uwu/v1/admin/sso/pair",
            Some(&token),
            json!({ "url": "http://127.0.0.1:9", "code": CODE, "masterPasswordHash": hash }),
        )
        .await;
    assert_eq!(not_uwuauth.status(), StatusCode::BAD_GATEWAY);
}

#[test]
fn pairing_input_takes_the_qr_text_or_both_fields() {
    assert_eq!(
        pairing_input(None, " https://auth.example.com/#pair=7KQ4-M2XD-9HFT ").unwrap(),
        ("https://auth.example.com".to_string(), "7KQ4-M2XD-9HFT".to_string())
    );
    assert_eq!(
        pairing_input(Some("https://auth.example.com/"), "7kq4m2xd9hft").unwrap(),
        ("https://auth.example.com".to_string(), "7kq4m2xd9hft".to_string())
    );
    assert!(pairing_input(Some("http://auth.example.com"), "x").is_err(), "https");
    assert!(pairing_input(None, "7KQ4").is_err(), "an address");
}

/// R5-3: a SCIM token, and SCIM deleting rather than disabling, keep power over every account
/// after the admin session is gone: both take the master password.
#[tokio::test]
async fn the_scim_token_and_what_scim_deletes_take_the_master_password() {
    let server = TestServer::new().await;
    let token = admin(&server).await;
    let refused = server.call("POST", "/uwu/v1/admin/scim/token", Some(&token), json!({})).await;
    assert_eq!(json(refused).await["code"], "password_required");
    let wrong = json!({ "masterPasswordHash": "wrong" });
    let refused = server.call("POST", "/uwu/v1/admin/scim/token", Some(&token), wrong).await;
    assert_eq!(json(refused).await["code"], "password_required");
    assert!(server.state.settings().scim.token_hash.is_none());
    let confirmed = json!({ "masterPasswordHash": password_hash("admin@example.com") });
    let made = json(server.call("POST", "/uwu/v1/admin/scim/token", Some(&token), confirmed).await).await;
    assert!(made["token"].as_str().is_some_and(|token| !token.is_empty()), "{made}");

    let mut general = json(server.get_as(&token, "/uwu/v1/admin/settings").await).await;
    general["scim"]["onDelete"] = "delete".into();
    let refused = server.call("PUT", "/uwu/v1/admin/settings", Some(&token), general.clone()).await;
    assert_eq!(json(refused).await["code"], "password_required");
    assert_eq!(server.state.settings().scim.on_delete, crate::scim::OnDelete::Disable);
    general["masterPasswordHash"] = password_hash("admin@example.com").into();
    let response = server.call("PUT", "/uwu/v1/admin/settings", Some(&token), general).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    assert_eq!(server.state.settings().scim.on_delete, crate::scim::OnDelete::Delete);
    // Everything else in the general settings still saves without it.
    let mut general = json(server.get_as(&token, "/uwu/v1/admin/settings").await).await;
    general["geoip"] = false.into();
    let response = server.call("PUT", "/uwu/v1/admin/settings", Some(&token), general).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
}
