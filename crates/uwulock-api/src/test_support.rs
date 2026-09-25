//! A whole API in memory, for tests: a database in a temporary directory, a mailer that keeps
//! what it sends, cheap hashing and limits nobody runs into. Requests go straight into the
//! router, without a socket.

use crate::auth::HashCost;
use crate::{ApiConfig, AppState, LogBuffer, Settings, router};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use base64::Engine as _;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uwulock_mail::Mailer;
use uwulock_store::Store;

pub(crate) struct TestServer {
    pub router: Router,
    pub state: AppState,
    _dir: tempfile::TempDir,
}

/// A logged-in account.
pub(crate) struct Account {
    pub id: String,
    pub email: String,
    pub token: String,
    pub refresh: String,
    pub device: String,
}

impl TestServer {
    pub(crate) async fn new() -> Self {
        Self::with_settings(Settings::default()).await
    }

    pub(crate) async fn with_settings(settings: Settings) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_sqlite(&dir.path().join("uwulock.db"), &uwulock_store::Options { readers: 2 }).unwrap();
        let config = ApiConfig {
            public: "https://vault.example.com".into(),
            trust_forwarded: false,
            hash_cost: HashCost::cheap(),
            backups: dir.path().join("backups"),
            start_settings: settings,
        };
        let mut state = AppState::new(store, config, "0.0.0-test", LogBuffer::new(100)).await.unwrap();
        state.mailer = Mailer::capturing();
        state.limits = Arc::new(crate::Limits::generous());
        Self { router: router(state.clone()), state, _dir: dir }
    }

    pub(crate) async fn send(&self, request: Request<Body>) -> Response<Body> {
        self.router.clone().oneshot(request).await.unwrap()
    }

    pub(crate) async fn get(&self, path: &str) -> Response<Body> {
        self.send(Request::get(path).body(Body::empty()).unwrap()).await
    }

    pub(crate) async fn get_as(&self, token: &str, path: &str) -> Response<Body> {
        self.send(Request::get(path).header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
    }

    /// `method` with a JSON body, and a token if there is one.
    pub(crate) async fn call(&self, method: &str, path: &str, token: Option<&str>, body: Value) -> Response<Body> {
        let mut request = Request::builder().method(method).uri(path).header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        self.send(request.body(Body::from(body.to_string())).unwrap()).await
    }

    pub(crate) async fn form(&self, path: &str, fields: &[(&str, &str)]) -> Response<Body> {
        let body =
            fields.iter().map(|(key, value)| format!("{key}={}", urlencode(value))).collect::<Vec<_>>().join("&");
        self.send(
            Request::post(path)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("bitwarden-client-version", "2026.9.0")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
    }

    /// Invite `email`, register it with the invitation, and log in on a new device.
    pub(crate) async fn account(&self, email: &str) -> Account {
        let token = self.invite(email, false).await;
        let response =
            self.call("POST", "/identity/accounts/register/finish", None, register_body(email, &token)).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        self.login(email, "device-1").await
    }

    /// An invitation for `email`; the token from its link.
    pub(crate) async fn invite(&self, email: &str, admin: bool) -> String {
        crate::admin::invite(&self.state, email, admin, None).await.unwrap().token
    }

    pub(crate) async fn login(&self, email: &str, device: &str) -> Account {
        let response = self.form("/identity/connect/token", &login_form(email, device)).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        let body = json(response).await;
        let user = self.state.store.user_by_email(email).await.unwrap().unwrap();
        Account {
            id: user.id,
            email: email.into(),
            token: body["access_token"].as_str().unwrap().into(),
            refresh: body["refresh_token"].as_str().unwrap().into(),
            device: device.into(),
        }
    }

    /// Log in with a master password hash other than the one [`password_hash`] makes; the
    /// access token.
    pub(crate) async fn login_with(&self, email: &str, hash: &str, device: &str) -> String {
        let mut form = login_form(email, device);
        form[2].1 = hash;
        let response = self.form("/identity/connect/token", &form).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
        json(response).await["access_token"].as_str().unwrap().to_string()
    }

    /// The first mail `matches` takes, once one was sent. Mails that go out on the side are
    /// sent by a task of their own, which gets its turn here.
    pub(crate) async fn wait_for_mail(&self, matches: impl Fn(&uwulock_mail::Sent) -> bool) -> uwulock_mail::Sent {
        for _ in 0..200 {
            if let Some(mail) = self.mails().into_iter().find(|mail| matches(mail)) {
                return mail;
            }
            tokio::task::yield_now().await;
        }
        panic!("no such mail among {:?}", self.mails());
    }

    pub(crate) fn mails(&self) -> Vec<uwulock_mail::Sent> {
        self.state.mailer.sent()
    }
}

/// What a client sends in place of the master password: here just a fixed string per address.
pub(crate) fn password_hash(email: &str) -> String {
    // Clients salt with the address trimmed and in lower case, so the hash is the same however
    // it was typed.
    base64::engine::general_purpose::STANDARD.encode(format!("hash of {}", email.trim().to_lowercase()))
}

pub(crate) fn register_body(email: &str, token: &str) -> Value {
    json!({
        "email": email,
        "name": "Nyu",
        "masterPasswordHash": password_hash(email),
        "masterPasswordHint": "the cat",
        "key": "2.userkey|userkey|userkey",
        "kdf": 0,
        "kdfIterations": 600000,
        "keys": { "encryptedPrivateKey": "2.private|private|private", "publicKey": "MIIBpublic" },
        "emailVerificationToken": token,
    })
}

pub(crate) fn login_form<'a>(email: &'a str, device: &'a str) -> Vec<(&'static str, &'a str)> {
    vec![
        ("grant_type", "password"),
        ("username", email),
        ("password", Box::leak(password_hash(email).into_boxed_str())),
        ("scope", "api offline_access"),
        ("client_id", "browser"),
        ("deviceType", "3"),
        ("deviceIdentifier", device),
        ("deviceName", "firefox"),
    ]
}

pub(crate) async fn json(response: Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("not JSON: {}", String::from_utf8_lossy(&bytes)))
}

pub(crate) async fn text(response: Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (byte as char).to_string(),
            other => format!("%{other:02X}"),
        })
        .collect()
}
