//! UwULock's desktop client library against the real server, on a free port: register with an
//! invitation, log in, sync and open the vault, save, change, trash and delete items, folders,
//! refresh, two-step login with a remembered device — all with the crypto the desktop app uses.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::oneshot;
use uwulock_bitwarden::api::{LoginOutcome, PasswordLogin, TwoFactorAnswer, parse_sync};
use uwulock_bitwarden::crypto::{self, EncString, SymmetricKey, decrypt_user_key};
use uwulock_bitwarden::vault::{Item, ItemKind};
use uwulock_bitwarden::{Client, Device, Kdf, Server, Vault};
use zeroize::Zeroizing;

const EMAIL: &str = "nyu@example.com";
const PASSWORD: &str = "correct horse battery staple";
const KDF: Kdf = Kdf::Pbkdf2 { iterations: 100_000 };

struct Running {
    url: String,
    stop: Option<oneshot::Sender<()>>,
    _dir: tempfile::TempDir,
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

/// A server on a free port, and an invitation for [`EMAIL`]: the token of its link.
async fn start() -> (Running, String) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let mut config = uwulock_server::Config { data_dir: dir.path().to_path_buf(), ..Default::default() };
    config.listen = "127.0.0.1:0".parse().unwrap();
    config.update_check = false;
    let store = uwulock_server::open_store(&config).unwrap();

    let (stop, stopped) = oneshot::channel::<()>();
    let (ready, listening) = oneshot::channel::<SocketAddr>();
    let serving = config.clone();
    let logs = uwulock_api::LogBuffer::new(100);
    tokio::spawn(uwulock_server::run(
        serving,
        store.clone(),
        logs.clone(),
        async move {
            let _ = stopped.await;
        },
        Some(ready),
    ));
    let addr = listening.await.unwrap();
    let url = format!("http://{addr}");

    config.public = Some(url.clone());
    let state = uwulock_server::app_state(&config, store, logs).await.unwrap();
    let invited = uwulock_api::invite(&state, EMAIL, true, None).await.unwrap();
    let token = invited.link.split("token=").nth(1).unwrap().split('&').next().unwrap().to_string();
    (Running { url, stop: Some(stop), _dir: dir }, token)
}

/// Register the way a client does: a user key, wrapped under the master key.
async fn register(url: &str, token: &str) -> SymmetricKey {
    let master = crypto::master_key(PASSWORD, EMAIL, KDF).unwrap();
    let user_key = SymmetricKey::generate();
    let protected = EncString::encrypt(&user_key.to_bytes(), &SymmetricKey::stretch(&master));
    let body = serde_json::json!({
        "email": EMAIL,
        "name": "Nyu",
        "masterPasswordHash": crypto::master_password_hash(&master, PASSWORD),
        "key": protected.to_string(),
        "kdf": 0,
        "kdfIterations": 100_000,
        "emailVerificationToken": token,
    });
    let response = reqwest::Client::new()
        .post(format!("{url}/identity/accounts/register/finish"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success(), "{}", response.text().await.unwrap());
    user_key
}

fn client(url: &str, device: &str) -> Client {
    Client::new(Server::self_hosted(url).unwrap(), Device::this_system(device.into())).unwrap()
}

async fn hash(client: &Client) -> (Zeroizing<[u8; 32]>, String) {
    let kdf = client.prelogin(EMAIL).await.unwrap();
    assert_eq!(kdf, KDF, "the prelogin says how the key was made");
    let master = crypto::master_key(PASSWORD, EMAIL, kdf).unwrap();
    let hash = crypto::master_password_hash(&master, PASSWORD);
    (master, hash)
}

fn login(hash: &str) -> PasswordLogin<'_> {
    PasswordLogin { email: EMAIL, password_hash: hash, two_factor: None, remember_token: None, new_device_code: None }
}

fn text(value: &Option<Zeroizing<String>>) -> Option<&str> {
    value.as_ref().map(|value| value.as_str())
}

#[tokio::test]
async fn the_desktop_client_logs_in_syncs_and_saves() {
    let (server, token) = start().await;
    let user_key = register(&server.url, &token).await;
    let client = client(&server.url, "5a0e9c1e-7d3b-4d0c-9a8e-000000000001");
    let (master, hash) = hash(&client).await;

    let LoginOutcome::LoggedIn(session) = client.login(login(&hash)).await.unwrap() else { panic!("a login") };
    let protected: EncString = session.protected_user_key.clone().unwrap().parse().unwrap();
    let opened = decrypt_user_key(&master, &protected).unwrap();
    assert_eq!(opened.to_bytes().as_slice(), user_key.to_bytes().as_slice(), "the same user key");

    // A folder and an item in it.
    let name = EncString::encrypt(b"Homelab", &opened).to_string();
    let folder = client.create_folder(&session.access_token, name).await.unwrap();
    let folder_id = folder["id"].as_str().unwrap().to_string();
    let mut item = Item::new(ItemKind::Login);
    item.name = Zeroizing::new("NAS".into());
    item.folder_id = Some(folder_id.clone());
    let login_data = item.login.as_mut().unwrap();
    login_data.username = Some(Zeroizing::new("nyu".into()));
    login_data.password = Some(Zeroizing::new("Katzenklo-2026".into()));
    let saved = client.create_cipher(&session.access_token, item.seal(&opened).unwrap(), &[]).await.unwrap();
    let id = saved["id"].as_str().unwrap().to_string();

    let vault = Vault::open(&parse_sync(&client.sync(&session.access_token).await.unwrap()).unwrap(), &opened).unwrap();
    assert_eq!(vault.email, EMAIL);
    assert_eq!(vault.folders[0].name, "Homelab");
    let nas = vault.item(&id).unwrap();
    assert!(!nas.broken);
    assert_eq!(text(&nas.login.as_ref().unwrap().password), Some("Katzenklo-2026"));
    assert_eq!(nas.folder_id.as_deref(), Some(folder_id.as_str()));

    // Changed, with the revision the client saw; an older copy is refused.
    let mut changed = nas.clone();
    changed.login.as_mut().unwrap().password = Some(Zeroizing::new("Katzenklo-2027".into()));
    let mut request = changed.seal(&opened).unwrap();
    request.last_known_revision_date = nas.revision_date.clone();
    client.update_cipher(&session.access_token, &id, request).await.unwrap();
    let mut stale = changed.seal(&opened).unwrap();
    stale.last_known_revision_date = Some("2020-01-01T00:00:00.000Z".into());
    let refused = client.update_cipher(&session.access_token, &id, stale).await;
    assert!(matches!(refused, Err(uwulock_bitwarden::Error::Conflict)), "{refused:?}");

    // Trash and back, then gone.
    client.trash_cipher(&session.access_token, &id).await.unwrap();
    let vault = Vault::open(&parse_sync(&client.sync(&session.access_token).await.unwrap()).unwrap(), &opened).unwrap();
    assert!(vault.item(&id).unwrap().deleted);
    client.restore_cipher(&session.access_token, &id).await.unwrap();
    client.delete_folder(&session.access_token, &folder_id).await.unwrap();
    let vault = Vault::open(&parse_sync(&client.sync(&session.access_token).await.unwrap()).unwrap(), &opened).unwrap();
    let nas = vault.item(&id).unwrap();
    assert!(!nas.deleted && nas.folder_id.is_none());
    assert_eq!(text(&nas.login.as_ref().unwrap().password), Some("Katzenklo-2027"));
    client.delete_cipher(&session.access_token, &id).await.unwrap();

    // A refresh gives a working token.
    let refreshed = client.refresh(session.refresh_token.as_ref().unwrap()).await.unwrap();
    let vault =
        Vault::open(&parse_sync(&client.sync(&refreshed.access_token).await.unwrap()).unwrap(), &opened).unwrap();
    assert!(vault.items.is_empty());

    // A wrong password is refused, as such.
    let wrong = crypto::master_password_hash(&crypto::master_key("wrong", EMAIL, KDF).unwrap(), "wrong");
    assert!(matches!(client.login(login(&wrong)).await, Err(uwulock_bitwarden::Error::Refused(_))));
}

/// The TOTP code for `secret` at `seconds`, the way an authenticator app makes it.
fn totp(secret: &str, seconds: u64) -> String {
    let totp = uwulock_bitwarden::totp::Totp::parse(secret).unwrap();
    totp.code_at(seconds).0.to_string()
}

#[tokio::test]
async fn two_step_login_and_a_remembered_device() {
    let (server, token) = start().await;
    register(&server.url, &token).await;
    let client = client(&server.url, "5a0e9c1e-7d3b-4d0c-9a8e-000000000002");
    let (_, hash) = hash(&client).await;
    let LoginOutcome::LoggedIn(session) = client.login(login(&hash)).await.unwrap() else { panic!("a login") };

    // Set up an authenticator app, the way the web vault does.
    let http = reqwest::Client::new();
    let api = |path: &str| format!("{}/api/two-factor/{path}", server.url);
    let secret: serde_json::Value = http
        .post(api("get-authenticator"))
        .bearer_auth(session.access_token.as_str())
        .json(&serde_json::json!({ "masterPasswordHash": hash }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key = secret["key"].as_str().unwrap().to_string();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let response = http
        .put(api("authenticator"))
        .bearer_auth(session.access_token.as_str())
        .json(&serde_json::json!({ "key": key, "token": totp(&key, now), "masterPasswordHash": hash }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success(), "{}", response.text().await.unwrap());

    let LoginOutcome::TwoFactor { methods, .. } = client.login(login(&hash)).await.unwrap() else {
        panic!("a second step is asked for");
    };
    assert_eq!(methods[0].kind, "authenticator");
    assert!(methods[0].supported);

    // The code of the next step: the one of this step went to setting it up.
    let answer = TwoFactorAnswer { provider: 0, code: totp(&key, now + 30), remember: true };
    let outcome = client.login(PasswordLogin { two_factor: Some(answer), ..login(&hash) }).await.unwrap();
    let LoginOutcome::LoggedIn(session) = outcome else { panic!("logged in with the code: {outcome:?}") };
    let remember = session.remember_token.clone().expect("a token to remember the device");

    let outcome =
        client.login(PasswordLogin { remember_token: Some(remember.as_str()), ..login(&hash) }).await.unwrap();
    assert!(matches!(outcome, LoginOutcome::LoggedIn(_)), "the remembered device skips the code");

    let elsewhere = self::client(&server.url, "5a0e9c1e-7d3b-4d0c-9a8e-000000000003");
    let outcome =
        elsewhere.login(PasswordLogin { remember_token: Some(remember.as_str()), ..login(&hash) }).await.unwrap();
    assert!(matches!(outcome, LoginOutcome::TwoFactor { .. }), "but only that device");
    tokio::time::sleep(Duration::from_millis(1)).await;
}
