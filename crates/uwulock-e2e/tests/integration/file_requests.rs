//! A file request end to end, with the crypto of UwULock's clients: the owner makes the extras
//! key and a request, somebody without an account uploads to its link with nothing but the
//! link, the owner opens what arrived and takes the file into an item — and the item's
//! attachment opens with the item's key, the bytes as the uploader encrypted them.

use crate::client::{client, hash, login, register, start};
use base64::Engine as _;
use serde_json::{Value, json};
use uwulock_bitwarden::LoginOutcome;
use uwulock_bitwarden::crypto::{EncString, decrypt_user_key};
use uwulock_core::crypto::PrivateKey;
use uwulock_core::extras::{self, Keys, Resolved};
use uwulock_core::file_request::{LinkSecret, PublicInfo, SealedFile, Sender, SubmissionKey, link, seal_label};

async fn call(http: &reqwest::Client, method: reqwest::Method, url: String, token: Option<&str>, body: Value) -> Value {
    let mut request = http.request(method, &url).json(&body);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    assert!(status.is_success(), "{url}: {status} {text}");
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

#[tokio::test]
async fn somebody_uploads_to_a_link_and_the_owner_takes_it_into_an_item() {
    let (server, token) = start().await;
    register(&server.url, &token).await;
    let owner = client(&server.url, "5a0e9c1e-7d3b-4d0c-9a8e-000000000009");
    let (master, hash) = hash(&owner).await;
    let LoginOutcome::LoggedIn(session) = owner.login(login(&hash)).await.unwrap() else { panic!("a login") };
    let user_key = decrypt_user_key(&master, &session.protected_user_key.clone().unwrap().parse().unwrap()).unwrap();
    let access = session.access_token.as_str();
    let http = reqwest::Client::new();
    let url = |path: &str| format!("{}{path}", server.url);
    let b64 = base64::engine::general_purpose::STANDARD;

    // The account's key pair, as a client makes it after registering.
    let private = PrivateKey::generate().unwrap();
    let public_der = private.public().to_der().unwrap();
    let keys = json!({
        "publicKey": b64.encode(&public_der),
        "encryptedPrivateKey": EncString::encrypt(&private.to_der().unwrap(), &user_key).to_string(),
    });
    call(&http, reqwest::Method::POST, url("/api/accounts/keys"), Some(access), keys).await;

    // The extras key: none yet, so the client makes one.
    let answer: Keys =
        serde_json::from_value(call(&http, reqwest::Method::GET, url("/uwu/v1/keys"), Some(access), Value::Null).await)
            .unwrap();
    let Resolved::Create(new) = extras::resolve(&answer, &user_key, Some(&private)).unwrap() else {
        panic!("a new key")
    };
    call(&http, reqwest::Method::POST, url("/uwu/v1/keys"), Some(access), serde_json::to_value(&new.request).unwrap())
        .await;
    let answer: Keys =
        serde_json::from_value(call(&http, reqwest::Method::GET, url("/uwu/v1/keys"), Some(access), Value::Null).await)
            .unwrap();
    let Resolved::Open { key: extras_key, rewrap: None, private_wrap: None } =
        extras::resolve(&answer, &user_key, Some(&private)).unwrap()
    else {
        panic!("the same key")
    };

    // The request.
    let secret = LinkSecret::generate();
    let info = PublicInfo::new("Passport scan", Some("Both pages, please."), Some("Nyu"), &private.public()).unwrap();
    let request = json!({
        "name": seal_label("Passport for the bank", &extras_key),
        "linkSecret": secret.seal(&extras_key),
        "publicInfo": info.seal(&secret).unwrap(),
        "passwordHash": secret.password_hash("cats"),
        "expirationDate": "2999-01-01T00:00:00Z",
        "maxSubmissions": 1,
        "maxFiles": 3,
        "maxFileBytes": 1024 * 1024,
        "textAllowed": true,
    });
    let refused = http.post(url("/uwu/v1/file-requests")).bearer_auth(access).json(&request).send().await.unwrap();
    assert_eq!(refused.status(), 400, "no request runs for centuries");
    let mut request = request;
    request["expirationDate"] = json!(uwulock_store::clock::in_seconds(7 * 86_400));
    let made = call(&http, reqwest::Method::POST, url("/uwu/v1/file-requests"), Some(access), request).await;
    let (request_id, access_id) =
        (made["id"].as_str().unwrap().to_string(), made["accessId"].as_str().unwrap().to_string());
    // The owner hands out the link only if what the server keeps encrypts for their own key.
    let kept = PublicInfo::open(made["publicInfo"].as_str().unwrap(), &secret).unwrap();
    assert!(kept.is_for(&private.public()));
    let shared = link(&server.url, &access_id, &secret, false);
    assert!(shared.ends_with(&format!("/#/request/{access_id}/{}", secret.to_link_part())));

    // The uploader has only the link.
    let part = shared.rsplit('/').next().unwrap();
    let theirs = LinkSecret::from_link_part(part).unwrap();
    let public = format!("/uwu/v1/public/file-requests/{access_id}");
    let opened = call(
        &http,
        reqwest::Method::POST,
        url(&format!("{public}/open")),
        None,
        json!({ "passwordHash": theirs.password_hash("cats") }),
    )
    .await;
    let info = PublicInfo::open(opened["publicInfo"].as_str().unwrap(), &theirs).unwrap();
    assert_eq!(info.title, "Passport scan");
    let upload_token = opened["token"].as_str().unwrap().to_string();
    let submission_key = SubmissionKey::generate();
    let (file_key, sealed) = submission_key.new_file("front.jpg");
    let contents = b"the front page of a passport".repeat(100);
    let encrypted = file_key.encrypt(&contents);
    let body = json!({
        "wrappedKey": submission_key.wrap(&info.public_key().unwrap()).unwrap(),
        "sender": submission_key.seal_sender(&Sender { name: Some("Mika".into()), email: None }).unwrap(),
        "text": submission_key.seal_text("Here you go").unwrap(),
        "files": [ { "fileName": sealed.file_name, "key": sealed.key, "size": encrypted.len() } ],
    });
    let started =
        call(&http, reqwest::Method::POST, url(&format!("{public}/submissions")), Some(&upload_token), body).await;
    let file_url = url(started["files"][0]["url"].as_str().unwrap());
    let put = http.put(&file_url).bearer_auth(&upload_token).body(encrypted.clone()).send().await.unwrap();
    assert!(put.status().is_success(), "{}", put.text().await.unwrap());
    let submission_id = started["id"].as_str().unwrap();
    call(
        &http,
        reqwest::Method::POST,
        url(&format!("{public}/submissions/{submission_id}/complete")),
        Some(&upload_token),
        json!({}),
    )
    .await;

    // The owner opens it with the private key.
    let owned = format!("/uwu/v1/file-requests/{request_id}");
    let list = call(&http, reqwest::Method::GET, url(&format!("{owned}/submissions")), Some(access), Value::Null).await;
    let got = &list["data"][0];
    let key = SubmissionKey::open(got["wrappedKey"].as_str().unwrap(), &private).unwrap();
    assert_eq!(key.open_text(got["text"].as_str().unwrap()).unwrap().as_str(), "Here you go");
    assert_eq!(key.open_sender(got["sender"].as_str().unwrap()).unwrap().name.as_deref(), Some("Mika"));
    let file = &got["files"][0];
    let (name, opened_key) = key
        .open_file(&SealedFile {
            file_name: file["fileName"].as_str().unwrap().into(),
            key: file["key"].as_str().unwrap().into(),
        })
        .unwrap();
    assert_eq!(name.as_str(), "front.jpg");
    let file_id = file["id"].as_str().unwrap();
    let bytes = http
        .get(url(&format!("{owned}/submissions/{submission_id}/files/{file_id}")))
        .bearer_auth(access)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(opened_key.decrypt(&bytes).unwrap().as_slice(), contents.as_slice());

    // Taken over: a note, and the file moved into it under the user key.
    let note = json!({ "type": 2, "name": EncString::encrypt(b"Passport", &user_key).to_string(), "secureNote": { "type": 0 } });
    let note = call(&http, reqwest::Method::POST, url("/api/ciphers"), Some(access), note).await;
    let cipher_id = note["id"].as_str().unwrap();
    let for_item = opened_key.for_item(&name, &user_key);
    let attach = json!({ "cipherId": cipher_id, "fileName": for_item.file_name, "key": for_item.key });
    let attached = call(
        &http,
        reqwest::Method::POST,
        url(&format!("{owned}/submissions/{submission_id}/files/{file_id}/attach")),
        Some(access),
        attach,
    )
    .await;
    let attachment = &attached["attachments"][0];
    let attachment_key =
        attachment["key"].as_str().unwrap().parse::<EncString>().unwrap().decrypt_key(&user_key).unwrap();
    let info = call(
        &http,
        reqwest::Method::GET,
        url(&format!("/api/ciphers/{cipher_id}/attachment/{}", attachment["id"].as_str().unwrap())),
        Some(access),
        Value::Null,
    )
    .await;
    // The link names the address the server was started with; the path is what counts.
    let link = info["url"].as_str().unwrap();
    let path = &link[link.find("/attachments/").unwrap()..];
    let bytes = http.get(url(path)).send().await.unwrap().bytes().await.unwrap();
    let plain = uwulock_core::crypto::decrypt_file(&bytes, &attachment_key).unwrap();
    assert_eq!(plain.as_slice(), contents.as_slice(), "the same bytes, opened as an attachment");
}
