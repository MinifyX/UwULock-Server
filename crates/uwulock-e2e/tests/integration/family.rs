//! A family end to end, with the crypto of UwULock's clients and two accounts: the owner makes
//! the family (its key wrapped for the owner's public key, its key pair, its first collection),
//! invites the other account, which accepts; both compare the fingerprint phrase and the owner
//! confirms with the family key wrapped for the member's public key; the owner moves an item
//! into the collection — and the member's client opens the family key with its private key and
//! reads the item, the collection's name too.

use crate::client::{KDF, PASSWORD, client, start_for};
use base64::Engine as _;
use serde_json::{Value, json};
use uwulock_bitwarden::api::{LoginOutcome, PasswordLogin, parse_sync};
use uwulock_bitwarden::crypto::{self, EncString, PrivateKey, PublicKey, SymmetricKey, decrypt_user_key};
use uwulock_bitwarden::vault::{Item, ItemKind};
use uwulock_bitwarden::{Client, Vault, wire};
use zeroize::Zeroizing;

const OWNER: &str = "nyu@example.com";
const MEMBER: &str = "mio@example.com";

/// A logged-in account with its keys, as a client holds them.
struct Person {
    client: Client,
    access: String,
    user_key: SymmetricKey,
    private: PrivateKey,
    id: String,
}

/// Register `email` the way a client does, with a key pair, and log in.
async fn person(url: &str, email: &str, token: &str, device: &str) -> Person {
    let b64 = base64::engine::general_purpose::STANDARD;
    let master = crypto::master_key(PASSWORD, email, KDF).unwrap();
    let user_key = SymmetricKey::generate();
    let private = PrivateKey::generate().unwrap();
    let body = json!({
        "email": email,
        "name": email.split('@').next(),
        "masterPasswordHash": crypto::master_password_hash(&master, PASSWORD),
        "key": EncString::encrypt(&user_key.to_bytes(), &SymmetricKey::stretch(&master)).to_string(),
        "kdf": 0,
        "kdfIterations": 100_000,
        "keys": {
            "publicKey": b64.encode(private.public().to_der().unwrap()),
            "encryptedPrivateKey": EncString::encrypt(&private.to_der().unwrap(), &user_key).to_string(),
        },
        "emailVerificationToken": token,
    });
    let response = reqwest::Client::new()
        .post(format!("{url}/identity/accounts/register/finish"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success(), "{}", response.text().await.unwrap());

    let client = client(url, device);
    let hash = crypto::master_password_hash(&master, PASSWORD);
    let login =
        PasswordLogin { email, password_hash: &hash, two_factor: None, remember_token: None, new_device_code: None };
    let LoginOutcome::LoggedIn(session) = client.login(login).await.unwrap() else { panic!("a login") };
    let opened = decrypt_user_key(&master, &session.protected_user_key.clone().unwrap().parse().unwrap()).unwrap();
    assert_eq!(opened.to_bytes().as_slice(), user_key.to_bytes().as_slice());
    let profile =
        call(format!("{url}/api/accounts/profile"), reqwest::Method::GET, &session.access_token, Value::Null).await;
    let id = profile["id"].as_str().unwrap().to_string();
    Person { client, access: session.access_token.to_string(), user_key, private, id }
}

async fn call(url: String, method: reqwest::Method, token: &str, body: Value) -> Value {
    let response = reqwest::Client::new().request(method, &url).bearer_auth(token).json(&body).send().await.unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    assert!(status.is_success(), "{url}: {status} {text}");
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

async fn vault(person: &Person) -> Vault {
    Vault::open(&parse_sync(&person.client.sync(&person.access).await.unwrap()).unwrap(), &person.user_key).unwrap()
}

#[tokio::test]
async fn a_family_shares_an_item_with_the_member_the_owner_confirmed() {
    let (server, tokens) = start_for(&[OWNER, MEMBER]).await;
    let url = |path: &str| format!("{}{path}", server.url);
    let owner = person(&server.url, OWNER, &tokens[0], "5a0e9c1e-7d3b-4d0c-9a8e-0000000000f1").await;
    let member = person(&server.url, MEMBER, &tokens[1], "5a0e9c1e-7d3b-4d0c-9a8e-0000000000f2").await;
    let b64 = base64::engine::general_purpose::STANDARD;
    let post = reqwest::Method::POST;

    // The family: its key, wrapped for the owner's own public key; its key pair; a collection.
    let family_key = SymmetricKey::generate();
    let family_pair = PrivateKey::generate().unwrap();
    let body = json!({
        "name": "Katzen",
        "billingEmail": OWNER,
        "planType": 22,
        "key": crypto::wrap_for(&owner.private.public(), &family_key).unwrap().to_string(),
        "keys": {
            "publicKey": b64.encode(family_pair.public().to_der().unwrap()),
            "encryptedPrivateKey": EncString::encrypt(&family_pair.to_der().unwrap(), &family_key).to_string(),
        },
        "collectionName": EncString::encrypt(b"Streaming", &family_key).to_string(),
    });
    let org = call(url("/api/organizations"), post.clone(), &owner.access, body).await;
    let org_id = org["id"].as_str().unwrap().to_string();
    let theirs = vault(&owner).await;
    assert_eq!(theirs.organizations[0].name, "Katzen", "the owner's client opens the family key");
    let collection = theirs.collections[0].clone();
    assert_eq!(collection.name, "Streaming");

    // Invited, and accepted in the member's vault (the server here sends no mail).
    let invite = json!({ "emails": [MEMBER], "type": 2, "collections": [{ "id": collection.id, "readOnly": true }] });
    call(url(&format!("/api/organizations/{org_id}/users/invite")), post.clone(), &owner.access, invite).await;
    let pending =
        call(url("/uwu/v1/organizations/invitations"), reqwest::Method::GET, &member.access, Value::Null).await;
    let membership = pending["data"][0]["id"].as_str().unwrap().to_string();
    let accept = url(&format!("/api/organizations/{org_id}/users/{membership}/accept"));
    call(accept, post.clone(), &member.access, json!({})).await;

    // The owner's phrase for the member's key is the member's own.
    let keys = call(
        url(&format!("/api/organizations/{org_id}/users/public-keys")),
        post.clone(),
        &owner.access,
        json!({ "ids": [membership] }),
    )
    .await;
    let their_key = b64.decode(keys["data"][0]["key"].as_str().unwrap()).unwrap();
    assert_eq!(keys["data"][0]["userId"], member.id.as_str());
    let seen_by_owner = crypto::fingerprint(&member.id, &their_key);
    let own = crypto::fingerprint(&member.id, &member.private.public().to_der().unwrap());
    assert_eq!(seen_by_owner, own, "the same phrase on both sides");
    let wrapped = crypto::wrap_for(&PublicKey::from_der(&their_key).unwrap(), &family_key).unwrap().to_string();
    let confirm = url(&format!("/api/organizations/{org_id}/users/{membership}/confirm"));
    call(confirm, post.clone(), &owner.access, json!({ "key": wrapped })).await;

    // A personal item of the owner's moves into the collection, encrypted anew under the family key.
    let mut item = Item::new(ItemKind::Login);
    item.name = Zeroizing::new("Streaming-Abo".into());
    let login = item.login.as_mut().unwrap();
    login.username = Some(Zeroizing::new("katzen@example.com".into()));
    login.password = Some(Zeroizing::new("Miau-2026!".into()));
    let saved = owner.client.create_cipher(&owner.access, item.seal(&owner.user_key).unwrap(), &[]).await.unwrap();
    let id = saved["id"].as_str().unwrap().to_string();
    item.organization_id = Some(org_id.clone());
    let share =
        wire::ShareRequest { cipher: item.seal(&family_key).unwrap(), collection_ids: vec![collection.id.clone()] };
    call(
        url(&format!("/api/ciphers/{id}/share")),
        reqwest::Method::PUT,
        &owner.access,
        serde_json::to_value(&share).unwrap(),
    )
    .await;

    // The member's client opens it all with its own keys.
    let seen = vault(&member).await;
    assert_eq!(seen.organizations[0].name, "Katzen");
    assert_eq!(seen.collections[0].name, "Streaming");
    let shared = seen.item(&id).expect("the shared item");
    assert!(!shared.broken);
    assert_eq!(shared.organization_id.as_deref(), Some(org_id.as_str()));
    assert_eq!(shared.login.as_ref().unwrap().password.as_ref().map(|p| p.as_str()), Some("Miau-2026!"));
    assert!(vault(&owner).await.item(&id).is_some(), "and the owner still has it");
}
