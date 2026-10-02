//! The delta sync (docs/uwu-api.md §4) in-process: a full sync, then only what changed, page by
//! page; everything again when a delta cannot say it; organisations counted once for all their
//! members; UwULock's own things and the suite beside the vault.

use crate::test_support::*;
use axum::http::StatusCode;
use base64::Engine as _;
use serde_json::{Value, json};

fn login_item(name: &str) -> Value {
    json!({
        "type": 1,
        "name": name,
        "notes": null,
        "favorite": false,
        "reprompt": 0,
        "folderId": null,
        "organizationId": null,
        "login": { "username": "2.u|u|u", "password": "2.p|p|p", "uris": [], "totp": null },
        "fields": null,
        "passwordHistory": null,
    })
}

async fn sync(server: &TestServer, token: &str, query: &str) -> Value {
    let response = server.get_as(token, &format!("/uwu/v1/sync?{query}")).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    json(response).await
}

async fn since(server: &TestServer, token: &str, cursor: &Value) -> Value {
    sync(server, token, &format!("since={}", cursor.as_str().unwrap())).await
}

/// The same, for a cursor made for other areas than the default ones.
async fn since_for(server: &TestServer, token: &str, include: &str, cursor: &Value) -> Value {
    sync(server, token, &format!("include={include}&since={}", cursor.as_str().unwrap())).await
}

async fn create(server: &TestServer, token: &str, name: &str) -> String {
    let response = server.call("POST", "/api/ciphers", Some(token), login_item(name)).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    json(response).await["id"].as_str().unwrap().to_string()
}

fn ids(list: &Value) -> Vec<String> {
    let mut ids: Vec<String> =
        list.as_array().unwrap().iter().map(|item| item["id"].as_str().unwrap().to_string()).collect();
    ids.sort();
    ids
}

fn sorted(mut list: Vec<String>) -> Vec<String> {
    list.sort();
    list
}

#[tokio::test]
async fn a_full_sync_then_only_what_changed() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let folder = server.call("POST", "/api/folders", Some(&nyu.token), json!({ "name": type2() })).await;
    let folder = json(folder).await["id"].as_str().unwrap().to_string();
    let first = create(&server, &nyu.token, "2.a|a|a").await;

    let full = sync(&server, &nyu.token, "").await;
    assert_eq!(
        (full["object"].as_str(), full["reset"].as_bool(), full["hasMore"].as_bool()),
        (Some("uwuSync"), Some(true), Some(false))
    );
    assert_eq!(ids(&full["vault"]["ciphers"]), vec![first.clone()]);
    assert_eq!(ids(&full["vault"]["folders"]), vec![folder.clone()]);
    assert_eq!(full["vault"]["profile"]["email"], "nyu@example.com");
    assert_eq!(full["vault"]["userDecryption"]["masterPasswordUnlock"]["salt"], "nyu@example.com");
    assert!(full["vault"]["domains"].is_object() && full["vault"]["policies"].is_array());
    assert_eq!(full["vault"]["deleted"]["ciphers"], json!([]));
    assert!(full["suite"].is_null(), "not asked for");
    assert_eq!(full["uwu"]["extrasKey"]["object"], "uwuKeys");
    assert_eq!(full["uwu"]["reminders"]["object"], "list");
    assert_eq!(full["uwu"]["travel"]["object"], "travelMode");
    assert_eq!(full["uwu"]["unseen"], json!({ "securityNotices": 0, "fileRequestSubmissions": 0 }));

    // Nothing happened: nothing comes.
    let same = since(&server, &nyu.token, &full["cursor"]).await;
    assert_eq!((same["reset"].as_bool(), same["hasMore"].as_bool()), (Some(false), Some(false)));
    assert_eq!(same["vault"]["ciphers"], json!([]));
    assert!(same["vault"]["profile"].is_null() && same["vault"]["domains"].is_null());
    assert!(same["uwu"]["reminders"].is_null() && same["uwu"]["extrasKey"].is_null());

    // Changed, new, deleted, and the profile.
    let mut changed = login_item("2.b|b|b");
    changed["lastKnownRevisionDate"] = full["vault"]["ciphers"][0]["revisionDate"].clone();
    let response = server.call("PUT", &format!("/api/ciphers/{first}"), Some(&nyu.token), changed).await;
    assert_eq!(response.status(), StatusCode::OK);
    let second = create(&server, &nyu.token, "2.c|c|c").await;
    let response = server.call("DELETE", &format!("/api/folders/{folder}"), Some(&nyu.token), json!({})).await;
    assert_eq!(response.status(), StatusCode::OK);
    server.call("PUT", "/api/accounts/profile", Some(&nyu.token), json!({ "name": "Mika" })).await;

    let delta = since(&server, &nyu.token, &full["cursor"]).await;
    assert_eq!(delta["reset"], false);
    assert_eq!(ids(&delta["vault"]["ciphers"]), sorted(vec![first.clone(), second.clone()]));
    assert_eq!(delta["vault"]["deleted"]["folders"], json!([folder]));
    assert_eq!(delta["vault"]["profile"]["name"], "Mika");
    assert!(delta["vault"]["domains"].is_object() && delta["vault"]["policies"].is_null());

    // Gone for good, and in the trash.
    server.call("DELETE", &format!("/api/ciphers/{second}"), Some(&nyu.token), json!({})).await;
    server.call("PUT", &format!("/api/ciphers/{first}/delete"), Some(&nyu.token), json!({})).await;
    let next = since(&server, &nyu.token, &delta["cursor"]).await;
    assert_eq!(next["vault"]["deleted"]["ciphers"], json!([second]));
    assert_eq!(ids(&next["vault"]["ciphers"]), vec![first.clone()]);
    assert!(next["vault"]["ciphers"][0]["deletedDate"].is_string());
    assert!(next["vault"]["profile"].is_null());
}

#[tokio::test]
async fn a_long_delta_comes_in_pages_in_order_of_change() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let full = sync(&server, &nyu.token, "").await;
    let mut made = Vec::new();
    for n in 0..5 {
        made.push(create(&server, &nyu.token, &format!("2.{n}|x|x")).await);
    }
    let mut cursor = full["cursor"].clone();
    let mut seen = Vec::new();
    let mut pages = Vec::new();
    loop {
        let page = sync(&server, &nyu.token, &format!("since={}&limit=2", cursor.as_str().unwrap())).await;
        let got: Vec<String> = page["vault"]["ciphers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap().to_string())
            .collect();
        pages.push(got.len());
        seen.extend(got);
        cursor = page["cursor"].clone();
        if !page["hasMore"].as_bool().unwrap() {
            break;
        }
    }
    assert_eq!(pages, vec![2, 2, 1]);
    assert_eq!(seen, made, "in the order they were made");
}

#[tokio::test]
async fn when_a_delta_cannot_say_it_everything_comes_again() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    create(&server, &nyu.token, "2.a|a|a").await;

    let response = server.get_as(&nyu.token, "/uwu/v1/sync?since=nonsense").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["code"], "invalid");
    let response = server.get_as(&nyu.token, "/uwu/v1/sync?include=vault,everything").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let full = sync(&server, &nyu.token, "include=vault").await;
    assert!(full["uwu"].is_null());
    // Another set of areas is another cursor.
    let other =
        sync(&server, &nyu.token, &format!("since={}&include=vault,uwu", full["cursor"].as_str().unwrap())).await;
    assert_eq!(other["reset"], true);
    let fine = sync(&server, &nyu.token, &format!("since={}&include=vault", full["cursor"].as_str().unwrap())).await;
    assert_eq!(fine["reset"], false);

    // The account's epoch (a new key, a membership, travel mode), the server's (a backup put
    // back): a full sync.
    server.state.store.bump_sync_epoch(&nyu.id).await.unwrap();
    let after = sync(&server, &nyu.token, &format!("since={}&include=vault", fine["cursor"].as_str().unwrap())).await;
    assert_eq!((after["reset"].as_bool(), after["vault"]["ciphers"].as_array().unwrap().len()), (Some(true), 1));
    server.state.store.new_sync_epoch().await.unwrap();
    let again = sync(&server, &nyu.token, &format!("since={}&include=vault", after["cursor"].as_str().unwrap())).await;
    assert_eq!(again["reset"], true);

    // A cursor from before the oldest tombstone that is left.
    let folder = server.call("POST", "/api/folders", Some(&nyu.token), json!({ "name": type2() })).await;
    let folder = json(folder).await["id"].as_str().unwrap().to_string();
    server.call("DELETE", &format!("/api/folders/{folder}"), Some(&nyu.token), json!({})).await;
    let in_time = since_for(&server, &nyu.token, "vault", &again["cursor"]).await;
    assert_eq!(in_time["vault"]["deleted"]["folders"], json!([folder]));
    let later = time::OffsetDateTime::now_utc().unix_timestamp() + 91 * 86_400;
    assert_eq!(server.state.store.prune_tombstones(later).await.unwrap(), 1);
    let too_old = since_for(&server, &nyu.token, "vault", &again["cursor"]).await;
    assert_eq!(too_old["reset"], true);
    let current = since_for(&server, &nyu.token, "vault", &in_time["cursor"]).await;
    assert_eq!(current["reset"], false, "a cursor after it is fine");
}

/// A family `owner` made, and `member` in its first collection; the family's id and the
/// collection's.
async fn family_with(server: &TestServer, owner: &Account, member: &Account) -> (String, String) {
    let public = base64::engine::general_purpose::STANDARD.encode([1u8; 294]);
    let body = json!({
        "name": "Katzen", "billingEmail": owner.email, "planType": 22, "key": type4(),
        "keys": { "publicKey": public, "encryptedPrivateKey": type2() }, "collectionName": type2(),
    });
    let org = json(server.call("POST", "/api/organizations", Some(&owner.token), body).await).await;
    let org = org["id"].as_str().unwrap().to_string();
    let collections = json(server.get_as(&owner.token, &format!("/api/organizations/{org}/collections")).await).await;
    let collection = collections["data"][0]["id"].as_str().unwrap().to_string();
    let invite =
        json!({ "emails": [member.email], "type": 2, "collections": [{ "id": collection, "readOnly": false }] });
    server.call("POST", &format!("/api/organizations/{org}/users/invite"), Some(&owner.token), invite).await;
    let mail = server.wait_for_mail(|mail| mail.to == member.email && mail.text.contains("accept-organization")).await;
    let link = mail.text.split_whitespace().find(|word| word.contains("accept-organization")).unwrap().to_string();
    let id = link.split("organizationUserId=").nth(1).unwrap().split('&').next().unwrap().to_string();
    let token = link.split("token=").nth(1).unwrap().split('&').next().unwrap();
    let token = url::form_urlencoded::parse(format!("t={token}").as_bytes()).next().unwrap().1.into_owned();
    let path = format!("/api/organizations/{org}/users/{id}/accept");
    assert_eq!(
        server.call("POST", &path, Some(&member.token), json!({ "token": token })).await.status(),
        StatusCode::OK
    );
    let path = format!("/api/organizations/{org}/users/{id}/confirm");
    assert_eq!(
        server.call("POST", &path, Some(&owner.token), json!({ "key": type4() })).await.status(),
        StatusCode::OK
    );
    (org, collection)
}

#[tokio::test]
async fn a_shared_item_is_counted_once_and_reaches_every_member() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let mio = server.account("mio@example.com").await;
    let (org, collection) = family_with(&server, &nyu, &mio).await;
    let full = sync(&server, &mio.token, "").await;
    assert_eq!(ids(&full["vault"]["collections"]), vec![collection.clone()]);
    let before = server.state.store.sync_counters(&mio.id).await.unwrap().unwrap();
    let org_before = before.orgs.iter().find(|counter| counter.id == org).unwrap().seq;

    let mut item = login_item("2.shared|s|s");
    item["organizationId"] = json!(org);
    let body = json!({ "cipher": item, "collectionIds": [collection] });
    let response = server.call("POST", "/api/ciphers/create", Some(&nyu.token), body).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    let shared = json(response).await["id"].as_str().unwrap().to_string();

    let after = server.state.store.sync_counters(&mio.id).await.unwrap().unwrap();
    assert_eq!(after.seq, before.seq, "the member's own counter stays");
    assert!(after.orgs.iter().find(|counter| counter.id == org).unwrap().seq > org_before);
    let delta = since(&server, &mio.token, &full["cursor"]).await;
    assert_eq!(delta["reset"], false);
    assert_eq!(ids(&delta["vault"]["ciphers"]), vec![shared.clone()]);
    assert_eq!(delta["vault"]["ciphers"][0]["collectionIds"], json!([collection]));

    // The member's own folder for it is the member's change, not the family's.
    let folder = json(server.call("POST", "/api/folders", Some(&mio.token), json!({ "name": type2() })).await).await;
    let folder = folder["id"].as_str().unwrap().to_string();
    let moved = json!({ "ids": [shared], "folderId": folder });
    assert_eq!(server.call("PUT", "/api/ciphers/move", Some(&mio.token), moved).await.status(), StatusCode::OK);
    let mine = since(&server, &mio.token, &delta["cursor"]).await;
    assert_eq!(mine["vault"]["ciphers"][0]["folderId"], folder.as_str());
    let theirs = sync(&server, &nyu.token, "").await;
    assert!(theirs["vault"]["ciphers"][0]["folderId"].is_null(), "the owner's copy has no folder");

    server.call("DELETE", &format!("/api/ciphers/{shared}"), Some(&nyu.token), json!({})).await;
    let gone = since(&server, &mio.token, &mine["cursor"]).await;
    assert_eq!(gone["vault"]["deleted"]["ciphers"], json!([shared]));

    // Out of the family: what the member sees changes wholesale.
    let members = json(server.get_as(&nyu.token, &format!("/api/organizations/{org}/users")).await).await;
    let member = members["data"].as_array().unwrap().iter().find(|m| m["email"] == mio.email).unwrap()["id"].clone();
    let path = format!("/api/organizations/{org}/users/{}", member.as_str().unwrap());
    assert_eq!(server.call("DELETE", &path, Some(&nyu.token), json!({})).await.status(), StatusCode::OK);
    let removed = since(&server, &mio.token, &gone["cursor"]).await;
    assert_eq!(removed["reset"], true);
    assert!(removed["vault"]["collections"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_member_hears_only_of_what_they_could_see() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let mio = server.account("mio@example.com").await;
    let (org, reached) = family_with(&server, &nyu, &mio).await;
    let other = json!({ "name": type2(), "users": [] });
    let other =
        json(server.call("POST", &format!("/api/organizations/{org}/collections"), Some(&nyu.token), other).await)
            .await["id"]
            .as_str()
            .unwrap()
            .to_string();
    let shared = |collection: &str| {
        let mut item = login_item("2.shared|s|s");
        item["organizationId"] = json!(org);
        json!({ "cipher": item, "collectionIds": [collection] })
    };
    let mut items = Vec::new();
    for collection in [&reached, &other] {
        let response = server.call("POST", "/api/ciphers/create", Some(&nyu.token), shared(collection)).await;
        let id = json(response).await["id"].as_str().unwrap().to_string();
        let icon = json!({ "data": type2(), "keyType": "organization" });
        let path = format!("/uwu/v1/icons/own/{id}");
        assert_eq!(server.call("PUT", &path, Some(&nyu.token), icon).await.status(), StatusCode::OK);
        items.push(id);
    }
    let full = sync(&server, &mio.token, "include=vault,uwu").await;
    for id in &items {
        let path = format!("/uwu/v1/icons/own/{id}");
        assert_eq!(
            server
                .call("PUT", &path, Some(&nyu.token), json!({ "data": type2(), "keyType": "organization" }))
                .await
                .status(),
            StatusCode::OK
        );
    }
    let changed = since_for(&server, &mio.token, "vault,uwu", &full["cursor"]).await;
    let icons: Vec<&str> =
        changed["uwu"]["icons"].as_array().unwrap().iter().map(|icon| icon["cipherId"].as_str().unwrap()).collect();
    assert_eq!(icons, vec![items[0].as_str()], "the other collection's icon is not the member's business (SV-L7)");

    for id in &items {
        let path = format!("/uwu/v1/icons/own/{id}");
        assert_eq!(server.call("DELETE", &path, Some(&nyu.token), json!({})).await.status(), StatusCode::OK);
    }
    let unset = since_for(&server, &mio.token, "vault,uwu", &changed["cursor"]).await;
    assert_eq!(unset["uwu"]["iconsDeleted"], json!([items[0]]));
    for id in &items {
        server.call("DELETE", &format!("/api/ciphers/{id}"), Some(&nyu.token), json!({})).await;
    }
    let gone = since_for(&server, &mio.token, "vault,uwu", &unset["cursor"]).await;
    assert_eq!(gone["vault"]["deleted"]["ciphers"], json!([items[0]]));
    let owner = sync(&server, &nyu.token, "include=vault,uwu").await;
    let everything = since_for(&server, &nyu.token, "vault,uwu", &owner["cursor"]).await;
    assert_eq!(everything["reset"], false);
}

#[tokio::test]
async fn edits_out_of_reach_tell_a_member_nothing_but_a_move_out_does() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let mio = server.account("mio@example.com").await;
    let (org, reached) = family_with(&server, &nyu, &mio).await;
    let other = json!({ "name": type2(), "users": [] });
    let other =
        json(server.call("POST", &format!("/api/organizations/{org}/collections"), Some(&nyu.token), other).await)
            .await["id"]
            .as_str()
            .unwrap()
            .to_string();
    let create = |collection: &str| {
        let mut item = login_item("2.shared|s|s");
        item["organizationId"] = json!(org);
        json!({ "cipher": item, "collectionIds": [collection] })
    };
    let mut listening = server.state.hub.listen(&mio.id).unwrap();
    let hidden = json(server.call("POST", "/api/ciphers/create", Some(&nyu.token), create(&other)).await).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    // The hub tells her to sync, but not the id or collection of an item she can't see (R1-8).
    let message = listening.messages.try_recv().expect("a message for Mio");
    let leaks = |needle: &str| message.windows(needle.len()).any(|window| window == needle.as_bytes());
    assert!(!leaks(&hidden) && !leaks(&other));
    drop(listening);
    let moved = json(server.call("POST", "/api/ciphers/create", Some(&nyu.token), create(&reached)).await).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let full = sync(&server, &mio.token, "include=vault,uwu").await;

    // An edit and the trash of an item in a collection Mio does not see: not a word (R1-7).
    let mut edit = login_item("2.edited|e|e");
    edit["organizationId"] = json!(org);
    assert_eq!(
        server.call("PUT", &format!("/api/ciphers/{hidden}"), Some(&nyu.token), edit).await.status(),
        StatusCode::OK
    );
    server.call("PUT", &format!("/api/ciphers/{hidden}/delete"), Some(&nyu.token), json!({})).await;
    let renamed = json!({ "name": type2(), "users": [] });
    server.call("PUT", &format!("/api/organizations/{org}/collections/{other}"), Some(&nyu.token), renamed).await;
    let quiet = since_for(&server, &mio.token, "vault,uwu", &full["cursor"]).await;
    assert_eq!(quiet["reset"], false);
    assert_eq!(quiet["vault"]["deleted"]["ciphers"], json!([]), "{quiet}");
    assert_eq!(quiet["vault"]["deleted"]["collections"], json!([]), "{quiet}");

    // An item moved out of her collection is gone for her.
    let body = json!({ "collectionIds": [other] });
    let response = server.call("PUT", &format!("/api/ciphers/{moved}/collections"), Some(&nyu.token), body).await;
    assert!(response.status().is_success(), "{}", text(response).await);
    let gone = since_for(&server, &mio.token, "vault,uwu", &quiet["cursor"]).await;
    assert_eq!(gone["vault"]["deleted"]["ciphers"], json!([moved]), "{gone}");
}

#[tokio::test]
async fn reminders_and_masked_links_go_with_the_membership() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let mio = server.account("mio@example.com").await;
    let (org, collection) = family_with(&server, &nyu, &mio).await;
    let mut item = login_item("2.shared|s|s");
    item["organizationId"] = json!(org);
    let body = json!({ "cipher": item, "collectionIds": [collection] });
    let shared = json(server.call("POST", "/api/ciphers/create", Some(&nyu.token), body).await).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let path = format!("/uwu/v1/reminders/{shared}");
    assert_eq!(
        server.call("PUT", &path, Some(&mio.token), json!({ "due": "2020-01-01" })).await.status(),
        StatusCode::OK
    );
    let link = uwulock_store::masked::MaskedLink {
        masked_id: "m1".into(),
        cipher_id: shared.clone(),
        email: "m1@masked.example.com".into(),
        state: None,
    };
    server.state.store.link_masked(&mio.id, link).await.unwrap().unwrap();
    assert_eq!(server.state.store.reminders_to_mail("2020-01-02").await.unwrap().len(), 1);

    // Without access to the collection: not shown, not mailed.
    let members = json(server.get_as(&nyu.token, &format!("/api/organizations/{org}/users")).await).await;
    let member = members["data"].as_array().unwrap().iter().find(|m| m["email"] == mio.email).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let other = json!({ "name": type2(), "users": [] });
    let other =
        json(server.call("POST", &format!("/api/organizations/{org}/collections"), Some(&nyu.token), other).await)
            .await["id"]
            .clone();
    let moved = json!({ "collectionIds": [other] });
    let response = server.call("PUT", &format!("/api/ciphers/{shared}/collections"), Some(&nyu.token), moved).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    assert!(json(server.get_as(&mio.token, "/uwu/v1/reminders").await).await["data"].as_array().unwrap().is_empty());
    assert!(server.state.store.reminders_to_mail("2020-01-02").await.unwrap().is_empty());
    assert!(server.state.store.masked_links(&mio.id).await.unwrap().is_empty());

    // Out of the family: gone for good (SV-L9).
    let path = format!("/api/organizations/{org}/users/{member}");
    assert_eq!(server.call("DELETE", &path, Some(&nyu.token), json!({})).await.status(), StatusCode::OK);
    let moved = json!({ "collectionIds": [collection] });
    server.call("PUT", &format!("/api/ciphers/{shared}/collections"), Some(&nyu.token), moved).await;
    let left = server.state.store.reminders_to_mail("2020-01-02").await.unwrap();
    assert!(left.is_empty(), "{left:?}");
    assert!(server.state.store.masked_links(&mio.id).await.unwrap().is_empty());
}

#[tokio::test]
async fn uwulocks_own_things_come_beside_the_vault() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let item = create(&server, &nyu.token, "2.a|a|a").await;
    let full = sync(&server, &nyu.token, "include=uwu").await;
    assert!(full["vault"].is_null() && full["uwu"].is_object());

    let keys = json!({ "userKeyWrapped": type2(), "privateKeyWrapped": type2() });
    assert_eq!(server.call("POST", "/uwu/v1/keys", Some(&nyu.token), keys).await.status(), StatusCode::OK);
    let reminder = json!({ "due": "2027-01-15" });
    let path = format!("/uwu/v1/reminders/{item}");
    assert_eq!(server.call("PUT", &path, Some(&nyu.token), reminder).await.status(), StatusCode::OK);
    let icon = json!({ "data": type2(), "keyType": "extras" });
    let path = format!("/uwu/v1/icons/own/{item}");
    let response = server.call("PUT", &path, Some(&nyu.token), icon).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);

    let delta = sync(&server, &nyu.token, &format!("include=uwu&since={}", full["cursor"].as_str().unwrap())).await;
    assert_eq!(delta["reset"], false);
    assert_eq!(delta["uwu"]["extrasKey"]["extrasKey"]["userKeyWrapped"], type2());
    assert_eq!(delta["uwu"]["reminders"]["data"][0]["cipherId"], item.as_str());
    assert_eq!(delta["uwu"]["icons"][0]["cipherId"], item.as_str());
    assert_eq!(delta["uwu"]["icons"][0]["keyType"], "extras");
    assert!(delta["uwu"]["icons"][0]["data"].is_null(), "only that it changed");
    assert_eq!(delta["uwu"]["unseen"]["securityNotices"], 1, "the notice of the new extras key");
    assert!(delta["vault"].is_null());

    assert_eq!(server.call("DELETE", &path, Some(&nyu.token), json!({})).await.status(), StatusCode::OK);
    let path = format!("/uwu/v1/reminders/{item}");
    assert_eq!(server.call("DELETE", &path, Some(&nyu.token), json!({})).await.status(), StatusCode::OK);
    let next = sync(&server, &nyu.token, &format!("include=uwu&since={}", delta["cursor"].as_str().unwrap())).await;
    assert_eq!(next["uwu"]["iconsDeleted"], json!([item]));
    assert_eq!(next["uwu"]["reminders"]["data"], json!([]));
    assert!(next["uwu"]["extrasKey"].is_null());
}

#[tokio::test]
async fn the_suite_syncs_in_the_same_answer() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let space = json!({ "id": "3f0e0c1e-0000-4000-8000-00000000000a", "key": type2() });
    assert_eq!(server.call("PUT", "/uwu/v1/suite/spaces/rdp", Some(&nyu.token), space).await.status(), StatusCode::OK);
    let full = sync(&server, &nyu.token, "include=suite").await;
    assert_eq!(full["suite"]["spaces"][0]["space"], "rdp");

    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let record = |id: &str, base: i64, deleted: bool| {
        json!({ "id": id, "kind": "host", "updatedAt": { "wallMs": 1, "counter": 0, "device": 1 },
                "baseSeq": base, "deleted": deleted, "nonce": b64(&[1; 24]), "blob": b64(b"x") })
    };
    let id = "9b2d0c1e-0000-4000-8000-000000000001";
    let body = json!({ "schema": 2, "records": [record(id, 0, false)] });
    let pushed = json(server.call("POST", "/uwu/v1/suite/spaces/rdp/records", Some(&nyu.token), body).await).await;
    let delta = since_for(&server, &nyu.token, "suite", &full["cursor"]).await;
    assert_ne!(delta["cursor"], full["cursor"]);
    // The cursor was made for the suite: the delta is too.
    assert_eq!(delta["suite"]["records"][0]["id"], id);
    assert!(delta["suite"]["spaces"].as_array().unwrap().is_empty(), "the space did not change");

    let seq = pushed["accepted"][0]["seq"].as_i64().unwrap();
    let body = json!({ "schema": 2, "records": [record(id, seq, true)] });
    server.call("POST", "/uwu/v1/suite/spaces/rdp/records", Some(&nyu.token), body).await;
    let deleted = since_for(&server, &nyu.token, "suite", &delta["cursor"]).await;
    assert_eq!(deleted["suite"]["records"][0]["deleted"], true, "a deleted record is its tombstone");

    // A new key: everything of the suite again.
    let rekey = json!({ "id": "3f0e0c1e-0000-4000-8000-00000000000b", "key": type2(),
                        "records": [record(id, deleted["suite"]["records"][0]["seq"].as_i64().unwrap(), true)] });
    let response = server.call("POST", "/uwu/v1/suite/spaces/rdp/rekey", Some(&nyu.token), rekey).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    let after = since_for(&server, &nyu.token, "suite", &deleted["cursor"]).await;
    assert_eq!(after["reset"], true);
    assert_eq!(after["suite"]["spaces"][0]["id"], "3f0e0c1e-0000-4000-8000-00000000000b");
    assert!(after["suite"]["records"].as_array().unwrap().is_empty(), "a fresh start needs no tombstones");
}

/// How long a sync of a vault with a few thousand items takes, and a delta of one and of 500
/// changes. Not a test: `cargo test -p uwulock-api --release -- --ignored --nocapture sync_speed`.
#[tokio::test]
#[ignore = "a measurement, for docs/performance.md"]
async fn sync_speed() {
    const ITEMS: usize = 5000;
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let ciphers: Vec<Value> = (0..ITEMS).map(|n| login_item(&format!("2.item{n}|{}|mac", "x".repeat(40)))).collect();
    let import = json!({ "ciphers": ciphers, "folders": [], "folderRelationships": [] });
    let response = server.call("POST", "/api/ciphers/import", Some(&nyu.token), import).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);

    let folder = json(server.call("POST", "/api/folders", Some(&nyu.token), json!({ "name": type2() })).await).await;
    let time = |label: &str, started: std::time::Instant| {
        println!("{label}: {:.1} ms", started.elapsed().as_secs_f64() * 1000.0)
    };
    let started = std::time::Instant::now();
    let bitwarden = json(server.get_as(&nyu.token, "/api/sync").await).await;
    time("/api/sync", started);
    assert_eq!(bitwarden["ciphers"].as_array().unwrap().len(), ITEMS);
    let started = std::time::Instant::now();
    let full = sync(&server, &nyu.token, "").await;
    time("full /uwu/v1/sync", started);
    assert_eq!(full["vault"]["ciphers"].as_array().unwrap().len(), ITEMS);

    let started = std::time::Instant::now();
    let none = since(&server, &nyu.token, &full["cursor"]).await;
    time("delta, nothing changed", started);
    create(&server, &nyu.token, "2.one|x|x").await;
    let started = std::time::Instant::now();
    let one = since(&server, &nyu.token, &none["cursor"]).await;
    time("delta, one change", started);
    assert_eq!(one["vault"]["ciphers"].as_array().unwrap().len(), 1);
    let ids: Vec<Value> =
        full["vault"]["ciphers"].as_array().unwrap().iter().take(500).map(|cipher| cipher["id"].clone()).collect();
    let moved = json!({ "ids": ids, "folderId": folder["id"] });
    assert_eq!(server.call("PUT", "/api/ciphers/move", Some(&nyu.token), moved).await.status(), StatusCode::OK);
    let started = std::time::Instant::now();
    let many = since(&server, &nyu.token, &one["cursor"]).await;
    time("delta, 500 changes", started);
    assert_eq!(many["vault"]["ciphers"].as_array().unwrap().len(), 500);
}
