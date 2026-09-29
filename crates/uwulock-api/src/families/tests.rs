//! Families through Bitwarden's organisation API, in-process: making one, inviting, accepting,
//! confirming, collections and who reaches them, leaving and deleting — and everything somebody
//! may not do.

use crate::Settings;
use crate::settings::{OrgSettings, WhoMayCreate};
use crate::test_support::*;
use axum::http::StatusCode;
use base64::Engine as _;
use serde_json::{Value, json};

fn new_family(name: &str) -> Value {
    let public = base64::engine::general_purpose::STANDARD.encode([1u8; 294]);
    json!({
        "name": name,
        "billingEmail": "nyu@example.com",
        "planType": 22,
        "key": type4(),
        "keys": { "publicKey": public, "encryptedPrivateKey": type2() },
        "collectionName": type2(),
    })
}

/// A family `owner` made; its id and its first collection's.
async fn family(server: &TestServer, owner: &Account) -> (String, String) {
    let response = server.call("POST", "/api/organizations", Some(&owner.token), new_family("Katzen")).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    let org = json(response).await;
    assert_eq!((org["planType"].as_i64(), org["object"].as_str()), (Some(22), Some("organization")));
    let id = org["id"].as_str().unwrap().to_string();
    let collections = json(server.get_as(&owner.token, &format!("/api/organizations/{id}/collections")).await).await;
    (id, collections["data"][0]["id"].as_str().unwrap().to_string())
}

fn token_of(link: &str) -> String {
    let token = link.split("token=").nth(1).unwrap().split('&').next().unwrap();
    url::form_urlencoded::parse(format!("t={token}").as_bytes()).next().unwrap().1.into_owned()
}

fn link_in(text: &str) -> String {
    text.split_whitespace().find(|word| word.contains("accept-organization")).unwrap().to_string()
}

/// `member` invited by `owner`, accepted with the mail's link, and confirmed; their membership id.
async fn join(server: &TestServer, owner: &Account, org: &str, member: &Account, collections: Value) -> String {
    let body = json!({ "emails": [member.email], "type": 2, "collections": collections });
    let response =
        server.call("POST", &format!("/api/organizations/{org}/users/invite"), Some(&owner.token), body).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    let mail = server.wait_for_mail(|mail| mail.to == member.email && mail.text.contains("accept-organization")).await;
    let link = link_in(&mail.text);
    assert!(link.contains("orgUserHasExistingUser=True"), "{link}");
    let id = link.split("organizationUserId=").nth(1).unwrap().split('&').next().unwrap().to_string();
    let accept = json!({ "token": token_of(&link) });
    let path = format!("/api/organizations/{org}/users/{id}/accept");
    assert_eq!(server.call("POST", &path, Some(&member.token), accept).await.status(), StatusCode::OK);
    let path = format!("/api/organizations/{org}/users/{id}/confirm");
    let response = server.call("POST", &path, Some(&owner.token), json!({ "key": type4() })).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    id
}

async fn sync(server: &TestServer, token: &str) -> Value {
    json(server.get_as(token, "/api/sync").await).await
}

#[tokio::test]
async fn a_family_from_the_invitation_to_a_shared_item() {
    let server = TestServer::new().await;
    let owner = server.account("nyu@example.com").await;
    let mio = server.account("mio@example.com").await;
    let (org, collection) = family(&server, &owner).await;

    let mine = sync(&server, &owner.token).await;
    let profile = &mine["profile"]["organizations"][0];
    assert_eq!((profile["productTierType"].as_i64(), profile["planType"].as_i64()), (Some(1), Some(22)));
    assert_eq!((profile["type"].as_i64(), profile["status"].as_i64()), (Some(0), Some(2)));
    assert_eq!(profile["key"], type4());
    assert_eq!(mine["profile"]["organizationsNew"][0]["id"], org.as_str(), "newer clients read this list");
    assert_eq!((profile["seats"].as_i64(), profile["useGroups"].as_bool()), (Some(6), Some(false)));
    assert_eq!(mine["collections"].as_array().unwrap().len(), 1);

    // Invited, the member sees nothing yet; accepted, the owner hears of it.
    let body =
        json!({ "emails": ["mio@example.com"], "type": 2, "collections": [{ "id": collection, "readOnly": true }] });
    let response =
        server.call("POST", &format!("/api/organizations/{org}/users/invite"), Some(&owner.token), body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mail =
        server.wait_for_mail(|mail| mail.to == "mio@example.com" && mail.text.contains("accept-organization")).await;
    assert!(mail.subject.contains("Katzen"));
    let link = link_in(&mail.text);
    let id = link.split("organizationUserId=").nth(1).unwrap().split('&').next().unwrap().to_string();
    assert!(sync(&server, &mio.token).await["profile"]["organizations"].as_array().unwrap().is_empty());

    let path = format!("/api/organizations/{org}/users/{id}/accept");
    let wrong = server.call("POST", &path, Some(&owner.token), json!({ "token": token_of(&link) })).await;
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST, "only for the address it went to");
    let forged = server.call("POST", &path, Some(&mio.token), json!({ "token": "nonsense" })).await;
    assert_eq!(forged.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        server.call("POST", &path, Some(&mio.token), json!({ "token": token_of(&link) })).await.status(),
        StatusCode::OK
    );
    server.wait_for_mail(|mail| mail.to == "nyu@example.com" && mail.text.contains("Fingerabdruck")).await;
    let waiting = sync(&server, &mio.token).await;
    assert_eq!(waiting["profile"]["organizations"][0]["status"], 1);
    assert!(waiting["profile"]["organizations"][0]["key"].is_null(), "no key before confirming");

    // The owner fetches the key to wrap for, and confirms.
    let keys = json(
        server
            .call(
                "POST",
                &format!("/api/organizations/{org}/users/public-keys"),
                Some(&owner.token),
                json!({ "ids": [id] }),
            )
            .await,
    )
    .await;
    assert_eq!(keys["data"][0]["userId"], mio.id.as_str());
    assert_eq!(keys["data"][0]["key"], "MIIBpublic");
    // The member's devices hear of it, to sync the family's key.
    let mut listening = server.state.hub.listen(&mio.id).unwrap();
    let path = format!("/api/organizations/{org}/users/{id}/confirm");
    let bad = server.call("POST", &path, Some(&owner.token), json!({ "key": type2() })).await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST, "only an RSA wrap");
    assert_eq!(
        server.call("POST", &path, Some(&owner.token), json!({ "key": type4() })).await.status(),
        StatusCode::OK
    );
    assert!(listening.messages.try_recv().is_ok(), "SyncOrgKeys went out");
    server
        .wait_for_mail(|mail| {
            mail.to == "mio@example.com"
                && mail.subject.contains("Katzen")
                && !mail.text.contains("accept-organization")
        })
        .await;
    let notices = json(server.get_as(&mio.token, "/uwu/v1/security/notices").await).await;
    assert_eq!(notices["data"][0]["kind"], "organizationJoined");
    assert_eq!(notices["data"][0]["detail"]["organization"], "Katzen");

    // An item of the owner's, moved into the collection: the member reads it, and only reads.
    let item = json!({ "type": 2, "name": type2(), "notes": null, "secureNote": { "type": 0 }, "folderId": null, "organizationId": null });
    let created = json(server.call("POST", "/api/ciphers", Some(&owner.token), item.clone()).await).await;
    let cipher = created["id"].as_str().unwrap().to_string();
    let mut shared = item;
    shared["organizationId"] = org.clone().into();
    let body = json!({ "cipher": shared, "collectionIds": [collection] });
    let response = server.call("PUT", &format!("/api/ciphers/{cipher}/share"), Some(&owner.token), body).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    let theirs = sync(&server, &mio.token).await;
    assert_eq!(theirs["profile"]["organizations"][0]["key"], type4());
    assert_eq!(theirs["ciphers"][0]["id"], cipher.as_str());
    assert_eq!(theirs["ciphers"][0]["edit"], false);

    // Write access: an owner changes the member's rights on the collection.
    let users = json!([{ "id": id, "readOnly": false, "hidePasswords": false, "manage": false }]);
    let body = json!({ "name": type2(), "users": users, "groups": [] });
    let path = format!("/api/organizations/{org}/collections/{collection}");
    assert_eq!(server.call("PUT", &path, Some(&owner.token), body).await.status(), StatusCode::OK);
    assert_eq!(sync(&server, &mio.token).await["ciphers"][0]["edit"], true);
    let details =
        json(server.get_as(&owner.token, &format!("/api/organizations/{org}/users?includeCollections=true")).await)
            .await;
    let member = details["data"].as_array().unwrap().iter().find(|m| m["id"] == id.as_str()).unwrap().clone();
    assert_eq!((member["email"].as_str(), member["status"].as_i64()), (Some("mio@example.com"), Some(2)));
    assert_eq!(member["collections"][0]["readOnly"], false);
}

#[tokio::test]
async fn only_owners_manage_and_outsiders_see_nothing() {
    let server = TestServer::new().await;
    let owner = server.account("nyu@example.com").await;
    let mio = server.account("mio@example.com").await;
    let rin = server.account("rin@example.com").await;
    let (org, collection) = family(&server, &owner).await;
    let member = join(&server, &owner, &org, &mio, json!([{ "id": collection }])).await;

    let tries = [
        ("POST", format!("/api/organizations/{org}/users/invite"), json!({ "emails": ["x@example.com"], "type": 2 })),
        ("POST", format!("/api/organizations/{org}/collections"), json!({ "name": type2(), "users": [] })),
        ("PUT", format!("/api/organizations/{org}"), json!({ "name": "Meins" })),
        ("DELETE", format!("/api/organizations/{org}/users/{member}"), Value::Null),
        ("DELETE", format!("/api/organizations/{org}/collections/{collection}"), Value::Null),
        ("POST", format!("/api/organizations/{org}/users/public-keys"), json!({ "ids": [member] })),
    ];
    for (method, path, body) in &tries {
        let response = server.call(method, path, Some(&mio.token), body.clone()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "a member: {method} {path}");
        let response = server.call(method, path, Some(&rin.token), body.clone()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "an outsider: {method} {path}");
    }
    for path in [
        format!("/api/organizations/{org}"),
        format!("/api/organizations/{org}/users"),
        format!("/api/organizations/{org}/keys"),
    ] {
        assert_eq!(server.get_as(&rin.token, &path).await.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(server.get_as(&mio.token, &path).await.status(), StatusCode::OK, "{path}");
    }
    let members =
        json(server.get_as(&mio.token, &format!("/api/organizations/{org}/users?includeCollections=true")).await).await;
    assert!(members["data"][0]["collections"].as_array().unwrap().is_empty(), "who reaches what is the owners'");

    // Owners and members only; no groups.
    let admin = json!({ "emails": ["x@example.com"], "type": 1 });
    let path = format!("/api/organizations/{org}/users/invite");
    assert_eq!(server.call("POST", &path, Some(&owner.token), admin).await.status(), StatusCode::BAD_REQUEST);
    let grouped = json!({ "emails": ["x@example.com"], "type": 2, "groups": ["g"] });
    assert_eq!(server.call("POST", &path, Some(&owner.token), grouped).await.status(), StatusCode::BAD_REQUEST);
    // A collection of another family is nobody's business here.
    let other = server.account("other@example.com").await;
    let (_, foreign) = family(&server, &other).await;
    let body = json!({ "type": 2, "collections": [{ "id": foreign, "readOnly": false }] });
    let path = format!("/api/organizations/{org}/users/{member}");
    assert_eq!(server.call("PUT", &path, Some(&owner.token), body).await.status(), StatusCode::OK);
    assert!(sync(&server, &mio.token).await["collections"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn seats_owners_and_who_may_make_one() {
    let settings = Settings {
        families: OrgSettings { who_may_create: WhoMayCreate::Everyone, max_members: 2, per_user: 1 },
        ..Settings::default()
    };
    let server = TestServer::with_settings(settings).await;
    let owner = server.account("nyu@example.com").await;
    let (org, _) = family(&server, &owner).await;
    let again = server.call("POST", "/api/organizations", Some(&owner.token), new_family("Zweite")).await;
    assert_eq!(again.status(), StatusCode::BAD_REQUEST, "one family per account");
    let me = json(server.get_as(&owner.token, "/uwu/v1/account").await).await;
    assert_eq!(me["families"], json!({ "mayCreate": false, "maxMembers": 2, "owned": 1, "perUser": 1 }));
    // What the clients look at first (the move from Bitwarden makes families only then).
    let info = json(server.get("/uwu/v1/info").await).await;
    assert!(info["features"].as_array().unwrap().contains(&json!("families")), "{info}");

    let path = format!("/api/organizations/{org}/users/invite");
    let two = json!({ "emails": ["a@example.com", "b@example.com"], "type": 2 });
    let response = server.call("POST", &path, Some(&owner.token), two).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(text(response).await.contains("maximum number of users"));
    let one = json!({ "emails": ["a@example.com"], "type": 2 });
    assert_eq!(server.call("POST", &path, Some(&owner.token), one.clone()).await.status(), StatusCode::OK);
    assert_eq!(server.call("POST", &path, Some(&owner.token), one).await.status(), StatusCode::BAD_REQUEST);

    let mut settings = server.state.settings();
    settings.families.who_may_create = WhoMayCreate::Admins;
    server.state.apply_settings(settings);
    let rin = server.account("rin@example.com").await;
    let response = server.call("POST", "/api/organizations", Some(&rin.token), new_family("Rins")).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let me = json(server.get_as(&rin.token, "/uwu/v1/account").await).await;
    assert_eq!(me["families"]["mayCreate"], false);

    // Keys the clients would not make, and plans that are no family.
    let mut settings = server.state.settings();
    settings.families.who_may_create = WhoMayCreate::Everyone;
    server.state.apply_settings(settings);
    let mut body = new_family("Rins");
    body["key"] = type2().into();
    assert_eq!(
        server.call("POST", "/api/organizations", Some(&rin.token), body).await.status(),
        StatusCode::BAD_REQUEST
    );
    let mut body = new_family("Rins");
    body["planType"] = 20.into();
    assert_eq!(
        server.call("POST", "/api/organizations", Some(&rin.token), body).await.status(),
        StatusCode::BAD_REQUEST
    );
    let response = server.call("POST", "/api/organizations", Some(&rin.token), new_family("Rins")).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn somebody_new_registers_with_the_family_s_invitation() {
    let settings = Settings { users_may_invite: true, invitations_per_user: 1, ..Settings::default() };
    let server = TestServer::with_settings(settings).await;
    let owner = server.account("nyu@example.com").await;
    let (org, _) = family(&server, &owner).await;
    let body = json!({ "emails": ["new@example.com", "late@example.com"], "type": 2 });
    let response =
        server.call("POST", &format!("/api/organizations/{org}/users/invite"), Some(&owner.token), body).await;
    assert_eq!(response.status(), StatusCode::OK);

    let mail = server.wait_for_mail(|mail| mail.to == "new@example.com").await;
    let link = link_in(&mail.text);
    assert!(link.contains("orgUserHasExistingUser=False"));
    let member = link.split("organizationUserId=").nth(1).unwrap().split('&').next().unwrap().to_string();
    let mut body = register_body("new@example.com", "");
    body["emailVerificationToken"] = Value::Null;
    body["orgInviteToken"] = token_of(&link).into();
    body["organizationUserId"] = member.clone().into();
    let response = server.call("POST", "/identity/accounts/register/finish", None, body).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    let new = server.login("new@example.com", "device-1").await;
    assert_eq!(sync(&server, &new.token).await["profile"]["organizations"][0]["status"], 1, "accepted with it");
    let mine = json(server.get_as(&owner.token, "/uwu/v1/invitations").await).await;
    assert_eq!(mine["used"], 1, "the account counts for the inviter");

    // The quota was used up: the second one has to ask for an account, and cannot register.
    let mail = server.wait_for_mail(|mail| mail.to == "late@example.com").await;
    assert!(mail.text.contains("Einladung") && mail.text.contains("Verwaltung"), "{}", mail.text);
    let link = link_in(&mail.text);
    let member = link.split("organizationUserId=").nth(1).unwrap().split('&').next().unwrap().to_string();
    let mut body = register_body("late@example.com", "");
    body["emailVerificationToken"] = Value::Null;
    body["orgInviteToken"] = token_of(&link).into();
    body["organizationUserId"] = member.into();
    let response = server.call("POST", "/identity/accounts/register/finish", None, body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(server.state.store.user_by_email("late@example.com").await.unwrap().is_none());
}

#[tokio::test]
async fn an_invitation_is_taken_in_the_web_vault_too() {
    let server = TestServer::new().await;
    let owner = server.account("nyu@example.com").await;
    let mio = server.account("mio@example.com").await;
    let rin = server.account("rin@example.com").await;
    let (org, _) = family(&server, &owner).await;
    let body = json!({ "emails": ["mio@example.com", "rin@example.com"], "type": 2 });
    server.call("POST", &format!("/api/organizations/{org}/users/invite"), Some(&owner.token), body).await;

    let pending = json(server.get_as(&mio.token, "/uwu/v1/organizations/invitations").await).await;
    assert_eq!(pending["data"][0]["organizationName"], "Katzen");
    let id = pending["data"][0]["id"].as_str().unwrap().to_string();
    // Not somebody else's.
    let path = format!("/api/organizations/{org}/users/{id}/accept");
    assert_eq!(server.call("POST", &path, Some(&rin.token), json!({})).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(server.call("POST", &path, Some(&mio.token), json!({})).await.status(), StatusCode::OK);
    assert!(
        json(server.get_as(&mio.token, "/uwu/v1/organizations/invitations").await).await["data"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let theirs = json(server.get_as(&rin.token, "/uwu/v1/organizations/invitations").await).await;
    let id = theirs["data"][0]["id"].as_str().unwrap();
    let response =
        server.call("DELETE", &format!("/uwu/v1/organizations/invitations/{id}"), Some(&rin.token), Value::Null).await;
    assert_eq!(response.status(), StatusCode::OK);
    let members = json(server.get_as(&owner.token, &format!("/api/organizations/{org}/users")).await).await;
    assert_eq!(members["data"].as_array().unwrap().len(), 2, "declined is gone");
}

#[tokio::test]
async fn leaving_handing_over_and_deleting() {
    let server = TestServer::new().await;
    let owner = server.account("nyu@example.com").await;
    let mio = server.account("mio@example.com").await;
    let (org, collection) = family(&server, &owner).await;
    let member = join(&server, &owner, &org, &mio, json!([{ "id": collection }])).await;

    let leave = format!("/api/organizations/{org}/leave");
    assert_eq!(server.call("POST", &leave, Some(&owner.token), Value::Null).await.status(), StatusCode::BAD_REQUEST);
    let delete = json!({ "masterPasswordHash": password_hash("nyu@example.com") });
    let response = server.call("DELETE", "/api/accounts", Some(&owner.token), delete).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "the only owner does not just go");

    // Handed over: mio becomes an owner, nyu leaves.
    let path = format!("/api/organizations/{org}/users/{member}");
    let body = json!({ "type": 0, "collections": [] });
    assert_eq!(server.call("PUT", &path, Some(&owner.token), body).await.status(), StatusCode::OK);
    let notices = json(server.get_as(&mio.token, "/uwu/v1/security/notices").await).await;
    assert_eq!(notices["data"][0]["kind"], "organizationRoleChanged");
    assert_eq!(server.call("POST", &leave, Some(&owner.token), Value::Null).await.status(), StatusCode::OK);
    assert!(sync(&server, &owner.token).await["profile"]["organizations"].as_array().unwrap().is_empty());

    // Deleting takes the master password.
    let path = format!("/api/organizations/{org}");
    let wrong = json!({ "masterPasswordHash": "wrong" });
    assert_eq!(server.call("DELETE", &path, Some(&mio.token), wrong).await.status(), StatusCode::BAD_REQUEST);
    let right = json!({ "masterPasswordHash": password_hash("mio@example.com") });
    assert_eq!(server.call("DELETE", &path, Some(&mio.token), right).await.status(), StatusCode::OK);
    assert!(sync(&server, &mio.token).await["profile"]["organizations"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn removed_members_lose_the_family_and_hear_of_it() {
    let server = TestServer::new().await;
    let owner = server.account("nyu@example.com").await;
    let mio = server.account("mio@example.com").await;
    let (org, collection) = family(&server, &owner).await;
    let member = join(&server, &owner, &org, &mio, json!([{ "id": collection }])).await;
    let path = format!("/api/organizations/{org}/users/{member}");
    assert_eq!(server.call("DELETE", &path, Some(&owner.token), Value::Null).await.status(), StatusCode::OK);
    assert!(sync(&server, &mio.token).await["profile"]["organizations"].as_array().unwrap().is_empty());
    let notices = json(server.get_as(&mio.token, "/uwu/v1/security/notices").await).await;
    assert_eq!(notices["data"][0]["kind"], "organizationRemoved");
    assert_eq!(server.get_as(&mio.token, &format!("/api/organizations/{org}")).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_admin_portal_lists_and_deletes_families() {
    let server = TestServer::new().await;
    let token = server.invite("boss@example.com", true).await;
    server.call("POST", "/identity/accounts/register/finish", None, register_body("boss@example.com", &token)).await;
    let admin = server.login("boss@example.com", "device-1").await;
    let owner = server.account("nyu@example.com").await;
    let (org, _) = family(&server, &owner).await;

    assert_eq!(server.get_as(&owner.token, "/uwu/v1/admin/organizations").await.status(), StatusCode::FORBIDDEN);
    let list = json(server.get_as(&admin.token, "/uwu/v1/admin/organizations").await).await;
    assert_eq!(list[0]["kind"], "family");
    assert_eq!(list[0]["owners"], json!(["nyu@example.com"]));
    assert_eq!(list[0]["members"], 1);
    let body = json!({ "masterPasswordHash": password_hash("boss@example.com") });
    let path = format!("/uwu/v1/admin/organizations/{org}");
    assert_eq!(server.call("DELETE", &path, Some(&admin.token), body).await.status(), StatusCode::OK);
    assert!(sync(&server, &owner.token).await["profile"]["organizations"].as_array().unwrap().is_empty());
    let notices = json(server.get_as(&owner.token, "/uwu/v1/security/notices").await).await;
    assert_eq!(notices["data"][0]["kind"], "organizationRemoved");
}

#[tokio::test]
async fn an_owner_by_invitation_counts_too() {
    let server = TestServer::new().await;
    let owner = server.account("nyu@example.com").await;
    let mio = server.account("mio@example.com").await;
    let (org, _) = family(&server, &owner).await;
    family(&server, &mio).await;
    let body = json!({ "emails": ["mio@example.com"], "type": 0 });
    server.call("POST", &format!("/api/organizations/{org}/users/invite"), Some(&owner.token), body).await;
    let pending = json(server.get_as(&mio.token, "/uwu/v1/organizations/invitations").await).await;
    let id = pending["data"][0]["id"].as_str().unwrap().to_string();
    let path = format!("/api/organizations/{org}/users/{id}/accept");
    assert_eq!(server.call("POST", &path, Some(&mio.token), json!({})).await.status(), StatusCode::OK);
    let path = format!("/api/organizations/{org}/users/{id}/confirm");
    let response = server.call("POST", &path, Some(&owner.token), json!({ "key": type4() })).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "mio owns one family already");

    let mut body = new_family("Zeile\nBcc: x@example.com");
    body["name"] = "Zeile\nBcc: x@example.com".into();
    let rin = server.account("rin@example.com").await;
    assert_eq!(
        server.call("POST", "/api/organizations", Some(&rin.token), body).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn a_family_s_files_count_against_its_owner_and_go_with_its_only_member() {
    let server = TestServer::with_settings(Settings { storage_per_user_mb: Some(1), ..Settings::default() }).await;
    let owner = server.account("nyu@example.com").await;
    let (org, collection) = family(&server, &owner).await;
    let item = json!({ "type": 2, "name": type2(), "notes": null, "secureNote": { "type": 0 }, "folderId": null, "organizationId": null });
    let personal = json(server.call("POST", "/api/ciphers", Some(&owner.token), item.clone()).await).await;
    let personal = personal["id"].as_str().unwrap().to_string();
    let shared = json(server.call("POST", "/api/ciphers", Some(&owner.token), item.clone()).await).await;
    let shared_id = shared["id"].as_str().unwrap().to_string();
    let mut moved = item;
    moved["organizationId"] = org.clone().into();
    let body = json!({ "cipher": moved, "collectionIds": [collection] });
    let response = server.call("PUT", &format!("/api/ciphers/{shared_id}/share"), Some(&owner.token), body).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);

    let announce = |size: i64| json!({ "key": type2(), "fileName": type2(), "fileSize": size });
    // More than the owner's storage, on the family's item: refused like on an own one.
    let path = format!("/api/ciphers/{shared_id}/attachment/v2");
    let refused = server.call("POST", &path, Some(&owner.token), announce(1_500_000)).await;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json(refused).await["code"], "quota");
    // What the family holds counts against its owner's own storage.
    let response = server.call("POST", &path, Some(&owner.token), announce(700_000)).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", text(response).await);
    assert_eq!(server.state.store.storage_used(&owner.id).await.unwrap(), 700_000);
    let own = format!("/api/ciphers/{personal}/attachment/v2");
    let refused = server.call("POST", &own, Some(&owner.token), announce(700_000)).await;
    assert_eq!(json(refused).await["code"], "quota");

    // The family's only member goes: so does the family, with its items and their files.
    let secret = json!({"masterPasswordHash": password_hash("nyu@example.com")});
    assert_eq!(server.call("DELETE", "/api/accounts", Some(&owner.token), secret).await.status(), StatusCode::OK);
    assert!(server.state.store.organization(&org).await.unwrap().is_none());
    assert!(server.state.store.attachments(&shared_id).await.unwrap().is_empty());
}
