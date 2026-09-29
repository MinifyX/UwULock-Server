//! SCIM as UwUAuth speaks it: people and groups pushed, looked up by filter, changed, removed.

use super::*;
use crate::test_support::*;
use axum::body::Body;
use axum::http::Request;

const TOKEN: &str = "a-scim-token-for-the-tests";

async fn server() -> TestServer {
    let server = TestServer::new().await;
    let mut settings = server.state.settings();
    settings.scim.token_hash = Some(crate::metrics::hex(&auth::sha256(TOKEN.as_bytes())));
    server.state.apply_settings(settings);
    server
}

async fn call(server: &TestServer, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    call_with(server, TOKEN, method, path, body).await
}

async fn call_with(
    server: &TestServer,
    token: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/scim+json")
        .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
        .unwrap();
    let response = server.send(request).await;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn replace(path: &str, value: Value) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{ "op": "replace", "path": path, "value": value }],
    })
}

fn user(email: &str) -> Value {
    json!({
        "schemas": [USER_SCHEMA],
        "userName": email,
        "externalId": format!("ext-{email}"),
        "displayName": "Mia",
        "name": { "formatted": "Mia", "givenName": "Mia" },
        "emails": [{ "value": email, "type": "work", "primary": true }],
        "preferredLanguage": "de",
        "active": true,
        "somethingUnknown": { "is": "ignored" },
    })
}

fn filter(attribute: &str, value: &str) -> String {
    crate::oidc::form_encode(&format!("{attribute} eq {}", Value::String(value.into())))
}

#[tokio::test]
async fn only_with_the_token_and_not_for_ever_without() {
    let server = server().await;
    let (status, body) = call_with(&server, "wrong", "GET", "/scim/v2/Users", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["schemas"], json!([ERROR_SCHEMA]));
    assert_eq!(call(&server, "GET", "/scim/v2/ServiceProviderConfig", None).await.0, StatusCode::OK);

    let server = TestServer::new().await.with_limits(crate::Limits::default());
    let mut settings = server.state.settings();
    settings.scim.token_hash = Some(crate::metrics::hex(&auth::sha256(TOKEN.as_bytes())));
    server.state.apply_settings(settings);
    for _ in 0..30 {
        assert_eq!(call_with(&server, "wrong", "GET", "/scim/v2/Users", None).await.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(call_with(&server, "wrong", "GET", "/scim/v2/Users", None).await.0, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(call(&server, "GET", "/scim/v2/Users", None).await.0, StatusCode::TOO_MANY_REQUESTS, "for a while");

    // No token set: nothing gets in.
    let server = TestServer::new().await;
    assert_eq!(call(&server, "GET", "/scim/v2/Users", None).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_new_person_may_sign_up_and_is_found_again() {
    let server = server().await;
    let (status, created) = call(&server, "POST", "/scim/v2/Users", Some(user("Mia@Example.com"))).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!((created["userName"].clone(), created["active"].clone()), (json!("mia@example.com"), json!(true)));
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(call(&server, "POST", "/scim/v2/Users", Some(user("mia@example.com"))).await.0, StatusCode::CONFLICT);
    let entry = server.state.store.scim_provisioned("mia@example.com").await.unwrap().unwrap();
    assert_eq!((entry.id.as_str(), entry.external_id.as_deref()), (id.as_str(), Some("ext-Mia@Example.com")));

    let (_, found) =
        call(&server, "GET", &format!("/scim/v2/Users?filter={}", filter("userName", "mia@example.com")), None).await;
    assert_eq!((found["totalResults"].clone(), found["Resources"][0]["id"].clone()), (json!(1), json!(id)));
    let (_, found) =
        call(&server, "GET", &format!("/scim/v2/Users?filter={}", filter("externalId", "ext-Mia@Example.com")), None)
            .await;
    assert_eq!(found["Resources"][0]["id"], id);
    let (_, none) =
        call(&server, "GET", &format!("/scim/v2/Users?filter={}", filter("userName", "x@example.com")), None).await;
    assert_eq!(none["totalResults"], 0);
    assert_eq!(
        call(&server, "GET", "/scim/v2/Users?filter=userName%20sw%20%22m%22", None).await.0,
        StatusCode::BAD_REQUEST
    );

    // Switched off: no sign-up; deleted: gone.
    let (status, _) =
        call(&server, "PATCH", &format!("/scim/v2/Users/{id}"), Some(replace("active", json!(false)))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!server.state.store.scim_user(&id).await.unwrap().unwrap().active);
    assert_eq!(call(&server, "DELETE", &format!("/scim/v2/Users/{id}"), None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(call(&server, "GET", &format!("/scim/v2/Users/{id}"), None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        call(&server, "PATCH", &format!("/scim/v2/Users/{id}"), Some(replace("active", json!(true)))).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn an_account_is_found_by_address_disabled_and_enabled() {
    let server = server().await;
    let account = server.account("mia@example.com").await;
    let (status, conflict) = call(&server, "POST", "/scim/v2/Users", Some(user("mia@example.com"))).await;
    assert_eq!((status, conflict["scimType"].clone()), (StatusCode::CONFLICT, json!("uniqueness")));
    let (_, found) =
        call(&server, "GET", &format!("/scim/v2/Users?filter={}", filter("userName", "mia@example.com")), None).await;
    let id = found["Resources"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(id, account.id);

    // As UwUAuth brings it up to date after a 409: one replace per field.
    let patch = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            { "op": "replace", "path": "active", "value": true },
            { "op": "replace", "path": "displayName", "value": "Mia Neko" },
            { "op": "replace", "path": "externalId", "value": "person-1" },
        ],
    });
    let (status, patched) = call(&server, "PATCH", &format!("/scim/v2/Users/{id}"), Some(patch)).await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    assert_eq!((patched["displayName"].clone(), patched["externalId"].clone()), (json!("Mia Neko"), json!("person-1")));
    assert_eq!(patched["id"], account.id, "the id it knows stays");
    let (_, found) =
        call(&server, "GET", &format!("/scim/v2/Users?filter={}", filter("externalId", "person-1")), None).await;
    assert_eq!(found["Resources"][0]["id"], account.id);

    // Disabled: sessions end, no login; enabled again: logs in.
    let (status, _) =
        call(&server, "PATCH", &format!("/scim/v2/Users/{id}"), Some(replace("active", json!("False")))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(server.get_as(&account.token, "/api/sync").await.status(), StatusCode::UNAUTHORIZED);
    let refused = server.form("/identity/connect/token", &login_form("mia@example.com", "d2")).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    call(&server, "PATCH", &format!("/scim/v2/Users/{id}"), Some(replace("active", json!(true)))).await;
    server.login("mia@example.com", "d2").await;

    // The address is the KDF salt: it does not change here.
    let (status, body) =
        call(&server, "PATCH", &format!("/scim/v2/Users/{id}"), Some(replace("userName", json!("new@example.com"))))
            .await;
    assert_eq!((status, body["scimType"].clone()), (StatusCode::BAD_REQUEST, json!("mutability")));
    let (status, _) =
        call(&server, "PATCH", &format!("/scim/v2/Users/{id}"), Some(replace("userName", json!("MIA@example.com"))))
            .await;
    assert_eq!(status, StatusCode::OK, "the same address is no change");
    let mut whole = user("new@example.com");
    let (status, _) = call(&server, "PUT", &format!("/scim/v2/Users/{id}"), Some(whole.clone())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    whole["userName"] = "mia@example.com".into();
    whole["emails"] = json!([{ "value": "mia@example.com", "primary": true }]);
    whole["active"] = false.into();
    assert_eq!(call(&server, "PUT", &format!("/scim/v2/Users/{id}"), Some(whole)).await.0, StatusCode::OK);
    assert!(server.state.store.user(&account.id).await.unwrap().unwrap().disabled);
}

#[tokio::test]
async fn deleting_disables_or_deletes_as_the_admin_chose() {
    let server = server().await;
    let mia = server.account("mia@example.com").await;
    assert_eq!(call(&server, "DELETE", &format!("/scim/v2/Users/{}", mia.id), None).await.0, StatusCode::NO_CONTENT);
    assert!(server.state.store.user(&mia.id).await.unwrap().unwrap().disabled, "disabled by default");

    let mut settings = server.state.settings();
    settings.scim.on_delete = OnDelete::Delete;
    server.state.apply_settings(settings);
    let ben = server.account("ben@example.com").await;
    assert_eq!(call(&server, "DELETE", &format!("/scim/v2/Users/{}", ben.id), None).await.0, StatusCode::NO_CONTENT);
    assert!(server.state.store.user(&ben.id).await.unwrap().is_none());

    // The last admin is neither.
    let admin = server.account("admin@example.com").await;
    server.state.store.update_user(&admin.id, |user| user.admin = true).await.unwrap();
    let (status, _) = call(&server, "DELETE", &format!("/scim/v2/Users/{}", admin.id), None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) =
        call(&server, "PATCH", &format!("/scim/v2/Users/{}", admin.id), Some(replace("active", json!(false)))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(server.state.store.user(&admin.id).await.unwrap().is_some());
}

#[tokio::test]
async fn leaving_the_admin_group_takes_the_admin_right() {
    let server = server().await;
    let mut settings = server.state.settings();
    settings.sso.admin_group = Some("vault-admins".into());
    server.state.apply_settings(settings);
    let mia = server.account("mia@example.com").await;
    let ben = server.account("ben@example.com").await;
    for id in [&mia.id, &ben.id] {
        server.state.store.update_user(id, |user| user.admin = true).await.unwrap();
    }
    let group = json!({
        "schemas": [GROUP_SCHEMA], "displayName": "vault-admins", "externalId": "g-1",
        "members": [{ "value": mia.id }, { "value": ben.id }],
    });
    let (status, created) = call(&server, "POST", "/scim/v2/Groups", Some(group.clone())).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(call(&server, "POST", "/scim/v2/Groups", Some(group)).await.0, StatusCode::CONFLICT);
    let (_, found) =
        call(&server, "GET", &format!("/scim/v2/Groups?filter={}", filter("displayName", "Vault-Admins")), None).await;
    assert_eq!(found["Resources"][0]["id"], id);

    // UwUAuth replaces the whole list: Ben is out.
    let members = json!([{ "value": mia.id }]);
    let (status, patched) =
        call(&server, "PATCH", &format!("/scim/v2/Groups/{id}"), Some(replace("members", members))).await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    assert_eq!(patched["members"], json!([{ "value": mia.id }]));
    assert!(!server.state.store.user(&ben.id).await.unwrap().unwrap().admin);
    assert!(server.state.store.user(&mia.id).await.unwrap().unwrap().admin);

    // The group gone: Mia would be out too, but she is the last admin now.
    assert_eq!(call(&server, "DELETE", &format!("/scim/v2/Groups/{id}"), None).await.0, StatusCode::NO_CONTENT);
    assert!(server.state.store.user(&mia.id).await.unwrap().unwrap().admin);
    assert_eq!(call(&server, "GET", &format!("/scim/v2/Groups/{id}"), None).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn groups_take_the_other_ways_of_patching() {
    let server = server().await;
    let (_, created) = call(&server, "POST", "/scim/v2/Groups", Some(json!({ "displayName": "team" }))).await;
    let id = created["id"].as_str().unwrap().to_string();
    let patch = json!({ "Operations": [
        { "op": "add", "path": "members", "value": [{ "value": "a" }, { "value": "b" }, { "value": "c" }] },
        { "op": "remove", "path": "members[value eq \"b\"]" },
        { "op": "replace", "value": { "displayName": "team-2" } },
    ]});
    let (status, patched) = call(&server, "PATCH", &format!("/scim/v2/Groups/{id}"), Some(patch)).await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    assert_eq!(patched["displayName"], "team-2");
    assert_eq!(patched["members"], json!([{ "value": "a" }, { "value": "c" }]));
    let (_, all) = call(&server, "GET", "/scim/v2/Groups", None).await;
    assert_eq!(all["totalResults"], 1);
    let (_, types) = call(&server, "GET", "/scim/v2/ResourceTypes", None).await;
    assert_eq!(types["totalResults"], 2);
    let (_, schemas) = call(&server, "GET", "/scim/v2/Schemas", None).await;
    assert_eq!(schemas["Resources"][0]["id"], USER_SCHEMA);
}

#[test]
fn filters_are_read_like_the_providers_write_them() {
    assert_eq!(parse_filter(r#"userName eq "a@example.com""#).unwrap(), ("username".into(), "a@example.com".into()));
    assert_eq!(
        parse_filter(r#"displayName  EQ "with \"quotes\"""#).unwrap(),
        ("displayname".into(), r#"with "quotes""#.into())
    );
    assert!(parse_filter(r#"userName co "a""#).is_err());
    assert!(parse_filter("userName eq a").is_err());
}
