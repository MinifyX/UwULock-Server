use crate::test_support::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use uwulock_store::clock;

async fn admin(server: &TestServer) -> Account {
    let token = server.invite("admin@example.com", true).await;
    let response = server
        .call("POST", "/identity/accounts/register/finish", None, register_body("admin@example.com", &token))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    server.login("admin@example.com", "admin-device").await
}

async fn add(server: &TestServer, admin: &Account, host: &str, tls: &str) -> Value {
    let response = server
        .call("POST", "/uwu/v1/admin/send-domains", Some(&admin.token), json!({ "host": host, "tls": tls }))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    json(response).await
}

/// `method path` as a request to `host`.
async fn on(
    server: &TestServer,
    host: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> axum::response::Response {
    let mut request = Request::builder().method(method).uri(path).header("host", host);
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let body = body.map_or_else(Body::empty, |body| Body::from(body.to_string()));
    server.send(request.body(body).unwrap()).await
}

fn text_send() -> Value {
    json!({
        "type": 0,
        "key": "2.key|key|key",
        "name": "2.name|name|name",
        "text": {"text": "2.text|text|text", "hidden": false, "response": null},
        "deletionDate": clock::in_seconds(86_400),
        "disabled": false,
    })
}

#[tokio::test]
async fn admins_add_change_and_remove_send_domains() {
    let server = TestServer::new().await;
    let admin = admin(&server).await;
    let user = server.account("nyu@example.com").await;
    let refused = server
        .call(
            "POST",
            "/uwu/v1/admin/send-domains",
            Some(&user.token),
            json!({ "host": "send.example.com", "tls": "proxy" }),
        )
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    for bad in [
        "https://send.example.com",
        "send.example.com:8443",
        "192.0.2.5",
        "vault.example.com",
        "nodot",
        "a..example.com",
    ] {
        let response = server
            .call("POST", "/uwu/v1/admin/send-domains", Some(&admin.token), json!({ "host": bad, "tls": "proxy" }))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
    let proxy = add(&server, &admin, "Send.Example.com", "proxy").await;
    assert_eq!(proxy["object"], "sendDomain");
    assert_eq!(proxy["host"], "send.example.com");
    assert_eq!(proxy["certificate"]["status"], "proxy");
    assert!(proxy["branding"].is_null());
    let taken = server
        .call(
            "POST",
            "/uwu/v1/admin/send-domains",
            Some(&admin.token),
            json!({ "host": "send.example.com", "tls": "acme" }),
        )
        .await;
    assert_eq!((taken.status(), json(taken).await["code"].clone()), (StatusCode::CONFLICT, json!("exists")));

    // A server behind a proxy cannot get certificates itself, and says so.
    let acme = add(&server, &admin, "files.example.org", "acme").await;
    assert_eq!(acme["certificate"]["status"], "failed");
    assert!(acme["certificate"]["error"].as_str().unwrap().contains("proxy"));
    assert_eq!(*server.state.send_domains.acme_hosts().borrow(), ["files.example.org"]);
    server.state.send_domains.serving_tls();
    let list = json(server.get_as(&admin.token, "/uwu/v1/admin/send-domains").await).await;
    assert_eq!(list["data"].as_array().unwrap().len(), 2);
    assert_eq!(list["data"][0]["certificate"]["status"], "pending", "ordered by host: files. first");
    server.state.send_domains.set_certificate(
        "files.example.org",
        super::Certificate { status: "ok", expires: Some(1_790_000_000), error: None },
    );
    let list = json(server.get_as(&admin.token, "/uwu/v1/admin/send-domains").await).await;
    assert_eq!(list["data"][0]["certificate"]["status"], "ok");
    assert!(list["data"][0]["certificate"]["expires"].as_str().unwrap().starts_with("2026-09-21"));
    let metrics = crate::metrics::render(&server.state).await.unwrap();
    let id = acme["id"].as_str().unwrap();
    let line = format!("uwulock_certificate_expiry_timestamp_seconds{{domain=\"{id}\"}} 1790000000");
    assert!(metrics.contains(&line), "{metrics}");

    let id = acme["id"].as_str().unwrap();
    let changed = server
        .call("PUT", &format!("/uwu/v1/admin/send-domains/{id}"), Some(&admin.token), json!({ "tls": "proxy" }))
        .await;
    assert_eq!(json(changed).await["certificate"]["status"], "proxy");
    assert!(server.state.send_domains.acme_hosts().borrow().is_empty());

    let info = json(server.get("/uwu/v1/info").await).await;
    assert!(info["features"].as_array().unwrap().contains(&json!("send-domains")));
    assert_eq!(info["sendDomains"].as_array().unwrap().len(), 2);
    assert_eq!(info["sendDomains"][0]["url"], "https://files.example.org");

    let gone = server.call("DELETE", &format!("/uwu/v1/admin/send-domains/{id}"), Some(&admin.token), json!({})).await;
    assert_eq!(gone.status(), StatusCode::OK);
    let list = json(server.get_as(&admin.token, "/uwu/v1/admin/send-domains").await).await;
    assert_eq!(list["data"].as_array().unwrap().len(), 1);
    let events = json(server.get_as(&admin.token, "/uwu/v1/admin/events").await).await.to_string();
    assert!(events.contains("added the send domain send.example.com") && events.contains("removed the send domain"));
}

#[tokio::test]
async fn a_send_domain_answers_only_for_sends() {
    let server = TestServer::new().await;
    let admin = admin(&server).await;
    let account = server.account("nyu@example.com").await;
    add(&server, &admin, "send.example.com", "proxy").await;
    let host = "send.example.com";

    for (method, path) in [
        ("GET", "/"),
        ("GET", "/admin"),
        ("GET", "/api/sync"),
        ("GET", "/uwu/v1/account"),
        ("GET", "/notifications/hub"),
    ] {
        assert_eq!(on(&server, host, method, path, None).await.status(), StatusCode::NOT_FOUND, "{method} {path}");
    }
    // With the port, and in capitals, it is the same host.
    assert_eq!(on(&server, "SEND.example.com:443", "GET", "/", None).await.status(), StatusCode::NOT_FOUND);
    // SV-L23: and with the dot of a fully qualified name.
    for dotted in ["send.example.com.", "send.example.com.:443", "send.example.com.."] {
        assert_eq!(on(&server, dotted, "GET", "/api/sync", None).await.status(), StatusCode::NOT_FOUND, "{dotted}");
    }
    let h2 = Request::get("https://send.example.com./api/sync").body(Body::empty()).unwrap();
    assert_eq!(server.send(h2).await.status(), StatusCode::NOT_FOUND);
    // HTTP/2 brings the host as `:authority`, in the URI, without a `Host` header.
    let h2 = Request::get("https://send.example.com/api/sync").body(Body::empty()).unwrap();
    assert_eq!(server.send(h2).await.status(), StatusCode::NOT_FOUND);
    let h2 = Request::get("https://send.example.com/uwu/v1/info").body(Body::empty()).unwrap();
    assert!(json(server.send(h2).await).await.get("publicUrl").is_none(), "the reduced one");
    assert_eq!(
        on(&server, "vault.example.com", "GET", "/uwu/v1/account", None).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let info = json(on(&server, host, "GET", "/uwu/v1/info", None).await).await;
    assert!(info.get("publicUrl").is_none() && info.get("sso").is_none() && info.get("sendDomains").is_none());
    let features: Vec<&str> = info["features"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert_eq!(features, ["sends", "send-emails", "file-requests"]);

    let created = json(server.call("POST", "/api/sends", Some(&account.token), text_send()).await).await;
    let access_id = created["accessId"].as_str().unwrap().to_string();
    let page = on(&server, host, "GET", &format!("/{access_id}"), None).await;
    assert_eq!(page.status(), StatusCode::OK);
    assert!(page.headers()["content-type"].to_str().unwrap().starts_with("text/html"));
    assert_eq!(on(&server, host, "GET", "/no-such-page", None).await.status(), StatusCode::NOT_FOUND);
    let opened = on(&server, host, "POST", &format!("/api/sends/access/{access_id}"), Some(json!({}))).await;
    assert_eq!(opened.status(), StatusCode::OK);

    let login = Request::post("/identity/connect/token")
        .header("host", host)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("grant_type=password&username=nyu%40example.com&password=x&scope=api+offline_access"))
        .unwrap();
    let refused = server.send(login).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(text(refused).await.contains("Only Sends"));
}

#[tokio::test]
async fn a_send_domain_has_its_own_look_and_mails_its_codes_in_it() {
    let server = TestServer::new().await;
    let admin = admin(&server).await;
    let account = server.account("nyu@example.com").await;
    let domain = add(&server, &admin, "send.example.com", "proxy").await;
    let id = domain["id"].as_str().unwrap();
    let host = "send.example.com";

    // Without branding of its own, the server's.
    let set =
        server.call("PUT", "/uwu/v1/admin/branding", Some(&admin.token), json!({ "name": "Katzen-Tresor" })).await;
    assert_eq!(set.status(), StatusCode::OK);
    let look = json(on(&server, host, "GET", "/uwu/v1/branding", None).await).await;
    assert_eq!(look["name"], "Katzen-Tresor");

    let path = format!("/uwu/v1/admin/send-domains/{id}/branding");
    let set =
        server.call("PUT", &path, Some(&admin.token), json!({ "name": "Katzen-Sends", "color": "#d9480f" })).await;
    assert_eq!(set.status(), StatusCode::OK);
    let set = json(set).await;
    assert_eq!((set["name"].as_str(), set["nameSet"].as_bool()), (Some("Katzen-Sends"), Some(true)));
    let look = json(on(&server, host, "GET", "/uwu/v1/branding", None).await).await;
    assert_eq!((look["name"].as_str(), look["color"].as_str()), (Some("Katzen-Sends"), Some("#d9480f")));
    let main = json(server.get("/uwu/v1/branding").await).await;
    assert_eq!(main["name"], "Katzen-Tresor", "the main host keeps the server's");
    let info = json(on(&server, host, "GET", "/uwu/v1/info", None).await).await;
    assert_eq!(info["branding"]["name"], "Katzen-Sends");
    let listed = json(server.get_as(&admin.token, "/uwu/v1/admin/send-domains").await).await;
    assert_eq!(listed["data"][0]["branding"]["name"], "Katzen-Sends");

    // A Send's code, asked for on the send domain, comes in its look.
    let mut send = text_send();
    send["emails"] = json!("friend@example.com");
    let created = json(server.call("POST", "/api/sends", Some(&account.token), send).await).await;
    let access_id = created["accessId"].as_str().unwrap();
    let form = format!(
        "grant_type=send_access&client_id=send&scope=api.send.access&send_id={access_id}&email=friend%40example.com"
    );
    let ask = Request::post("/identity/connect/token")
        .header("host", host)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .unwrap();
    assert_eq!(server.send(ask).await.status(), StatusCode::BAD_REQUEST, "the code is mailed first");
    let mail = server.wait_for_mail(|mail| mail.to == "friend@example.com").await;
    assert!(mail.text.contains("Katzen-Sends"), "{}", mail.text);

    let reset = server.call("DELETE", &path, Some(&admin.token), json!({})).await;
    assert_eq!(json(reset).await["nameSet"], false);
    let look = json(on(&server, host, "GET", "/uwu/v1/branding", None).await).await;
    assert_eq!(look["name"], "Katzen-Tresor", "back to the server's");
}

#[tokio::test]
async fn sends_use_the_account_default_unless_they_choose() {
    let server = TestServer::new().await;
    let admin = admin(&server).await;
    let account = server.account("nyu@example.com").await;
    let other = server.account("other@example.com").await;
    let domain = add(&server, &admin, "send.example.com", "proxy").await;
    let id = domain["id"].as_str().unwrap();

    let unknown = server
        .call("PUT", "/uwu/v1/account/send-domain", Some(&account.token), json!({ "sendDomainId": "nope" }))
        .await;
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
    let set =
        server.call("PUT", "/uwu/v1/account/send-domain", Some(&account.token), json!({ "sendDomainId": id })).await;
    assert_eq!(set.status(), StatusCode::OK);
    let me = json(server.get_as(&account.token, "/uwu/v1/account").await).await;
    assert_eq!(me["sendDomainId"], id);

    // What an official client makes gets the default.
    let first = json(server.call("POST", "/api/sends", Some(&account.token), text_send()).await).await;
    let first_id = first["id"].as_str().unwrap();
    let choices = json(server.get_as(&account.token, "/uwu/v1/sends/domains").await).await;
    assert_eq!(choices[first_id], id);

    let chosen = server
        .call("PUT", &format!("/uwu/v1/sends/{first_id}/domain"), Some(&account.token), json!({ "sendDomainId": null }))
        .await;
    assert_eq!(json(chosen).await, json!({ "object": "sendDomainChoice", "sendId": first_id, "sendDomainId": null }));
    let theirs = server
        .call("PUT", &format!("/uwu/v1/sends/{first_id}/domain"), Some(&other.token), json!({ "sendDomainId": id }))
        .await;
    assert_eq!(theirs.status(), StatusCode::NOT_FOUND, "not yours is 404");
    // An update through Bitwarden's API keeps the choice.
    let updated = server.call("PUT", &format!("/api/sends/{first_id}"), Some(&account.token), text_send()).await;
    assert_eq!(updated.status(), StatusCode::OK);
    let choices = json(server.get_as(&account.token, "/uwu/v1/sends/domains").await).await;
    assert_eq!(choices[first_id], Value::Null);

    let gone = server.call("DELETE", &format!("/uwu/v1/admin/send-domains/{id}"), Some(&admin.token), json!({})).await;
    assert_eq!(gone.status(), StatusCode::OK);
    let me = json(server.get_as(&account.token, "/uwu/v1/account").await).await;
    assert_eq!(me["sendDomainId"], Value::Null, "back to the main host");
}

#[tokio::test]
async fn a_file_send_opened_on_a_send_domain_is_downloaded_from_there() {
    let server = TestServer::new().await;
    let admin = admin(&server).await;
    let account = server.account("nyu@example.com").await;
    add(&server, &admin, "send.example.com", "proxy").await;
    let mut send = text_send();
    send["type"] = json!(1);
    send["text"] = json!(null);
    send["file"] = json!({"fileName": "2.file|file|file"});
    send["fileLength"] = json!(4);
    let answer = json(server.call("POST", "/api/sends/file/v2", Some(&account.token), send).await).await;
    let url = answer["url"].as_str().unwrap().to_string();
    let (id, file) =
        (answer["sendResponse"]["id"].as_str().unwrap(), answer["sendResponse"]["file"]["id"].as_str().unwrap());
    let body = "--b\r\nContent-Disposition: form-data; name=\"data\"; filename=\"f\"\r\n\r\nabcd\r\n--b--\r\n";
    let upload = Request::post(format!("/api{url}"))
        .header("authorization", format!("Bearer {}", account.token))
        .header("content-type", "multipart/form-data; boundary=b")
        .body(Body::from(body))
        .unwrap();
    assert_eq!(server.send(upload).await.status(), StatusCode::OK);

    let link = json(
        on(&server, "send.example.com", "POST", &format!("/api/sends/{id}/access/file/{file}"), Some(json!({}))).await,
    )
    .await;
    let path =
        link["url"].as_str().unwrap().strip_prefix("https://send.example.com").expect("on the send domain").to_string();
    let response = on(&server, "send.example.com", "GET", &path, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let link = json(server.call("POST", &format!("/api/sends/{id}/access/file/{file}"), None, json!({})).await).await;
    assert!(link["url"].as_str().unwrap().starts_with("https://vault.example.com/"), "the main host keeps its own");
}

#[tokio::test]
async fn choices_come_with_the_delta_sync_and_changes_on_the_realtime_channel() {
    use uwulock_notify::realtime::Live;
    let server = TestServer::new().await;
    let admin = admin(&server).await;
    let account = server.account("nyu@example.com").await;
    let mut live = server.state.realtime.join(&account.id).unwrap();
    let domain = add(&server, &admin, "send.example.com", "proxy").await;
    let id = domain["id"].as_str().unwrap();
    assert_eq!(live.events.try_recv().unwrap().live, Live::Info, "/uwu/v1/info lists the domains");

    let send = json(server.call("POST", "/api/sends", Some(&account.token), text_send()).await).await;
    let send_id = send["id"].as_str().unwrap();
    let full = json(server.get_as(&account.token, "/uwu/v1/sync?include=uwu").await).await;
    assert_eq!(full["uwu"]["sendDomains"], json!({ send_id: null }));
    while live.events.try_recv().is_ok() {}

    let path = format!("/uwu/v1/sends/{send_id}/domain");
    server.call("PUT", &path, Some(&account.token), json!({ "sendDomainId": id })).await;
    assert_eq!(live.events.try_recv().unwrap().live, Live::changed("uwu"));
    let path = format!("/uwu/v1/sync?include=uwu&since={}", full["cursor"].as_str().unwrap());
    let delta = json(server.get_as(&account.token, &path).await).await;
    assert_eq!((delta["reset"].as_bool(), &delta["uwu"]["sendDomains"]), (Some(false), &json!({ send_id: id })));
    assert!(delta["vault"].is_null());

    // The domain goes: the Send falls back to the main host, which the next delta says.
    let gone = server.call("DELETE", &format!("/uwu/v1/admin/send-domains/{id}"), Some(&admin.token), json!({})).await;
    assert_eq!(gone.status(), StatusCode::OK);
    assert_eq!(live.events.try_recv().unwrap().live, Live::Info);
    let path = format!("/uwu/v1/sync?include=uwu&since={}", delta["cursor"].as_str().unwrap());
    let next = json(server.get_as(&account.token, &path).await).await;
    assert_eq!(next["uwu"]["sendDomains"], json!({ send_id: null }));
}
