use crate::test_support::*;
use axum::http::StatusCode;
use serde_json::{Value, json};

async fn created(server: &TestServer, token: &str, folder: Option<&str>) -> String {
    let item = json!({"type": 2, "name": "2.n|n|n", "secureNote": {"type": 0}, "folderId": folder});
    json(server.call("POST", "/api/ciphers", Some(token), item).await).await["id"].as_str().unwrap().to_string()
}

async fn synced_ids(server: &TestServer, token: &str) -> (Vec<Value>, Vec<Value>) {
    let sync = json(server.get_as(token, "/api/sync").await).await;
    let ids = |key: &str| sync[key].as_array().unwrap().iter().map(|entry| entry["id"].clone()).collect();
    (ids("ciphers"), ids("folders"))
}

fn six_digits(text: &str) -> String {
    let bytes = text.as_bytes();
    (0..bytes.len().saturating_sub(5))
        .find(|&at| {
            bytes[at..at + 6].iter().all(u8::is_ascii_digit) && !bytes.get(at + 6).is_some_and(u8::is_ascii_digit)
        })
        .map(|at| text[at..at + 6].to_string())
        .expect("a code in the mail")
}

#[tokio::test]
async fn hidden_folders_leave_every_view_until_the_second_step_brings_them_back() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let other = server.account("other@example.com").await;
    let folder = json(server.call("POST", "/api/folders", Some(&nyu.token), json!({"name": "2.f|f|f"})).await).await;
    let folder = folder["id"].as_str().unwrap().to_string();
    let theirs = json(server.call("POST", "/api/folders", Some(&other.token), json!({"name": "2.o|o|o"})).await).await;
    let hidden = created(&server, &nyu.token, Some(&folder)).await;
    let shown = created(&server, &nyu.token, None).await;

    let marks = |ids: Value| json!({ "folderIds": ids });
    let response = server.call("PUT", "/uwu/v1/travel/folders", Some(&nyu.token), marks(json!([theirs["id"]]))).await;
    assert_eq!((response.status(), json(response).await["code"].clone()), (StatusCode::BAD_REQUEST, json!("invalid")));
    let response = server.call("POST", "/uwu/v1/travel/enable", Some(&nyu.token), json!({})).await;
    assert_eq!(json(response).await["code"], "no_folders");
    let marked =
        json(server.call("PUT", "/uwu/v1/travel/folders", Some(&nyu.token), marks(json!([folder]))).await).await;
    assert_eq!((marked["enabled"].as_bool(), marked["folderIds"].clone()), (Some(false), json!([folder])));
    let response = server.call("POST", "/uwu/v1/travel/enable", Some(&nyu.token), json!({})).await;
    assert_eq!(json(response).await["code"], "two_factor_required");

    server.state.store.set_two_factor(&nyu.id, 0, "JBSWY3DPEHPK3PXP".into(), "RECOVER".into()).await.unwrap();
    let email = json!({"email": "nyu@example.com"}).to_string();
    server.state.store.set_two_factor(&nyu.id, 1, email, "RECOVER".into()).await.unwrap();
    // Something to hide besides the item: a version, an own icon, a reminder.
    let path = format!("/api/ciphers/{hidden}");
    let mut change = json!({"type": 2, "name": "2.m|m|m", "secureNote": {"type": 0}, "folderId": folder});
    change["lastKnownRevisionDate"] = json!(null);
    assert_eq!(server.call("PUT", &path, Some(&nyu.token), change).await.status(), StatusCode::OK);
    let icon = json!({"data": type2(), "keyType": "extras"});
    server.call("PUT", &format!("/uwu/v1/icons/own/{hidden}"), Some(&nyu.token), icon).await;
    server.call("PUT", &format!("/uwu/v1/reminders/{hidden}"), Some(&nyu.token), json!({"due": "2020-01-01"})).await;

    let on = json(server.call("POST", "/uwu/v1/travel/enable", Some(&nyu.token), json!({})).await).await;
    assert_eq!((on["enabled"].as_bool(), on["hiddenCount"].as_i64()), (Some(true), Some(1)));
    assert!(json(server.get_as(&nyu.token, "/uwu/v1/account").await).await["travel"]["enabled"] == true);
    let (ciphers, folders) = synced_ids(&server, &nyu.token).await;
    assert_eq!(ciphers, [json!(shown)]);
    assert!(folders.is_empty(), "the folder is gone too");
    assert_eq!(server.get_as(&nyu.token, &path).await.status(), StatusCode::BAD_REQUEST, "as if there were none");
    let list = json(server.get_as(&nyu.token, "/api/ciphers").await).await;
    assert_eq!(list["data"].as_array().unwrap().len(), 1);
    let change = json!({"type": 2, "name": "2.x|x|x", "secureNote": {"type": 0}});
    assert_eq!(server.call("PUT", &path, Some(&nyu.token), change).await.status(), StatusCode::BAD_REQUEST);
    for uwu in [format!("/uwu/v1/ciphers/{hidden}/versions"), format!("/uwu/v1/icons/own/{hidden}")] {
        assert_eq!(server.get_as(&nyu.token, &uwu).await.status(), StatusCode::NOT_FOUND, "{uwu}");
    }
    assert!(json(server.get_as(&nyu.token, "/uwu/v1/reminders").await).await["data"].as_array().unwrap().is_empty());
    assert!(json(server.get_as(&nyu.token, "/uwu/v1/icons/own").await).await["data"].as_array().unwrap().is_empty());
    let purge = json!({"masterPasswordHash": password_hash("nyu@example.com")});
    let response = server.call("POST", "/api/ciphers/purge", Some(&nyu.token), purge).await;
    assert_eq!(json(response).await["code"], "travel_active");
    let response = server.call("PUT", "/uwu/v1/travel/folders", Some(&nyu.token), marks(json!([]))).await;
    assert_eq!(json(response).await["code"], "travel_active", "nothing comes back while travelling");

    // Off: the password, then a code.
    let right = password_hash("nyu@example.com");
    let wrong = json!({"masterPasswordHash": "wrong", "twoFactorProvider": 0, "twoFactorToken": "123456"});
    let response = server.call("POST", "/uwu/v1/travel/disable", Some(&nyu.token), wrong).await;
    assert_eq!((response.status(), json(response).await["code"].clone()), (StatusCode::BAD_REQUEST, json!("invalid")));
    let bad_code = json!({"masterPasswordHash": right, "twoFactorProvider": 0, "twoFactorToken": "000000x"});
    assert_eq!(
        server.call("POST", "/uwu/v1/travel/disable", Some(&nyu.token), bad_code).await.status(),
        StatusCode::BAD_REQUEST
    );
    let recovery = json!({"masterPasswordHash": right, "twoFactorProvider": 8, "twoFactorToken": "RECOVER"});
    let response = server.call("POST", "/uwu/v1/travel/disable", Some(&nyu.token), recovery).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "not with the recovery code");
    let notices = json(server.get_as(&nyu.token, "/uwu/v1/security/notices").await).await;
    let kinds: Vec<&str> =
        notices["data"].as_array().unwrap().iter().filter_map(|notice| notice["kind"].as_str()).collect();
    assert!(kinds.contains(&"travelModeEnabled") && kinds.contains(&"travelDisableFailed"), "{kinds:?}");

    let ask = json!({"masterPasswordHash": right});
    assert_eq!(
        server.call("POST", "/uwu/v1/travel/disable/send-email", Some(&nyu.token), ask).await.status(),
        StatusCode::OK
    );
    let mail = server.wait_for_mail(|mail| mail.subject.starts_with("Dein Anmeldecode")).await;
    let code = six_digits(&mail.subject);
    let by_mail = json!({"masterPasswordHash": right, "twoFactorProvider": 1, "twoFactorToken": code});
    let off = json(server.call("POST", "/uwu/v1/travel/disable", Some(&nyu.token), by_mail).await).await;
    assert_eq!((off["enabled"].as_bool(), off["hiddenCount"].as_i64()), (Some(false), Some(0)));
    let (ciphers, folders) = synced_ids(&server, &nyu.token).await;
    assert_eq!((ciphers.len(), folders.len()), (2, 1));
    assert_eq!(json(server.get_as(&nyu.token, "/uwu/v1/reminders").await).await["data"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn the_authenticator_switches_it_off_and_wrong_tries_run_out() {
    let limits = crate::Limits {
        travel: crate::limits::Limiter::new(2, std::time::Duration::from_secs(3600)),
        ..crate::Limits::generous()
    };
    let server = TestServer::new().await.with_limits(limits);
    let nyu = server.account("nyu@example.com").await;
    let folder = json(server.call("POST", "/api/folders", Some(&nyu.token), json!({"name": "2.f|f|f"})).await).await;
    server.call("PUT", "/uwu/v1/travel/folders", Some(&nyu.token), json!({"folderIds": [folder["id"]]})).await;
    server.state.store.set_two_factor(&nyu.id, 0, "JBSWY3DPEHPK3PXP".into(), "RECOVER".into()).await.unwrap();
    assert_eq!(
        server.call("POST", "/uwu/v1/travel/enable", Some(&nyu.token), json!({})).await.status(),
        StatusCode::OK
    );

    let right = password_hash("nyu@example.com");
    let secret = crate::totp::base32_decode("JBSWY3DPEHPK3PXP").unwrap();
    let code = crate::totp::code(&secret, crate::auth::now_seconds() / 30);
    let good = json!({"masterPasswordHash": right, "twoFactorProvider": 0, "twoFactorToken": code});
    assert_eq!(server.call("POST", "/uwu/v1/travel/disable", Some(&nyu.token), good).await.status(), StatusCode::OK);

    assert_eq!(
        server.call("POST", "/uwu/v1/travel/enable", Some(&nyu.token), json!({})).await.status(),
        StatusCode::OK
    );
    let wrong = json!({"masterPasswordHash": "wrong", "twoFactorProvider": 0, "twoFactorToken": "123456"});
    for _ in 0..2 {
        let response = server.call("POST", "/uwu/v1/travel/disable", Some(&nyu.token), wrong.clone()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let response = server.call("POST", "/uwu/v1/travel/disable", Some(&nyu.token), wrong).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json(response).await["code"], "rate_limited");
}
