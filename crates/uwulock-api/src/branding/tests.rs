//! Branding: what the admin sets, what pages, the API and mails get.

use super::*;
use crate::test_support::*;
use axum::body::Body;
use axum::http::Request;

async fn admin(server: &TestServer) -> Account {
    let token = server.invite("admin@example.com", true).await;
    let response = server
        .call("POST", "/identity/accounts/register/finish", None, register_body("admin@example.com", &token))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    server.login("admin@example.com", "admin-device").await
}

fn png_of(width: u32, height: u32) -> Vec<u8> {
    let mut png = Vec::new();
    image::RgbaImage::from_pixel(width, height, image::Rgba([3, 105, 161, 255]))
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    png
}

async fn put_bytes(server: &TestServer, token: &str, path: &str, bytes: Vec<u8>) -> Response {
    server
        .send(
            Request::put(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/octet-stream")
                .body(Body::from(bytes))
                .unwrap(),
        )
        .await
        .into_response()
}

async fn bytes(response: Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap().to_vec()
}

#[tokio::test]
async fn without_branding_uwulock_stays_itself() {
    let server = TestServer::new().await;
    let branding = json(server.get("/uwu/v1/branding").await).await;
    assert_eq!(branding["object"], "branding");
    assert_eq!(branding["name"], DEFAULT_NAME);
    assert_eq!(branding["color"], DEFAULT_COLOR);
    assert_eq!(branding["custom"], false);
    assert!(branding["logoLight"].is_null() && branding["logoDark"].is_null() && branding["favicon"].is_null());
    let info = json(server.get("/uwu/v1/info").await).await;
    assert_eq!(info["branding"]["name"], DEFAULT_NAME);
    assert_eq!(server.get("/uwu/v1/branding/logo/light").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(server.get("/uwu/v1/branding/favicon").await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn only_admins_change_it() {
    let server = TestServer::new().await;
    let user = server.account("nyu@example.com").await;
    let body = json!({ "name": "Post & Co", "color": null });
    assert_eq!(
        server.call("PUT", "/uwu/v1/admin/branding", Some(&user.token), body.clone()).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(server.call("PUT", "/uwu/v1/admin/branding", None, body).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        put_bytes(&server, &user.token, "/uwu/v1/admin/branding/favicon", png_of(8, 8)).await.status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn name_and_colour_are_checked_and_reach_the_mails() {
    let server = TestServer::new().await;
    let admin = admin(&server).await;
    let set = |name: Value, color: Value| {
        let (server, token) = (&server, admin.token.clone());
        async move {
            server.call("PUT", "/uwu/v1/admin/branding", Some(&token), json!({ "name": name, "color": color })).await
        }
    };
    // Yellow is lost on white, near-black on the dark theme.
    for color in ["#ffee00", "#1c1420", "blue", "#12345"] {
        let response = set(json!("Post & Co"), json!(color)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{color}");
    }
    assert_eq!(set(json!("x".repeat(41)), Value::Null).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(set(json!("Post\u{7}Co"), Value::Null).await.status(), StatusCode::BAD_REQUEST);

    let saved = json(set(json!("  Post & Co "), json!("#0369A1")).await).await;
    assert_eq!(saved["name"], "Post & Co");
    assert_eq!(saved["color"], "#0369a1");
    assert_eq!(saved["custom"], true);
    assert_eq!(saved["contrast"]["ok"], true);
    let public = json(server.get("/uwu/v1/branding").await).await;
    assert_eq!(public["name"], "Post & Co");

    // The preview says why a colour would be refused.
    let preview = json(server.get_as(&admin.token, "/uwu/v1/admin/branding/preview?color=%23ffee00").await).await;
    assert_eq!(preview["contrast"]["ok"], false);
    assert!(preview["light"]["--uwu-pink-solid"].is_string());

    // The mails carry the name.
    server.state.mailer.send("nyu@example.com", &uwulock_mail::Mail::Test, uwulock_mail::Language::En).await.unwrap();
    let mail = server.wait_for_mail(|mail| mail.to == "nyu@example.com").await;
    assert_eq!(mail.subject, "Test mail from Post & Co");

    // Empty again: UwULock's own.
    let back = json(set(json!(""), Value::Null).await).await;
    assert_eq!(back["name"], DEFAULT_NAME);
    assert_eq!(back["custom"], false);
}

#[tokio::test]
async fn pictures_are_drawn_again_as_png() {
    let server = TestServer::new().await;
    let admin = admin(&server).await;
    let wide = put_bytes(&server, &admin.token, "/uwu/v1/admin/branding/logo/light", png_of(1024, 256)).await;
    assert_eq!(wide.status(), StatusCode::OK);
    let saved = json(wide).await;
    let url = saved["logoLight"].as_str().unwrap();
    assert!(url.starts_with("https://vault.example.com/uwu/v1/branding/logo/light?v="), "{url}");

    let logo = server.get("/uwu/v1/branding/logo/light").await;
    assert_eq!(logo.headers()["content-type"], "image/png");
    assert_eq!(logo.headers()["x-content-type-options"], "nosniff");
    let png = image::load_from_memory(&bytes(logo.into_response()).await).unwrap();
    assert_eq!((png.width(), png.height()), (512, 128), "made smaller, in proportion");

    // An SVG is drawn; what it tried to run or load is gone.
    let svg = br##"<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><script>alert(1)</script>
        <image href="https://tracker.example.com/x.png" width="64" height="64"/><rect width="64" height="64" fill="#0369a1"/></svg>"##;
    let response = put_bytes(&server, &admin.token, "/uwu/v1/admin/branding/logo/dark", svg.to_vec()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let dark = bytes(server.get("/uwu/v1/branding/logo/dark").await.into_response()).await;
    assert!(dark.starts_with(b"\x89PNG"));
    assert!(!String::from_utf8_lossy(&dark).contains("script"));

    for (path, body) in [
        ("/uwu/v1/admin/branding/favicon", b"<html><script>alert(1)</script></html>".to_vec()),
        ("/uwu/v1/admin/branding/favicon", Vec::new()),
        ("/uwu/v1/admin/branding/favicon", vec![0u8; FAVICON_BYTES + 1]),
        ("/uwu/v1/admin/branding/logo/sideways", png_of(8, 8)),
    ] {
        let status = put_bytes(&server, &admin.token, path, body).await.status();
        assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND, "{path}: {status}");
    }

    let response = server.call("DELETE", "/uwu/v1/admin/branding/logo/light", Some(&admin.token), Value::Null).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(json(response).await["logoLight"].is_null());
    assert_eq!(server.get("/uwu/v1/branding/logo/light").await.status(), StatusCode::NOT_FOUND);
}

#[test]
fn the_page_carries_name_favicon_and_colours() {
    let page = "<!doctype html><html><head><meta charset=\"UTF-8\" />\
        <link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\" /><title>UwULock</title></head><body></body></html>";
    let plain = Loaded::new(Branding::default());
    assert!(brand_page(page, &plain).is_none(), "nothing to change");

    let branded = Loaded::new(Branding {
        name: Some("<Post & Co>".into()),
        color: Some("#0369a1".into()),
        favicon: Some(vec![1]),
        revision: "2026-09-29T08:00:00Z".into(),
        ..Branding::default()
    });
    let out = brand_page(page, &branded).unwrap();
    assert!(out.contains("<title>&lt;Post &amp; Co&gt;</title>"), "{out}");
    assert!(out.contains(&format!("href=\"/uwu/v1/branding/favicon?v={}\"", branded.version)));
    assert!(!out.contains("favicon.svg"));
    assert!(out.contains("<style id=\"uwu-branding\">html:root {"));
    assert!(out.contains("<meta name=\"theme-color\" content=\"#0369a1\" />"));
    assert!(out.find("uwu-branding").unwrap() < out.find("</head>").unwrap());
}

#[tokio::test]
async fn hosts_are_read_without_their_port() {
    let server = TestServer::new().await;
    let host = |value: &str, forwarded: Option<&str>| {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, value.parse().unwrap());
        if let Some(forwarded) = forwarded {
            headers.insert("x-forwarded-host", forwarded.parse().unwrap());
        }
        request_host(&server.state, &headers)
    };
    assert_eq!(host("Lock.Example.com", None).as_deref(), Some("lock.example.com"));
    assert_eq!(host("send.example.com:8443", None).as_deref(), Some("send.example.com"));
    assert_eq!(host("[2001:db8::1]:443", None).as_deref(), Some("2001:db8::1"));
    // Not behind a proxy it trusts: what a client claims does not count.
    assert_eq!(host("lock.example.com", Some("send.example.com")).as_deref(), Some("lock.example.com"));
}
