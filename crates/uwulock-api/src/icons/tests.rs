//! Icons against fake websites on 127.0.0.1: the names they are reached by are answered without
//! DNS, and only in these tests is 127.0.0.1 let through the checks.

use crate::icon_fetch::Upstream;
use crate::test_support::*;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use serde_json::json;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn png_of(size: u32) -> Vec<u8> {
    let mut png = Vec::new();
    image::RgbaImage::from_pixel(size, size, image::Rgba([10, 200, 120, 255]))
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    png
}

/// The fake internet: pages and icons by `Host`, the selfh.st index and one library icon. Counts
/// the requests it got.
async fn fake_web() -> (u16, Arc<AtomicUsize>) {
    use axum::response::IntoResponse;
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = hits.clone();
    let app = axum::Router::new().fallback(move |headers: HeaderMap, uri: axum::http::Uri| {
        let counted = counted.clone();
        async move {
            counted.fetch_add(1, Ordering::SeqCst);
            let host = headers.get("host").and_then(|host| host.to_str().ok()).unwrap_or("").split(':').next().unwrap_or("").to_string();
            let path = uri.path().to_string();
            let png = |bytes: Vec<u8>| ([("content-type", "image/png")], bytes).into_response();
            match (host.as_str(), path.as_str()) {
                ("shop.example.com", "/") => (
                    [("content-type", "text/html")],
                    r#"<html><head><link rel="icon" sizes="16x16" href="/small.png"><link rel="apple-touch-icon" sizes="180x180" href="/touch.png"></head></html>"#,
                )
                    .into_response(),
                ("shop.example.com", "/small.png") => png(png_of(16)),
                // Says it is text; it is a PNG all the same.
                ("shop.example.com", "/touch.png") => ([("content-type", "text/plain")], png_of(180)).into_response(),
                ("plain.example.net", "/favicon.ico") => png(png_of(32)),
                ("away.example.org", "/") => {
                    (StatusCode::FOUND, [("location", "http://169.254.169.254/latest/meta-data")]).into_response()
                }
                ("library.example.com", "/index.json") => axum::Json(json!([
                    {"Name": "Nextcloud", "Reference": "nextcloud", "PNG": "Yes", "Light": "Yes", "Dark": "No"},
                    {"Name": "Broken", "Reference": "../../etc", "PNG": "Yes"},
                    {"Name": "No PNG", "Reference": "svg-only", "PNG": "No"},
                ]))
                .into_response(),
                ("library.example.com", "/png/nextcloud.png") => png(png_of(512)),
                ("library.example.com", "/2fa.json") => axum::Json(json!([
                    ["Shop", {"domain": "shop.example.com", "tfa": ["totp"], "documentation": "https://shop.example.com/2fa"}],
                    ["Plain", {"domain": "plain.example.net"}],
                ]))
                .into_response(),
                _ => StatusCode::NOT_FOUND.into_response(),
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (port, hits)
}

fn upstream(port: u16, allow: bool) -> Upstream {
    let local: IpAddr = "127.0.0.1".parse().unwrap();
    let mut fixed = HashMap::new();
    for name in ["shop.example.com", "plain.example.net", "away.example.org", "library.example.com"] {
        fixed.insert(name.to_string(), vec![local]);
    }
    // One public address and one of the local network: refused, whatever the first is.
    fixed.insert("rebind.example.com".into(), vec!["1.1.1.1".parse().unwrap(), "10.0.0.7".parse().unwrap()]);
    Upstream {
        fixed,
        allowed: if allow { vec![local] } else { Vec::new() },
        https_port: port,
        http_port: port,
        selfhst: format!("http://library.example.com:{port}"),
        twofa: format!("http://library.example.com:{port}/2fa.json"),
    }
}

async fn icon(server: &TestServer, host: &str) -> (StatusCode, String, Vec<u8>) {
    let response = server.send(Request::get(format!("/icons/{host}/icon.png")).body(Body::empty()).unwrap()).await;
    let status = response.status();
    let cache = response.headers().get("cache-control").and_then(|value| value.to_str().ok()).unwrap_or("").to_string();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap().to_vec();
    (status, cache, bytes)
}

#[tokio::test]
async fn a_site_s_icon_is_fetched_converted_and_kept() {
    let (port, hits) = fake_web().await;
    let server = TestServer::new().await.with_upstream(upstream(port, true));

    let (status, cache, bytes) = icon(&server, "Shop.Example.com").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache, "public, max-age=604800");
    let image = image::load_from_memory(&bytes).unwrap();
    assert_eq!((image.width(), image.height()), (64, 64), "the 180 px one, made 64");
    let asked = hits.load(Ordering::SeqCst);
    assert_eq!(icon(&server, "shop.example.com").await.0, StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), asked, "from the cache");

    let (status, _, bytes) = icon(&server, "plain.example.net").await;
    assert_eq!(status, StatusCode::OK, "no page, but /favicon.ico");
    assert_eq!(image::load_from_memory(&bytes).unwrap().width(), 32);

    let (status, cache, bytes) = icon(&server, "away.example.org").await;
    assert_eq!((status, cache.as_str(), bytes.len()), (StatusCode::NOT_FOUND, "public, max-age=86400", 0));
    assert_eq!(icon(&server, "rebind.example.com").await.0, StatusCode::NOT_FOUND);
    for local in ["nas.local", "192.168.1.1", "localhost", "router", "printer.lan"] {
        assert_eq!(icon(&server, local).await.0, StatusCode::NOT_FOUND, "{local}");
    }
    let admin = server.account("admin@example.com").await;
    server.state.store.update_user(&admin.id, |user| user.admin = true).await.unwrap();
    let status = json(server.get_as(&admin.token, "/uwu/v1/admin/icons").await).await;
    assert_eq!(status["cached"], 4, "two icons, two sites without one");
    assert_eq!(
        server.call("DELETE", "/uwu/v1/admin/icons/cache", Some(&admin.token), json!({})).await.status(),
        StatusCode::OK
    );
    assert_eq!(json(server.get_as(&admin.token, "/uwu/v1/admin/icons").await).await["cached"], 0);
}

#[tokio::test]
async fn without_the_test_allowance_the_local_network_is_never_asked() {
    let (port, hits) = fake_web().await;
    let server = TestServer::new().await.with_upstream(upstream(port, false));
    assert_eq!(icon(&server, "shop.example.com").await.0, StatusCode::NOT_FOUND);
    assert_eq!(hits.load(Ordering::SeqCst), 0, "127.0.0.1 is not public");
}

#[tokio::test]
async fn switched_off_and_out_of_tries() {
    let (port, hits) = fake_web().await;
    let mut settings = crate::Settings::default();
    settings.icons.automatic = false;
    let server = TestServer::with_settings(settings).await.with_upstream(upstream(port, true));
    assert_eq!(icon(&server, "shop.example.com").await.0, StatusCode::NOT_FOUND);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let info = json(server.get("/uwu/v1/info").await).await;
    assert!(!info["features"].as_array().unwrap().contains(&json!("icons")));
    assert_eq!(info["icons"]["automatic"], false);

    let limits = crate::Limits {
        icons: crate::limits::Limiter::new(1, std::time::Duration::from_secs(3600)),
        ..crate::Limits::generous()
    };
    let server = TestServer::new().await.with_upstream(upstream(port, true)).with_limits(limits);
    assert_eq!(icon(&server, "plain.example.net").await.0, StatusCode::OK);
    let (status, cache, _) = icon(&server, "shop.example.com").await;
    assert_eq!((status, cache.as_str()), (StatusCode::NOT_FOUND, "no-store"), "out of tries, not remembered");
    assert_eq!(icon(&server, "plain.example.net").await.0, StatusCode::OK, "the cache costs nothing");
}

#[tokio::test]
async fn the_library_is_mirrored_and_its_icons_fetched_on_demand() {
    let (port, _) = fake_web().await;
    let server = TestServer::new().await.with_upstream(upstream(port, true));
    let account = server.account("nyu@example.com").await;
    assert_eq!(server.get("/uwu/v1/icons/library").await.status(), StatusCode::UNAUTHORIZED);
    let response = server.get_as(&account.token, "/uwu/v1/icons/library").await;
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response.headers().get("etag").unwrap().to_str().unwrap().to_string();
    let library = json(response).await;
    assert_eq!(library["sources"][0]["license"], "CC BY 4.0");
    let icons = library["icons"].as_array().unwrap();
    assert_eq!(icons.len(), 1, "only plain ids with a PNG");
    assert_eq!(icons[0]["variants"], json!(["default", "light"]));

    let again = Request::get("/uwu/v1/icons/library")
        .header("authorization", format!("Bearer {}", account.token))
        .header("if-none-match", &etag)
        .body(Body::empty())
        .unwrap();
    assert_eq!(server.send(again).await.status(), StatusCode::NOT_MODIFIED);

    let response = server.get_as(&account.token, "/uwu/v1/icons/library/selfhst/nextcloud.png?variant=default").await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(image::load_from_memory(&bytes).unwrap().width(), 128);
    for missing in [
        "/uwu/v1/icons/library/selfhst/nextcloud.png?variant=dark",
        "/uwu/v1/icons/library/selfhst/unknown.png",
        "/uwu/v1/icons/library/other/nextcloud.png",
        "/uwu/v1/icons/library/selfhst/..%2F..%2Fetc.png",
    ] {
        assert_eq!(server.get_as(&account.token, missing).await.status(), StatusCode::NOT_FOUND, "{missing}");
    }
}

#[tokio::test]
async fn own_icons_are_the_account_s_items_only() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let other = server.account("other@example.com").await;
    let item = json!({"type": 2, "name": "2.n|n|n", "secureNote": {"type": 0}});
    let id = json(server.call("POST", "/api/ciphers", Some(&nyu.token), item).await).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let path = format!("/uwu/v1/icons/own/{id}");
    let body = json!({"data": type2(), "keyType": "extras"});

    assert_eq!(server.call("PUT", &path, Some(&other.token), body.clone()).await.status(), StatusCode::NOT_FOUND);
    let wrong_key = json!({"data": type2(), "keyType": "organization"});
    assert_eq!(server.call("PUT", &path, Some(&nyu.token), wrong_key).await.status(), StatusCode::BAD_REQUEST);
    let plain = json!({"data": "a PNG in the clear", "keyType": "extras"});
    assert_eq!(server.call("PUT", &path, Some(&nyu.token), plain).await.status(), StatusCode::BAD_REQUEST);
    let huge = json!({"data": format!("2.{}", "A".repeat(100 * 1024)), "keyType": "extras"});
    let response = server.call("PUT", &path, Some(&nyu.token), huge).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json(response).await["code"], "too_large");

    let saved = json(server.call("PUT", &path, Some(&nyu.token), body).await).await;
    assert_eq!((saved["object"].as_str(), saved["keyType"].as_str()), (Some("ownIcon"), Some("extras")));
    assert!(saved.get("data").is_none());
    assert_eq!(json(server.get_as(&nyu.token, &path).await).await["data"], type2());
    assert_eq!(server.get_as(&other.token, &path).await.status(), StatusCode::NOT_FOUND);
    let listed = json(server.get_as(&nyu.token, "/uwu/v1/icons/own").await).await;
    assert_eq!(listed["data"].as_array().unwrap().len(), 1);
    assert!(listed["data"][0].get("data").is_none());
    let many = json!({"cipherIds": [id, "5f7c2a1e-0000-4000-8000-000000000000"]});
    let got = json(server.call("POST", "/uwu/v1/icons/own/get", Some(&other.token), many.clone()).await).await;
    assert!(got["data"].as_array().unwrap().is_empty(), "not theirs to see");
    let got = json(server.call("POST", "/uwu/v1/icons/own/get", Some(&nyu.token), many).await).await;
    assert_eq!(got["data"][0]["data"], type2());
    let used = json(server.get_as(&nyu.token, "/uwu/v1/account").await).await["storage"]["usedBytes"].as_i64().unwrap();
    assert!(used >= type2().len() as i64, "counts toward the storage");

    assert_eq!(server.call("DELETE", &path, Some(&other.token), json!({})).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(server.call("DELETE", &path, Some(&nyu.token), json!({})).await.status(), StatusCode::OK);
    assert_eq!(server.get_as(&nyu.token, &path).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_2fa_directory_is_mirrored_for_accounts_only() {
    let (port, hits) = fake_web().await;
    let server = TestServer::new().await.with_upstream(upstream(port, true));
    assert_eq!(server.get("/uwu/v1/twofa-directory").await.status(), StatusCode::UNAUTHORIZED);
    let account = server.account("nyu@example.com").await;
    let response = server.get_as(&account.token, "/uwu/v1/twofa-directory").await;
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response.headers()["etag"].to_str().unwrap().to_string();
    let list = json(response).await;
    assert_eq!(list["object"], "twofaDirectory");
    assert_eq!(list["entries"].as_array().unwrap().len(), 1, "only sites with a second factor");
    assert_eq!(list["entries"][0]["documentation"], "https://shop.example.com/2fa");

    let asked = hits.load(Ordering::SeqCst);
    let again = server
        .send(
            Request::get("/uwu/v1/twofa-directory")
                .header("authorization", format!("Bearer {}", account.token))
                .header("if-none-match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(hits.load(Ordering::SeqCst), asked, "from the mirror");

    // The daily refresh fetches it again, now that it is in use.
    crate::reports::daily(&server.state).await;
    assert_eq!(hits.load(Ordering::SeqCst), asked + 1);
}

/// Review finding R3-2: anonymous callers can have any host fetched, so the cache has a ceiling
/// (the oldest go past it), old entries go once a day, and the admin sees both numbers.
#[tokio::test]
async fn the_cache_of_website_icons_has_a_ceiling_and_forgets_old_entries() {
    let data = tempfile::tempdir().unwrap();
    let icons = crate::icons::Icons::new(data.path(), Upstream::default()).with_limits(10, 1 << 20);
    let auto = data.path().join("icons/auto");
    for n in 0..10 {
        icons.keep(&format!("site{n}.example.com"), Some(&[n as u8; 100])).await;
    }
    assert_eq!(icons.counted().await, (10, 1000));
    // The first ones are the oldest.
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    for n in 0..3 {
        let (path, _) = icons.cached(&format!("site{n}.example.com"));
        std::fs::File::options().write(true).open(path).unwrap().set_modified(old).unwrap();
    }
    icons.keep("one-more.example.com", None).await;
    let (files, _) = icons.counted().await;
    assert_eq!(files, 8, "down to 80 %");
    assert_eq!(std::fs::read_dir(&auto).unwrap().count(), 8);
    for n in 0..3 {
        assert!(icons.cached_icon(&format!("site{n}.example.com")).await.is_none(), "the oldest went");
    }
    assert!(icons.cached_icon("one-more.example.com").await.is_some());
    assert!(icons.bytes().await >= 700);

    // Once a day: what is too old to be used goes.
    let (path, _) = icons.cached("site9.example.com");
    let month = std::time::SystemTime::now() - std::time::Duration::from_secs(31 * 86_400);
    std::fs::File::options().write(true).open(path).unwrap().set_modified(month).unwrap();
    icons.evict(true).await;
    assert_eq!(icons.counted().await.0, 7);
    icons.clear().await.unwrap();
    assert_eq!(icons.counted().await, (0, 0));
}

#[tokio::test]
async fn the_admin_sees_the_cache_and_its_ceiling() {
    let server = TestServer::new().await;
    let token = server.invite("admin@example.com", true).await;
    server.call("POST", "/identity/accounts/register/finish", None, register_body("admin@example.com", &token)).await;
    let admin = server.login("admin@example.com", "admin-device").await;
    let status = json(server.get_as(&admin.token, "/uwu/v1/admin/icons").await).await;
    assert_eq!(status["cacheMaxBytes"], crate::icons::CACHE_MAX_BYTES);
    assert_eq!(status["cacheMaxFiles"], crate::icons::CACHE_MAX_FILES);
    assert_eq!(status["cached"], 0);
}
