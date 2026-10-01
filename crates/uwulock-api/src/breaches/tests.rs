//! The breach sources against a fake internet on 127.0.0.1: Have I Been Pwned's and
//! XposedOrNot's lists, XposedOrNot's passwords and addresses, and websites with and without a
//! change-password page. Names are answered without DNS; only here is 127.0.0.1 let through.

use super::*;
use crate::icon_fetch::Upstream;
use crate::settings::BreachSettings;
use crate::test_support::{TestServer, json as body};
use axum::http::Uri;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct Asked {
    lists: AtomicUsize,
    passwords: AtomicUsize,
    emails: AtomicUsize,
    pages: AtomicUsize,
}

const NAMES: [&str; 6] = [
    "lists.example.net",
    "pass.example.net",
    "mail.example.net",
    "shop.example.com",
    "plain.example.org",
    "every.example.org",
];

async fn fake_internet() -> (Upstream, Arc<Asked>) {
    let asked = Arc::new(Asked::default());
    let counted = asked.clone();
    let app = axum::Router::new().fallback(move |headers: HeaderMap, uri: Uri| {
        let asked = counted.clone();
        async move {
            let host = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("").split(':').next().unwrap_or("").to_string();
            let path = uri.path().to_string();
            match (host.as_str(), path.as_str()) {
                ("lists.example.net", "/hibp") => {
                    asked.lists.fetch_add(1, Ordering::SeqCst);
                    Json(json!([
                        {"Name": "Shop", "Title": "Shop Inc.", "Domain": "www.Shop.example.com", "BreachDate": "2024-05-01",
                         "AddedDate": "2024-06-01T10:00:00Z", "PwnCount": 1000, "DataClasses": ["Email addresses", "Passwords"],
                         "IsFabricated": false, "IsSpamList": false},
                        {"Name": "Fake", "Domain": "fake.example.com", "BreachDate": "2024-01-01", "IsFabricated": true},
                        {"Name": "NoDomain", "Domain": "", "BreachDate": "2024-01-01"},
                        {"Name": "Local", "Domain": "192.0.2.1", "BreachDate": "2024-01-01"},
                    ]))
                    .into_response()
                }
                ("lists.example.net", "/down") => {
                    asked.lists.fetch_add(1, Ordering::SeqCst);
                    StatusCode::SERVICE_UNAVAILABLE.into_response()
                }
                ("lists.example.net", "/xon") => {
                    asked.lists.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"status": "success", "exposedBreaches": [
                        {"breachID": "ShopLeak", "breachedDate": "2024-05-20T00:00:00+00:00", "addedDate": "2024-05-25T00:00:00+00:00",
                         "domain": "shop.example.com", "exposedData": ["Names", "Phone numbers"], "exposedRecords": 1200,
                         "passwordRisk": "unknown", "breachType": "DataBreach"},
                        {"breachID": "Plain2019", "breachedDate": "2019-02-01T00:00:00+00:00", "domain": "plain.example.org",
                         "exposedData": ["Email addresses"], "exposedRecords": 5, "passwordRisk": "plaintext", "breachType": "DataBreach"},
                        {"breachID": "Combo", "breachedDate": "2020-01-01T00:00:00+00:00", "domain": "combo.example.org",
                         "breachType": "ComboList"},
                    ]}))
                    .into_response()
                }
                ("pass.example.net", path) => {
                    asked.passwords.fetch_add(1, Ordering::SeqCst);
                    if path.ends_with("/a6818b8188") {
                        Json(json!({"SearchPassAnon": {"anon": "a6818b8188", "char": "D:0;A:8;S:0;L:8", "count": "1590937"}}))
                            .into_response()
                    } else {
                        (StatusCode::NOT_FOUND, Json(json!({"Error": "Not found"}))).into_response()
                    }
                }
                ("mail.example.net", path) => {
                    let n = asked.emails.fetch_add(1, Ordering::SeqCst);
                    if path.ends_with("/limit@example.com") || n >= 50 {
                        return StatusCode::TOO_MANY_REQUESTS.into_response();
                    }
                    if path.ends_with("/nyu@example.com") {
                        Json(json!({"breaches": [["ShopLeak", "Plain2019"]], "email": "nyu@example.com", "status": "success"}))
                            .into_response()
                    } else {
                        Json(json!({"Error": "Not found", "email": null})).into_response()
                    }
                }
                ("shop.example.com", WELL_KNOWN) => {
                    asked.pages.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::FOUND, [("location", "/account/password")]).into_response()
                }
                ("shop.example.com", "/account/password") => "change it here".into_response(),
                ("every.example.org", _) => "everything is here".into_response(),
                _ => StatusCode::NOT_FOUND.into_response(),
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let local: IpAddr = "127.0.0.1".parse().unwrap();
    let upstream = Upstream {
        fixed: NAMES.iter().map(|name| (name.to_string(), vec![local])).collect(),
        allowed: vec![local],
        https_port: port,
        http_port: port,
        hibp_breaches: format!("http://lists.example.net:{port}/hibp"),
        xon_breaches: format!("http://lists.example.net:{port}/xon"),
        xon_passwords: format!("http://pass.example.net:{port}/api/v1/pass/anon"),
        xon_email: format!("http://mail.example.net:{port}/v1/check-email"),
        change_password_scheme: "http",
        ..Upstream::default()
    };
    (upstream, asked)
}

fn all_on() -> crate::Settings {
    crate::Settings {
        breaches: BreachSettings { xon_passwords: true, site_breaches: true, email_check: true, change_password: true },
        ..crate::Settings::default()
    }
}

fn quick() -> Breaches {
    Breaches::with_limits(BudgetLimits { spacing: Duration::ZERO, per_hour: 3, per_day: 100, per_account_day: 100 })
}

async fn server() -> (TestServer, Arc<Asked>) {
    let (upstream, asked) = fake_internet().await;
    (TestServer::with_settings(all_on()).await.with_upstream(upstream).with_breaches(quick()), asked)
}

#[tokio::test]
async fn a_password_prefix_is_asked_at_xposedornot_once_per_account() {
    let (server, asked) = server().await;
    let nyu = server.account("nyu@example.com").await;
    let found = body(server.get_as(&nyu.token, "/uwu/v1/xon/A6818B8188").await).await;
    assert_eq!(found, json!({ "object": "xonPassword", "count": 1590937 }), "only the count, not the characters");
    server.get_as(&nyu.token, "/uwu/v1/xon/a6818b8188").await;
    assert_eq!(asked.passwords.load(Ordering::SeqCst), 1, "the second came from memory");
    let unknown = body(server.get_as(&nyu.token, "/uwu/v1/xon/0000000000").await).await;
    assert_eq!(unknown["count"], 0);
    assert_eq!(server.get_as(&nyu.token, "/uwu/v1/xon/12345").await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(server.get("/uwu/v1/xon/0000000000").await.status(), StatusCode::UNAUTHORIZED);
    let mio = server.account("mio@example.com").await;
    server.get_as(&mio.token, "/uwu/v1/xon/a6818b8188").await;
    assert_eq!(asked.passwords.load(Ordering::SeqCst), 3, "nobody sees what others checked");
}

#[tokio::test]
async fn the_site_lists_are_fetched_merged_and_served_with_an_etag() {
    let (server, asked) = server().await;
    let nyu = server.account("nyu@example.com").await;
    let response = server.get_as(&nyu.token, "/uwu/v1/breaches/sites").await;
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response.headers()["etag"].to_str().unwrap().to_string();
    let list = body(response).await;
    assert_eq!(list["object"], "siteBreaches");
    assert_eq!(list["sources"].as_array().unwrap().len(), 2);
    assert_eq!(list["sources"][0]["license"], "CC BY 4.0");
    let breaches = list["breaches"].as_array().unwrap();
    assert_eq!(breaches.len(), 2, "{breaches:?}");
    // Both sources' breach of the shop is one: the earlier date, both names, passwords from HIBP.
    let shop = &breaches[1];
    assert_eq!(shop["domain"], "shop.example.com");
    assert_eq!(shop["date"], "2024-05-01");
    assert_eq!(shop["sources"], json!({ "hibp": "Shop", "xon": "ShopLeak" }));
    assert_eq!(shop["passwords"], true);
    assert_eq!(shop["records"], 1200);
    assert!(shop["dataClasses"].as_array().unwrap().iter().any(|class| class == "Phone numbers"));
    // XposedOrNot says passwords by their risk as well.
    assert_eq!(breaches[0]["domain"], "plain.example.org");
    assert_eq!(breaches[0]["passwords"], true);
    let fetched = asked.lists.load(Ordering::SeqCst);
    assert_eq!(fetched, 2);
    let request = axum::http::Request::get("/uwu/v1/breaches/sites")
        .header("authorization", format!("Bearer {}", nyu.token))
        .header("if-none-match", &etag)
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(server.send(request).await.status(), StatusCode::NOT_MODIFIED);
    // The daily refresh asks again; the list came from disk in between.
    daily(&server.state).await;
    assert_eq!(asked.lists.load(Ordering::SeqCst), 4);
    assert_eq!(server.get("/uwu/v1/breaches/sites").await.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn domains_are_made_plain() {
    assert_eq!(plain_domain("https://WWW.Example.com/login").as_deref(), Some("example.com"));
    assert_eq!(plain_domain("shop.example.co.uk").as_deref(), Some("shop.example.co.uk"));
    assert_eq!(plain_domain("192.0.2.1"), None);
    assert_eq!(plain_domain("localhost"), None);
    assert_eq!(plain_domain(""), None);
}

#[test]
fn breaches_far_apart_stay_two() {
    let breach = |source: &str, date: &str| Breach {
        domain: "example.com".into(),
        title: source.into(),
        date: Some(date.into()),
        added: None,
        records: 1,
        passwords: false,
        data_classes: Vec::new(),
        sources: BTreeMap::from([(source.to_string(), source.to_string())]),
    };
    let merged = merge(vec![vec![breach("hibp", "2012-06-05")], vec![breach("xon", "2016-05-17")]]);
    assert_eq!(merged.len(), 2);
    let merged = merge(vec![vec![breach("hibp", "2012-06-05")], vec![breach("xon", "2012-07-01")]]);
    assert_eq!(merged.len(), 1);
}

#[test]
fn a_hostile_list_cannot_make_merging_slow() {
    // Every breach of both lists for one domain, none close enough to another to be the same:
    // without a ceiling each would be compared with every other.
    let many = |source: &str, date: &str| -> Vec<Breach> {
        (0..MOST_BREACHES)
            .map(|n| Breach {
                domain: "example.com".into(),
                title: format!("{source}{n}"),
                date: Some(date.into()),
                added: None,
                records: 1,
                passwords: false,
                data_classes: Vec::new(),
                sources: BTreeMap::from([(source.to_string(), format!("{source}{n}"))]),
            })
            .collect()
    };
    let started = Instant::now();
    let merged = merge(vec![many("hibp", "2001-01-01"), many("xon", "2021-01-01")]);
    assert_eq!(merged.len(), MOST_PER_DOMAIN);
    assert!(started.elapsed() < Duration::from_secs(30), "{:?}", started.elapsed());
}

#[tokio::test]
async fn sources_that_are_down_are_not_asked_again_for_every_request() {
    let (mut upstream, asked) = fake_internet().await;
    upstream.hibp_breaches = upstream.hibp_breaches.replace("/hibp", "/down");
    upstream.xon_breaches = upstream.xon_breaches.replace("/xon", "/down");
    let server = TestServer::with_settings(all_on()).await.with_upstream(upstream).with_breaches(quick());
    let nyu = server.account("nyu@example.com").await;
    for _ in 0..3 {
        let response = server.get_as(&nyu.token, "/uwu/v1/breaches/sites").await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }
    assert_eq!(asked.lists.load(Ordering::SeqCst), 2, "one try per source, then a pause");
    // After the pause it asks again.
    *server.state.breaches.sites.failed.lock() = None;
    assert_eq!(server.get_as(&nyu.token, "/uwu/v1/breaches/sites").await.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(asked.lists.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn errors_never_carry_the_prefix_or_the_address() {
    // The checked client refuses a name of the home network: the request fails, and its error
    // names the address it went to.
    let client = crate::icon_fetch::client(Arc::new(Upstream::default())).unwrap();
    let error =
        client.get("https://router.home.arpa/api/v1/pass/anon/0123456789?nyu@example.com").send().await.unwrap_err();
    assert!(error.to_string().contains("0123456789"), "{error}");
    let quiet = quiet(error);
    assert!(!quiet.contains("0123456789") && !quiet.contains("nyu@"), "{quiet}");
}

#[tokio::test]
async fn addresses_need_the_switch_and_the_account_s_consent() {
    let (upstream, _) = fake_internet().await;
    let server = TestServer::new().await.with_upstream(upstream).with_breaches(quick());
    let nyu = server.account("nyu@example.com").await;
    let check = json!({ "emails": ["nyu@example.com"] });
    let off = server.call("POST", "/uwu/v1/breaches/emails", Some(&nyu.token), check.clone()).await;
    assert_eq!(off.status(), StatusCode::NOT_FOUND, "off by default");
    assert_eq!(body(off).await["code"], "feature_off");
    server.state.apply_settings(all_on());
    let not_agreed = server.call("POST", "/uwu/v1/breaches/emails", Some(&nyu.token), check.clone()).await;
    assert_eq!(not_agreed.status(), StatusCode::FORBIDDEN);
    assert_eq!(body(not_agreed).await["code"], "opt_in");
    let account = body(server.get_as(&nyu.token, "/uwu/v1/account").await).await;
    assert_eq!(account["emailBreachCheck"]["optedIn"], false);
    let agreed =
        body(server.call("PUT", "/uwu/v1/breaches/emails/opt-in", Some(&nyu.token), json!({ "optedIn": true })).await)
            .await;
    assert_eq!(agreed["optedIn"], true);
    assert!(agreed["since"].is_string());
    let answer = server.call("POST", "/uwu/v1/breaches/emails", Some(&nyu.token), check).await;
    assert_eq!(answer.status(), StatusCode::OK);
    let answer = body(answer).await;
    assert_eq!(answer["results"][0]["status"], "found");
    assert_eq!(answer["results"][0]["breaches"], json!(["Plain2019", "ShopLeak"]));
    let back =
        body(server.call("PUT", "/uwu/v1/breaches/emails/opt-in", Some(&nyu.token), json!({ "optedIn": false })).await)
            .await;
    assert_eq!(back["optedIn"], false);
}

#[tokio::test]
async fn addresses_are_cached_by_hash_and_kept_within_the_budget() {
    let (server, asked) = server().await;
    let nyu = server.account("nyu@example.com").await;
    server.call("PUT", "/uwu/v1/breaches/emails/opt-in", Some(&nyu.token), json!({ "optedIn": true })).await;
    let emails =
        json!({ "emails": ["Nyu@Example.com ", "a@example.org", "b@example.org", "c@example.org", "nyu@example.com"] });
    let first = body(server.call("POST", "/uwu/v1/breaches/emails", Some(&nyu.token), emails.clone()).await).await;
    let results = first["results"].as_array().unwrap();
    assert_eq!(results.len(), 4, "the same address once");
    assert_eq!(results[0]["email"], "nyu@example.com");
    assert_eq!(results[0]["status"], "found");
    assert_eq!(results[1]["status"], "clean");
    assert_eq!(results[2]["status"], "clean");
    // Three an hour in this test: the fourth waits.
    assert_eq!(results[3]["status"], "later");
    assert!(first["retryAfter"].as_u64().unwrap() > 0);
    assert_eq!(asked.emails.load(Ordering::SeqCst), 3);
    // Answers come from the cache, not from XposedOrNot again.
    let again = body(server.call("POST", "/uwu/v1/breaches/emails", Some(&nyu.token), emails).await).await;
    assert_eq!(again["results"][0]["status"], "found");
    assert_eq!(asked.emails.load(Ordering::SeqCst), 3);
    // The database holds no address it checked, only hashes.
    let mut stored = Vec::new();
    for name in ["uwulock.db", "uwulock.db-wal"] {
        stored.extend(std::fs::read(server.state.config.data.join(name)).unwrap_or_default());
    }
    assert!(!stored.is_empty());
    assert!(!stored.windows(13).any(|window| window == b"a@example.org"));
    assert_eq!(
        server
            .call("POST", "/uwu/v1/breaches/emails", Some(&nyu.token), json!({ "emails": ["not an address"] }))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn too_many_requests_stop_the_queue_for_an_hour() {
    let (upstream, _) = fake_internet().await;
    let server =
        TestServer::with_settings(all_on()).await.with_upstream(upstream).with_breaches(Breaches::with_limits(
            BudgetLimits { spacing: Duration::ZERO, per_hour: 100, per_day: 100, per_account_day: 100 },
        ));
    let nyu = server.account("nyu@example.com").await;
    server.call("PUT", "/uwu/v1/breaches/emails/opt-in", Some(&nyu.token), json!({ "optedIn": true })).await;
    let answer = body(
        server
            .call(
                "POST",
                "/uwu/v1/breaches/emails",
                Some(&nyu.token),
                json!({ "emails": ["limit@example.com", "a@example.org"] }),
            )
            .await,
    )
    .await;
    assert_eq!(answer["results"][0]["status"], "later");
    assert_eq!(answer["results"][1]["status"], "later");
    assert_eq!(answer["retryAfter"], 3600);
}

#[tokio::test]
async fn a_change_password_page_is_found_and_never_on_the_local_network() {
    let (server, asked) = server().await;
    let nyu = server.account("nyu@example.com").await;
    let found = body(server.get_as(&nyu.token, "/uwu/v1/change-password/Shop.Example.com").await).await;
    assert_eq!(found["host"], "shop.example.com");
    let url = found["url"].as_str().unwrap();
    assert!(url.starts_with("http://shop.example.com:") && url.ends_with("/.well-known/change-password"), "{url}");
    server.get_as(&nyu.token, "/uwu/v1/change-password/shop.example.com").await;
    assert_eq!(asked.pages.load(Ordering::SeqCst), 1, "kept");
    // A site that answers everything with 200 says nothing.
    let every = body(server.get_as(&nyu.token, "/uwu/v1/change-password/every.example.org").await).await;
    assert!(every["url"].is_null());
    let none = body(server.get_as(&nyu.token, "/uwu/v1/change-password/plain.example.org").await).await;
    assert!(none["url"].is_null());
    // Addresses and local names are never asked.
    for host in ["127.0.0.1", "192.168.1.1", "nas.local", "localhost", "router"] {
        let answer = body(server.get_as(&nyu.token, &format!("/uwu/v1/change-password/{host}")).await).await;
        assert!(answer["url"].is_null(), "{host}");
    }
}

#[tokio::test]
async fn each_source_can_be_switched_off() {
    let server = TestServer::with_settings(crate::Settings {
        breaches: BreachSettings {
            xon_passwords: false,
            site_breaches: false,
            email_check: false,
            change_password: false,
        },
        ..crate::Settings::default()
    })
    .await;
    let nyu = server.account("nyu@example.com").await;
    for path in [
        "/uwu/v1/xon/a6818b8188",
        "/uwu/v1/breaches/sites",
        "/uwu/v1/change-password/example.com",
        "/uwu/v1/breaches/emails/opt-in",
    ] {
        let response = server.get_as(&nyu.token, path).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
    let info = body(server.get("/uwu/v1/info").await).await;
    assert_eq!(info["breaches"]["xonPasswords"], false);
    assert_eq!(info["breaches"]["hibp"], true);
    let features = info["features"].as_array().unwrap();
    assert!(!features.iter().any(|feature| feature == "site-breaches"));
    let on = TestServer::with_settings(all_on()).await;
    let info = body(on.get("/uwu/v1/info").await).await;
    for name in ["xon-passwords", "site-breaches", "email-breaches", "change-password"] {
        assert!(info["features"].as_array().unwrap().iter().any(|feature| feature == name), "{name}");
    }
}

#[test]
fn answers_are_read_carefully() {
    assert_eq!(xon_count(404, b"{}"), Ok(0));
    assert_eq!(xon_count(200, br#"{"SearchPassAnon":{"count":"12"}}"#), Ok(12));
    assert_eq!(xon_count(200, br#"{"Error":"Not found"}"#), Ok(0));
    assert!(xon_count(500, b"").is_err());
    assert!(xon_count(200, b"<html>").is_err());
    assert_eq!(xon_email_breaches(200, br#"{"Error":"Not found","email":null}"#), Ok(vec![]));
    assert_eq!(xon_email_breaches(200, br#"{"breaches":[["B","A","B"]]}"#), Ok(vec!["A".to_string(), "B".to_string()]));
    assert_eq!(plain_address(" Nyu@Example.COM ").as_deref(), Some("nyu@example.com"));
    for bad in ["nyu", "@example.com", "nyu@localhost", "nyu@example.com/../x", "a b@example.com", "nyu@exa_mple.com"] {
        assert_eq!(plain_address(bad), None, "{bad}");
    }
}
