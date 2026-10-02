use super::*;
use crate::test_support::*;
use axum::http::StatusCode;
use serde_json::json;

/// One endpoint of each switch (every route group behind one), as `method path`.
const ENDPOINTS: &[(Feature, &str, &str)] = &[
    (Feature::Families, "POST", "/api/organizations"),
    (Feature::Families, "GET", "/uwu/v1/organizations/invitations"),
    (Feature::Families, "GET", "/uwu/v1/admin/organizations"),
    (Feature::FileRequests, "GET", "/uwu/v1/file-requests"),
    (Feature::FileRequests, "GET", "/uwu/v1/public/file-requests/AAAAAAAAAAAAAAAAAAAAAA"),
    (Feature::FileRequests, "PUT", "/uwu/v1/public/file-requests/AAAAAAAAAAAAAAAAAAAAAA/submissions/s/files/f"),
    (Feature::SendDomains, "GET", "/uwu/v1/admin/send-domains"),
    (Feature::SendDomains, "GET", "/uwu/v1/sends/domains"),
    (Feature::MaskedAddresses, "GET", "/uwu/v1/masked/connection"),
    (Feature::MaskedAddresses, "POST", "/uwu/v1/masked/addy/api/v1/aliases"),
    (Feature::Versions, "GET", "/uwu/v1/versions"),
    (Feature::Reminders, "GET", "/uwu/v1/reminders"),
    (Feature::TravelMode, "GET", "/uwu/v1/travel"),
    (Feature::OwnIcons, "GET", "/uwu/v1/icons/own"),
    (Feature::IconLibrary, "GET", "/uwu/v1/icons/library"),
    (Feature::TwofaDirectory, "GET", "/uwu/v1/twofa-directory"),
    (Feature::Sso, "GET", "/identity/sso/prevalidate"),
    (Feature::Sso, "GET", "/uwu/v1/admin/sso"),
    (Feature::Scim, "GET", "/scim/v2/Users"),
    (Feature::Scim, "POST", "/uwu/v1/admin/scim/token"),
    (Feature::OffsiteBackups, "GET", "/uwu/v1/admin/backups/offsite"),
    (Feature::AdminNotifications, "GET", "/uwu/v1/admin/notifications"),
    (Feature::Suite, "GET", "/uwu/v1/suite/spaces"),
    (Feature::Suite, "POST", "/uwu/v1/suite/spaces/ssh/records"),
    (Feature::Suite, "POST", "/uwu/v1/suite/spaces/ssh/rekey"),
];

/// Whether the answer is the switch's 404.
async fn switched_off(response: axum::http::Response<axum::body::Body>) -> bool {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice::<serde_json::Value>(&bytes).is_ok_and(|body| body["code"] == "feature_off")
}

#[test]
fn every_switch_has_a_name_a_group_and_comes_back_from_its_json() {
    for feature in Feature::ALL {
        assert_eq!(Feature::from_id(feature.id()), Some(feature));
    }
    let some = Features::none().with(Feature::Families, true).with(Feature::Sso, true);
    assert_eq!(Features::from_json(&some.to_json()), some);
    assert_eq!(Features::from_json(&json!({"families": true, "tomorrows-feature": true})).names(), ["families"]);
    assert_eq!(Features::parse_list("all").unwrap(), Features::all());
    assert_eq!(Features::parse_list("").unwrap(), Features::none());
    assert_eq!(Features::parse_list("families, sso").unwrap(), some);
    assert!(Features::parse_list("families,nonsense").is_err());
    // A library icon is kept as an own icon: without those, no library.
    let library = Features::none().with(Feature::IconLibrary, true);
    assert!(library.switched_on(Feature::IconLibrary) && !library.on(Feature::IconLibrary));
    assert!(library.with(Feature::OwnIcons, true).on(Feature::IconLibrary));
}

#[tokio::test]
async fn a_switched_off_feature_answers_404_everywhere_and_comes_back() {
    let server = TestServer::new().await;
    let admin = server.admin().await;
    // Masked addresses need a UwUMail server besides their switch.
    let mut settings = server.state.settings();
    settings.masked.servers =
        vec![crate::settings::MaskedServer { url: "https://mail.example.com".into(), name: "Mail".into() }];
    server.state.apply_settings(settings);
    for (feature, method, path) in ENDPOINTS {
        let on = server.call(method, path, Some(&admin.token), json!({})).await;
        let status = on.status();
        assert!(!switched_off(on).await, "{path} while {} is on", feature.id());
        server.switch(*feature, false);
        let off = server.call(method, path, Some(&admin.token), json!({})).await;
        assert_eq!(off.status(), StatusCode::NOT_FOUND, "{method} {path} with {} off", feature.id());
        assert!(switched_off(off).await, "{path}");
        // Without a session too: the route is not there, whoever asks.
        let anonymous = server.call(method, path, None, json!({})).await;
        assert_eq!(anonymous.status(), StatusCode::NOT_FOUND, "{path} without a session");
        server.switch(*feature, true);
        let again = server.call(method, path, Some(&admin.token), json!({})).await;
        assert_eq!(again.status(), status, "{path} is back");
    }
}

#[tokio::test]
async fn the_vault_and_bitwarden_s_own_endpoints_never_are_switched_off() {
    let server = TestServer::with_settings(crate::Settings::default()).await;
    server.state.apply_features(Features::none());
    let nyu = server.account("nyu@example.com").await;
    for path in ["/api/sync", "/api/sends", "/api/emergency-access/trusted", "/api/organizations", "/uwu/v1/account"] {
        let response = server.get_as(&nyu.token, path).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
    // Website icons keep their own switch.
    let info = json(server.get("/uwu/v1/info").await).await;
    assert!(info["features"].as_array().unwrap().iter().any(|feature| feature == "icons"));
}

#[tokio::test]
async fn info_says_which_are_on() {
    let server = TestServer::new().await;
    server.state.apply_features(Features::none().with(Feature::Reminders, true));
    let info = json(server.get("/uwu/v1/info").await).await;
    let features: Vec<&str> = info["features"].as_array().unwrap().iter().filter_map(|f| f.as_str()).collect();
    assert!(features.contains(&"reminders") && features.contains(&"vault") && features.contains(&"icons"));
    for off in ["families", "file-requests", "travel-mode", "own-icons", "icon-library", "versions", "suite"] {
        assert!(!features.contains(&off), "{off}");
    }
    assert_eq!(info["switches"]["reminders"], true);
    assert_eq!(info["switches"]["families"], false);
    assert_eq!(info["switches"].as_object().unwrap().len(), Feature::ALL.len());
    let nyu = server.account("nyu@example.com").await;
    let account = json(server.get_as(&nyu.token, "/uwu/v1/account").await).await;
    assert_eq!(account["families"]["mayCreate"], false, "no families to make while they are off");
}

#[tokio::test]
async fn the_admin_switches_them_with_an_event_and_nothing_is_lost() {
    let server = TestServer::new().await;
    let admin = server.admin().await;
    let nyu = server.account("nyu@example.com").await;
    let item = json!({"type": 1, "name": "2.n|n|n", "login": {"password": "2.p|p|p"}});
    let id = json(server.call("POST", "/api/ciphers", Some(&nyu.token), item).await).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let reminder = format!("/uwu/v1/reminders/{id}");
    assert_eq!(
        server.call("PUT", &reminder, Some(&nyu.token), json!({"due": "2099-01-01"})).await.status(),
        StatusCode::OK
    );

    assert_eq!(server.get_as(&nyu.token, "/uwu/v1/admin/features").await.status(), StatusCode::FORBIDDEN);
    let listed = json(server.get_as(&admin.token, "/uwu/v1/admin/features").await).await;
    let reminders = listed["features"].as_array().unwrap().iter().find(|f| f["id"] == "reminders").unwrap().clone();
    assert_eq!(
        reminders,
        json!({"id": "reminders", "group": "vault", "on": true, "works": true, "requires": null, "inUse": true})
    );

    let bad = server.call("PUT", "/uwu/v1/admin/features", Some(&admin.token), json!({"nonsense": true})).await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    let changed = server
        .call("PUT", "/uwu/v1/admin/features", Some(&admin.token), json!({"reminders": false, "own-icons": false}))
        .await;
    assert_eq!(changed.status(), StatusCode::OK);
    let body = json(changed).await;
    let own = body["features"].as_array().unwrap().iter().find(|f| f["id"] == "icon-library").unwrap().clone();
    assert_eq!((own["on"].as_bool(), own["works"].as_bool()), (Some(true), Some(false)), "it needs own icons");
    assert!(!server.state.feature(Feature::Reminders));
    assert_eq!(
        Features::load(&server.state.store, Some(&Features::all())).await.unwrap(),
        server.state.features(),
        "kept in the database"
    );
    let events = json(server.get_as(&admin.token, "/uwu/v1/admin/events?kind=admin").await).await;
    assert!(
        events
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["detail"] == "switched features: reminders off, own-icons off"),
        "{events}"
    );
    assert_eq!(server.get_as(&nyu.token, "/uwu/v1/reminders").await.status(), StatusCode::NOT_FOUND);

    server.call("PUT", "/uwu/v1/admin/features", Some(&admin.token), json!({"reminders": true})).await;
    let back = json(server.get_as(&nyu.token, "/uwu/v1/reminders").await).await;
    assert_eq!(back["data"][0]["due"], "2099-01-01", "the reminder is still there");
}

#[tokio::test]
async fn travel_mode_stays_on_while_somebody_travels() {
    let server = TestServer::new().await;
    let admin = server.admin().await;
    let nyu = server.account("nyu@example.com").await;
    server.state.store.set_travelling(&nyu.id, true).await.unwrap();
    let refused = server.call("PUT", "/uwu/v1/admin/features", Some(&admin.token), json!({"travel-mode": false})).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(refused).await["code"], "travelling");
    assert!(server.state.feature(Feature::TravelMode));
}

#[tokio::test]
async fn what_runs_by_itself_stops_while_off() {
    let server = TestServer::new().await;
    let nyu = server.account("nyu@example.com").await;
    let item = json!({"type": 1, "name": "2.a|a|a", "login": {"password": "2.p|p|p"}});
    let created = json(server.call("POST", "/api/ciphers", Some(&nyu.token), item).await).await;
    let id = created["id"].as_str().unwrap().to_string();
    let path = format!("/uwu/v1/reminders/{id}");
    server.call("PUT", &path, Some(&nyu.token), json!({"due": "2020-01-01"})).await;

    // Reminders: nothing is mailed while off; the due one comes once it is on again.
    server.switch(Feature::Reminders, false);
    crate::reminders::tend(&server.state).await;
    let due = |server: &TestServer| server.mails().into_iter().filter(|mail| mail.subject.contains("fällig")).count();
    assert_eq!(due(&server), 0);
    server.switch(Feature::Reminders, true);
    crate::reminders::tend(&server.state).await;
    assert_eq!(due(&server), 1);

    // Versions: none made while off, the ones there stay.
    let mut changed = created.clone();
    changed["name"] = json!("2.b|b|b");
    server.call("PUT", &format!("/api/ciphers/{id}"), Some(&nyu.token), changed.clone()).await;
    assert_eq!(server.state.store.versions(&id).await.unwrap().len(), 1);
    server.switch(Feature::Versions, false);
    changed["name"] = json!("2.c|c|c");
    server.call("PUT", &format!("/api/ciphers/{id}"), Some(&nyu.token), changed).await;
    server.state.store.prune_versions().await.unwrap();
    assert_eq!(server.state.store.versions(&id).await.unwrap().len(), 1);
    server.switch(Feature::Versions, true);
    assert_eq!(
        json(server.get_as(&nyu.token, &format!("/uwu/v1/ciphers/{id}/versions")).await).await["data"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Off-site backups: no alert about them while off.
    server.switch(Feature::OffsiteBackups, false);
    assert!(crate::offsite::problems(&server.state).await.is_empty());
}

#[tokio::test]
async fn sso_switched_off_lets_passwords_in_again() {
    let server = TestServer::new().await;
    let _admin = server.admin().await;
    server.account("nyu@example.com").await;
    let mut settings = server.state.settings();
    settings.sso.enabled = true;
    settings.sso.issuer = "https://auth.example.com".into();
    settings.sso.client_id = "uwulock".into();
    settings.sso.only = true;
    settings.sso.admins_only_with_sso = true;
    server.state.apply_settings(settings);
    let refused = server.form("/identity/connect/token", &login_form("nyu@example.com", "d1")).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "only SSO");
    assert_eq!(json(server.get("/uwu/v1/info").await).await["sso"]["enabled"], true);

    server.switch(Feature::Sso, false);
    let nyu = server.form("/identity/connect/token", &login_form("nyu@example.com", "d2")).await;
    assert_eq!(nyu.status(), StatusCode::OK);
    let admin = server.login("admin@example.com", "d3").await;
    assert_eq!(server.get_as(&admin.token, "/uwu/v1/admin/features").await.status(), StatusCode::OK);
    let info = json(server.get("/uwu/v1/info").await).await;
    assert_eq!((info["sso"]["enabled"].as_bool(), info["sso"]["only"].as_bool()), (Some(false), Some(false)));
    assert!(server.state.settings().sso.only, "the settings stay for when it is on again");
}

#[tokio::test]
async fn send_domains_switched_off_answer_as_the_main_host() {
    let server = TestServer::new().await;
    let admin = server.admin().await;
    let added = server
        .call(
            "POST",
            "/uwu/v1/admin/send-domains",
            Some(&admin.token),
            json!({"host": "send.example.com", "tls": "proxy"}),
        )
        .await;
    assert_eq!(added.status(), StatusCode::OK);
    assert_eq!(server.state.send_domains.all().len(), 1);
    let changed =
        server.call("PUT", "/uwu/v1/admin/features", Some(&admin.token), json!({"send-domains": false})).await;
    assert_eq!(changed.status(), StatusCode::OK);
    assert!(server.state.send_domains.all().is_empty(), "no domain answers, none gets a certificate");
    assert!(json(server.get("/uwu/v1/info").await).await["sendDomains"].as_array().unwrap().is_empty());
    server.call("PUT", "/uwu/v1/admin/features", Some(&admin.token), json!({"send-domains": true})).await;
    assert_eq!(server.state.send_domains.all().len(), 1, "back, with nothing lost");
}

#[tokio::test]
async fn a_new_server_starts_with_the_start_features() {
    let server = TestServer::new().await;
    // No switches in the database: what the configuration starts with (all, for the tests).
    assert_eq!(server.state.store.setting(KEY).await.unwrap(), None);
    assert_eq!(Features::load(&server.state.store, Some(&Features::none())).await.unwrap(), Features::none());
    Features::none().with(Feature::Suite, true).save(&server.state.store).await.unwrap();
    assert_eq!(
        Features::load(&server.state.store, Some(&Features::all())).await.unwrap().names(),
        ["suite"],
        "the database wins"
    );
}

/// `UWULOCK_FEATURES` is not in a backup: what it said is kept in the database, so a server
/// restored on a machine without it keeps its switches, and an admin's switch still wins.
#[tokio::test]
async fn what_the_environment_said_goes_along_into_the_backup() {
    let server = TestServer::new().await;
    let store = &server.state.store;
    let kept = store.setting(START_KEY).await.unwrap().expect("kept at the start");
    assert_eq!(Features::from_json(&serde_json::from_str(&kept).unwrap()), Features::all());
    assert_eq!(Features::load(store, None).await.unwrap(), Features::all(), "restored, without the environment");

    // It counts as long as nobody switched: a changed environment is taken over, and kept.
    let some = Features::parse_list("families,offsite-backups").unwrap();
    assert_eq!(Features::load(store, Some(&some)).await.unwrap(), some);
    Features::remember_start(store, Some(&some)).await.unwrap();
    assert_eq!(Features::load(store, None).await.unwrap(), some);
    Features::remember_start(store, None).await.unwrap();
    assert_eq!(Features::load(store, None).await.unwrap(), some, "no environment changes nothing");

    // Switched once, the switches are the admin's, whatever the environment says.
    let switched = some.clone().with(Feature::Families, false);
    switched.save(store).await.unwrap();
    Features::remember_start(store, Some(&Features::all())).await.unwrap();
    assert_eq!(Features::load(store, Some(&Features::all())).await.unwrap(), switched);
    assert_eq!(Features::load(store, None).await.unwrap(), switched);
    let kept = store.setting(START_KEY).await.unwrap().unwrap();
    assert_eq!(Features::from_json(&serde_json::from_str(&kept).unwrap()), some, "left alone once switched");
}
