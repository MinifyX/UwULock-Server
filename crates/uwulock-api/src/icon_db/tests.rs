//! The icon databases, made from tiny upstream checkouts written here: no network, a few files.

use super::build::{Source, build_all, slug, tile};
use super::*;
use std::path::Path;

/// A square SVG in one colour.
pub(crate) fn square(color: &str) -> String {
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" fill="{color}"/></svg>"#
    )
}

fn png_of(size: u32) -> Vec<u8> {
    let mut png = Vec::new();
    image::RgbaImage::from_pixel(size, size, image::Rgba([200, 30, 90, 255]))
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    png
}

fn about(id: &str) -> About {
    About {
        id: id.into(),
        name: id.into(),
        url: "https://example.com/".into(),
        license: "MIT".into(),
        license_url: "https://example.com/license".into(),
        attribution: "Example".into(),
        repository: "https://example.com/repo".into(),
        commit: "0123456789abcdef".into(),
    }
}

/// Small databases for the server's tests: 2FA Directory knows `example.org` and
/// `aws.example.net`, Simple Icons `example.net`, Dashboard Icons `jellyfin` (alias `jf`) and
/// `home-assistant`.
pub(crate) fn fixture() -> Databases {
    let mut twofa = Writer::new(about(TWOFA));
    let icon = twofa.icon(square("#112233").as_bytes(), Kind::Svg);
    twofa.domain("example.org", icon);
    let icon = twofa.icon(square("#445566").as_bytes(), Kind::Svg);
    twofa.domain("aws.example.net", icon);
    let mut simple = Writer::new(about(SIMPLE));
    let icon = simple.icon(square("#778899").as_bytes(), Kind::Svg);
    simple.domain("example.net", icon);
    let mut dashboard = Writer::new(about(DASHBOARD));
    let icon = dashboard.icon(square("#aabbcc").as_bytes(), Kind::Svg);
    for name in ["jellyfin", "jf"] {
        dashboard.name(name, icon);
    }
    dashboard.library(LibraryEntry {
        id: "jellyfin".into(),
        name: "Jellyfin".into(),
        aliases: vec!["jf".into()],
        icon,
    });
    let icon = dashboard.icon(&png_of(64), Kind::Png);
    dashboard.name("home-assistant", icon);
    dashboard.name("homeassistant", icon);
    dashboard.library(LibraryEntry {
        id: "home-assistant".into(),
        name: "Home Assistant".into(),
        aliases: Vec::new(),
        icon,
    });
    Databases::parse(vec![Cow::Owned(dashboard.finish()), Cow::Owned(simple.finish()), Cow::Owned(twofa.finish())])
}

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// The three repositories as the update script checks them out, with a handful of entries.
fn upstream(dir: &Path) {
    let twofa = dir.join(TWOFA);
    let entry = |name: &str, body: serde_json::Value| serde_json::to_vec(&serde_json::json!({ name: body })).unwrap();
    write(
        &twofa.join("entries/s/shop.example.com.json"),
        entry("Shop", serde_json::json!({"domain": "shop.example.com"})),
    );
    write(&twofa.join("img/s/shop.example.com.svg"), square("#123456"));
    write(
        &twofa.join("entries/c/cloud.example.net.json"),
        entry(
            "Example Cloud",
            serde_json::json!({"domain": "cloud.example.net", "additional-domains": ["Cloud.Example.org."], "img": "cloud.png"}),
        ),
    );
    write(&twofa.join("img/c/cloud.png"), png_of(32));
    // No logo at all, and a logo that is no picture.
    write(
        &twofa.join("entries/n/nologo.example.com.json"),
        entry("No Logo", serde_json::json!({"domain": "nologo.example.com"})),
    );
    write(
        &twofa.join("entries/b/broken.example.com.json"),
        entry("Broken", serde_json::json!({"domain": "broken.example.com"})),
    );
    write(&twofa.join("img/b/broken.example.com.svg"), "<svg");
    // Same logo as the shop's: kept once.
    write(
        &twofa.join("entries/t/twin.example.com.json"),
        entry("Twin", serde_json::json!({"domain": "twin.example.com", "img": "shop.example.com.svg"})),
    );

    let simple = dir.join(SIMPLE);
    let path = |d: &str| {
        format!(
            r#"<svg role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><title>x</title><path d="{d}"/></svg>"#
        )
    };
    write(
        &simple.join("data/simple-icons.json"),
        serde_json::to_vec(&serde_json::json!([
            // By the host of its source: example.com is the site of brand.example.com.
            {"title": "Example", "hex": "FFFFFF", "source": "https://brand.example.com/logo"},
            // By 2FA Directory's name (strong), and a weak claim on shop.example.com by nobody else.
            {"title": "Shop", "hex": "000000", "source": "https://github.com/shop"},
            // Both claim example.org by their source and an alias, weakly: nobody gets it.
            {"title": "Twice A", "slug": "twice", "hex": "FF0000", "source": "https://www.example.org", "aliases": {"aka": ["Example"]}},
            {"title": "Twice B", "slug": "twice", "hex": "00FF00", "source": "https://example.org/b", "aliases": {"aka": ["Example"]}},
            {"title": "Rules", "hex": "0000FF", "source": "https://rules.example.com", "guidelines": "https://rules.example.com/brand"},
            {"title": "Licensed", "hex": "0000FF", "source": "https://licensed.example.com", "license": {"type": "CC-BY-4.0"}},
        ]))
        .unwrap(),
    );
    write(
        &simple.join("slugs.md"),
        "# Slugs\n\n| Brand name | Brand slug |\n| :--- | :--- |\n| `Example` | `example` |\n| `Shop` | `shop` |\n| `Rules` | `rules` |\n| `Licensed` | `licensed` |\n",
    );
    for slug in ["example", "shop", "twice", "rules", "licensed"] {
        write(&simple.join(format!("icons/{slug}.svg")), path("M0 0h24v24H0z"));
    }

    let dashboard = dir.join(DASHBOARD);
    write(
        &dashboard.join("metadata.json"),
        serde_json::to_vec(&serde_json::json!({
            "jellyfin": {"base": "svg", "aliases": ["JF Media"]},
            "home-assistant": {"base": "png", "aliases": []},
            "empty": {"base": "svg"},
            "../etc": {"base": "svg"},
        }))
        .unwrap(),
    );
    write(&dashboard.join("svg/jellyfin.svg"), square("#aa00ff"));
    write(&dashboard.join("png/jellyfin.png"), png_of(512));
    write(&dashboard.join("png/home-assistant.png"), png_of(512));
    write(&dashboard.join("svg/empty.svg"), r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"/>"#);
}

fn sources() -> BTreeMap<String, Source> {
    ALL.iter()
        .map(|id| {
            let source = Source { repository: format!("https://example.com/{id}"), commit: "abc".into() };
            (id.to_string(), source)
        })
        .collect()
}

#[test]
fn the_packs_are_made_from_the_upstream_repositories() {
    let dir = tempfile::tempdir().unwrap();
    upstream(dir.path());
    let built = build_all(dir.path(), &sources()).unwrap();
    let again = build_all(dir.path(), &sources()).unwrap();
    assert!(built.iter().zip(&again).all(|(a, b)| a.pack == b.pack), "the same checkouts, the same bytes");
    let databases = Databases::parse(built.iter().map(|built| Cow::Owned(built.pack.clone())).collect());
    assert_eq!(databases.all().len(), 3);

    let twofa = databases.get(TWOFA).unwrap();
    assert_eq!(twofa.about.license, "MIT");
    assert_eq!(twofa.about.commit, "abc");
    assert_eq!(twofa.counts().0, 2, "the shop's logo once, the cloud's; none for the broken one");
    assert_eq!(built[0].skipped, 2);
    let shop = twofa.by_domain("shop.example.com").unwrap();
    assert_eq!(shop.kind, Kind::Svg);
    assert_eq!(twofa.by_domain("twin.example.com").unwrap().hash, shop.hash);
    assert_eq!(twofa.by_domain("cloud.example.org").unwrap().kind, Kind::Png, "an additional domain, made plain");
    assert!(twofa.by_domain("login.cloud.example.net").is_some(), "a host below it");
    assert!(twofa.by_domain("example.net").is_none(), "not a domain above it");
    assert!(twofa.by_domain("nologo.example.com").is_none());

    let simple = databases.get(SIMPLE).unwrap();
    assert_eq!(built[1].skipped, 2, "its own licence, or guidelines");
    assert_eq!(simple.counts().0, 4);
    let example = simple.by_domain("example.com").expect("by the host of its source");
    let svg = std::str::from_utf8(example.bytes).unwrap();
    assert!(svg.contains(r##"fill="#ffffff""##) && svg.contains(r##"fill="#1b1b1f""##), "dark on white: {svg}");
    assert!(simple.by_domain("www.example.com").is_some());
    assert!(simple.by_domain("shop.example.com").is_some(), "by 2FA Directory's name");
    assert!(simple.by_domain("example.org").is_none(), "claimed by two alike");
    let example = example.hash.to_string();
    assert_eq!(simple.by_domain("rules.example.com").unwrap().hash, example, "not the left-out icon, its domain's");

    let dashboard = databases.get(DASHBOARD).unwrap();
    assert_eq!(built[2].skipped, 1, "it draws nothing; `../etc` is no name at all");
    assert_eq!(dashboard.by_name("jellyfin").unwrap().kind, Kind::Svg, "a small SVG is kept as it is");
    let home = dashboard.by_name("homeassistant").unwrap();
    assert_eq!(home.kind, Kind::Png);
    let image = image::load_from_memory(home.bytes).unwrap();
    assert_eq!((image.width(), image.height()), (64, 64), "made small");
    assert!(dashboard.by_name("home-assistant").is_some() && dashboard.by_name("home_assistant").is_some());
    assert!(dashboard.by_name("jf-media").is_some() && dashboard.by_name("jfmedia").is_some(), "by its alias");
    let library: Vec<(&str, &str)> =
        dashboard.library().iter().map(|entry| (entry.id.as_str(), entry.name.as_str())).collect();
    assert_eq!(library, [("home-assistant", "Home Assistant"), ("jellyfin", "Jellyfin")]);
    assert!(dashboard.library_icon("jellyfin").is_some() && dashboard.library_icon("empty").is_none());
}

#[test]
fn a_host_is_looked_up_in_the_databases_switched_on() {
    let databases = fixture();
    let all: Vec<String> = ALL.iter().map(|id| id.to_string()).collect();
    assert_eq!(databases.for_host(&all, "example.org").unwrap().database, TWOFA);
    assert_eq!(databases.for_host(&all, "console.aws.example.net").unwrap().database, TWOFA, "2FA Directory first");
    assert_eq!(databases.for_host(&all, "www.example.net").unwrap().database, SIMPLE);
    let no_twofa = vec![SIMPLE.to_string()];
    assert_eq!(databases.for_host(&no_twofa, "aws.example.net").unwrap().database, SIMPLE);
    assert!(databases.for_host(&[], "example.org").is_none());
    assert!(databases.for_host(&all, "jellyfin.example.com").is_none(), "Dashboard Icons is not for public names");

    assert_eq!(databases.for_local(&all, "jellyfin.local").unwrap().database, DASHBOARD);
    assert!(databases.for_local(&all, "JF.home.arpa.").is_some());
    assert!(databases.for_local(&all, "homeassistant").is_some());
    assert!(databases.for_local(&all, "jellyfin.example.com").is_none(), "a public name has its own");
    assert!(databases.for_local(&no_twofa, "jellyfin.local").is_none(), "switched off");
}

#[test]
fn only_names_in_the_home_network_have_a_label() {
    for (host, label) in [
        ("nextcloud.home.arpa", Some("nextcloud")),
        ("Jellyfin.local", Some("jellyfin")),
        ("jellyfin", Some("jellyfin")),
        ("nas.lan.", Some("nas")),
        ("192.168.1.10", None),
        ("10.0.0.1.local", None),
        ("[2001:db8::1]", None),
        ("2001:db8::1", None),
        ("localhost", None),
        ("shop.example.com", None),
        ("bad label.local", None),
    ] {
        assert_eq!(local_label(host).as_deref(), label, "{host}");
    }
}

#[test]
fn a_pack_that_is_not_one_is_refused() {
    let mut writer = Writer::new(about(TWOFA));
    let icon = writer.icon(b"<svg/>", Kind::Svg);
    writer.domain("example.com", icon);
    let pack = writer.finish();
    assert!(Database::parse(Cow::Owned(pack.clone())).is_ok());
    assert!(Database::parse(Cow::Owned(pack[..pack.len() - 1].to_vec())).is_err(), "cut short");
    assert!(Database::parse(Cow::Owned(b"PK\x03\x04".to_vec())).is_err());
    let unknown = Writer::new(about("somebody-else")).finish();
    assert!(Databases::parse(vec![Cow::Owned(unknown), Cow::Owned(pack)]).all().len() == 1);
}

#[test]
fn simple_icons_look_like_app_icons() {
    assert_eq!(slug("Sam's Club"), "samsclub");
    assert_eq!(slug("about.me"), "aboutdotme");
    assert_eq!(slug("C++"), "cplusplus");
    assert_eq!(slug("Bakaláři"), "bakalari");
    assert_eq!(slug("H&M"), "handm");
    let white = tile("FFFFFF", "M0 0h1v1H0z").unwrap();
    assert!(white.contains(r##"fill="#1b1b1f""##) && white.contains(r##"stroke="#000000""##));
    let black = tile("000000", "M0 0h1v1H0z").unwrap();
    assert!(black.contains(r##"fill="#ffffff""##) && black.contains(r##"stroke="#ffffff""##));
    let blue = tile("1DA1F2", "M0 0h1v1H0z").unwrap();
    assert!(!blue.contains("stroke"));
    assert!(tile("12345", "M0 0").is_none() && tile("GGGGGG", "M0 0").is_none());
    assert!(crate::icon_fetch::to_png(white.as_bytes(), 64).is_some());
}
