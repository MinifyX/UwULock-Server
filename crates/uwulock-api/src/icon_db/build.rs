//! Making the packs from the upstream repositories, as `scripts/icons/update.mjs` checked them
//! out at the commits in `sources.json`. The same checkouts give the same packs, byte for byte:
//! everything is taken in a fixed order, and nothing depends on the time or the machine.
//!
//! - **2FA Directory**: every entry with a logo — its `domain` and `additional-domains` get it.
//!   The logos are small SVGs and PNGs and are kept as they are.
//! - **Simple Icons**: every icon whose data has neither a `license` of its own nor
//!   `guidelines` (those brands ask for more than CC0 does, so they are left out). The glyph is
//!   put on a rounded tile in the brand's colour, white or dark, whichever reads better, with a
//!   thin edge on very light and very dark tiles — an app icon in light and dark mode alike.
//!   Simple Icons has no domains, so they are worked out, and only where that is unambiguous:
//!   1. a 2FA Directory entry whose name makes the icon's slug (or one of its `aka` aliases)
//!      gives the icon all its domains (a strong claim);
//!   2. a registrable domain whose name is the slug — the host of the icon's `source` address
//!      (`brand.spotify.com` → `spotify.com` for `spotify`) or one of 2FA Directory's domains —
//!      is the icon's (a weak claim).
//!
//!   A domain goes to the one icon that claims it strongly; with no strong claim, to the one
//!   that claims it weakly; claimed by two icons alike, it goes to none.
//! - **Dashboard Icons**: every icon in `metadata.json`, by its name, its name without dashes
//!   and its aliases. Kept as SVG when that is small and draws without pictures inside, else as a
//!   PNG of at most 64 pixels — whichever is smaller. The light and dark variants are left out.

use super::{About, DASHBOARD, Kind, LibraryEntry, SIMPLE, TWOFA, Writer};
use crate::icon_fetch;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Where a database comes from: `sources.json` next to the packs.
#[derive(Debug, Clone, Deserialize)]
pub struct Source {
    pub repository: String,
    pub commit: String,
}

/// A pack made, and what is in it.
pub struct Built {
    pub id: &'static str,
    pub pack: Vec<u8>,
    pub icons: usize,
    pub domains: usize,
    pub names: usize,
    /// Upstream icons left out: no logo, licence or guidelines of their own, unreadable.
    pub skipped: usize,
}

/// The largest upstream file taken: an icon, and a list of them.
const FILE_BYTES: u64 = 1024 * 1024;
const LIST_BYTES: u64 = 32 * 1024 * 1024;
/// An SVG of Dashboard Icons is kept as it is up to this size.
const SVG_KEPT: usize = 16 * 1024;
/// Dashboard Icons that are no small SVG are kept at most this large, the size the server hands
/// out automatic icons in.
const DASHBOARD_PIXELS: u32 = icon_fetch::AUTO_PIXELS;

fn about(id: &'static str, source: &Source) -> About {
    let (name, url, license, license_url, attribution) = match id {
        TWOFA => (
            "2FA Directory",
            "https://2fa.directory/",
            "MIT",
            "https://github.com/2factorauth/twofactorauth/blob/master/LICENSE.md",
            "© 2014–2020 Josh Davis, © 2021 2factorauth and contributors",
        ),
        SIMPLE => (
            "Simple Icons",
            "https://simpleicons.org/",
            "CC0 1.0",
            "https://creativecommons.org/publicdomain/zero/1.0/",
            "Simple Icons contributors; the logos are trademarks of their owners",
        ),
        _ => (
            "Dashboard Icons",
            "https://dashboardicons.com/",
            "Apache-2.0",
            "https://www.apache.org/licenses/LICENSE-2.0",
            "© Bjorn Lammers, Meier Lukas, Thomas Camlong and Homarr Labs; converted by UwULock",
        ),
    };
    About {
        id: id.into(),
        name: name.into(),
        url: url.into(),
        license: license.into(),
        license_url: license_url.into(),
        attribution: attribution.into(),
        repository: source.repository.clone(),
        commit: source.commit.clone(),
    }
}

/// All three packs, from the checkouts under `upstream/<id>`.
pub fn build_all(upstream: &Path, sources: &BTreeMap<String, Source>) -> Result<Vec<Built>, String> {
    let source = |id: &str| sources.get(id).ok_or_else(|| format!("sources.json names no {id}"));
    let sites = twofa_sites(&upstream.join(TWOFA))?;
    Ok(vec![
        twofa(&sites, about(TWOFA, source(TWOFA)?)),
        simple(&upstream.join(SIMPLE), &sites, about(SIMPLE, source(SIMPLE)?))?,
        dashboard(&upstream.join(DASHBOARD), about(DASHBOARD, source(DASHBOARD)?))?,
    ])
}

fn read(path: &Path) -> Option<Vec<u8>> {
    read_up_to(path, FILE_BYTES)
}

fn read_up_to(path: &Path, most: u64) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    (meta.is_file() && meta.len() <= most).then(|| std::fs::read(path).ok()).flatten()
}

fn kind(bytes: &[u8]) -> Kind {
    if bytes.starts_with(b"\x89PNG") { Kind::Png } else { Kind::Svg }
}

/// Whether an image draws as something: at least a few percent of it not transparent. An SVG
/// whose picture is an embedded image draws as nothing here (the server never reads those).
fn visible(bytes: &[u8], pixels: u32) -> Option<Vec<u8>> {
    let (png, _) = icon_fetch::to_png(bytes, pixels)?;
    let image = image::load_from_memory(&png).ok()?.to_rgba8();
    let area = (image.width() * image.height()) as usize;
    let seen = image.pixels().filter(|pixel| pixel[3] > 16).count();
    (seen * 50 >= area).then_some(png)
}

/// A PNG as small as it gets: compressed as hard as the format goes.
fn smallest_png(png: &[u8]) -> Option<Vec<u8>> {
    use image::ImageEncoder;
    use image::codecs::png::{CompressionType, FilterType, PngEncoder};
    let image = image::load_from_memory(png).ok()?.to_rgba8();
    let mut out = Vec::new();
    PngEncoder::new_with_quality(&mut out, CompressionType::Best, FilterType::Adaptive)
        .write_image(&image, image.width(), image.height(), image::ExtendedColorType::Rgba8)
        .ok()?;
    Some(if out.len() < png.len() { out } else { png.to_vec() })
}

/// Each item of `items` through `work`, on every core, the answers in the same order.
fn par_map<T: Sync, U: Send>(items: &[T], work: impl Fn(&T) -> U + Sync) -> Vec<U> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let next = AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get()).min(8);
    let mut done: Vec<(usize, U)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut mine = Vec::new();
                    loop {
                        let at = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(at) else { break };
                        mine.push((at, work(item)));
                    }
                    mine
                })
            })
            .collect();
        handles.into_iter().flat_map(|handle| handle.join().expect("a worker")).collect()
    });
    done.sort_by_key(|(at, _)| *at);
    done.into_iter().map(|(_, answer)| answer).collect()
}

/// Simple Icons' `titleToSlug`: lower case, `+` `.` `&` spelled out, accents gone, only letters
/// and digits left. Used for 2FA Directory's names too, to compare them with slugs.
pub fn slug(title: &str) -> String {
    let mut out = String::new();
    for c in title.to_lowercase().chars() {
        match c {
            '+' => out.push_str("plus"),
            '.' => out.push_str("dot"),
            '&' => out.push_str("and"),
            'ß' => out.push_str("ss"),
            'æ' => out.push_str("ae"),
            'œ' => out.push_str("oe"),
            'a'..='z' | '0'..='9' => out.push(c),
            _ => {
                let plain = match c {
                    'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' => 'a',
                    'ç' | 'ć' | 'č' => 'c',
                    'ď' | 'đ' => 'd',
                    'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ė' | 'ę' | 'ě' => 'e',
                    'ğ' => 'g',
                    'ħ' => 'h',
                    'ì' | 'í' | 'î' | 'ï' | 'ī' | 'ı' => 'i',
                    'ĸ' => 'k',
                    'ł' | 'ŀ' | 'ľ' => 'l',
                    'ñ' | 'ń' | 'ň' => 'n',
                    'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ő' => 'o',
                    'ř' => 'r',
                    'ś' | 'š' | 'ş' => 's',
                    'ť' | 'ŧ' | 'ţ' => 't',
                    'ù' | 'ú' | 'û' | 'ü' | 'ū' | 'ů' | 'ű' => 'u',
                    'ý' | 'ÿ' => 'y',
                    'ź' | 'ż' | 'ž' => 'z',
                    _ => continue,
                };
                out.push(plain);
            }
        }
    }
    out
}

// ── 2FA Directory ──────────────────────────────────────────

/// An entry of 2FA Directory: its name, its domains (made plain), and its logo.
struct Site {
    name: String,
    domains: Vec<String>,
    logo: Option<Vec<u8>>,
}

/// Every entry under `entries/`, in the order of their files.
fn twofa_sites(dir: &Path) -> Result<Vec<Site>, String> {
    let mut files = Vec::new();
    let entries = dir.join("entries");
    for letter in std::fs::read_dir(&entries).map_err(|error| format!("{}: {error}", entries.display()))? {
        let letter = letter.map_err(|error| error.to_string())?.path();
        for file in std::fs::read_dir(&letter).map_err(|error| error.to_string())?.flatten() {
            if file.path().extension().is_some_and(|extension| extension == "json") {
                files.push(file.path());
            }
        }
    }
    files.sort();
    let sites = par_map(&files, |file| {
        let mut found = Vec::new();
        let Some(Ok(Value::Object(entry))) = read(file).map(|bytes| serde_json::from_slice::<Value>(&bytes)) else {
            return found;
        };
        for (name, site) in entry {
            let Some(domain) = site.get("domain").and_then(Value::as_str) else { continue };
            let more = site.get("additional-domains").and_then(Value::as_array).cloned().unwrap_or_default();
            let domains: Vec<String> = std::iter::once(domain)
                .chain(more.iter().filter_map(Value::as_str))
                .filter_map(icon_fetch::normalize_host)
                .collect();
            let logo = match site.get("img").and_then(Value::as_str) {
                Some(image) => logo_file(dir, image).and_then(|path| read(&path)),
                None => [format!("{domain}.svg"), format!("{domain}.png")]
                    .iter()
                    .find_map(|image| logo_file(dir, image).and_then(|path| read(&path))),
            };
            let logo = logo.filter(|bytes| visible(bytes, icon_fetch::AUTO_PIXELS).is_some());
            found.push(Site { name, domains, logo });
        }
        found
    });
    Ok(sites.into_iter().flatten().collect())
}

/// `img/<first letter>/<file>`, for a plain file name only.
fn logo_file(dir: &Path, image: &str) -> Option<PathBuf> {
    let plain = !image.is_empty()
        && !image.starts_with('.')
        && image.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    let first = image.chars().next()?.to_ascii_lowercase();
    plain.then(|| dir.join("img").join(first.to_string()).join(image))
}

fn twofa(sites: &[Site], about: About) -> Built {
    let mut writer = Writer::new(about);
    let mut skipped = 0;
    let mut domains = BTreeSet::new();
    for site in sites {
        let Some(logo) = &site.logo else {
            skipped += 1;
            continue;
        };
        let icon = writer.icon(logo, kind(logo));
        for domain in &site.domains {
            writer.domain(domain, icon);
            domains.insert(domain.clone());
        }
    }
    let icons = writer.icons.len();
    Built { id: TWOFA, pack: writer.finish(), icons, domains: domains.len(), names: 0, skipped }
}

// ── Simple Icons ───────────────────────────────────────────

/// `slugs.md`: `| \`Title\` | \`slug\` |` a line.
fn slugs(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('`').collect();
            (parts.len() >= 5 && line.starts_with("| `")).then(|| (parts[1].to_string(), parts[3].to_string()))
        })
        .collect()
}

/// The `d` of the icon's one `<path>`.
fn glyph(svg: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(svg).ok()?;
    let doc = resvg::usvg::roxmltree::Document::parse(text).ok()?;
    let path = doc.descendants().find(|node| node.has_tag_name("path"))?;
    let d = path.attribute("d")?;
    d.bytes().all(|b| b.is_ascii_alphanumeric() || b" .,-+".contains(&b)).then(|| d.to_string())
}

/// The relative luminance of an sRGB colour (WCAG).
fn luminance(rgb: [u8; 3]) -> f64 {
    let channel = |value: u8| {
        let value = f64::from(value) / 255.0;
        if value <= 0.03928 { value / 12.92 } else { ((value + 0.055) / 1.055).powf(2.4) }
    };
    0.2126 * channel(rgb[0]) + 0.7152 * channel(rgb[1]) + 0.0722 * channel(rgb[2])
}

/// The glyph on a rounded tile of the brand's colour.
pub fn tile(hex: &str, d: &str) -> Option<String> {
    if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let value = |at: usize| u8::from_str_radix(&hex[at..at + 2], 16).ok();
    let rgb = [value(0)?, value(2)?, value(4)?];
    let light = luminance(rgb);
    const DARK: [u8; 3] = [0x1b, 0x1b, 0x1f];
    let contrast = |a: f64, b: f64| (a.max(b) + 0.05) / (a.min(b) + 0.05);
    let ink = if contrast(light, 1.0) >= contrast(light, luminance(DARK)) { "#ffffff" } else { "#1b1b1f" };
    let edge = if light > 0.8 {
        r##" stroke="#000000" stroke-opacity=".16""##
    } else if light < 0.02 {
        r##" stroke="#ffffff" stroke-opacity=".24""##
    } else {
        ""
    };
    let hex = hex.to_ascii_lowercase();
    Some(format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect x=".5" y=".5" width="31" height="31" rx="7" fill="#{hex}"{edge}/><path transform="translate(6.4 6.4) scale(.8)" fill="{ink}" d="{d}"/></svg>"##
    ))
}

fn simple(dir: &Path, sites: &[Site], about: About) -> Result<Built, String> {
    let data =
        read_up_to(&dir.join("data/simple-icons.json"), LIST_BYTES).ok_or("simple-icons: no data/simple-icons.json")?;
    let data: Vec<Value> = serde_json::from_slice(&data).map_err(|error| format!("simple-icons.json: {error}"))?;
    let slugs = slugs(&std::fs::read_to_string(dir.join("slugs.md")).map_err(|error| format!("slugs.md: {error}"))?);

    // 2FA Directory by the slug of its names, and by the name of its registrable domains.
    let mut by_title: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    let mut by_label: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for site in sites {
        for domain in &site.domains {
            by_title.entry(slug(&site.name)).or_default().push(domain);
            if icon_fetch::base_domain(domain).is_none()
                && let Some(label) = domain.split('.').next()
            {
                by_label.entry(slug(label)).or_default().push(domain);
            }
        }
    }

    let tiles = par_map(&data, |entry| {
        if entry.get("license").is_some() || entry.get("guidelines").is_some() {
            return None;
        }
        let title = entry.get("title")?.as_str()?;
        let slug_of = match entry.get("slug").and_then(Value::as_str) {
            Some(slug) => slug.to_string(),
            None => slugs.get(title)?.clone(),
        };
        if slug_of.is_empty() || !slug_of.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            return None;
        }
        let d = glyph(&read(&dir.join("icons").join(format!("{slug_of}.svg")))?)?;
        let svg = tile(entry.get("hex")?.as_str()?, &d)?;
        visible(svg.as_bytes(), icon_fetch::AUTO_PIXELS)?;
        Some((slug_of, svg))
    });

    let mut writer = Writer::new(about);
    let mut skipped = 0;
    // Domain → (strong claims, weak claims), as icon numbers.
    let mut claims: BTreeMap<String, (BTreeSet<u32>, BTreeSet<u32>)> = BTreeMap::new();
    for (entry, made) in data.iter().zip(tiles) {
        let Some((slug_of, svg)) = made else {
            skipped += 1;
            continue;
        };
        let icon = writer.icon(svg.as_bytes(), Kind::Svg);
        let mut keys = BTreeSet::from([slug_of.clone()]);
        if let Some(aka) = entry.pointer("/aliases/aka").and_then(Value::as_array) {
            keys.extend(aka.iter().filter_map(Value::as_str).map(slug).filter(|key| key.len() >= 3));
        }
        for key in &keys {
            for domain in by_title.get(key).into_iter().flatten() {
                claims.entry(domain.to_string()).or_default().0.insert(icon);
            }
            for domain in by_label.get(key).into_iter().flatten() {
                claims.entry(domain.to_string()).or_default().1.insert(icon);
            }
        }
        let source = entry.get("source").and_then(Value::as_str).and_then(|source| url::Url::parse(source).ok());
        if let Some(host) = source.as_ref().and_then(|url| url.host_str()).and_then(icon_fetch::normalize_host) {
            let site = icon_fetch::base_domain(&host).unwrap_or(host);
            if site.split('.').next().is_some_and(|label| keys.contains(&slug(label))) {
                claims.entry(site).or_default().1.insert(icon);
            }
        }
    }
    let mut domains = 0;
    for (domain, (strong, weak)) in claims {
        let only = if strong.is_empty() { weak } else { strong };
        if only.len() == 1 {
            writer.domain(&domain, *only.first().expect("one"));
            domains += 1;
        }
    }
    let icons = writer.icons.len();
    Ok(Built { id: SIMPLE, pack: writer.finish(), icons, domains, names: 0, skipped })
}

// ── Dashboard Icons ────────────────────────────────────────

/// `home-assistant` as `Home Assistant`.
fn display_name(id: &str) -> String {
    id.split(['-', '_'])
        .filter(|word| !word.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            chars.next().map(|first| first.to_ascii_uppercase().to_string() + chars.as_str()).unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A name as a device would be called: lower case, words joined by dashes.
fn name_key(name: &str) -> String {
    let lower = name.to_lowercase();
    let words: Vec<&str> = lower.split(|c: char| !c.is_ascii_alphanumeric()).filter(|word| !word.is_empty()).collect();
    words.join("-")
}

fn dashboard(dir: &Path, about: About) -> Result<Built, String> {
    let metadata = read_up_to(&dir.join("metadata.json"), LIST_BYTES).ok_or("dashboard-icons: no metadata.json")?;
    let metadata: BTreeMap<String, Value> =
        serde_json::from_slice(&metadata).map_err(|error| format!("metadata.json: {error}"))?;
    let ids: Vec<(&String, &Value)> = metadata
        .iter()
        .filter(|(id, _)| {
            (1..=100).contains(&id.len())
                && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        .collect();
    let made = par_map(&ids, |(id, meta)| {
        let svg = read(&dir.join("svg").join(format!("{id}.svg")));
        let svg_png = svg.as_deref().and_then(|svg| visible(svg, DASHBOARD_PIXELS));
        let png = match &svg_png {
            Some(png) if meta.get("base").and_then(Value::as_str) != Some("png") => Some(png.clone()),
            _ => read(&dir.join("png").join(format!("{id}.png"))).and_then(|png| visible(&png, DASHBOARD_PIXELS)),
        }
        .and_then(|png| smallest_png(&png));
        let plain_svg = svg.filter(|svg| {
            let text = String::from_utf8_lossy(svg);
            svg_png.is_some() && svg.len() <= SVG_KEPT && !text.contains("<image") && !text.contains("data:")
        });
        match (plain_svg, png) {
            (Some(svg), Some(png)) if svg.len() <= png.len() => Some((svg, Kind::Svg)),
            (_, Some(png)) => Some((png, Kind::Png)),
            (Some(svg), None) => Some((svg, Kind::Svg)),
            (None, None) => None,
        }
    });

    let mut writer = Writer::new(about);
    let mut skipped = 0;
    let mut aliases = Vec::new();
    for ((id, meta), made) in ids.iter().zip(made) {
        let Some((bytes, kind)) = made else {
            skipped += 1;
            continue;
        };
        let icon = writer.icon(&bytes, kind);
        writer.name(id, icon);
        let words: Vec<String> = meta
            .get("aliases")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|alias| (1..=60).contains(&alias.len()))
            .take(10)
            .map(str::to_string)
            .collect();
        aliases.push((id.to_string(), words.clone(), icon));
        writer.library(LibraryEntry { id: id.to_string(), name: display_name(id), aliases: words, icon });
    }
    // Ids first, then the same without dashes, then aliases: an alias never takes another's id.
    for (id, _, icon) in &aliases {
        writer.name(&id.replace('-', ""), *icon);
    }
    for (_, words, icon) in &aliases {
        for alias in words {
            let key = name_key(alias);
            if !key.is_empty() {
                writer.name(&key, *icon);
                writer.name(&key.replace('-', ""), *icon);
            }
        }
    }
    let (icons, names) = (writer.icons.len(), writer.names.len());
    Ok(Built { id: DASHBOARD, pack: writer.finish(), icons, domains: 0, names, skipped })
}
