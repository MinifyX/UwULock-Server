//! Fetching from the internet on nobody's behalf but the server's: websites' icons and the icon
//! library (docs/uwu-api.md §7). The host comes from whoever asks, so this is where the server
//! must not be turned against its own network:
//!
//! - Every name is looked up here, and **every** address it has is checked: loopback, private,
//!   CGNAT, link-local, unique-local, multicast, documentation, benchmarking and the other
//!   special ranges (also inside IPv4-mapped, 6to4, NAT64 and Teredo addresses) are refused.
//!   The connection goes to exactly the addresses that were checked — there is no second
//!   lookup a DNS server could answer differently (DNS rebinding).
//! - Redirects (at most five) are checked the same way before they are followed: http or https,
//!   the usual ports, no addresses of the local network, no names that are local.
//! - Connecting takes at most 5 s, everything at most 10 s; a page is read up to 512 KiB, an
//!   icon up to 512 KiB, and an image is decoded only up to 2048 × 2048 pixels and 64 MiB, so a
//!   small file that unpacks into a huge one is refused.
//! - What an icon is, is decided by its first bytes, not by what the site says it is.
//!
//! Tests reach fake websites on 127.0.0.1: they hand [`Upstream`] a list of names answered
//! without DNS, the addresses allowed despite the checks, and the ports to use. A server builds
//! it with [`Upstream::default`], which allows nothing of the kind.

use image::ImageFormat;
use std::collections::HashMap;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// A page is read this far: its `<head>` is all that is needed.
pub const PAGE_BYTES: usize = 512 * 1024;
/// The largest icon file taken.
pub const ICON_BYTES: usize = 512 * 1024;
/// Automatic icons are handed out at most this large.
pub const AUTO_PIXELS: u32 = 64;
/// Library icons at most this large.
pub const LIBRARY_PIXELS: u32 = 128;
/// Everything one fetch does, at most.
pub const WHOLE: Duration = Duration::from_secs(10);
const REDIRECTS: usize = 5;
/// Images are decoded up to this size, and no more memory than this.
const DECODE_PIXELS: u32 = 2048;
const DECODE_BYTES: u64 = 64 * 1024 * 1024;

/// Where the fetches go. Only tests change it.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// Names answered without asking DNS.
    pub fixed: HashMap<String, Vec<IpAddr>>,
    /// Addresses let through although the checks would refuse them.
    pub allowed: Vec<IpAddr>,
    /// The ports of https and http.
    pub https_port: u16,
    pub http_port: u16,
    /// Where the selfh.st icons are: their index and their files.
    pub selfhst: String,
    /// 2FA Directory's list of sites and the second factors they offer.
    pub twofa: String,
}

impl Default for Upstream {
    fn default() -> Self {
        Upstream {
            fixed: HashMap::new(),
            allowed: Vec::new(),
            https_port: 443,
            http_port: 80,
            selfhst: "https://cdn.jsdelivr.net/gh/selfhst/icons@main".into(),
            twofa: crate::reports::UPSTREAM.into(),
        }
    }
}

impl Upstream {
    fn allows(&self, ip: IpAddr) -> bool {
        self.allowed.contains(&ip) || public(ip)
    }

    fn port_ok(&self, url: &url::Url) -> bool {
        match url.port() {
            None => true,
            Some(port) => port == self.https_port || port == self.http_port,
        }
    }

    /// Whether the server may go to `url` at all: http or https, no credentials, one of the
    /// usual ports, and a host that is neither a local name nor a refused address.
    pub fn url_ok(&self, url: &url::Url) -> bool {
        if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty() || url.password().is_some() {
            return false;
        }
        if !self.port_ok(url) {
            return false;
        }
        match url.host() {
            Some(url::Host::Domain(name)) => {
                self.fixed.contains_key(name) || normalize_host(name).is_some_and(|normal| normal == name)
            }
            Some(url::Host::Ipv4(ip)) => self.allows(IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => self.allows(IpAddr::V6(ip)),
            None => false,
        }
    }
}

// ── Addresses ─────────────────────────────────────────────

/// Whether `ip` is an address on the public internet: none of the special ranges.
pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => public_v6(ip),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let refused = a == 0                                  // "this network"
        || a == 10                                        // private
        || a == 127                                       // loopback
        || (a == 100 && (64..128).contains(&b))           // CGNAT
        || (a == 169 && b == 254)                         // link-local
        || (a == 172 && (16..32).contains(&b))            // private
        || (a == 192 && b == 0 && c == 0)                 // IETF protocol assignments
        || (a == 192 && b == 0 && c == 2)                 // documentation
        || (a == 192 && b == 88 && c == 99)               // 6to4 relay anycast
        || (a == 192 && b == 168)                         // private
        || (a == 198 && (b == 18 || b == 19))             // benchmarking
        || (a == 198 && b == 51 && c == 100)              // documentation
        || (a == 203 && b == 0 && c == 113)               // documentation
        || a >= 224; // multicast, reserved, broadcast
    !refused
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    // IPv4 inside: mapped (::ffff:a.b.c.d), compatible (::a.b.c.d), NAT64 (64:ff9b::/96).
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    if segments[..6] == [0, 0, 0, 0, 0, 0] {
        return public_v4(Ipv4Addr::from(((segments[6] as u32) << 16) | segments[7] as u32));
    }
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] || segments[..3] == [0x64, 0xff9b, 1] {
        return public_v4(Ipv4Addr::from(((segments[6] as u32) << 16) | segments[7] as u32));
    }
    // 6to4 (2002::/16) carries an IPv4 address in the next 32 bits.
    if segments[0] == 0x2002 {
        return public_v4(Ipv4Addr::from(((segments[1] as u32) << 16) | segments[2] as u32));
    }
    // Teredo (2001::/32): the client's address, inverted, in the last 32 bits; refused whole,
    // since the server it names is somebody's relay anyway.
    if segments[0] == 0x2001 && segments[1] == 0 {
        return false;
    }
    let refused = (segments[0] & 0xfe00) == 0xfc00      // unique local
        || (segments[0] & 0xffc0) == 0xfe80              // link-local
        || (segments[0] & 0xffc0) == 0xfec0              // site-local (deprecated)
        || (segments[0] == 0x2001 && segments[1] == 0xdb8) // documentation
        || (segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0010) // ORCHID
        || (segments[0] == 0x2001 && segments[1] == 0x2 && segments[2] == 0) // benchmarking
        || (segments[0] == 0x0100 && segments[1..4] == [0, 0, 0]) // discard-only
        || segments[0] == 0x3fff && segments[1] < 0x1000; // documentation (2024)
    !refused
}

/// Last labels of names that are never on the internet, or not on the public one.
const LOCAL_ENDINGS: [&str; 14] = [
    "local",
    "lan",
    "home",
    "internal",
    "intranet",
    "localhost",
    "localdomain",
    "test",
    "invalid",
    "example",
    "onion",
    "arpa",
    "corp",
    "private",
];

/// A host as the clients put it into `/icons/<host>/icon.png`, made plain: percent-decoded,
/// lower case, IDNA as ASCII, without a trailing dot. None for anything that is not a public
/// name with a dot: IP addresses, local names, and whatever is not a hostname at all.
pub fn normalize_host(raw: &str) -> Option<String> {
    let decoded = percent_decode(raw)?;
    let trimmed = decoded.strip_suffix('.').unwrap_or(&decoded);
    if trimmed.is_empty() || trimmed.len() > 253 {
        return None;
    }
    let host = match url::Host::parse(trimmed).ok()? {
        url::Host::Domain(name) => name.to_ascii_lowercase(),
        _ => return None,
    };
    if host.len() > 253 || !host.contains('.') {
        return None;
    }
    let labels_ok = host.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if !labels_ok {
        return None;
    }
    let last = host.rsplit('.').next()?;
    // A name that is all digits in its last label reads as an address somewhere.
    if LOCAL_ENDINGS.contains(&last) || last.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(host)
}

fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

// ── The HTTP client ───────────────────────────────────────

/// Looks names up, and hands on only what passed the checks — and nothing, if one address
/// did not.
struct Resolver {
    upstream: Arc<Upstream>,
}

impl reqwest::dns::Resolve for Resolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let upstream = self.upstream.clone();
        let name = name.as_str().to_ascii_lowercase();
        Box::pin(async move {
            let addresses: Vec<IpAddr> = match upstream.fixed.get(&name) {
                Some(fixed) => fixed.clone(),
                None => {
                    if normalize_host(&name).is_none() {
                        return Err(refused("not a public name"));
                    }
                    tokio::net::lookup_host((name.as_str(), 0)).await?.map(|address| address.ip()).collect()
                }
            };
            if addresses.is_empty() || addresses.iter().any(|ip| !upstream.allows(*ip)) {
                return Err(refused("an address that is not public"));
            }
            let addresses: Box<dyn Iterator<Item = SocketAddr> + Send> =
                Box::new(addresses.into_iter().map(|ip| SocketAddr::new(ip, 0)).collect::<Vec<_>>().into_iter());
            Ok(addresses)
        })
    }
}

fn refused(why: &str) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::new(std::io::ErrorKind::PermissionDenied, why.to_string()))
}

/// The client for fetching icons: the checked lookups above, checked redirects, the limits.
pub fn client(upstream: Arc<Upstream>) -> Result<reqwest::Client, String> {
    let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let checking = upstream.clone();
    let redirects = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= REDIRECTS {
            attempt.error("too many redirects")
        } else if !checking.url_ok(attempt.url()) {
            attempt.error("a redirect to where the server does not go")
        } else {
            attempt.follow()
        }
    });
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .user_agent(concat!("Mozilla/5.0 (compatible; UwULock-Server/", env!("CARGO_PKG_VERSION"), "; icons)"))
        .dns_resolver(Arc::new(Resolver { upstream }))
        .redirect(redirects)
        // A proxy from the environment would do the lookup itself, past every check here.
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(WHOLE)
        .build()
        .map_err(|error| error.to_string())
}

/// What a fetch brought: where it ended up after redirects, and the bytes, at most `limit` of
/// them. `cut` is whether there was more.
pub struct Fetched {
    pub url: url::Url,
    pub status: u16,
    pub bytes: Vec<u8>,
    pub cut: bool,
}

/// GET `url`, reading at most `limit` bytes.
pub async fn get(
    client: &reqwest::Client,
    upstream: &Upstream,
    url: url::Url,
    limit: usize,
) -> Result<Fetched, String> {
    if !upstream.url_ok(&url) {
        return Err("refused".into());
    }
    let mut response = client
        .get(url)
        .header("accept", "text/html,image/*;q=0.9,*/*;q=0.5")
        .send()
        .await
        .map_err(|error| crate::outbound::error_text(&error))?;
    let url = response.url().clone();
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    let mut cut = false;
    while let Some(chunk) = response.chunk().await.map_err(|error| crate::outbound::error_text(&error))? {
        if bytes.len() + chunk.len() > limit {
            bytes.extend_from_slice(&chunk[..limit - bytes.len()]);
            cut = true;
            break;
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Fetched { url, status, bytes, cut })
}

// ── Pages ─────────────────────────────────────────────────

/// An icon a page names: where, and the size it says it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub url: String,
    /// The largest size in `sizes`, if it says one.
    pub size: Option<u32>,
}

/// The `<link rel="icon">`s (and their relatives) of a page, resolved against `base` (or the
/// page's `<base href>`).
pub fn icon_links(html: &str, base: &url::Url) -> Vec<Candidate> {
    let mut base = base.clone();
    let mut found = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut at = 0;
    while let Some(start) = find_tag(&lower, at) {
        let (name, attributes, end) = read_tag(html, start);
        at = end.max(start + 1);
        match name.as_str() {
            "base" => {
                if let Some(href) = attribute(&attributes, "href").and_then(|href| base.join(href).ok()) {
                    base = href;
                }
            }
            "link" => {
                let rel = attribute(&attributes, "rel").unwrap_or_default().to_ascii_lowercase();
                let icon = rel
                    .split_ascii_whitespace()
                    .any(|word| matches!(word, "icon" | "apple-touch-icon" | "apple-touch-icon-precomposed"));
                if !icon {
                    continue;
                }
                let Some(href) = attribute(&attributes, "href").filter(|href| !href.trim().is_empty()) else {
                    continue;
                };
                let size = attribute(&attributes, "sizes").and_then(|sizes| {
                    sizes
                        .split_ascii_whitespace()
                        .filter_map(|size| size.to_ascii_lowercase().split_once('x').and_then(|(w, _)| w.parse().ok()))
                        .max()
                });
                if href.trim_start().starts_with("data:") {
                    found.push(Candidate { url: href.trim().to_string(), size });
                } else if let Ok(url) = base.join(href.trim()) {
                    found.push(Candidate { url: url.to_string(), size });
                }
            }
            "body" => break,
            _ => {}
        }
        if found.len() >= 20 {
            break;
        }
    }
    found
}

/// Where the next tag starts, skipping comments and scripts.
fn find_tag(lower: &str, from: usize) -> Option<usize> {
    let mut at = from;
    loop {
        let start = at + lower.get(at..)?.find('<')?;
        let rest = &lower[start..];
        if rest.starts_with("<!--") {
            at = start + rest.find("-->").map_or(rest.len(), |end| end + 3);
        } else if rest.starts_with("<script") || rest.starts_with("<style") {
            let close = if rest.starts_with("<script") { "</script" } else { "</style" };
            at = start + rest.find(close).unwrap_or(rest.len());
        } else {
            return Some(start);
        }
    }
}

/// A tag's name, its attributes and where it ends.
fn read_tag(html: &str, start: usize) -> (String, Vec<(String, String)>, usize) {
    let bytes = html.as_bytes();
    let mut index = start + 1;
    let name_start = index;
    while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'-') {
        index += 1;
    }
    let name = html[name_start..index].to_ascii_lowercase();
    let mut attributes = Vec::new();
    loop {
        while index < bytes.len() && (bytes[index].is_ascii_whitespace() || bytes[index] == b'/') {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] == b'>' {
            return (name, attributes, index + 1);
        }
        let key_start = index;
        while index < bytes.len() && !bytes[index].is_ascii_whitespace() && !matches!(bytes[index], b'=' | b'>' | b'/')
        {
            index += 1;
        }
        let key = html[key_start..index].to_ascii_lowercase();
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let mut value = String::new();
        if index < bytes.len() && bytes[index] == b'=' {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if index < bytes.len() && (bytes[index] == b'"' || bytes[index] == b'\'') {
                let quote = bytes[index];
                let value_start = index + 1;
                index = value_start;
                while index < bytes.len() && bytes[index] != quote {
                    index += 1;
                }
                value = html[value_start..index.min(bytes.len())].to_string();
                index += 1;
            } else {
                let value_start = index;
                while index < bytes.len() && !bytes[index].is_ascii_whitespace() && bytes[index] != b'>' {
                    index += 1;
                }
                value = html[value_start..index].to_string();
            }
        }
        if key.is_empty() {
            index += 1;
            continue;
        }
        attributes.push((key, decode_entities(&value)));
    }
}

fn attribute<'a>(attributes: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attributes.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
}

fn decode_entities(text: &str) -> String {
    text.replace("&amp;", "&").replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">")
}

/// The bytes of a `data:` URL, at most [`ICON_BYTES`] of them.
pub fn data_url(url: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let rest = url.trim().strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    let bytes = if meta.ends_with(";base64") {
        let cleaned: String = data.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        base64::engine::general_purpose::STANDARD.decode(cleaned).ok()?
    } else {
        percent_decode(data).map(String::into_bytes)?
    };
    (bytes.len() <= ICON_BYTES).then_some(bytes)
}

// ── Images ────────────────────────────────────────────────

/// What an image file is, by its first bytes.
fn sniff(bytes: &[u8]) -> Option<ImageFormat> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(ImageFormat::Png)
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some(ImageFormat::Jpeg)
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some(ImageFormat::Gif)
    } else if bytes.len() > 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some(ImageFormat::WebP)
    } else if bytes.starts_with(&[0, 0, 1, 0]) {
        Some(ImageFormat::Ico)
    } else {
        None
    }
}

fn looks_like_svg(bytes: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(2048)]).to_ascii_lowercase();
    head.contains("<svg")
}

/// An image, read and made a PNG of at most `pixels` × `pixels` (never made larger), with the
/// size it had. None for anything that is not an image this reads, or too large to unpack.
pub fn to_png(bytes: &[u8], pixels: u32) -> Option<(Vec<u8>, u32)> {
    let image = match sniff(bytes) {
        Some(format) => {
            let mut reader = image::ImageReader::with_format(Cursor::new(bytes), format);
            let mut limits = image::Limits::default();
            limits.max_image_width = Some(DECODE_PIXELS);
            limits.max_image_height = Some(DECODE_PIXELS);
            limits.max_alloc = Some(DECODE_BYTES);
            reader.limits(limits);
            reader.decode().ok()?
        }
        None if looks_like_svg(bytes) => svg(bytes, pixels)?,
        None => return None,
    };
    let (width, height) = (image.width(), image.height());
    if width == 0 || height == 0 {
        return None;
    }
    let size = width.max(height);
    let image = if size > pixels { image.resize(pixels, pixels, image::imageops::FilterType::Lanczos3) } else { image };
    let mut png = Vec::new();
    image.to_rgba8().write_to(&mut Cursor::new(&mut png), ImageFormat::Png).ok()?;
    Some((png, size))
}

/// An SVG drawn at `pixels` × `pixels`: without text, fonts or images it points to — nothing
/// outside the file is read.
fn svg(bytes: &[u8], pixels: u32) -> Option<image::DynamicImage> {
    let text = std::str::from_utf8(bytes).ok()?;
    let lower = text.to_ascii_lowercase();
    // Entities and `<use>` are how a small file becomes a huge drawing.
    if lower.contains("<!entity") || lower.matches("<use").count() > 16 {
        return None;
    }
    let options = resvg::usvg::Options {
        resources_dir: None,
        image_href_resolver: resvg::usvg::ImageHrefResolver {
            resolve_data: Box::new(|_, _, _| None),
            resolve_string: Box::new(|_, _| None),
        },
        ..resvg::usvg::Options::default()
    };
    let tree = resvg::usvg::Tree::from_str(text, &options).ok()?;
    let size = tree.size();
    let scale = pixels as f32 / size.width().max(size.height()).max(1.0);
    let (width, height) = (
        ((size.width() * scale).round() as u32).clamp(1, pixels),
        ((size.height() * scale).round() as u32).clamp(1, pixels),
    );
    let mut pixmap = resvg::tiny_skia::Pixmap::new(width, height)?;
    resvg::render(&tree, resvg::tiny_skia::Transform::from_scale(scale, scale), &mut pixmap.as_mut());
    let rgba: Vec<u8> = pixmap
        .pixels()
        .iter()
        .flat_map(|pixel| {
            let color = pixel.demultiply();
            [color.red(), color.green(), color.blue(), color.alpha()]
        })
        .collect();
    image::RgbaImage::from_raw(width, height, rgba).map(image::DynamicImage::ImageRgba8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a00:1",
            "2002:7f00:1::",
            "2002:c0a8:0101::1",
            "2001:0:4136:e378::1",
            "2001:db8::1",
            "3fff::1",
        ] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "::ffff:1.1.1.1", "2002:0101:0101::1"] {
            assert!(public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn hosts_are_public_names() {
        assert_eq!(normalize_host("Shop.Example.COM.").as_deref(), Some("shop.example.com"));
        assert_eq!(normalize_host("b%C3%BCcher.example.com").as_deref(), Some("xn--bcher-kva.example.com"));
        assert_eq!(normalize_host("bücher.example.com").as_deref(), Some("xn--bcher-kva.example.com"));
        for bad in [
            "localhost",
            "nas",
            "nas.local",
            "router.lan",
            "printer.home",
            "wiki.internal",
            "192.168.1.1",
            "127.0.0.1",
            "[::1]",
            "0x7f.1",
            "2130706433",
            "a.test",
            "b.example",
            "c.invalid",
            "shop.example.com:8080",
            "shop.example.com/path",
            "user@shop.example.com",
            "",
            "a..b",
        ] {
            assert_eq!(normalize_host(bad), None, "{bad}");
        }
    }

    #[test]
    fn redirects_stay_on_the_internet() {
        let upstream = Upstream::default();
        let ok = |url: &str| upstream.url_ok(&url::Url::parse(url).unwrap());
        assert!(ok("https://shop.example.com/favicon.ico"));
        assert!(ok("http://shop.example.com:80/"));
        assert!(!ok("https://shop.example.com:8443/"), "an unusual port");
        assert!(!ok("http://127.0.0.1/"));
        assert!(!ok("http://[::1]/"));
        assert!(!ok("http://169.254.169.254/latest/meta-data"));
        assert!(!ok("http://nas.local/"));
        assert!(!ok("ftp://shop.example.com/"));
        assert!(!ok("https://user:pw@shop.example.com/"));
        assert!(ok("https://1.1.1.1/"));
    }

    #[test]
    fn links_in_a_head() {
        let base = url::Url::parse("https://shop.example.com/de/index.html").unwrap();
        let html = r#"<!doctype html><html><head>
            <!-- <link rel="icon" href="/commented.png"> -->
            <script>var x = '<link rel="icon" href="/script.png">';</script>
            <link rel="stylesheet" href="/style.css">
            <link rel="shortcut icon" href="/favicon.ico">
            <LINK REL="apple-touch-icon" SIZES="180x180" HREF="touch.png">
            <link rel=icon sizes="16x16 32x32" href='//cdn.example.net/i.png?a=1&amp;b=2'>
            <link rel="icon" href="data:image/png;base64,iVBORw0KGgo=">
            </head><body><link rel="icon" href="/late.png"></body></html>"#;
        let links = icon_links(html, &base);
        let urls: Vec<&str> = links.iter().map(|link| link.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://shop.example.com/favicon.ico",
                "https://shop.example.com/de/touch.png",
                "https://cdn.example.net/i.png?a=1&b=2",
                "data:image/png;base64,iVBORw0KGgo=",
            ]
        );
        assert_eq!(links[1].size, Some(180));
        assert_eq!(links[2].size, Some(32));
    }

    fn png_of(width: u32, height: u32) -> Vec<u8> {
        let mut png = Vec::new();
        image::RgbaImage::from_pixel(width, height, image::Rgba([200, 30, 90, 255]))
            .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
            .unwrap();
        png
    }

    #[test]
    fn images_become_small_pngs() {
        let (png, size) = to_png(&png_of(256, 128), 64).unwrap();
        assert_eq!(size, 256);
        let image = image::load_from_memory(&png).unwrap();
        assert_eq!((image.width(), image.height()), (64, 32));
        let (png, _) = to_png(&png_of(16, 16), 64).unwrap();
        assert_eq!(image::load_from_memory(&png).unwrap().width(), 16, "never larger");

        let svg = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#f0a"/></svg>"##;
        let (png, _) = to_png(svg, 64).unwrap();
        assert_eq!(image::load_from_memory(&png).unwrap().width(), 64);
        let outside = br#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="8" height="8"><image href="/etc/passwd" width="8" height="8"/></svg>"#;
        assert!(to_png(outside, 64).is_some(), "drawn, without what it points to");
        let bomb = format!("<svg xmlns=\"http://www.w3.org/2000/svg\">{}</svg>", "<use href=\"#a\"/>".repeat(20));
        assert!(to_png(bomb.as_bytes(), 64).is_none());
        assert!(to_png(b"<html>no image</html>", 64).is_none());
        assert!(to_png(b"\x89PNG\r\n\x1a\nbroken", 64).is_none());
    }

    #[test]
    fn a_small_file_that_unpacks_into_a_huge_image_is_refused() {
        // 20000 × 20000 pixels of nothing: a few KiB as PNG, 1.6 GB unpacked.
        let mut png = Vec::new();
        let encoder = image::codecs::png::PngEncoder::new(&mut png);
        use image::ImageEncoder as _;
        let row = vec![0u8; 20_000];
        let mut data = Vec::with_capacity(20_000 * 100);
        for _ in 0..100 {
            data.extend_from_slice(&row);
        }
        // Only the header matters: the decoder refuses before it reads the pixels.
        encoder.write_image(&data, 20_000, 100, image::ExtendedColorType::L8).unwrap();
        let mut header = png.clone();
        header[16..20].copy_from_slice(&20_000u32.to_be_bytes());
        header[20..24].copy_from_slice(&20_000u32.to_be_bytes());
        assert!(to_png(&header, 64).is_none());
        assert!(to_png(&png, 64).is_none(), "wider than the decoder takes");
    }

    #[test]
    fn data_urls() {
        assert_eq!(data_url("data:image/png;base64,AAEC").unwrap(), [0, 1, 2]);
        assert_eq!(data_url("data:image/svg+xml,%3Csvg%3E").unwrap(), b"<svg>");
        assert!(data_url("https://shop.example.com/").is_none());
    }
}
