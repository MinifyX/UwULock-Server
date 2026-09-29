//! The server's own look (docs/uwu-api.md §14.4): a name, an accent colour, logos for the light
//! and the dark theme, and a favicon, for the web vault, the login, the Send and file-request
//! pages and the mails. The official clients stay as they are.
//!
//! Pictures come in as PNG, JPEG, WebP, GIF, ICO or SVG, recognised by their content, and are
//! kept as PNG the server drew itself: whatever else was in the file — metadata, scripts in an
//! SVG, a second image behind the first — never comes out again. An SVG is drawn without fonts,
//! text or anything it points to.
//!
//! What a page sees depends on the host it was opened on: the server's branding here, a send
//! domain's own with Stufe 6 ([`scope_for_host`] is where that plugs in).

use crate::auth::Admin;
use crate::errors::{ApiError, ApiResult};
use crate::palette::{self, Rgb};
use crate::{AppState, icon_fetch};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use parking_lot::RwLock;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use uwulock_store::branding::{Branding, Image, SERVER};

/// UwULock's own name and colour, when the admin chose none.
pub const DEFAULT_NAME: &str = "UwULock";
pub const DEFAULT_COLOR: &str = "#ff4d8d";
/// The largest logo file taken, and the largest favicon.
pub const LOGO_BYTES: usize = 512 * 1024;
pub const FAVICON_BYTES: usize = 128 * 1024;
/// Logos are kept at most this wide or high, favicons this large.
const LOGO_PIXELS: u32 = 512;
const FAVICON_PIXELS: u32 = 192;
/// A name longer than this does not fit the title bar.
const NAME_CHARS: usize = 40;
/// The contrast an accent colour needs against white and against the dark theme's background.
const MIN_CONTRAST: f64 = 3.0;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/branding", get(public))
        .route("/uwu/v1/branding/logo/{variant}", get(logo))
        .route("/uwu/v1/branding/favicon", get(favicon))
        .route("/uwu/v1/admin/branding", get(admin_get).put(admin_set))
        .route("/uwu/v1/admin/branding/preview", get(preview))
        .route("/uwu/v1/admin/branding/logo/{variant}", put(upload_logo).delete(remove_logo))
        .route("/uwu/v1/admin/branding/favicon", put(upload_favicon).delete(remove_favicon))
}

/// One scope's branding as it is handed out, worked out once.
pub struct Loaded {
    pub stored: Branding,
    /// Changes whenever anything changed: for the pictures' URLs, so browsers fetch them again.
    pub version: String,
    /// The accent tokens for both themes; empty for UwULock's own colours.
    pub css: String,
}

impl Loaded {
    fn new(stored: Branding) -> Self {
        let version = crate::auth::sha256(stored.revision.as_bytes())[..6].iter().map(|b| format!("{b:02x}")).collect();
        let css = stored
            .color
            .as_deref()
            .and_then(palette::parse_hex)
            .map(|accent| palette::palette(accent).css())
            .unwrap_or_default();
        Loaded { stored, version, css }
    }

    pub fn custom(&self) -> bool {
        self.stored.custom()
    }

    pub fn name(&self) -> &str {
        self.stored.name.as_deref().unwrap_or(DEFAULT_NAME)
    }

    /// `{ name, color, custom, logoLight, logoDark, favicon }` with the pictures' URLs under `base`.
    pub fn json(&self, base: &str) -> Value {
        let base = base.trim_end_matches('/');
        let url =
            |present: bool, path: &str| present.then(|| format!("{base}/uwu/v1/branding/{path}?v={}", self.version));
        json!({
            "name": self.name(),
            "color": self.stored.color.as_deref().unwrap_or(DEFAULT_COLOR),
            "custom": self.custom(),
            "logoLight": url(self.stored.logo_light.is_some(), "logo/light"),
            "logoDark": url(self.stored.logo_dark.is_some(), "logo/dark"),
            "favicon": url(self.stored.favicon.is_some(), "favicon"),
        })
    }

    /// The look of the server's mails.
    fn mail_brand(&self) -> uwulock_mail::Brand {
        let mut brand = uwulock_mail::Brand::default();
        if let Some(name) = &self.stored.name {
            brand.name = name.clone();
            brand.custom_name = true;
        }
        if let Some(accent) = self.stored.color.as_deref().and_then(palette::parse_hex) {
            // The button carries white text: the shade made for that.
            let solid = palette::palette(accent).light.iter().find(|(name, _)| *name == "--uwu-pink-solid").cloned();
            if let Some((_, solid)) = solid {
                brand.color = solid;
            }
        }
        brand
    }
}

/// The branding of every scope asked for so far, read from the database once.
#[derive(Default)]
pub struct Cache {
    loaded: RwLock<HashMap<String, Arc<Loaded>>>,
}

impl Cache {
    /// Everything is read again next time: after a change or a restore.
    pub fn forget(&self) {
        self.loaded.write().clear();
    }
}

/// Which branding a request to `host` gets. Until Stufe 6 brings send domains, always the
/// server's; then a send domain's id, when it has branding of its own.
pub(crate) fn scope_for_host(_state: &AppState, _host: Option<&str>) -> String {
    SERVER.to_string()
}

/// The host a request was made to, for [`scope_for_host`]: `Host`, or `X-Forwarded-Host` behind
/// a proxy the server trusts. Lower case, without the port.
pub(crate) fn request_host(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let forwarded = state.config.trust_forwarded.then(|| headers.get("x-forwarded-host")).flatten();
    let value = forwarded.or_else(|| headers.get(header::HOST))?.to_str().ok()?;
    let host = value.split(',').next()?.trim().to_ascii_lowercase();
    // `[2001:db8::1]:443`, `lock.example.com:8443`, or no port.
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default().to_string(),
        None => host.split(':').next().unwrap_or_default().to_string(),
    };
    (!name.is_empty()).then_some(name)
}

/// The branding of `scope`, from memory or the database. UwULock's own when there is none or the
/// database does not answer.
pub(crate) async fn get_scope(state: &AppState, scope: &str) -> Arc<Loaded> {
    if let Some(loaded) = state.branding.loaded.read().get(scope) {
        return loaded.clone();
    }
    let stored = match state.store.branding(scope).await {
        Ok(stored) => stored.unwrap_or_else(|| Branding { scope: scope.to_string(), ..Branding::default() }),
        Err(error) => {
            tracing::warn!(%error, "the branding could not be read");
            return Arc::new(Loaded::new(Branding::default()));
        }
    };
    let loaded = Arc::new(Loaded::new(stored));
    state.branding.loaded.write().insert(scope.to_string(), loaded.clone());
    loaded
}

/// The branding a request gets, by the host it went to.
pub(crate) async fn for_request(state: &AppState, headers: &HeaderMap) -> Arc<Loaded> {
    let scope = scope_for_host(state, request_host(state, headers).as_deref());
    get_scope(state, &scope).await
}

/// After a change or a restore: read again, and the mails follow.
pub async fn reload(state: &AppState) {
    state.branding.forget();
    let server = get_scope(state, SERVER).await;
    state.mailer.set_brand(server.mail_brand());
}

// ── The page ──────────────────────────────────────────────

/// The web vault's `index.html` with the branding in it, so the title, the favicon and the
/// colours are right before any script runs. `None`: nothing to change.
pub(crate) fn brand_page(page: &str, loaded: &Loaded) -> Option<String> {
    if !loaded.custom() {
        return None;
    }
    let mut page = page.to_string();
    if loaded.stored.name.is_some()
        && let (Some(start), Some(end)) = (page.find("<title>"), page.find("</title>"))
        && start < end
    {
        page.replace_range(start..end + "</title>".len(), &format!("<title>{}</title>", escape(loaded.name())));
    }
    if loaded.stored.favicon.is_some()
        && let Some(start) = page.find("<link rel=\"icon\"")
        && let Some(length) = page[start..].find('>')
    {
        page.replace_range(
            start..start + length + 1,
            &format!("<link rel=\"icon\" type=\"image/png\" href=\"/uwu/v1/branding/favicon?v={}\" />", loaded.version),
        );
    }
    let mut head = String::new();
    if !loaded.css.is_empty() {
        head.push_str(&format!("<style id=\"uwu-branding\">{}</style>", loaded.css));
        if let Some(color) = &loaded.stored.color {
            head.push_str(&format!("<meta name=\"theme-color\" content=\"{}\" />", escape(color)));
        }
    }
    if let Some(end) = page.find("</head>") {
        page.insert_str(end, &head);
    }
    Some(page)
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

// ── Public ────────────────────────────────────────────────

async fn public(State(state): State<AppState>, headers: HeaderMap) -> Json<Value> {
    let loaded = for_request(&state, &headers).await;
    let mut body = loaded.json(&state.config.public);
    body["object"] = json!("branding");
    Json(body)
}

fn picture(bytes: Option<&Vec<u8>>) -> Response {
    let Some(bytes) = bytes else {
        return (StatusCode::NOT_FOUND, "No such picture").into_response();
    };
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("image/png")),
            (header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600")),
            (header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
            (header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox")),
        ],
        bytes.clone(),
    )
        .into_response()
}

fn logo_image(variant: &str) -> ApiResult<Image> {
    match variant {
        "light" => Ok(Image::LogoLight),
        "dark" => Ok(Image::LogoDark),
        _ => Err(ApiError::not_found("There is no such logo.")),
    }
}

async fn logo(State(state): State<AppState>, headers: HeaderMap, Path(variant): Path<String>) -> ApiResult<Response> {
    let image = logo_image(&variant)?;
    let loaded = for_request(&state, &headers).await;
    Ok(picture(match image {
        Image::LogoLight => loaded.stored.logo_light.as_ref(),
        _ => loaded.stored.logo_dark.as_ref(),
    }))
}

async fn favicon(State(state): State<AppState>, headers: HeaderMap) -> Response {
    picture(for_request(&state, &headers).await.stored.favicon.as_ref())
}

// ── Admin ─────────────────────────────────────────────────

/// What the admin portal shows: the public object, and the contrast of the colour.
async fn admin_get(State(state): State<AppState>, _admin: Admin) -> Json<Value> {
    let loaded = get_scope(&state, SERVER).await;
    let mut body = loaded.json(&state.config.public);
    body["object"] = json!("branding");
    body["nameSet"] = json!(loaded.stored.name.is_some());
    body["colorSet"] = json!(loaded.stored.color.is_some());
    body["contrast"] = contrast_of(loaded.stored.color.as_deref().unwrap_or(DEFAULT_COLOR));
    Json(body)
}

fn contrast_of(color: &str) -> Value {
    match palette::parse_hex(color) {
        Some(rgb) => json!({
            "light": round(palette::contrast(rgb, palette::WHITE)),
            "dark": round(palette::contrast(rgb, palette::DARK_CANVAS)),
            "ok": readable(rgb),
        }),
        None => Value::Null,
    }
}

fn round(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn readable(rgb: Rgb) -> bool {
    palette::contrast(rgb, palette::WHITE) >= MIN_CONTRAST
        && palette::contrast(rgb, palette::DARK_CANVAS) >= MIN_CONTRAST
}

#[derive(Deserialize)]
struct TextChange {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    color: Option<String>,
}

/// A name as it is kept: trimmed, without control characters, not too long; empty is none.
fn clean_name(name: Option<String>) -> ApiResult<Option<String>> {
    let Some(name) = name.map(|name| name.trim().to_string()).filter(|name| !name.is_empty()) else {
        return Ok(None);
    };
    if name.chars().any(char::is_control) {
        return Err(ApiError::bad("The name can't contain control characters.").code("brandName"));
    }
    if name.chars().count() > NAME_CHARS {
        return Err(ApiError::bad(format!("The name can have at most {NAME_CHARS} characters.")).code("brandName"));
    }
    Ok(Some(name))
}

/// A colour as it is kept: `#rrggbb`, lower case, readable on white and on the dark theme.
fn clean_color(color: Option<String>) -> ApiResult<Option<String>> {
    let Some(color) = color.map(|color| color.trim().to_ascii_lowercase()).filter(|color| !color.is_empty()) else {
        return Ok(None);
    };
    let rgb = palette::parse_hex(&color)
        .filter(|_| color.len() == 7)
        .ok_or_else(|| ApiError::bad("The colour has to be written like #ff4d8d.").code("brandColor"))?;
    if !readable(rgb) {
        return Err(ApiError::bad(format!(
            "This colour stands out too little: {:.1}:1 against white and {:.1}:1 against the dark theme; both need at least 3:1.",
            palette::contrast(rgb, palette::WHITE),
            palette::contrast(rgb, palette::DARK_CANVAS),
        ))
        .code("brandContrast"));
    }
    Ok(Some(color))
}

async fn admin_set(
    State(state): State<AppState>,
    admin: Admin,
    Json(change): Json<TextChange>,
) -> ApiResult<Json<Value>> {
    let name = clean_name(change.name)?;
    let color = clean_color(change.color)?;
    state.store.set_branding_text(SERVER, name.clone(), color.clone()).await?;
    reload(&state).await;
    crate::admin::record(
        &state,
        &admin,
        format!(
            "set the branding: name {}, colour {}",
            name.as_deref().unwrap_or("UwULock's"),
            color.as_deref().unwrap_or("UwULock's")
        ),
    )
    .await;
    Ok(admin_get(State(state), admin).await)
}

#[derive(Deserialize)]
struct PreviewQuery {
    color: String,
}

/// The colours a choice would give, and whether it may be saved: for the preview before saving.
async fn preview(_admin: Admin, Query(query): Query<PreviewQuery>) -> ApiResult<Json<Value>> {
    let accent = palette::parse_hex(&query.color)
        .ok_or_else(|| ApiError::bad("The colour has to be written like #ff4d8d.").code("brandColor"))?;
    let palette = palette::palette(accent);
    let tokens = |tokens: &palette::Tokens| {
        Value::Object(tokens.iter().map(|(name, value)| ((*name).to_owned(), Value::from(value.as_str()))).collect())
    };
    Ok(Json(json!({
        "light": tokens(&palette.light),
        "dark": tokens(&palette.dark),
        "contrast": contrast_of(&query.color),
    })))
}

/// A picture as it is kept: read by its content, drawn again as PNG of at most `pixels`.
fn reencode(body: &[u8], limit: usize, pixels: u32) -> ApiResult<Vec<u8>> {
    if body.is_empty() {
        return Err(ApiError::bad("The file is empty.").code("brandImage"));
    }
    if body.len() > limit {
        return Err(ApiError::bad(format!("The file can be at most {} KiB.", limit / 1024)).code("brandImageSize"));
    }
    icon_fetch::to_png(body, pixels).map(|(png, _)| png).ok_or_else(|| {
        ApiError::bad("This is not a picture this server reads: PNG, JPEG, WebP, GIF, ICO or SVG.").code("brandImage")
    })
}

async fn set_image(state: &AppState, admin: &Admin, image: Image, png: Option<Vec<u8>>) -> ApiResult<()> {
    let what = match image {
        Image::LogoLight => "the light logo",
        Image::LogoDark => "the dark logo",
        Image::Favicon => "the favicon",
    };
    let removed = png.is_none();
    state.store.set_branding_image(SERVER, image, png).await?;
    reload(state).await;
    crate::admin::record(state, admin, format!("{} {what} of the branding", if removed { "removed" } else { "set" }))
        .await;
    Ok(())
}

async fn upload_logo(
    State(state): State<AppState>,
    admin: Admin,
    Path(variant): Path<String>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let image = logo_image(&variant)?;
    let png = reencode(&body, LOGO_BYTES, LOGO_PIXELS)?;
    set_image(&state, &admin, image, Some(png)).await?;
    Ok(admin_get(State(state), admin).await)
}

async fn remove_logo(
    State(state): State<AppState>,
    admin: Admin,
    Path(variant): Path<String>,
) -> ApiResult<Json<Value>> {
    set_image(&state, &admin, logo_image(&variant)?, None).await?;
    Ok(admin_get(State(state), admin).await)
}

async fn upload_favicon(State(state): State<AppState>, admin: Admin, body: Bytes) -> ApiResult<Json<Value>> {
    let png = reencode(&body, FAVICON_BYTES, FAVICON_PIXELS)?;
    set_image(&state, &admin, Image::Favicon, Some(png)).await?;
    Ok(admin_get(State(state), admin).await)
}

async fn remove_favicon(State(state): State<AppState>, admin: Admin) -> ApiResult<Json<Value>> {
    set_image(&state, &admin, Image::Favicon, None).await?;
    Ok(admin_get(State(state), admin).await)
}

#[cfg(test)]
mod tests;
