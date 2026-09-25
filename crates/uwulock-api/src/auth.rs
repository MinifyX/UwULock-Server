//! Who is asking: tokens, the server's hash of the master password hash, and the session every
//! request after the login carries.
//!
//! - The **access token** is a JWT the clients read (they take the user's name, address and
//!   premium status from it) but never check: only this server does. It is signed with Ed25519,
//!   with a key made on the first start and kept in the database, so a backup that is put back
//!   keeps everyone logged in. It lasts an hour.
//! - The **refresh token** is 64 random bytes. The database keeps only its SHA-256, next to the
//!   device it belongs to; a device that is not used for 30 days (90 for the phone apps) is
//!   logged out.
//! - The **master password hash** a client sends at login is hashed again here, with Argon2id,
//!   so a stolen database does not log anybody in.

use crate::AppState;
use crate::errors::{ApiError, ApiResult};
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use uwulock_store::{SessionUser, User};

/// How long an access token is good for.
pub const ACCESS_SECONDS: i64 = 60 * 60;
/// How long a device stays logged in without being used.
pub const REFRESH_DAYS: i64 = 30;
/// The same for the phone apps, which are opened less often.
pub const REFRESH_DAYS_MOBILE: i64 = 90;
/// How long "remember this device" skips two-step login.
pub const REMEMBER_DAYS: i64 = 30;

const TOKEN_KEY: &str = "token_key";

/// `bytes` random bytes, from the operating system.
pub fn random_bytes(bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; bytes];
    SystemRandom::new().fill(&mut out).expect("the system has randomness");
    out
}

/// A random token for a URL or a header: base64url of `bytes` random bytes.
pub fn random_token(bytes: usize) -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(bytes))
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().to_vec()
}

/// A random number with `digits` digits, leading zeros kept: a code for a mail.
pub fn random_code(digits: u32) -> String {
    let max = 10u64.pow(digits);
    // Rejection sampling, so every code is as likely as any other.
    let limit = u64::MAX - u64::MAX % max;
    loop {
        let bytes: [u8; 8] = random_bytes(8).try_into().expect("8 bytes");
        let value = u64::from_le_bytes(bytes);
        if value < limit {
            return format!("{:0width$}", value % max, width = digits as usize);
        }
    }
}

/// Compare without telling by the time it takes where the first difference is.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ── Tokens ────────────────────────────────────────────────

/// Signs and checks access tokens.
pub struct Tokens {
    key: Ed25519KeyPair,
    issuer: String,
}

/// What an access token says, the way Bitwarden's server writes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    /// The user's id.
    pub sub: String,
    pub premium: bool,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub sstamp: String,
    /// The device's identifier.
    pub device: String,
    /// The device's type, spelled out.
    pub devicetype: String,
    pub client_id: String,
    pub scope: Vec<String>,
    pub amr: Vec<String>,
}

impl Tokens {
    /// The signing key from the database, made there on the first start.
    pub async fn load(store: &uwulock_store::Store, public: &str) -> Result<Self, String> {
        let fresh = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| "no randomness for a key")?;
        let stored = store
            .setting_or_insert(TOKEN_KEY, &STANDARD.encode(fresh.as_ref()))
            .await
            .map_err(|error| error.to_string())?;
        let pkcs8 = STANDARD.decode(stored).map_err(|_| "the token key in the database is damaged")?;
        let key = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| "the token key in the database is damaged")?;
        Ok(Tokens { key, issuer: format!("{public}|login") })
    }

    /// An access token for `user` on `device`, and how many seconds it lasts.
    pub fn access_token(&self, user: &User, device: &str, device_type: i64, client_id: &str) -> (String, i64) {
        let now = now_seconds();
        let claims = Claims {
            nbf: now,
            exp: now + ACCESS_SECONDS,
            iss: self.issuer.clone(),
            sub: user.id.clone(),
            premium: true,
            name: user.name.clone().unwrap_or_else(|| user.email.clone()),
            email: user.email.clone(),
            email_verified: true,
            sstamp: user.security_stamp.clone(),
            device: device.to_string(),
            devicetype: device_type_name(device_type).to_string(),
            client_id: client_id.to_string(),
            scope: vec!["api".into(), "offline_access".into()],
            amr: vec!["Application".into()],
        };
        (self.sign(&claims), ACCESS_SECONDS)
    }

    fn sign(&self, claims: &Claims) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialize"));
        let signed = format!("{header}.{payload}");
        let signature = URL_SAFE_NO_PAD.encode(self.key.sign(signed.as_bytes()).as_ref());
        format!("{signed}.{signature}")
    }

    /// The claims of a token this server signed and that has not run out. Nothing otherwise.
    pub fn verify(&self, token: &str) -> Option<Claims> {
        let token = token.trim();
        let (signed, signature) = token.rsplit_once('.')?;
        let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
        UnparsedPublicKey::new(&ED25519, self.key.public_key().as_ref()).verify(signed.as_bytes(), &signature).ok()?;
        let (_, payload) = signed.split_once('.')?;
        let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        let now = now_seconds();
        // Half a minute of leeway for clocks that differ a little.
        (claims.iss == self.issuer && claims.nbf <= now + 30 && now < claims.exp + 30).then_some(claims)
    }
}

pub fn now_seconds() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Bitwarden's device types, as the access token spells them.
pub fn device_type_name(kind: i64) -> &'static str {
    match kind {
        0 | 15 => "Android",
        1 => "iOS",
        2 => "Chrome Extension",
        3 => "Firefox Extension",
        4 => "Opera Extension",
        5 => "Edge Extension",
        6 => "Windows",
        7 => "macOS",
        8 => "Linux",
        9 => "Chrome",
        10 => "Firefox",
        11 => "Opera",
        12 => "Edge",
        13 => "Internet Explorer",
        16 => "UWP",
        17 => "Safari",
        18 => "Vivaldi",
        19 => "Vivaldi Extension",
        20 => "Safari Extension",
        21 => "SDK",
        22 => "Server",
        23 => "Windows CLI",
        24 => "macOS CLI",
        25 => "Linux CLI",
        26 => "DuckDuckGo",
        _ => "Unknown Browser",
    }
}

/// The phone apps get a longer time before an unused device is logged out.
pub fn refresh_days(device_type: i64) -> i64 {
    if matches!(device_type, 0 | 1 | 15) { REFRESH_DAYS_MOBILE } else { REFRESH_DAYS }
}

// ── The server's hash of the master password hash ─────────

/// How hard Argon2id works. OWASP's recommendation for a server by default; tests use less.
#[derive(Debug, Clone, Copy)]
pub struct HashCost {
    pub memory_kib: u32,
    pub iterations: u32,
}

impl Default for HashCost {
    fn default() -> Self {
        HashCost { memory_kib: 19 * 1024, iterations: 2 }
    }
}

impl HashCost {
    /// Cheap, for tests, where nobody attacks the hash.
    pub fn cheap() -> Self {
        HashCost { memory_kib: 64, iterations: 1 }
    }

    fn argon2(self) -> argon2::Argon2<'static> {
        let params = argon2::Params::new(self.memory_kib, self.iterations, 1, None).expect("valid Argon2 parameters");
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
    }
}

/// Hash what the client sent in place of the master password. Off the async threads: it takes
/// a few dozen milliseconds on purpose.
pub async fn hash_password(cost: HashCost, secret: &str) -> ApiResult<String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let secret = secret.to_string();
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::encode_b64(&random_bytes(16)).map_err(ApiError::internal)?;
        cost.argon2().hash_password(secret.as_bytes(), &salt).map(|hash| hash.to_string()).map_err(ApiError::internal)
    })
    .await
    .map_err(ApiError::internal)?
}

/// Whether `secret` is what `hash` was made from. For an account that does not exist, pass
/// `None`: the same work is done anyway, so the time taken does not tell which addresses have
/// one.
pub async fn verify_password(cost: HashCost, hash: Option<&str>, secret: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let hash = hash.map(str::to_string);
    let secret = secret.to_string();
    tokio::task::spawn_blocking(move || match hash {
        Some(hash) => PasswordHash::new(&hash)
            .is_ok_and(|parsed| argon2::Argon2::default().verify_password(secret.as_bytes(), &parsed).is_ok()),
        None => {
            use argon2::password_hash::{PasswordHasher, SaltString};
            let salt = SaltString::encode_b64(&[0u8; 16]).expect("a fixed salt");
            let _ = cost.argon2().hash_password(secret.as_bytes(), &salt);
            false
        }
    })
    .await
    .unwrap_or(false)
}

// ── Where a request comes from ────────────────────────────

/// The address a request comes from: the peer's, or behind a trusted proxy the first one in
/// `X-Forwarded-For` (or `X-Real-IP`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(client_ip(parts, state.config.trust_forwarded)))
    }
}

pub(crate) fn client_ip(parts: &Parts, trust_forwarded: bool) -> IpAddr {
    if trust_forwarded {
        let header = |name: &str| parts.headers.get(name).and_then(|value| value.to_str().ok());
        let forwarded = header("x-forwarded-for")
            .and_then(|list| list.split(',').next())
            .or_else(|| header("x-real-ip"))
            .and_then(|value| value.trim().parse::<IpAddr>().ok());
        if let Some(ip) = forwarded {
            return canonical(ip);
        }
    }
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| canonical(info.0.ip()))
        .unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

// ── The session of a request ──────────────────────────────

/// A request with a valid access token: who it is from, and on which device.
#[derive(Debug, Clone)]
pub struct Session {
    pub user: Arc<User>,
    pub device: String,
}

impl FromRequestParts<AppState> for Session {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let header = parts.headers.get("authorization").and_then(|value| value.to_str().ok()).unwrap_or_default();
        // Bitwarden takes what follows the last "Bearer ", or the whole value.
        let token = header.rsplit_once("Bearer ").map_or(header, |(_, token)| token);
        if token.is_empty() {
            return Err(ApiError::unauthorized());
        }
        let claims = state.tokens.verify(token).ok_or_else(ApiError::unauthorized)?;
        let Some(SessionUser { user, devices }) = state.store.session_user(&claims.sub).await? else {
            return Err(ApiError::unauthorized());
        };
        if user.disabled || user.security_stamp != claims.sstamp || !devices.contains(&claims.device) {
            return Err(ApiError::unauthorized());
        }
        Ok(Session { user, device: claims.device })
    }
}

/// A session whose user is an admin.
#[derive(Debug, Clone)]
pub struct Admin(pub Session);

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state).await?;
        if !session.user.admin {
            return Err(ApiError::forbidden("Only admins can do this."));
        }
        Ok(Admin(session))
    }
}

/// The version of Bitwarden's client in `Bitwarden-Client-Version`, as numbers to compare:
/// `2024.12.0` is `(2024, 12, 0)`. Nothing when it is not there.
pub fn client_version(headers: &axum::http::HeaderMap) -> Option<(u32, u32, u32)> {
    let text = headers.get("bitwarden-client-version")?.to_str().ok()?;
    let mut parts = text.trim().split(['.', '-', '+']).map(|part| part.parse::<u32>().ok());
    Some((parts.next()??, parts.next().flatten().unwrap_or(0), parts.next().flatten().unwrap_or(0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> User {
        User {
            id: "u1".into(),
            email: "nyu@example.com".into(),
            name: Some("Nyu".into()),
            password_hash: String::new(),
            password_hint: None,
            user_key: String::new(),
            private_key: None,
            public_key: None,
            kdf: uwulock_store::Kdf { kind: 0, iterations: 600_000, memory: None, parallelism: None },
            security_stamp: "stamp".into(),
            language: "de".into(),
            avatar_color: None,
            equivalent_domains: "[]".into(),
            excluded_globals: "[]".into(),
            recovery_code: None,
            admin: false,
            disabled: false,
            created: String::new(),
            updated: String::new(),
            revision: String::new(),
            last_login: None,
        }
    }

    async fn tokens() -> (Tokens, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store =
            uwulock_store::Store::open_sqlite(&dir.path().join("db"), &uwulock_store::Options { readers: 1 }).unwrap();
        (Tokens::load(&store, "https://vault.example.com").await.unwrap(), dir)
    }

    #[tokio::test]
    async fn a_token_says_who_and_where() {
        let (tokens, _dir) = tokens().await;
        let (token, lasts) = tokens.access_token(&user(), "device-1", 3, "browser");
        assert_eq!(lasts, ACCESS_SECONDS);
        let claims = tokens.verify(&token).unwrap();
        assert_eq!((claims.sub.as_str(), claims.device.as_str()), ("u1", "device-1"));
        assert_eq!(claims.devicetype, "Firefox Extension");
        assert_eq!(claims.iss, "https://vault.example.com|login");
    }

    #[tokio::test]
    async fn a_changed_token_is_refused() {
        let (tokens, _dir) = tokens().await;
        let (token, _) = tokens.access_token(&user(), "device-1", 3, "browser");
        let (signed, signature) = token.rsplit_once('.').unwrap();
        let (header, _) = signed.split_once('.').unwrap();
        let mut claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(signed.split_once('.').unwrap().1).unwrap()).unwrap();
        claims["sub"] = "somebody-else".into();
        let forged = format!("{header}.{}.{signature}", URL_SAFE_NO_PAD.encode(claims.to_string()));
        assert!(tokens.verify(&forged).is_none());
        assert!(tokens.verify("not.a.token").is_none());
        let (other, _dir2) = self::tokens().await;
        assert!(other.verify(&token).is_none(), "another server's key");
    }

    #[tokio::test]
    async fn the_key_is_made_once() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            uwulock_store::Store::open_sqlite(&dir.path().join("db"), &uwulock_store::Options { readers: 1 }).unwrap();
        let first = Tokens::load(&store, "https://vault.example.com").await.unwrap();
        let second = Tokens::load(&store, "https://vault.example.com").await.unwrap();
        let (token, _) = first.access_token(&user(), "d", 8, "desktop");
        assert!(second.verify(&token).is_some(), "a restart keeps sessions");
    }

    #[tokio::test]
    async fn the_server_s_hash_takes_only_the_right_secret() {
        let hash = hash_password(HashCost::cheap(), "client-hash").await.unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(HashCost::cheap(), Some(&hash), "client-hash").await);
        assert!(!verify_password(HashCost::cheap(), Some(&hash), "other").await);
        assert!(!verify_password(HashCost::cheap(), None, "client-hash").await);
        assert!(!verify_password(HashCost::cheap(), Some("garbage"), "client-hash").await);
    }

    #[test]
    fn codes_have_their_digits() {
        for _ in 0..50 {
            let code = random_code(6);
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn client_versions_compare() {
        let mut headers = axum::http::HeaderMap::new();
        assert_eq!(client_version(&headers), None);
        headers.insert("bitwarden-client-version", "2024.12.1".parse().unwrap());
        assert!(client_version(&headers).unwrap() >= (2024, 12, 0));
        headers.insert("bitwarden-client-version", "2024.11.0-beta".parse().unwrap());
        assert!(client_version(&headers).unwrap() < (2024, 12, 0));
    }
}
