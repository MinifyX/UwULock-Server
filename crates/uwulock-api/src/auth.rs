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

pub(crate) const TOKEN_KEY: &str = "token_key";

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

/// What a download link's or a Send's token says: which, until when, and what for (in the
/// issuer, so no such token passes as an access token or as the other kind).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LinkClaims {
    sub: String,
    exp: i64,
    iss: String,
    /// For a Send only given addresses may open: the address that proved itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    /// For a download link of an organisation's item: the member it was made for, whose travel
    /// mode the download follows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    viewer: Option<String>,
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

    /// An access token for `user` on `device`, and how many seconds it lasts. `sso`: the login
    /// came through SSO, which its `amr` says.
    pub fn access_token(
        &self,
        user: &User,
        device: &str,
        device_type: i64,
        client_id: &str,
        sso: bool,
    ) -> (String, i64) {
        self.access_token_for(user, device, device_type, client_id, sso, false)
    }

    /// Like [`Tokens::access_token`]; `setup_only` makes a token for the two-step login setup
    /// alone ([`SETUP_SCOPE`]).
    pub fn access_token_for(
        &self,
        user: &User,
        device: &str,
        device_type: i64,
        client_id: &str,
        sso: bool,
        setup_only: bool,
    ) -> (String, i64) {
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
            // A suite app's token opens its space and nothing else (docs/uwu-api.md §6.5).
            scope: if crate::suite::space_of_client(client_id).is_some() {
                vec![crate::suite::SCOPE.into(), "offline_access".into()]
            } else if setup_only {
                vec![SETUP_SCOPE.into(), "offline_access".into()]
            } else {
                vec!["api".into(), "offline_access".into()]
            },
            amr: if sso { vec!["Application".into(), "sso".into()] } else { vec!["Application".into()] },
        };
        (self.sign(&claims), ACCESS_SECONDS)
    }

    /// A token for one file, `subject`, that works for `seconds`: download links carry it.
    pub fn file_token(&self, subject: &str, seconds: i64) -> String {
        self.file_token_for(subject, seconds, None)
    }

    /// Like [`Tokens::file_token`], made for `viewer` (see [`Tokens::file_token_viewer`]).
    pub fn file_token_for(&self, subject: &str, seconds: i64, viewer: Option<&str>) -> String {
        let claims = LinkClaims {
            sub: subject.to_string(),
            exp: now_seconds() + seconds,
            iss: self.link_issuer("file"),
            email: None,
            viewer: viewer.map(str::to_string),
        };
        self.sign(&claims)
    }

    /// Whether `token` is a file token for `subject` that has not run out.
    pub fn check_file_token(&self, token: &str, subject: &str) -> bool {
        self.file_token_viewer(token, subject).is_some()
    }

    /// For a valid file token for `subject`: whom it was made for, if for anybody.
    pub fn file_token_viewer(&self, token: &str, subject: &str) -> Option<Option<String>> {
        self.verify_link(token, "file").filter(|claims| claims.sub == subject).map(|claims| claims.viewer)
    }

    /// A token that opens one Send, `send_id`, for a short while: what the send access grant
    /// hands out after the password.
    pub fn send_token(&self, send_id: &str, email: Option<&str>) -> (String, i64) {
        let seconds = 2 * 60;
        let claims = LinkClaims {
            sub: send_id.to_string(),
            exp: now_seconds() + seconds,
            iss: self.link_issuer("send"),
            email: email.map(str::to_string),
            viewer: None,
        };
        (self.sign(&claims), seconds)
    }

    /// The Send a send access token opens.
    pub fn check_send_token(&self, token: &str) -> Option<String> {
        self.verify_link(token, "send").map(|claims| claims.sub)
    }

    /// The token a file request's upload page gets once the link (and its password) opened:
    /// it may start submissions to `request_id` for an hour.
    pub fn upload_token(&self, request_id: &str) -> (String, i64) {
        let seconds = 60 * 60;
        let claims = LinkClaims {
            sub: request_id.to_string(),
            exp: now_seconds() + seconds,
            iss: self.link_issuer("filerequest"),
            email: None,
            viewer: None,
        };
        (self.sign(&claims), seconds)
    }

    /// What `/identity/sso/prevalidate` hands out, for `/identity/connect/authorize`: two minutes.
    pub fn sso_token(&self) -> String {
        let claims = LinkClaims {
            sub: "sso".into(),
            exp: now_seconds() + 2 * 60,
            iss: self.link_issuer("sso"),
            email: None,
            viewer: None,
        };
        self.sign(&claims)
    }

    /// Whether `token` is one [`Tokens::sso_token`] made, and has not run out.
    pub fn check_sso_token(&self, token: &str) -> bool {
        self.verify_link(token, "sso").is_some()
    }

    /// The file request an upload token is for.
    pub fn check_upload_token(&self, token: &str) -> Option<String> {
        self.verify_link(token, "filerequest").map(|claims| claims.sub)
    }

    /// The token of an organisation's invitation: for membership `member_id` and the address it
    /// went to, five days, as Bitwarden's.
    pub fn org_invite_token(&self, member_id: &str, email: &str) -> String {
        let claims = LinkClaims {
            sub: member_id.to_string(),
            exp: now_seconds() + 5 * 86_400,
            iss: self.link_issuer("orginvite"),
            email: Some(email.to_string()),
            viewer: None,
        };
        self.sign(&claims)
    }

    /// The membership and address an invitation's token is for, if it has not run out.
    pub fn check_org_invite_token(&self, token: &str) -> Option<(String, String)> {
        let claims = self.verify_link(token, "orginvite")?;
        Some((claims.sub, claims.email?))
    }

    fn link_issuer(&self, what: &str) -> String {
        format!("{}|{what}", self.issuer.trim_end_matches("|login"))
    }

    fn verify_link(&self, token: &str, what: &str) -> Option<LinkClaims> {
        let (signed, signature) = token.trim().rsplit_once('.')?;
        let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
        UnparsedPublicKey::new(&ED25519, self.key.public_key().as_ref()).verify(signed.as_bytes(), &signature).ok()?;
        let (_, payload) = signed.split_once('.')?;
        let claims: LinkClaims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        (claims.iss == self.link_issuer(what) && now_seconds() < claims.exp).then_some(claims)
    }

    fn sign(&self, claims: &impl Serialize) -> String {
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

/// How many hashes run at once. Each takes its memory (19 MiB by default) for as long as it runs;
/// without a bound, many logins at the same moment — from many addresses, which the rate limits
/// do not stop — would take as much memory as they like. The rest wait their turn.
static HASHING_SLOTS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

fn hashing() -> &'static tokio::sync::Semaphore {
    static HASHING: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    HASHING.get_or_init(|| {
        let cores = std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get);
        let slots = (cores * 2).clamp(2, 32);
        let _ = HASHING_SLOTS.set(slots);
        tokio::sync::Semaphore::new(slots)
    })
}

/// How many hashes wait for a turn now.
static WAITING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A turn at hashing, counted while it is waited for.
async fn hashing_turn() -> Result<tokio::sync::SemaphorePermit<'static>, tokio::sync::AcquireError> {
    use std::sync::atomic::Ordering;
    struct Waiting;
    impl Drop for Waiting {
        fn drop(&mut self) {
            WAITING.fetch_sub(1, Ordering::Relaxed);
        }
    }
    WAITING.fetch_add(1, Ordering::Relaxed);
    let _waiting = Waiting;
    hashing().acquire().await
}

/// Whether so many hashes wait already that a login should get "busy" at once rather than queue
/// up until the request times out (R1-2): more than eight per slot, a fraction of a second.
pub fn hashing_busy() -> bool {
    let _ = hashing();
    queue_full(WAITING.load(std::sync::atomic::Ordering::Relaxed), HASHING_SLOTS.get().copied().unwrap_or(2))
}

fn queue_full(waiting: usize, slots: usize) -> bool {
    waiting >= 8 * slots
}

/// Hash what the client sent in place of the master password. Off the async threads: it takes
/// a few dozen milliseconds on purpose.
pub async fn hash_password(cost: HashCost, secret: &str) -> ApiResult<String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let secret = secret.to_string();
    let turn = hashing_turn().await.map_err(ApiError::internal)?;
    tokio::task::spawn_blocking(move || {
        // Held until the hash is done, even when the request that wanted it is gone.
        let _turn = turn;
        let salt = SaltString::encode_b64(&random_bytes(16)).map_err(ApiError::internal)?;
        cost.argon2().hash_password(secret.as_bytes(), &salt).map(|hash| hash.to_string()).map_err(ApiError::internal)
    })
    .await
    .map_err(ApiError::internal)?
}

/// How a hash that came over from Vaultwarden starts: PBKDF2-SHA256 as it made them, with its
/// rounds, salt and hash after it (`vw-pbkdf2$<rounds>$<salt>$<hash>`, base64). They are
/// checked as they are and replaced by Argon2id at the next login.
pub const LEGACY_HASH: &str = "vw-pbkdf2$";

pub fn is_legacy(hash: &str) -> bool {
    hash.starts_with(LEGACY_HASH)
}

fn verify_legacy(hash: &str, secret: &str) -> bool {
    let mut parts = hash[LEGACY_HASH.len()..].split('$');
    let (Some(rounds), Some(salt), Some(expected), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let (Ok(rounds), Ok(salt), Ok(expected)) =
        (rounds.parse::<u32>(), STANDARD.decode(salt), STANDARD.decode(expected))
    else {
        return false;
    };
    let Some(rounds) = std::num::NonZeroU32::new(rounds) else { return false };
    ring::pbkdf2::verify(ring::pbkdf2::PBKDF2_HMAC_SHA256, rounds, &salt, secret.as_bytes(), &expected).is_ok()
}

/// Whether `secret` is what `hash` was made from. For an account that does not exist, pass
/// `None`: the same work is done anyway, so the time taken does not tell which addresses have
/// one.
pub async fn verify_password(cost: HashCost, hash: Option<&str>, secret: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let hash = hash.map(str::to_string);
    let secret = secret.to_string();
    let Ok(turn) = hashing_turn().await else { return false };
    tokio::task::spawn_blocking(move || {
        let _turn = turn;
        match hash {
            Some(hash) if is_legacy(&hash) => verify_legacy(&hash, &secret),
            Some(hash) => PasswordHash::new(&hash)
                .is_ok_and(|parsed| argon2::Argon2::default().verify_password(secret.as_bytes(), &parsed).is_ok()),
            None => {
                use argon2::password_hash::{PasswordHasher, SaltString};
                let salt = SaltString::encode_b64(&[0u8; 16]).expect("a fixed salt");
                let _ = cost.argon2().hash_password(secret.as_bytes(), &salt);
                false
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// Like [`verify_password`], for a login: while hashes from Vaultwarden are left, every check
/// does the work of both kinds — Argon2id, and PBKDF2 with the most rounds among them — so the
/// time a login takes does not tell an account that has not logged in since the move from one
/// that has, or from an address without one.
pub async fn verify_login(cost: HashCost, hash: Option<&str>, secret: &str, legacy_rounds: u32) -> bool {
    if legacy_rounds == 0 {
        return verify_password(cost, hash, secret).await;
    }
    use argon2::password_hash::{PasswordHasher, PasswordVerifier, SaltString};
    let hash = hash.map(str::to_string);
    let secret = secret.to_string();
    let Ok(turn) = hashing_turn().await else { return false };
    tokio::task::spawn_blocking(move || {
        let _turn = turn;
        let dummy_pbkdf2 = || {
            let mut out = [0u8; 32];
            let rounds = std::num::NonZeroU32::new(legacy_rounds).expect("not 0");
            ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, rounds, &[0u8; 16], secret.as_bytes(), &mut out);
        };
        let dummy_argon2 = || {
            let salt = SaltString::encode_b64(&[0u8; 16]).expect("a fixed salt");
            let _ = cost.argon2().hash_password(secret.as_bytes(), &salt);
        };
        match hash {
            Some(hash) if is_legacy(&hash) => {
                dummy_argon2();
                verify_legacy(&hash, &secret)
            }
            Some(hash) => {
                dummy_pbkdf2();
                argon2::password_hash::PasswordHash::new(&hash)
                    .is_ok_and(|parsed| argon2::Argon2::default().verify_password(secret.as_bytes(), &parsed).is_ok())
            }
            None => {
                dummy_pbkdf2();
                dummy_argon2();
                false
            }
        }
    })
    .await
    .unwrap_or(false)
}

// ── Where a request comes from ────────────────────────────

/// The address a request comes from: the peer's, or behind a trusted proxy the last one in
/// `X-Forwarded-For` (or `X-Real-IP`).
///
/// The last, not the first: a proxy like nginx with `$proxy_add_x_forwarded_for` appends the
/// address it sees to whatever the client sent, so everything before that is the client's to
/// make up — and with it, a fresh rate limit on every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(client_ip(parts, &state.config)))
    }
}

/// The address a request comes from, as the server's configuration says to believe it.
pub(crate) fn client_ip(parts: &Parts, config: &crate::ApiConfig) -> IpAddr {
    client_ip_with(parts, config.trust_forwarded, &config.trusted_proxies, config.real_ip_header)
}

/// The connection's own address: the proxy's, behind one.
fn peer_ip(extensions: &axum::http::Extensions) -> Option<IpAddr> {
    extensions.get::<ConnectInfo<SocketAddr>>().map(|info| canonical(info.0.ip()))
}

/// Whether the forwarding headers of this request are believed: trust is on, and the peer is one
/// of the trusted proxies (`UWULOCK_TRUSTED_PROXIES`; none listed means every peer, R1-13).
pub(crate) fn trusts_forwarding(
    extensions: &axum::http::Extensions,
    trust_forwarded: bool,
    proxies: &[crate::networks::IpNetwork],
) -> bool {
    trust_forwarded
        && (proxies.is_empty()
            || peer_ip(extensions).is_some_and(|peer| proxies.iter().any(|proxy| proxy.contains(peer))))
}

/// Where a request comes from. Behind a proxy that is believed, the header it sets: the last
/// entry of `X-Forwarded-For` (`X-Real-IP` only when there is no `X-Forwarded-For` at all), or
/// with `real_ip` (`UWULOCK_CLIENT_IP_HEADER=x-real-ip`) `X-Real-IP` and nothing else — for a
/// proxy that sets it and passes the client's own `X-Forwarded-For` on unchanged (R5 I-2).
/// Otherwise, and when the header is not an address, the peer.
pub(crate) fn client_ip_with(
    parts: &Parts,
    trust_forwarded: bool,
    proxies: &[crate::networks::IpNetwork],
    real_ip: bool,
) -> IpAddr {
    if trusts_forwarding(&parts.extensions, trust_forwarded, proxies) {
        let real_ip_header = || {
            parts
                .headers
                .get("x-real-ip")
                .and_then(|value| std::str::from_utf8(value.as_bytes()).ok())
                .and_then(|value| value.trim().parse::<IpAddr>().ok())
        };
        // Several headers of the same name count as one list, in order. Read as raw bytes: a
        // value with a byte ≥ 0x80 is not `to_str()`-able, and must not let `X-Real-IP` (which
        // the client can send itself) take over (R1-1).
        let forwarded_for = parts.headers.get_all("x-forwarded-for").into_iter().next_back();
        let forwarded = match forwarded_for {
            Some(value) if !real_ip => value
                .as_bytes()
                .rsplit(|byte| *byte == b',')
                .next()
                .and_then(|last| std::str::from_utf8(last).ok())
                .and_then(|last| last.trim().parse::<IpAddr>().ok()),
            _ => real_ip_header(),
        };
        if let Some(ip) = forwarded {
            return canonical(ip);
        }
    }
    peer_ip(&parts.extensions).unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

// ── The session of a request ──────────────────────────────

/// The scope of a web vault token for an account that has to set up two-step login first
/// (docs/uwu-api.md §20): it opens that setup and what the web vault needs around it, nothing
/// else, until the account has a second step.
pub const SETUP_SCOPE: &str = "uwu.twofactor-setup";

/// What a setup-only session may reach: the two-step login setup, and what the web vault needs to
/// unlock and show it (the sync hands out only the profile then).
fn setup_allows(method: &axum::http::Method, path: &str) -> bool {
    let read = method == axum::http::Method::GET;
    path.starts_with("/api/two-factor/")
        || path == "/api/two-factor"
        || path.starts_with("/uwu/v1/devices")
        || path.starts_with("/uwu/v1/security/notices")
        || path == "/uwu/v1/account/language"
        || (read
            && matches!(
                path,
                "/api/sync" | "/api/accounts/revision-date" | "/api/accounts/profile" | "/uwu/v1/account"
            ))
}

/// A request with a valid access token: who it is from, and on which device.
#[derive(Debug, Clone)]
pub struct Session {
    pub user: Arc<User>,
    pub device: String,
    /// The client the token was made for: `web`, `browser`, `desktop`, `cli`, `mobile`, …
    pub client_id: String,
    /// The login came through SSO.
    pub sso: bool,
    /// A suite app's token (scope `uwu.suite`): the one space it may touch. Such a session is
    /// only ever made by [`AnySession`]; the plain extractor refuses the token.
    pub space: Option<&'static str>,
    /// When the access token runs out, in Unix seconds.
    pub expires: i64,
    /// A web vault token for the two-step login setup only ([`SETUP_SCOPE`]), while the account
    /// still has no second step.
    pub setup_only: bool,
}

/// The bearer token of a request: Bitwarden takes what follows the last "Bearer ", or the whole
/// value.
fn bearer(parts: &Parts) -> &str {
    let header = parts.headers.get("authorization").and_then(|value| value.to_str().ok()).unwrap_or_default();
    header.rsplit_once("Bearer ").map_or(header, |(_, token)| token)
}

impl FromRequestParts<AppState> for Session {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let session = Session::from_token(state, bearer(parts)).await?;
        session.check_setup(parts)?;
        Ok(session)
    }
}

/// A session of either kind: an account's (`user`) or a suite app's (`suite`), for the few
/// endpoints a suite app may use (docs/uwu-api.md §6.5). Each checks the space itself.
#[derive(Debug, Clone)]
pub struct AnySession(pub Session);

impl FromRequestParts<AppState> for AnySession {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let session = Session::from_any_token(state, bearer(parts)).await?;
        session.check_setup(parts)?;
        Ok(AnySession(session))
    }
}

impl Session {
    /// The session an access token stands for, if it still does. A suite app's token is
    /// refused with 403 `scope`: it may use nothing but its space.
    pub async fn from_token(state: &AppState, token: &str) -> Result<Self, ApiError> {
        let session = Self::from_any_token(state, token).await?;
        if session.space.is_some() {
            return Err(crate::suite::scope_error());
        }
        Ok(session)
    }

    /// Like [`Session::from_token`], for an account's token or a suite app's.
    pub async fn from_any_token(state: &AppState, token: &str) -> Result<Self, ApiError> {
        if token.is_empty() {
            return Err(ApiError::unauthorized());
        }
        let claims = state.tokens.verify(token).ok_or_else(ApiError::unauthorized)?;
        let mut setup_only = false;
        let space = if claims.scope.iter().any(|scope| scope == crate::suite::SCOPE) {
            Some(crate::suite::space_of_client(&claims.client_id).ok_or_else(ApiError::unauthorized)?)
        } else if claims.scope.iter().any(|scope| scope == "api") {
            None
        } else if claims.scope.iter().any(|scope| scope == SETUP_SCOPE) {
            setup_only = true;
            None
        } else {
            return Err(ApiError::unauthorized());
        };
        let Some(SessionUser { user, devices }) = state.store.session_user(&claims.sub).await? else {
            return Err(ApiError::unauthorized());
        };
        if user.disabled || user.security_stamp != claims.sstamp || !devices.contains(&claims.device) {
            return Err(ApiError::unauthorized());
        }
        let sso = claims.amr.iter().any(|method| method == "sso");
        // Once there is a second step (or the rule is gone), the same token opens everything:
        // the web vault goes on without logging in again.
        if setup_only && !crate::identity::must_set_up_two_factor(state, &user).await? {
            setup_only = false;
        }
        Ok(Session {
            user,
            device: claims.device,
            client_id: claims.client_id,
            sso,
            space,
            expires: claims.exp,
            setup_only,
        })
    }

    /// A setup-only session reaches only the two-step login setup: 403 `two_factor_required`.
    fn check_setup(&self, parts: &Parts) -> Result<(), ApiError> {
        if self.setup_only && !setup_allows(&parts.method, parts.uri.path()) {
            return Err(ApiError::forbidden("This server requires two-step login. Set it up first.")
                .code("two_factor_required"));
        }
        Ok(())
    }

    /// Whether the session may use an admin's rights outside the admin portal (invitations
    /// without a quota): an admin, from inside the admin networks, and through SSO where the
    /// portal asks for it — the same rules as [`Admin`].
    pub fn acts_as_admin(&self, state: &AppState, ip: IpAddr) -> bool {
        let settings = state.settings.read();
        self.user.admin
            && crate::networks::allowed(&settings.admin_networks, ip)
            && (self.sso || !(settings.sso.enabled && settings.sso.admins_only_with_sso))
    }

    /// Whether this is a suite app's session.
    pub fn is_suite(&self) -> bool {
        self.space.is_some()
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
        // With the `sso` switch off, admins log in with their password like everybody.
        let only_sso = state.feature(crate::Feature::Sso) && {
            let settings = state.settings.read();
            settings.sso.enabled && settings.sso.admins_only_with_sso
        };
        if only_sso && !session.sso {
            return Err(ApiError::forbidden("Log in with SSO to use the admin portal.").code("sso_required"));
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
            user_key_id: None,
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
        let (token, lasts) = tokens.access_token(&user(), "device-1", 3, "browser", false);
        assert_eq!(lasts, ACCESS_SECONDS);
        let claims = tokens.verify(&token).unwrap();
        assert_eq!((claims.sub.as_str(), claims.device.as_str()), ("u1", "device-1"));
        assert_eq!(claims.devicetype, "Firefox Extension");
        assert_eq!(claims.iss, "https://vault.example.com|login");
    }

    #[tokio::test]
    async fn a_changed_token_is_refused() {
        let (tokens, _dir) = tokens().await;
        let (token, _) = tokens.access_token(&user(), "device-1", 3, "browser", false);
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
    async fn link_tokens_open_one_thing_and_nothing_else() {
        let (tokens, _dir) = tokens().await;
        let file = tokens.file_token("c1/a1", 60);
        assert!(tokens.check_file_token(&file, "c1/a1"));
        assert!(!tokens.check_file_token(&file, "c1/a2"));
        assert!(tokens.verify(&file).is_none(), "not an access token");
        assert!(tokens.check_send_token(&file).is_none(), "not a Send token");
        let (send, _) = tokens.send_token("s1", None);
        assert_eq!(tokens.check_send_token(&send).as_deref(), Some("s1"));
        assert!(!tokens.check_file_token(&send, "s1"));
        let (login, _) = tokens.access_token(&user(), "d", 3, "browser", false);
        assert!(!tokens.check_file_token(&login, "u1"), "an access token opens no file");
        assert!(!tokens.check_file_token(&tokens.file_token("c1/a1", -1), "c1/a1"), "ran out");
        // A link for an organisation's item names the member it was made for (SV-L8).
        let bound = tokens.file_token_for("c1/a1", 60, Some("u1"));
        assert_eq!(tokens.file_token_viewer(&bound, "c1/a1"), Some(Some("u1".to_string())));
        assert_eq!(tokens.file_token_viewer(&file, "c1/a1"), Some(None));
        assert_eq!(tokens.file_token_viewer(&bound, "c1/a2"), None);
    }

    #[tokio::test]
    async fn the_key_is_made_once() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            uwulock_store::Store::open_sqlite(&dir.path().join("db"), &uwulock_store::Options { readers: 1 }).unwrap();
        let first = Tokens::load(&store, "https://vault.example.com").await.unwrap();
        let second = Tokens::load(&store, "https://vault.example.com").await.unwrap();
        let (token, _) = first.access_token(&user(), "d", 8, "desktop", true);
        let claims = second.verify(&token).expect("a restart keeps sessions");
        assert_eq!(claims.amr, ["Application", "sso"]);
        assert!(second.check_sso_token(&second.sso_token()));
        assert!(!second.check_sso_token(&token), "an access token is no SSO token");
        assert!(second.verify(&second.sso_token()).is_none(), "nor the other way round");
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

    #[tokio::test]
    async fn a_hash_from_vaultwarden_still_verifies() {
        let salt = [7u8; 64];
        let mut expected = [0u8; 32];
        let rounds = std::num::NonZeroU32::new(1000).unwrap();
        ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, rounds, &salt, b"client-hash", &mut expected);
        let hash = format!("{LEGACY_HASH}1000${}${}", STANDARD.encode(salt), STANDARD.encode(expected));
        assert!(is_legacy(&hash));
        assert!(verify_password(HashCost::cheap(), Some(&hash), "client-hash").await);
        assert!(!verify_password(HashCost::cheap(), Some(&hash), "other").await);
        assert!(!verify_password(HashCost::cheap(), Some("vw-pbkdf2$x$y"), "client-hash").await);

        // A login does the work of both kinds while such hashes are left, and says the same.
        let argon = hash_password(HashCost::cheap(), "client-hash").await.unwrap();
        for rounds in [0, 1000] {
            assert!(verify_login(HashCost::cheap(), Some(&hash), "client-hash", rounds).await);
            assert!(verify_login(HashCost::cheap(), Some(&argon), "client-hash", rounds).await);
            assert!(!verify_login(HashCost::cheap(), Some(&argon), "other", rounds).await);
            assert!(!verify_login(HashCost::cheap(), None, "client-hash", rounds).await);
        }
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
    fn behind_a_proxy_the_address_it_added_counts() {
        let parts = |headers: &[(&str, &str)]| {
            let mut request = axum::http::Request::get("/");
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            let mut parts = request.body(()).unwrap().into_parts().0;
            parts.extensions.insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000))));
            parts
        };
        let client_ip = |parts: &Parts, trust: bool| client_ip_with(parts, trust, &[], false);
        // nginx appends what it sees to what the client sent.
        let spoofed = parts(&[("x-forwarded-for", "203.0.113.9, 198.51.100.7")]);
        assert_eq!(client_ip(&spoofed, true), IpAddr::from([198, 51, 100, 7]));
        assert_eq!(client_ip(&spoofed, false), IpAddr::from([127, 0, 0, 1]), "not believed unless trusted");
        let two = parts(&[("x-forwarded-for", "203.0.113.9"), ("x-forwarded-for", "198.51.100.7")]);
        assert_eq!(client_ip(&two, true), IpAddr::from([198, 51, 100, 7]));
        let real = parts(&[("x-real-ip", "198.51.100.8")]);
        assert_eq!(client_ip(&real, true), IpAddr::from([198, 51, 100, 8]));
        let garbage = parts(&[("x-forwarded-for", "not an address")]);
        assert_eq!(client_ip(&garbage, true), IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn a_long_hashing_queue_is_busy() {
        assert!(!queue_full(0, 4));
        assert!(!queue_full(31, 4));
        assert!(queue_full(32, 4));
        assert!(!hashing_busy(), "nothing waits in a test");
    }

    #[test]
    fn obs_text_in_forwarded_for_does_not_hand_over_to_x_real_ip() {
        // R1-1: the client sends `X-Forwarded-For: \xff` and `X-Real-IP`, the proxy appends.
        let mut request = axum::http::Request::get("/");
        request =
            request.header("x-forwarded-for", axum::http::HeaderValue::from_bytes(b"\xff, 198.51.100.7").unwrap());
        request = request.header("x-real-ip", "192.0.2.10");
        let mut parts = request.body(()).unwrap().into_parts().0;
        parts.extensions.insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000))));
        assert_eq!(client_ip_with(&parts, true, &[], false), IpAddr::from([198, 51, 100, 7]));
        // Only the bad entry: the peer, never X-Real-IP.
        let mut request = axum::http::Request::get("/");
        request = request.header("x-forwarded-for", axum::http::HeaderValue::from_bytes(b"\xff").unwrap());
        request = request.header("x-real-ip", "192.0.2.10");
        let mut parts = request.body(()).unwrap().into_parts().0;
        parts.extensions.insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000))));
        assert_eq!(client_ip_with(&parts, true, &[], false), IpAddr::from([127, 0, 0, 1]));
    }

    /// R5 I-2: behind a proxy that sets `X-Real-IP` and passes the client's `X-Forwarded-For`
    /// on, `UWULOCK_CLIENT_IP_HEADER=x-real-ip` reads only `X-Real-IP`.
    #[test]
    fn x_real_ip_alone_when_the_proxy_sets_that() {
        let mut request = axum::http::Request::get("/");
        request = request.header("x-forwarded-for", "192.0.2.66").header("x-real-ip", "198.51.100.7");
        let mut parts = request.body(()).unwrap().into_parts().0;
        parts.extensions.insert(ConnectInfo(SocketAddr::from(([172, 20, 0, 2], 5000))));
        assert_eq!(client_ip_with(&parts, true, &[], true), IpAddr::from([198, 51, 100, 7]));
        assert_eq!(client_ip_with(&parts, true, &[], false), IpAddr::from([192, 0, 2, 66]), "the default");
        assert_eq!(client_ip_with(&parts, false, &[], true), IpAddr::from([172, 20, 0, 2]), "only behind a proxy");
        parts.headers.remove("x-real-ip");
        assert_eq!(client_ip_with(&parts, true, &[], true), IpAddr::from([172, 20, 0, 2]), "never X-Forwarded-For");
    }

    #[test]
    fn forwarding_headers_count_only_from_trusted_proxies() {
        use crate::networks::IpNetwork;
        let from = |peer: [u8; 4]| {
            let request = axum::http::Request::get("/").header("x-forwarded-for", "198.51.100.7");
            let mut parts = request.body(()).unwrap().into_parts().0;
            parts.extensions.insert(ConnectInfo(SocketAddr::from((peer, 5000))));
            parts
        };
        let proxies = [IpNetwork::parse("172.20.0.2").unwrap()];
        assert_eq!(client_ip_with(&from([172, 20, 0, 2]), true, &proxies, false), IpAddr::from([198, 51, 100, 7]));
        assert_eq!(
            client_ip_with(&from([172, 20, 0, 9]), true, &proxies, false),
            IpAddr::from([172, 20, 0, 9]),
            "another container on the proxy network is not believed (R1-13)"
        );
        assert_eq!(
            client_ip_with(&from([172, 20, 0, 9]), true, &[], false),
            IpAddr::from([198, 51, 100, 7]),
            "no list: every peer"
        );
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
