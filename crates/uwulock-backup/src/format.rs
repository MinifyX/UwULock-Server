//! How a backup repository looks: a small plain config, objects under `data/<2 hex>/<id>` and one
//! manifest per snapshot under `snapshots/`. Every object is compressed and, unless the repository
//! was created without, encrypted with ChaCha20-Poly1305.
//!
//! An object's id comes from the SHA-256 of its content: keyed with HMAC in an encrypted
//! repository, so the names on the backup server give nothing away, and plain otherwise. The same
//! content is stored once, whichever snapshot brought it.
//!
//! The same format as UwUMail Server's backups (its `uwumail-backup` crate), with UwULock's own
//! config name and manifest.

use std::io::{Read, Write};

use data_encoding::BASE32_NOPAD;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hmac;
use serde::{Deserialize, Serialize};

use crate::Error;

pub const CONFIG_PATH: &str = "uwulock-backup.json";
pub const FORMAT: u32 = 1;
const OBJECT_VERSION: u8 = 1;
const FLAG_ENCRYPTED: u8 = 0x80;
const FLAG_COMPRESSED: u8 = 0x01;
const KEY_CHECK: &[u8] = b"uwulock backup key check";

/// Lower-case hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 15)] as char);
    }
    out
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

pub(crate) fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0u8; N];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).map_err(|_| Error::Crypto)?;
    Ok(bytes)
}

/// The secret of an encrypted repository. It never leaves the server except as the recovery key.
#[derive(Clone)]
pub struct RepoKey {
    secret: [u8; 32],
}

impl std::fmt::Debug for RepoKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RepoKey(…)")
    }
}

impl RepoKey {
    pub fn generate() -> RepoKey {
        RepoKey { secret: random().expect("the system random generator works") }
    }

    /// The key as people write it down: groups of four letters and digits.
    pub fn recovery_text(&self) -> String {
        let encoded = BASE32_NOPAD.encode(&self.secret);
        encoded.as_bytes().chunks(4).map(|chunk| String::from_utf8_lossy(chunk)).collect::<Vec<_>>().join("-")
    }

    /// Reads a recovery key; dashes, spaces and lower case do not matter.
    pub fn from_recovery_text(text: &str) -> Result<RepoKey, Error> {
        let cleaned: String =
            text.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect();
        let bytes = BASE32_NOPAD.decode(cleaned.as_bytes()).map_err(|_| Error::WrongKey)?;
        let secret: [u8; 32] = bytes.try_into().map_err(|_| Error::WrongKey)?;
        Ok(RepoKey { secret })
    }

    fn derived(&self, purpose: &[u8]) -> [u8; 32] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.secret);
        hmac::sign(&key, purpose).as_ref().try_into().expect("HMAC-SHA256 has 32 bytes")
    }

    fn check(&self) -> String {
        hex(&self.derived(KEY_CHECK))
    }
}

/// `uwulock-backup.json`: readable without the key, so a restore knows what to ask for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepoConfig {
    pub format: u32,
    pub encrypted: bool,
    /// Tells a wrong recovery key apart from damaged data.
    pub key_check: Option<String>,
    pub created_at: i64,
}

/// Turns content into stored objects and back.
#[derive(Clone)]
pub struct Codec {
    key: Option<RepoKey>,
}

impl Codec {
    /// Whether the repository is encrypted is this server's decision, made by whether it has a
    /// key, and never the backup server's: `uwulock-backup.json` lies there unauthenticated, so a
    /// repository that says "not encrypted" to a server with a key was changed, or is not one to
    /// write plain text into.
    pub fn new(config: &RepoConfig, key: Option<RepoKey>) -> Result<Codec, Error> {
        match (config.encrypted, key) {
            (false, None) => Ok(Codec { key: None }),
            (false, Some(_)) => Err(Error::Damaged(
                "the backup server says this backup is not encrypted, but this server encrypts its backups; \
                 it was changed, or the folder holds another backup"
                    .into(),
            )),
            (true, None) => Err(Error::WrongKey),
            (true, Some(key)) => {
                if config.key_check.as_deref() != Some(key.check().as_str()) {
                    return Err(Error::WrongKey);
                }
                Ok(Codec { key: Some(key) })
            }
        }
    }

    pub fn config_for(key: Option<&RepoKey>, created_at: i64) -> RepoConfig {
        RepoConfig { format: FORMAT, encrypted: key.is_some(), key_check: key.map(RepoKey::check), created_at }
    }

    /// The id of content whose SHA-256 is `sha256` (hex).
    pub fn id_for_hash(&self, sha256: &str) -> String {
        match &self.key {
            Some(key) => {
                let ids = hmac::Key::new(hmac::HMAC_SHA256, &key.derived(b"ids"));
                hex(hmac::sign(&ids, sha256.as_bytes()).as_ref())
            }
            None => sha256.to_owned(),
        }
    }

    pub fn id_for(&self, content: &[u8]) -> String {
        self.id_for_hash(&sha256_hex(content))
    }

    fn sealing_key(key: &RepoKey) -> Result<LessSafeKey, Error> {
        Ok(LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key.derived(b"encrypt")).map_err(|_| Error::Crypto)?))
    }

    pub fn encode(&self, content: &[u8]) -> Result<Vec<u8>, Error> {
        let mut compressor = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        compressor.write_all(content)?;
        let compressed = compressor.finish()?;
        let (flags, body) =
            if compressed.len() < content.len() { (FLAG_COMPRESSED, compressed) } else { (0, content.to_vec()) };
        let Some(key) = &self.key else {
            let mut object = vec![OBJECT_VERSION, flags];
            object.extend_from_slice(&body);
            return Ok(object);
        };
        let nonce: [u8; NONCE_LEN] = random()?;
        let header = [OBJECT_VERSION, flags | FLAG_ENCRYPTED];
        let mut sealed = body;
        Self::sealing_key(key)?
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(header), &mut sealed)
            .map_err(|_| Error::Crypto)?;
        let mut object = header.to_vec();
        object.extend_from_slice(&nonce);
        object.extend_from_slice(&sealed);
        Ok(object)
    }

    /// The content of a stored object, refused when it would be longer than `limit` bytes.
    pub fn decode(&self, object: &[u8], limit: u64) -> Result<Vec<u8>, Error> {
        let [version, flags, rest @ ..] = object else { return Err(Error::Damaged("an object is too short".into())) };
        if *version != OBJECT_VERSION {
            return Err(Error::Damaged(format!("unknown object version {version}")));
        }
        // Every object this server writes into an encrypted repository is sealed. One that is not
        // was put there by someone without the key, and is never read, let alone inflated.
        if self.key.is_some() && flags & FLAG_ENCRYPTED == 0 {
            return Err(Error::Damaged("an object in this encrypted backup is not encrypted; it was changed".into()));
        }
        let body = if flags & FLAG_ENCRYPTED != 0 {
            let key = self.key.as_ref().ok_or(Error::WrongKey)?;
            if rest.len() < NONCE_LEN {
                return Err(Error::Damaged("an encrypted object is too short".into()));
            }
            let (nonce, sealed) = rest.split_at(NONCE_LEN);
            let mut sealed = sealed.to_vec();
            let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| Error::Crypto)?;
            let header = [*version, *flags];
            let plain = Self::sealing_key(key)?
                .open_in_place(nonce, Aad::from(header), &mut sealed)
                .map_err(|_| Error::Damaged("an object does not decrypt; it was changed or the key is wrong".into()))?;
            plain.to_vec()
        } else {
            rest.to_vec()
        };
        let too_long = || Error::Damaged(format!("an object is longer than the {limit} bytes it may have"));
        if flags & FLAG_COMPRESSED == 0 {
            return if body.len() as u64 > limit { Err(too_long()) } else { Ok(body) };
        }
        // Inflated only up to the limit, so a small object cannot unpack into all the memory there is.
        let mut content = Vec::new();
        flate2::read::DeflateDecoder::new(&body[..]).take(limit.saturating_add(1)).read_to_end(&mut content)?;
        if content.len() as u64 > limit {
            return Err(too_long());
        }
        Ok(content)
    }
}

/// Object ids are the hex of a SHA-256, keyed or plain, and nothing else may ever reach a path.
/// The names a backup server lists, and what a snapshot names, are what a hostile server controls.
pub fn checked_id(id: &str) -> Result<&str, Error> {
    if id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(id);
    }
    Err(Error::Damaged(format!("the backup names something that is not an id: {}", id.escape_debug())))
}

/// The path of an object in the repository.
pub fn object_path(id: &str) -> Result<String, Error> {
    let id = checked_id(id)?;
    Ok(format!("data/{}/{id}", &id[..2]))
}

/// Whether a name under `snapshots/` is one this server gives: the time, a dash and six hex digits.
pub fn is_snapshot_name(name: &str) -> bool {
    let Some((time, suffix)) = name.split_once('-') else { return false };
    time.len() == 12
        && time.bytes().all(|byte| byte.is_ascii_digit())
        && suffix.len() == 6
        && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// A file from the data directory: an attachment, a Send's file, a file-request upload, an icon,
/// a certificate or key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    /// Relative to the data directory, with `/`.
    pub path: String,
    /// Its content-defined chunks, in order.
    pub chunks: Vec<String>,
    pub size: u64,
    /// When it was last changed, in nanoseconds since 1970: with the size, how the next backup knows
    /// the file is the same without reading it again.
    #[serde(default)]
    pub modified: i64,
}

/// What one snapshot holds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub format: u32,
    pub created_at: i64,
    /// The server's public host, to tell the snapshots of several servers apart.
    pub hostname: String,
    pub version: String,
    /// The database's schema version.
    pub schema: i64,
    /// The database, in order.
    pub database: Vec<String>,
    pub database_size: u64,
    pub files: Vec<FileEntry>,
    pub files_size: u64,
    /// Bytes this snapshot had to upload.
    pub uploaded: u64,
    /// The name it is stored under, so an authentic manifest cannot be passed off under another.
    pub name: String,
}

impl Manifest {
    /// Every object the snapshot needs.
    pub fn objects(&self) -> impl Iterator<Item = &String> {
        self.database.iter().chain(self.files.iter().flat_map(|file| file.chunks.iter()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objects_round_trip_and_hide_their_content() {
        let key = RepoKey::generate();
        let config = Codec::config_for(Some(&key), 0);
        let codec = Codec::new(&config, Some(key.clone())).unwrap();
        let content = b"a vault a vault a vault a vault a vault a vault a vault".repeat(20);
        let object = codec.encode(&content).unwrap();
        assert!(object.len() < content.len(), "compressed");
        assert!(!object.windows(5).any(|window| window == b"vault"), "encrypted");
        assert_eq!(codec.decode(&object, u64::MAX).unwrap(), content);
        let id = codec.id_for(&content);
        assert_ne!(id, sha256_hex(&content), "ids are keyed");

        let mut tampered = object.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(codec.decode(&tampered, u64::MAX), Err(Error::Damaged(_))));
        assert!(matches!(Codec::new(&config, Some(RepoKey::generate())), Err(Error::WrongKey)));

        let text = key.recovery_text();
        assert_eq!(text.len(), 52 + 12, "52 characters in groups of four");
        let typed = text.to_lowercase().replace('-', " ");
        assert!(Codec::new(&config, Some(RepoKey::from_recovery_text(&typed).unwrap())).is_ok());
    }

    #[test]
    fn a_key_is_never_given_up_for_what_the_backup_server_says() {
        let key = RepoKey::generate();
        let plain_config = Codec::config_for(None, 0);
        assert!(matches!(Codec::new(&plain_config, Some(key.clone())), Err(Error::Damaged(_))));
        let codec = Codec::new(&Codec::config_for(Some(&key), 0), Some(key)).unwrap();
        let plain = Codec::new(&plain_config, None).unwrap();
        for object in [plain.encode(b"not sealed").unwrap(), plain.encode(&[b'x'; 4096]).unwrap()] {
            assert!(matches!(codec.decode(&object, u64::MAX), Err(Error::Damaged(_))), "{:?}", &object[..2]);
        }
    }

    #[test]
    fn plain_repositories_only_compress_and_inflate_no_further_than_their_limit() {
        let codec = Codec::new(&Codec::config_for(None, 0), None).unwrap();
        let object = codec.encode(b"x").unwrap();
        assert_eq!(object, [OBJECT_VERSION, 0, b'x'], "not worth compressing");
        assert_eq!(codec.id_for(b"x"), sha256_hex(b"x"));
        let object = codec.encode(&vec![0u8; 1024 * 1024]).unwrap();
        assert!(object.len() < 4096);
        assert_eq!(codec.decode(&object, 1024 * 1024).unwrap().len(), 1024 * 1024);
        assert!(matches!(codec.decode(&object, 64 * 1024), Err(Error::Damaged(_))));
    }

    #[test]
    fn only_ids_and_snapshot_names_reach_a_path() {
        let id = "ab".repeat(32);
        assert_eq!(object_path(&id).unwrap(), format!("data/ab/{id}"));
        for bad in ["x", "é", "", "../../etc/passwd", &"g".repeat(64), &format!("{id}0")] {
            assert!(object_path(bad).is_err(), "{bad}");
        }
        assert!(is_snapshot_name("000001000000-0a1b2c"));
        for bad in ["x", "000001000000-0a1b2", "00000100000a-0a1b2c", "../000001000000-0a1b2c"] {
            assert!(!is_snapshot_name(bad), "{bad}");
        }
    }
}
