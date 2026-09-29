//! Secrets the server keeps for talking to others — an OpenID Connect client secret, later the
//! tokens of masked addresses — encrypted at rest (docs/uwu-api.md §13.2, §19.5).
//!
//! AES-256-GCM under a key in a file of its own in the data directory (`secret.key`, made on
//! first use, mode 0600), not in the database: a copy of the database alone opens none of them.
//! The off-site backups take the file along, as they take the rest of the data directory. What
//! a value is for goes in as associated data, so one sealed value does not pass as another.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use parking_lot::Mutex;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use std::path::PathBuf;
use std::sync::Arc;

/// How a sealed value starts.
const PREFIX: &str = "v1.";
const FILE: &str = "secret.key";

/// The server's secret for values at rest, read (or made) when first needed.
pub struct ServerSecret {
    path: PathBuf,
    key: Mutex<Option<Arc<LessSafeKey>>>,
}

impl ServerSecret {
    pub fn new(data: &std::path::Path) -> Self {
        ServerSecret { path: data.join(FILE), key: Mutex::new(None) }
    }

    /// Read the file again on the next use: a restore may have brought another.
    pub fn forget(&self) {
        *self.key.lock() = None;
    }

    fn key(&self) -> Result<Arc<LessSafeKey>, String> {
        let mut held = self.key.lock();
        if let Some(key) = held.as_ref() {
            return Ok(key.clone());
        }
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let fresh = crate::auth::random_bytes(32);
                write_private(&self.path, &fresh).map_err(|error| format!("{}: {error}", self.path.display()))?;
                fresh
            }
            Err(error) => return Err(format!("{}: {error}", self.path.display())),
        };
        let key = UnboundKey::new(&AES_256_GCM, &bytes)
            .map_err(|_| format!("{} is damaged: it is not a key of 32 bytes", self.path.display()))?;
        let key = Arc::new(LessSafeKey::new(key));
        *held = Some(key.clone());
        Ok(key)
    }

    /// `plain`, encrypted for `purpose`: `v1.` and base64 of nonce and ciphertext.
    pub fn seal(&self, plain: &str, purpose: &str) -> Result<String, String> {
        let key = self.key()?;
        let nonce: [u8; NONCE_LEN] = crate::auth::random_bytes(NONCE_LEN).try_into().expect("12 bytes");
        let mut sealed = plain.as_bytes().to_vec();
        key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(purpose.as_bytes()), &mut sealed)
            .map_err(|_| "the value could not be encrypted".to_string())?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&sealed);
        Ok(format!("{PREFIX}{}", STANDARD.encode(out)))
    }

    /// What [`ServerSecret::seal`] sealed for `purpose`. A value that was never sealed (typed in
    /// on the command line) comes back as it is.
    pub fn open(&self, sealed: &str, purpose: &str) -> Result<String, String> {
        let Some(encoded) = sealed.strip_prefix(PREFIX) else { return Ok(sealed.to_string()) };
        let refused = || format!("a value in the database does not open with {}", self.path.display());
        let bytes = STANDARD.decode(encoded).map_err(|_| refused())?;
        if bytes.len() < NONCE_LEN {
            return Err(refused());
        }
        let (nonce, sealed) = bytes.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| refused())?;
        let mut sealed = sealed.to_vec();
        let key = self.key()?;
        let plain =
            key.open_in_place(nonce, Aad::from(purpose.as_bytes()), &mut sealed).map_err(|_| refused())?.to_vec();
        String::from_utf8(plain).map_err(|_| refused())
    }
}

/// A new file only its owner reads.
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_value_opens_only_for_its_purpose_and_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let secret = ServerSecret::new(dir.path());
        let sealed = secret.seal("geheim", "sso.clientSecret").unwrap();
        assert!(sealed.starts_with("v1.") && !sealed.contains("geheim"));
        assert_eq!(secret.open(&sealed, "sso.clientSecret").unwrap(), "geheim");
        assert!(secret.open(&sealed, "something else").is_err());
        assert_eq!(secret.open("typed in", "sso.clientSecret").unwrap(), "typed in", "never sealed");

        // The same file opens it after a restart; another does not.
        let again = ServerSecret::new(dir.path());
        assert_eq!(again.open(&sealed, "sso.clientSecret").unwrap(), "geheim");
        let other = tempfile::tempdir().unwrap();
        assert!(ServerSecret::new(other.path()).open(&sealed, "sso.clientSecret").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.path().join(FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
