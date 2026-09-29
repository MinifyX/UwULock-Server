//! Backups over SFTP. The server's host key is remembered the first time (like `ssh` asks once) and
//! must stay the same afterwards. Logging in works with this server's own key, which the admin puts
//! into `authorized_keys`, or with a password for NAS systems that only offer that.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::ssh_key::LineEnding;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh_sftp::client::{RawSftpSession, SftpSession};
use russh_sftp::protocol::StatusCode;
use serde::{Deserialize, Serialize};

use crate::Error;

const TIMEOUT: Duration = Duration::from_secs(60);
/// Pages of a listing that bring no name at all, before the server counts as stalling.
const EMPTY_PAGES_MAX: usize = 100;

/// How to log in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "camelCase")]
pub enum Login {
    /// This server's own key, in OpenSSH format.
    Key {
        private_key: String,
    },
    Password {
        password: String,
    },
}

/// An SFTP server the backups go to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SftpTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// The directory on the server, e.g. `/volume1/backups/uwulock`.
    pub path: String,
    pub login: Login,
    /// `SHA256:…` of the server's host key once known.
    pub host_key: Option<String>,
}

/// A new key pair for logging in: the private key in OpenSSH format and the public line for
/// `authorized_keys`.
pub fn generate_key(comment: &str) -> Result<(String, String), Error> {
    let seed: [u8; 32] = crate::format::random()?;
    let key =
        PrivateKey::new(KeypairData::from(Ed25519Keypair::from_seed(&seed)), comment).map_err(|_| Error::Crypto)?;
    let private = key.to_openssh(LineEnding::LF).map_err(|_| Error::Crypto)?.to_string();
    let public = key.public_key().to_openssh().map_err(|_| Error::Crypto)?;
    Ok((private, public))
}

/// The public line for `authorized_keys` of a stored private key.
pub fn public_key_line(private_key: &str) -> Result<String, Error> {
    let key =
        PrivateKey::from_openssh(private_key).map_err(|_| Error::Config("the stored SSH key is damaged".into()))?;
    key.public_key().to_openssh().map_err(|_| Error::Crypto)
}

struct HostKeyCheck {
    expected: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
}

impl client::Handler for HostKeyCheck {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else { return Ok(false) };
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        let trusted = self.expected.as_ref().is_none_or(|expected| *expected == fingerprint);
        *self.seen.lock().expect("host key lock") = Some(fingerprint);
        Ok(trusted)
    }
}

pub struct Sftp {
    session: SftpSession,
    /// A second SFTP channel for directory listings, read page by page with a ceiling:
    /// `SftpSession::read_dir` collects whatever the server sends, for as long as it sends it.
    lister: RawSftpSession,
    handle: Handle<HostKeyCheck>,
    root: String,
    /// The host key this connection saw, to remember after the first one.
    pub host_key: String,
}

fn sftp_error(err: russh_sftp::client::error::Error) -> Error {
    Error::Storage(err.to_string())
}

fn not_found(err: &russh_sftp::client::error::Error) -> bool {
    matches!(err, russh_sftp::client::error::Error::Status(status) if status.status_code == StatusCode::NoSuchFile)
}

impl Sftp {
    pub async fn connect(target: &SftpTarget) -> Result<Sftp, Error> {
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(300)),
            keepalive_interval: Some(Duration::from_secs(30)),
            ..Default::default()
        };
        let seen = Arc::new(Mutex::new(None));
        let check = HostKeyCheck { expected: target.host_key.clone(), seen: seen.clone() };
        let connecting = client::connect(Arc::new(config), (target.host.as_str(), target.port), check);
        let mut handle = match tokio::time::timeout(TIMEOUT, connecting).await {
            Err(_) => return Err(Error::Storage(format!("{}:{} did not answer", target.host, target.port))),
            Ok(Err(err)) => {
                let seen = seen.lock().expect("host key lock").clone();
                return Err(match (seen, &target.host_key) {
                    (Some(seen), Some(expected)) if &seen != expected => {
                        Error::HostKeyChanged { expected: expected.clone(), seen }
                    }
                    _ => Error::Storage(format!("connecting to {}:{}: {err}", target.host, target.port)),
                });
            }
            Ok(Ok(handle)) => handle,
        };
        let host_key = seen.lock().expect("host key lock").clone().unwrap_or_default();

        let authenticated = match &target.login {
            Login::Key { private_key } => {
                let key = PrivateKey::from_openssh(private_key)
                    .map_err(|_| Error::Config("the stored SSH key is damaged".into()))?;
                let hash =
                    handle.best_supported_rsa_hash().await.map_err(|err| Error::Storage(err.to_string()))?.flatten();
                handle.authenticate_publickey(&target.user, PrivateKeyWithHashAlg::new(Arc::new(key), hash)).await
            }
            Login::Password { password } => handle.authenticate_password(&target.user, password).await,
        }
        .map_err(|err| Error::Storage(format!("logging in: {err}")))?;
        if !authenticated.success() {
            return Err(Error::LoginRefused(target.user.clone()));
        }

        let channel = handle.channel_open_session().await.map_err(|err| Error::Storage(err.to_string()))?;
        channel.request_subsystem(true, "sftp").await.map_err(|err| Error::Storage(err.to_string()))?;
        let session = SftpSession::new(channel.into_stream()).await.map_err(sftp_error)?;
        session.set_timeout(TIMEOUT.as_secs());
        let channel = handle.channel_open_session().await.map_err(|err| Error::Storage(err.to_string()))?;
        channel.request_subsystem(true, "sftp").await.map_err(|err| Error::Storage(err.to_string()))?;
        let lister = RawSftpSession::new(channel.into_stream());
        lister.set_timeout(TIMEOUT.as_secs());
        lister.init().await.map_err(sftp_error)?;
        let root = target.path.trim_end_matches('/').to_owned();
        let root = if root.is_empty() { ".".to_owned() } else { root };
        let sftp = Sftp { session, lister, handle, root, host_key };
        sftp.create_dirs("").await?;
        Ok(sftp)
    }

    fn full(&self, path: &str) -> String {
        if path.is_empty() { self.root.clone() } else { format!("{}/{path}", self.root) }
    }

    /// A file's content, up to one byte past `limit`: whatever size the server claims or sends, no
    /// more than that is ever held.
    pub async fn read(&self, path: &str, limit: u64) -> Result<Option<Vec<u8>>, Error> {
        use tokio::io::AsyncReadExt;
        let file = match self.session.open(self.full(path)).await {
            Ok(file) => file,
            Err(err) if not_found(&err) => return Ok(None),
            Err(err) => return Err(sftp_error(err)),
        };
        let mut bytes = Vec::new();
        let mut limited = file.take(limit.saturating_add(1));
        limited.read_to_end(&mut bytes).await?;
        let _ = limited.into_inner().close().await;
        Ok(Some(bytes))
    }

    pub async fn write(&self, path: &str, bytes: &[u8]) -> Result<(), Error> {
        use tokio::io::AsyncWriteExt;
        let mut file = self.session.create(self.full(path)).await.map_err(sftp_error)?;
        file.write_all(bytes).await?;
        file.shutdown().await?;
        Ok(())
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<(), Error> {
        // Plain SFTP refuses to rename onto an existing file.
        let _ = self.session.remove_file(self.full(to)).await;
        self.session.rename(self.full(from), self.full(to)).await.map_err(sftp_error)
    }

    /// The names in a directory, with the same ceiling as an S3 listing: a backup server that is
    /// not ours must not be able to have this one collect names until the memory is gone.
    pub async fn list(&self, dir: &str) -> Result<Vec<String>, Error> {
        self.list_within(dir, crate::MAX_LISTED_NAMES, crate::MAX_LISTED_BYTES).await
    }

    /// [`Sftp::list`] with other ceilings, for the tests.
    #[doc(hidden)]
    pub async fn list_within(&self, dir: &str, max_names: usize, max_bytes: usize) -> Result<Vec<String>, Error> {
        let handle = match self.lister.opendir(self.full(dir)).await {
            Ok(opened) => opened.handle,
            Err(err) if not_found(&err) => return Ok(Vec::new()),
            Err(err) => return Err(sftp_error(err)),
        };
        let listed = self.pages(&handle, max_names, max_bytes).await;
        let _ = self.lister.close(handle).await;
        listed
    }

    async fn pages(&self, handle: &str, max_names: usize, max_bytes: usize) -> Result<Vec<String>, Error> {
        let (mut names, mut bytes, mut empty) = (Vec::new(), 0usize, 0usize);
        loop {
            let page = match self.lister.readdir(handle).await {
                Ok(page) => page,
                Err(russh_sftp::client::error::Error::Status(status)) if status.status_code == StatusCode::Eof => {
                    return Ok(names);
                }
                Err(err) => return Err(sftp_error(err)),
            };
            if page.files.is_empty() {
                empty += 1;
                if empty > EMPTY_PAGES_MAX {
                    return Err(Error::Damaged("the backup server never finished its listing".into()));
                }
            }
            for file in page.files {
                bytes += file.filename.len();
                names.push(file.filename);
                if names.len() > max_names || bytes > max_bytes {
                    return Err(Error::Damaged("the backup server lists more than this reads".into()));
                }
            }
        }
    }

    pub async fn remove(&self, path: &str) -> Result<(), Error> {
        match self.session.remove_file(self.full(path)).await {
            Err(err) if !not_found(&err) => Err(sftp_error(err)),
            _ => Ok(()),
        }
    }

    /// Creates the directory and its parents below the repository root, and the root itself.
    pub async fn create_dirs(&self, dir: &str) -> Result<(), Error> {
        let mut current = String::new();
        let root_parts: Vec<&str> = self.root.split('/').collect();
        let absolute = self.root.starts_with('/');
        let parts = root_parts.iter().copied().chain(dir.split('/')).filter(|part| !part.is_empty() && *part != ".");
        for part in parts {
            current = if current.is_empty() && !absolute { part.to_owned() } else { format!("{current}/{part}") };
            match self.session.try_exists(current.clone()).await {
                Ok(true) => continue,
                Ok(false) => self.session.create_dir(current.clone()).await.map_err(sftp_error)?,
                Err(err) => return Err(sftp_error(err)),
            }
        }
        Ok(())
    }

    pub async fn close(self) {
        let _ = self.lister.close_session();
        let _ = self.session.close().await;
        let _ = self.handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
    }
}
