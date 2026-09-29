//! Backups over SFTP, against a small SFTP server that runs inside the test: russh's server side
//! with the files in memory. It checks the login and has a host key of its own.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use russh::keys::PrivateKey;
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode};
use uwulock_backup::sftp::{Sftp, generate_key, public_key_line};
use uwulock_backup::{Error, Login, RepoKey, Repository, SftpTarget, Storage};

use crate::support::*;

#[derive(Default)]
struct Disk {
    files: BTreeMap<String, Vec<u8>>,
    dirs: BTreeSet<String>,
}

type Shared = Arc<Mutex<Disk>>;

#[derive(Clone)]
struct SshServer {
    disk: Shared,
    /// The `authorized_keys` line of the one key that may log in.
    authorized: String,
}

impl russh::server::Server for SshServer {
    type Handler = Connection;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Connection {
        Connection { server: self.clone(), channels: HashMap::new() }
    }
}

struct Connection {
    server: SshServer,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl russh::server::Handler for Connection {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if user == "backup" && password == "geheim" { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_publickey(&mut self, user: &str, key: &russh::keys::PublicKey) -> Result<Auth, Self::Error> {
        let line = key.to_openssh().unwrap_or_default();
        let known = self.server.authorized.split_whitespace().take(2).collect::<Vec<_>>();
        let offered = line.split_whitespace().take(2).collect::<Vec<_>>();
        Ok(if user == "backup" && known == offered { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_eof(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.close(channel)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match (name, self.channels.remove(&channel)) {
            ("sftp", Some(open)) => {
                session.channel_success(channel)?;
                let files = Files { disk: self.server.disk.clone(), handles: HashMap::new(), next: 0 };
                tokio::spawn(russh_sftp::server::run(open.into_stream(), files));
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }
}

/// The SFTP side: files and folders in memory.
struct Files {
    disk: Shared,
    /// Open handles: the path, and for a folder whether its listing went out already.
    handles: HashMap<String, (String, bool)>,
    next: u32,
}

fn ok(id: u32) -> Status {
    Status { id, status_code: StatusCode::Ok, error_message: "Ok".into(), language_tag: "en-US".into() }
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

impl Files {
    fn handle(&mut self, path: String) -> String {
        self.next += 1;
        let handle = format!("h{}", self.next);
        self.handles.insert(handle.clone(), (path, false));
        handle
    }

    fn path(&self, handle: &str) -> Result<String, StatusCode> {
        self.handles.get(handle).map(|(path, _)| path.clone()).ok_or(StatusCode::Failure)
    }

    fn attributes(disk: &Disk, path: &str) -> Option<FileAttributes> {
        let mut attrs = FileAttributes::empty();
        if let Some(content) = disk.files.get(path) {
            attrs.size = Some(content.len() as u64);
            attrs.permissions = Some(0o100_600);
        } else if disk.dirs.contains(path) {
            attrs.permissions = Some(0o040_700);
        } else {
            return None;
        }
        Some(attrs)
    }
}

impl russh_sftp::server::Handler for Files {
    type Error = StatusCode;

    fn unimplemented(&self) -> StatusCode {
        StatusCode::OpUnsupported
    }

    async fn open(&mut self, id: u32, path: String, flags: OpenFlags, _: FileAttributes) -> Result<Handle, StatusCode> {
        {
            let mut disk = self.disk.lock().unwrap();
            if !disk.dirs.contains(parent(&path)) {
                return Err(StatusCode::NoSuchFile);
            }
            let exists = disk.files.contains_key(&path);
            if flags.contains(OpenFlags::CREATE) && (!exists || flags.contains(OpenFlags::TRUNCATE)) {
                disk.files.insert(path.clone(), Vec::new());
            } else if !exists {
                return Err(StatusCode::NoSuchFile);
            }
        }
        Ok(Handle { id, handle: self.handle(path) })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, StatusCode> {
        self.handles.remove(&handle);
        Ok(ok(id))
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, StatusCode> {
        let path = self.path(&handle)?;
        let disk = self.disk.lock().unwrap();
        let content = disk.files.get(&path).ok_or(StatusCode::NoSuchFile)?;
        let start = offset as usize;
        if start >= content.len() {
            return Err(StatusCode::Eof);
        }
        let end = (start + len as usize).min(content.len());
        Ok(Data { id, data: content[start..end].to_vec() })
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, StatusCode> {
        let path = self.path(&handle)?;
        let mut disk = self.disk.lock().unwrap();
        let content = disk.files.get_mut(&path).ok_or(StatusCode::NoSuchFile)?;
        let end = offset as usize + data.len();
        if content.len() < end {
            content.resize(end, 0);
        }
        content[offset as usize..end].copy_from_slice(&data);
        Ok(ok(id))
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, StatusCode> {
        let disk = self.disk.lock().unwrap();
        Files::attributes(&disk, &path).map(|attrs| Attrs { id, attrs }).ok_or(StatusCode::NoSuchFile)
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, StatusCode> {
        self.stat(id, path).await
    }

    async fn mkdir(&mut self, id: u32, path: String, _: FileAttributes) -> Result<Status, StatusCode> {
        let mut disk = self.disk.lock().unwrap();
        if !disk.dirs.contains(parent(&path)) || !disk.dirs.insert(path) {
            return Err(StatusCode::Failure);
        }
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, StatusCode> {
        if !self.disk.lock().unwrap().dirs.contains(&path) {
            return Err(StatusCode::NoSuchFile);
        }
        Ok(Handle { id, handle: self.handle(path) })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, StatusCode> {
        let (path, listed) = self.handles.get_mut(&handle).ok_or(StatusCode::Failure)?;
        // A hostile server: names for ever, or pages with none, never the end.
        if path.ends_with("/endless") {
            self.next += 1;
            let files = (0..10).map(|n| File::dummy(format!("{}-{n}", self.next))).collect();
            return Ok(Name { id, files });
        }
        if path.ends_with("/stalling") {
            return Ok(Name { id, files: Vec::new() });
        }
        if *listed {
            return Err(StatusCode::Eof);
        }
        *listed = true;
        let disk = self.disk.lock().unwrap();
        let prefix = format!("{path}/");
        let children = disk.files.keys().chain(disk.dirs.iter()).filter_map(|name| name.strip_prefix(&prefix));
        let files = children
            .filter(|name| !name.contains('/'))
            .map(|name| File::new(name, Files::attributes(&disk, &format!("{prefix}{name}")).unwrap()))
            .collect();
        Ok(Name { id, files })
    }

    async fn remove(&mut self, id: u32, path: String) -> Result<Status, StatusCode> {
        match self.disk.lock().unwrap().files.remove(&path) {
            Some(_) => Ok(ok(id)),
            None => Err(StatusCode::NoSuchFile),
        }
    }

    async fn rename(&mut self, id: u32, from: String, to: String) -> Result<Status, StatusCode> {
        let mut disk = self.disk.lock().unwrap();
        // Plain SFTP does not rename onto an existing file.
        if disk.files.contains_key(&to) {
            return Err(StatusCode::Failure);
        }
        let content = disk.files.remove(&from).ok_or(StatusCode::NoSuchFile)?;
        disk.files.insert(to, content);
        Ok(ok(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, StatusCode> {
        Ok(Name { id, files: vec![File::dummy(path)] })
    }
}

/// An SFTP server on a free port, with an empty `/srv` and a host key of its own.
async fn sftp_server(authorized: String) -> (u16, Shared) {
    let disk = Shared::default();
    disk.lock().unwrap().dirs.extend(["".to_string(), "/srv".to_string()]);
    let (host_key, _) = generate_key("host").unwrap();
    let config = russh::server::Config {
        keys: vec![PrivateKey::from_openssh(&host_key).unwrap()],
        auth_rejection_time: std::time::Duration::ZERO,
        auth_rejection_time_initial: Some(std::time::Duration::ZERO),
        ..Default::default()
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut server = SshServer { disk: disk.clone(), authorized };
    tokio::spawn(async move {
        let _ = server.run_on_socket(Arc::new(config), &listener).await;
    });
    (port, disk)
}

#[tokio::test]
async fn a_backup_goes_over_sftp_and_comes_back() {
    let (private_key, public_line) = generate_key("uwulock@lock.example.com").unwrap();
    assert_eq!(public_key_line(&private_key).unwrap(), public_line);
    let (port, disk) = sftp_server(public_line).await;
    let target = |login: Login, host_key: Option<String>| SftpTarget {
        host: "127.0.0.1".into(),
        port,
        user: "backup".into(),
        path: "/srv/uwulock".into(),
        login,
        host_key,
    };
    let with_key = Login::Key { private_key: private_key.clone() };

    let first = Sftp::connect(&target(with_key.clone(), None)).await.unwrap();
    let host_key = first.host_key.clone();
    assert!(host_key.starts_with("SHA256:"), "{host_key}");
    let server = Server::new().await;
    let key = RepoKey::generate();
    let repo = Repository::open(Storage::Sftp(Box::new(first)), Some(key.clone()), 1).await.unwrap();
    let report = server.backup(&repo, 1_000).await;
    assert!(uwulock_backup::check(&repo, &report.snapshot).await.unwrap().is_empty());
    repo.storage.close().await;
    assert!(disk.lock().unwrap().files.keys().any(|name| name.starts_with("/srv/uwulock/snapshots/")));

    // Another host key than the one remembered: nothing goes there.
    let other = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    assert!(matches!(Sftp::connect(&target(with_key.clone(), Some(other))).await, Err(Error::HostKeyChanged { .. })));
    // A password works too; a wrong one does not.
    let wrong = target(Login::Password { password: "falsch".into() }, Some(host_key.clone()));
    assert!(matches!(Sftp::connect(&wrong).await, Err(Error::LoginRefused(_))));
    let password = target(Login::Password { password: "geheim".into() }, Some(host_key.clone()));

    let again = Sftp::connect(&password).await.unwrap();
    let repo = Repository::open_existing(Storage::Sftp(Box::new(again)), Some(key)).await.unwrap();
    let new = tempfile::tempdir().unwrap();
    uwulock_backup::restore_into(&repo, &report.snapshot, new.path()).await.unwrap();
    repo.storage.close().await;
    check_restored(new.path()).await;
}

/// A backup server that lists without end does not get this one to collect names until the
/// memory is gone (review finding M2).
#[tokio::test]
async fn an_endless_listing_is_cut_off() {
    let (port, disk) = sftp_server(String::new()).await;
    disk.lock().unwrap().dirs.extend(["/srv/endless".to_string(), "/srv/stalling".to_string()]);
    let target = SftpTarget {
        host: "127.0.0.1".into(),
        port,
        user: "backup".into(),
        path: "/srv".into(),
        login: Login::Password { password: "geheim".into() },
        host_key: None,
    };
    let sftp = Sftp::connect(&target).await.unwrap();
    let error = sftp.list_within("endless", 100, 1 << 20).await.unwrap_err();
    assert!(error.to_string().contains("more than this reads"), "{error}");
    let error = sftp.list_within("endless", 1_000_000, 500).await.unwrap_err();
    assert!(error.to_string().contains("more than this reads"), "{error}");
    let error = sftp.list("stalling").await.unwrap_err();
    assert!(error.to_string().contains("never finished"), "{error}");
    assert!(sftp.list("missing").await.unwrap().is_empty());
    sftp.close().await;
}
