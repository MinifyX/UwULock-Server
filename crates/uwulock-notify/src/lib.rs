//! Live updates for the clients.
//!
//! Bitwarden's browser extension, desktop app and web vault keep a WebSocket open to
//! `/notifications/hub` and speak SignalR over it, with MessagePack: when something of the account
//! changes on another device, the server says what, and they sync it at once instead of on their
//! next look. A device that is not logged in yet — one that asked another to let it in — listens
//! on `/notifications/anonymous-hub` for the answer. The phone apps are asleep most of the time;
//! they are woken through Bitwarden's push relay ([`relay`]).
//!
//! This crate is the part that knows no HTTP server: who listens, what the messages look like,
//! and how the relay is asked. The API crate hands it the sockets and calls it where things
//! change.

pub mod msgpack;
pub mod relay;

use msgpack::Value;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

/// What changed, as Bitwarden's clients number it (`PushType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    CipherUpdate = 0,
    CipherCreate = 1,
    LoginDelete = 2,
    FolderDelete = 3,
    Ciphers = 4,
    Vault = 5,
    OrgKeys = 6,
    FolderCreate = 7,
    FolderUpdate = 8,
    CipherDelete = 9,
    Settings = 10,
    LogOut = 11,
    SendCreate = 12,
    SendUpdate = 13,
    SendDelete = 14,
    AuthRequest = 15,
    AuthRequestResponse = 16,
}

/// What a message is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    /// An item; `revision` in the database's time format.
    Cipher {
        id: String,
        organization_id: Option<String>,
        collection_ids: Option<Vec<String>>,
        revision: String,
    },
    Folder {
        id: String,
        revision: String,
    },
    Send {
        id: String,
        revision: String,
    },
    /// The whole account: its settings, its vault, a log out.
    User {
        date: String,
    },
    AuthRequest {
        id: String,
    },
}

/// One change, for everybody listening for `user_id` — except the device that made it, which
/// knows already.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub kind: Kind,
    pub user_id: String,
    pub subject: Subject,
    /// The device the change came from.
    pub acting_device: Option<String>,
}

fn timestamp(text: &str) -> Value {
    time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .map(|when| Value::Timestamp(when.unix_timestamp(), when.nanosecond()))
        .unwrap_or(Value::Nil)
}

impl Update {
    /// The payload, with Bitwarden's names.
    fn payload(&self) -> Vec<(Value, Value)> {
        let user = || ("UserId".into(), Value::from(self.user_id.as_str()));
        match &self.subject {
            Subject::Cipher { id, organization_id, collection_ids, revision } => vec![
                ("Id".into(), id.as_str().into()),
                // An item of an organisation goes to its members by the organisation, not a user.
                ("UserId".into(), if organization_id.is_some() { Value::Nil } else { self.user_id.as_str().into() }),
                ("OrganizationId".into(), organization_id.as_deref().into()),
                (
                    "CollectionIds".into(),
                    collection_ids
                        .as_ref()
                        .map_or(Value::Nil, |ids| Value::Array(ids.iter().map(|id| id.as_str().into()).collect())),
                ),
                ("RevisionDate".into(), timestamp(revision)),
            ],
            Subject::Folder { id, revision } | Subject::Send { id, revision } => {
                vec![("Id".into(), id.as_str().into()), user(), ("RevisionDate".into(), timestamp(revision))]
            }
            Subject::User { date } => vec![user(), ("Date".into(), timestamp(date))],
            Subject::AuthRequest { id } => vec![("Id".into(), id.as_str().into()), user()],
        }
    }

    /// The SignalR invocation of `ReceiveMessage`, framed.
    pub fn message(&self) -> Vec<u8> {
        msgpack::frame(&Value::Array(vec![
            Value::Int(1),
            Value::Map(Vec::new()),
            Value::Nil,
            "ReceiveMessage".into(),
            Value::Array(vec![Value::Map(vec![
                ("ContextId".into(), self.acting_device.as_deref().into()),
                ("Type".into(), Value::Int(self.kind as i64)),
                ("Payload".into(), Value::Map(self.payload())),
            ])]),
        ]))
    }

    /// For the anonymous hub: the answer to a request to log in with another device. The
    /// method's name is misspelt the way Bitwarden's server and clients spell it.
    pub fn anonymous_message(&self) -> Vec<u8> {
        msgpack::frame(&Value::Array(vec![
            Value::Int(1),
            Value::Map(Vec::new()),
            Value::Nil,
            "AuthRequestResponseRecieved".into(),
            Value::Array(vec![Value::Map(vec![
                ("Type".into(), Value::Int(self.kind as i64)),
                ("Payload".into(), Value::Map(self.payload())),
                ("UserId".into(), self.user_id.as_str().into()),
            ])]),
        ]))
    }
}

/// SignalR's ping, which keeps the connection (and every proxy on the way) awake.
pub fn ping() -> Vec<u8> {
    msgpack::frame(&Value::Array(vec![Value::Int(6)]))
}

/// What a client sends first, and what it is answered: JSON with a record separator.
pub const HANDSHAKE_ANSWER: &[u8] = b"{}\x1e";

/// Whether `text` is the handshake of a client that speaks MessagePack.
pub fn is_handshake(text: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct Handshake {
        protocol: String,
        version: i64,
    }
    serde_json::from_str::<Handshake>(text.trim_end_matches('\u{1e}'))
        .is_ok_and(|handshake| handshake.protocol == "messagepack" && handshake.version == 1)
}

/// How many connections one account may hold open: every browser, app and tab.
const PER_USER: usize = 64;
/// How many anonymous ones one address may: one per pending request, a few behind a NAT. An
/// IPv6 address counts by its /64, like everywhere else on this server.
const PER_ADDRESS: u32 = 25;
/// How many anonymous ones there may be at all: devices that wait for a yes, never many at once.
const MOST_ANONYMOUS: u32 = 1000;
/// Messages that wait for a slow connection before it is dropped.
const QUEUE: usize = 64;

type Senders = Vec<(u64, mpsc::Sender<Arc<[u8]>>)>;

/// Who listens.
#[derive(Default)]
pub struct Hub {
    users: Mutex<HashMap<String, Senders>>,
    /// By the id of the request a device waits for the answer to.
    anonymous: Mutex<HashMap<String, Senders>>,
    addresses: Mutex<HashMap<IpAddr, u32>>,
    next: AtomicU64,
}

/// A connection's place in the hub; it leaves when this is dropped.
pub struct Listening {
    hub: Arc<Hub>,
    key: String,
    id: u64,
    anonymous: Option<IpAddr>,
    pub messages: mpsc::Receiver<Arc<[u8]>>,
}

impl Drop for Listening {
    fn drop(&mut self) {
        let map = if self.anonymous.is_some() { &self.hub.anonymous } else { &self.hub.users };
        let mut map = map.lock();
        if let Some(senders) = map.get_mut(&self.key) {
            senders.retain(|(id, _)| *id != self.id);
            if senders.is_empty() {
                map.remove(&self.key);
            }
        }
        drop(map);
        if let Some(ip) = self.anonymous {
            let mut addresses = self.hub.addresses.lock();
            if let Some(count) = addresses.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    addresses.remove(&ip);
                }
            }
        }
    }
}

/// The address a count belongs to: an IPv4 address as it is, an IPv6 address by its /64.
fn network(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::from(octets)
        }
    }
}

impl Hub {
    fn join(self: &Arc<Self>, key: &str, anonymous: Option<IpAddr>) -> Option<Listening> {
        let map = if anonymous.is_some() { &self.anonymous } else { &self.users };
        let mut map = map.lock();
        let senders = map.entry(key.to_string()).or_default();
        if senders.len() >= PER_USER {
            return None;
        }
        let (sender, messages) = mpsc::channel(QUEUE);
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        senders.push((id, sender));
        Some(Listening { hub: self.clone(), key: key.to_string(), id, anonymous, messages })
    }

    /// A connection of `user_id`'s. Nothing when the account holds too many already.
    pub fn listen(self: &Arc<Self>, user_id: &str) -> Option<Listening> {
        self.join(user_id, None)
    }

    /// A device that waits for the answer to its request `request_id`. Nothing when its address
    /// holds too many such connections already.
    pub fn listen_anonymous(self: &Arc<Self>, request_id: &str, ip: IpAddr) -> Option<Listening> {
        let ip = network(ip);
        {
            let mut addresses = self.addresses.lock();
            if addresses.values().sum::<u32>() >= MOST_ANONYMOUS {
                return None;
            }
            let count = addresses.entry(ip).or_default();
            if *count >= PER_ADDRESS {
                return None;
            }
            *count += 1;
        }
        let joined = self.join(request_id, Some(ip));
        if joined.is_none() {
            let mut addresses = self.addresses.lock();
            if let Some(count) = addresses.get_mut(&ip) {
                *count = count.saturating_sub(1);
            }
        }
        joined
    }

    fn deliver(map: &Mutex<HashMap<String, Senders>>, key: &str, message: Arc<[u8]>) {
        let senders = map.lock().get(key).cloned().unwrap_or_default();
        for (_, sender) in senders {
            // A connection that does not keep up misses this one; it syncs when it catches up.
            let _ = sender.try_send(message.clone());
        }
    }

    /// Tell every connection of the update's account.
    pub fn publish(&self, update: &Update) {
        Self::deliver(&self.users, &update.user_id, update.message().into());
    }

    /// Tell the device that waits for `request_id` that it has an answer.
    pub fn publish_anonymous(&self, request_id: &str, update: &Update) {
        Self::deliver(&self.anonymous, request_id, update.anonymous_message().into());
    }

    /// How many connections are open, of logged-in devices and of devices that wait for a
    /// "log in with a device" answer.
    pub fn connection_counts(&self) -> (usize, usize) {
        (
            self.users.lock().values().map(Vec::len).sum::<usize>(),
            self.anonymous.lock().values().map(Vec::len).sum::<usize>(),
        )
    }

    /// How many connections are open, for the admin portal.
    pub fn connections(&self) -> usize {
        self.users.lock().values().map(Vec::len).sum::<usize>()
            + self.anonymous.lock().values().map(Vec::len).sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(user: &str) -> Update {
        Update {
            kind: Kind::CipherUpdate,
            user_id: user.into(),
            subject: Subject::Cipher {
                id: "c1".into(),
                organization_id: None,
                collection_ids: None,
                revision: "2026-09-27T12:00:00.000000Z".into(),
            },
            acting_device: Some("d1".into()),
        }
    }

    #[test]
    fn a_message_is_signalr_s_invocation() {
        let message = update("u1").message();
        // Length, then an array of five: 1 (an invocation), headers, no id, the target.
        assert_eq!(&message[1..3], &[0x95, 0x01]);
        let text = String::from_utf8_lossy(&message);
        for part in ["ReceiveMessage", "ContextId", "d1", "Payload", "RevisionDate", "c1", "u1"] {
            assert!(text.contains(part), "{part}");
        }
        assert!(String::from_utf8_lossy(&update("u1").anonymous_message()).contains("AuthRequestResponseRecieved"));
    }

    #[test]
    fn only_messagepack_is_spoken() {
        assert!(is_handshake("{\"protocol\":\"messagepack\",\"version\":1}\u{1e}"));
        assert!(!is_handshake("{\"protocol\":\"json\",\"version\":1}\u{1e}"));
    }

    #[tokio::test]
    async fn every_connection_of_the_account_hears_it_and_nobody_else() {
        let hub = Arc::new(Hub::default());
        let mut first = hub.listen("u1").unwrap();
        let mut second = hub.listen("u1").unwrap();
        let mut other = hub.listen("u2").unwrap();
        hub.publish(&update("u1"));
        assert!(first.messages.try_recv().is_ok());
        assert!(second.messages.try_recv().is_ok());
        assert!(other.messages.try_recv().is_err());
        drop(first);
        drop(second);
        assert_eq!(hub.connections(), 1, "gone with their connections");
    }

    #[tokio::test]
    async fn an_address_holds_only_so_many_anonymous_connections() {
        let hub = Arc::new(Hub::default());
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let held: Vec<_> = (0..PER_ADDRESS).map(|n| hub.listen_anonymous(&n.to_string(), ip).unwrap()).collect();
        assert!(hub.listen_anonymous("one more", ip).is_none());
        drop(held);
        let mut waiting = hub.listen_anonymous("r1", ip).unwrap();
        hub.publish_anonymous("r1", &update("u1"));
        assert!(waiting.messages.try_recv().is_ok());
    }

    #[tokio::test]
    async fn an_ipv6_network_counts_as_one_address_and_all_of_them_have_a_ceiling() {
        let hub = Arc::new(Hub::default());
        let held: Vec<_> = (0..PER_ADDRESS)
            .map(|n| hub.listen_anonymous(&n.to_string(), format!("2001:db8:1:2::{n:x}").parse().unwrap()).unwrap())
            .collect();
        assert!(hub.listen_anonymous("x", "2001:db8:1:2:ffff::1".parse().unwrap()).is_none(), "the same /64");
        drop(held);
        let held: Vec<_> = (0..MOST_ANONYMOUS)
            .map(|n| {
                let ip = IpAddr::from([198, 51, (n / 250) as u8, (n % 250) as u8]);
                hub.listen_anonymous(&n.to_string(), ip).unwrap()
            })
            .collect();
        assert!(hub.listen_anonymous("x", "203.0.113.1".parse().unwrap()).is_none(), "full");
        drop(held);
        assert!(hub.listen_anonymous("x", "203.0.113.1".parse().unwrap()).is_some());
    }
}
