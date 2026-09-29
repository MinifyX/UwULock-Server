//! UwULock's own realtime channel (docs/uwu-api.md §5): one WebSocket per device that says
//! *that* something changed, never what — the device then asks the delta sync. So what goes
//! over it carries no secrets and may get lost: the sync is the truth.
//!
//! This is the part without HTTP: who listens, and what a message looks like. Every change the
//! SignalR hub hears is passed on here too ([`Live::from_update`]); what only UwULock's clients
//! care about — their own extras, the suite spaces, notices — is published here alone.

use crate::{Kind, Update};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

/// What the server tells a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Live {
    /// Something in these areas (`vault`, `uwu`, `suite`) changed; for `suite`, in these spaces.
    Changed { areas: Vec<&'static str>, spaces: Vec<String> },
    /// The session ended: `securityStamp`, `deviceRemoved`, `disabled`, `keysRotated`.
    Logout { reason: &'static str },
    /// Somebody asks to log in with this account's approval.
    AuthRequest { id: String },
    /// A security notice (`securityNotice`, with its id), something for a file request
    /// (`fileRequest`, with the request's id), a reminder that became due (`reminderDue`).
    Notice { kind: &'static str, id: Option<String> },
    /// `/uwu/v1/info` changed.
    Info,
}

impl Live {
    pub fn changed(area: &'static str) -> Self {
        Live::Changed { areas: vec![area], spaces: Vec::new() }
    }

    pub fn suite(space: &str) -> Self {
        Live::Changed { areas: vec!["suite"], spaces: vec![space.to_string()] }
    }

    /// What an update for Bitwarden's clients means here.
    pub fn from_update(update: &Update) -> Option<Self> {
        match update.kind {
            Kind::LogOut => Some(Live::Logout { reason: "securityStamp" }),
            Kind::AuthRequest => match &update.subject {
                crate::Subject::AuthRequest { id } => Some(Live::AuthRequest { id: id.clone() }),
                _ => None,
            },
            // The asking device hears the answer on the anonymous hub.
            Kind::AuthRequestResponse => None,
            _ => Some(Live::changed("vault")),
        }
    }

    /// The message as it goes out.
    pub fn to_json(&self) -> String {
        let value = match self {
            Live::Changed { areas, spaces } if spaces.is_empty() => {
                serde_json::json!({ "type": "changed", "areas": areas })
            }
            Live::Changed { areas, spaces } => {
                serde_json::json!({ "type": "changed", "areas": areas, "spaces": spaces })
            }
            Live::Logout { reason } => serde_json::json!({ "type": "logout", "reason": reason }),
            Live::AuthRequest { id } => serde_json::json!({ "type": "authRequest", "id": id }),
            // A security notice's id is a number (§12), a file request's a UUID.
            Live::Notice { kind, id: Some(id) } => match id.parse::<i64>() {
                Ok(number) if *kind == "securityNotice" => {
                    serde_json::json!({ "type": "notice", "kind": kind, "id": number })
                }
                _ => serde_json::json!({ "type": "notice", "kind": kind, "id": id }),
            },
            Live::Notice { kind, id: None } => serde_json::json!({ "type": "notice", "kind": kind }),
            Live::Info => serde_json::json!({ "type": "info" }),
        };
        value.to_string()
    }

    /// What of it a device with only a suite app's token hears: changes of its space, the end
    /// of the session, `info`.
    pub fn for_suite(&self, space: &str) -> Option<Self> {
        match self {
            Live::Changed { areas, spaces } if areas.contains(&"suite") && spaces.iter().any(|s| s == space) => {
                Some(Live::suite(space))
            }
            Live::Logout { .. } | Live::Info => Some(self.clone()),
            _ => None,
        }
    }

    /// What of it a device that syncs `areas` hears (`None` for everything).
    pub fn for_areas(&self, areas: &[&str]) -> Option<Self> {
        match self {
            Live::Changed { areas: changed, spaces } => {
                let kept: Vec<&'static str> = changed.iter().copied().filter(|area| areas.contains(area)).collect();
                (!kept.is_empty()).then(|| Live::Changed { areas: kept, spaces: spaces.clone() })
            }
            _ => Some(self.clone()),
        }
    }
}

/// One message on its way: what, and the device that caused it (which does not hear it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub live: Live,
    pub acting_device: Option<String>,
    /// Only for this device (a device that was removed hears that it was).
    pub only_device: Option<String>,
}

impl Event {
    pub fn new(live: Live, acting_device: Option<String>) -> Self {
        Event { live, acting_device, only_device: None }
    }

    /// Whether the device `device` hears it.
    pub fn is_for(&self, device: &str) -> bool {
        self.acting_device.as_deref() != Some(device) && self.only_device.as_deref().is_none_or(|only| only == device)
    }
}

/// How many connections one account may hold (the 21st is closed with 4429).
pub const PER_ACCOUNT: usize = 20;
/// Messages that wait for a slow connection; more are dropped, the next sync catches up.
const QUEUE: usize = 32;

type Senders = Vec<(u64, mpsc::Sender<Arc<Event>>)>;

/// Who listens on the realtime channel.
#[derive(Default)]
pub struct Realtime {
    users: Mutex<HashMap<String, Senders>>,
    next: AtomicU64,
}

/// A connection's place; it leaves when this is dropped.
pub struct Connection {
    realtime: Arc<Realtime>,
    user_id: String,
    id: u64,
    pub events: mpsc::Receiver<Arc<Event>>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        let mut users = self.realtime.users.lock();
        if let Some(senders) = users.get_mut(&self.user_id) {
            senders.retain(|(id, _)| *id != self.id);
            if senders.is_empty() {
                users.remove(&self.user_id);
            }
        }
    }
}

impl Connection {
    pub fn user_id(&self) -> &str {
        &self.user_id
    }
}

impl Realtime {
    /// A connection of `user_id`'s; nothing when the account holds [`PER_ACCOUNT`] already.
    pub fn join(self: &Arc<Self>, user_id: &str) -> Option<Connection> {
        let mut users = self.users.lock();
        let senders = users.entry(user_id.to_string()).or_default();
        if senders.len() >= PER_ACCOUNT {
            return None;
        }
        let (sender, events) = mpsc::channel(QUEUE);
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        senders.push((id, sender));
        Some(Connection { realtime: self.clone(), user_id: user_id.to_string(), id, events })
    }

    /// Tell every connection of `user_id`.
    pub fn publish(&self, user_id: &str, event: Event) {
        let senders = self.users.lock().get(user_id).cloned().unwrap_or_default();
        let event = Arc::new(event);
        for (_, sender) in senders {
            let _ = sender.try_send(event.clone());
        }
    }

    /// Tell every connection there is: `info` after an admin saved the settings.
    pub fn broadcast(&self, live: Live) {
        let senders: Vec<_> = self.users.lock().values().flatten().map(|(_, sender)| sender.clone()).collect();
        let event = Arc::new(Event::new(live, None));
        for sender in senders {
            let _ = sender.try_send(event.clone());
        }
    }

    /// Open connections, for the admin portal and the metrics.
    pub fn connections(&self) -> usize {
        self.users.lock().values().map(Vec::len).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_the_contract_s_json() {
        assert_eq!(Live::changed("vault").to_json(), r#"{"areas":["vault"],"type":"changed"}"#);
        assert_eq!(Live::suite("ssh").to_json(), r#"{"areas":["suite"],"spaces":["ssh"],"type":"changed"}"#);
        assert_eq!(
            Live::Notice { kind: "reminderDue", id: None }.to_json(),
            r#"{"kind":"reminderDue","type":"notice"}"#
        );
        let notice = Live::Notice { kind: "securityNotice", id: Some("123".into()) };
        assert_eq!(notice.to_json(), r#"{"id":123,"kind":"securityNotice","type":"notice"}"#);
        assert_eq!(Live::Logout { reason: "keysRotated" }.to_json(), r#"{"reason":"keysRotated","type":"logout"}"#);
    }

    #[test]
    fn a_suite_app_hears_only_its_space_the_logout_and_info() {
        assert_eq!(Live::suite("ssh").for_suite("ssh"), Some(Live::suite("ssh")));
        assert_eq!(Live::suite("rdp").for_suite("ssh"), None);
        assert_eq!(Live::changed("vault").for_suite("ssh"), None);
        assert_eq!(Live::AuthRequest { id: "a".into() }.for_suite("ssh"), None);
        assert!(Live::Info.for_suite("ssh").is_some());
        assert_eq!(Live::changed("uwu").for_areas(&["vault"]), None);
    }

    #[tokio::test]
    async fn every_connection_of_the_account_hears_it_up_to_twenty() {
        let realtime = Arc::new(Realtime::default());
        let mut held: Vec<_> = (0..PER_ACCOUNT).map(|_| realtime.join("u1").unwrap()).collect();
        assert!(realtime.join("u1").is_none(), "the 21st");
        let mut other = realtime.join("u2").unwrap();
        realtime.publish("u1", Event::new(Live::changed("vault"), None));
        assert!(held[0].events.try_recv().is_ok());
        assert!(other.events.try_recv().is_err());
        realtime.broadcast(Live::Info);
        assert_eq!(other.events.try_recv().unwrap().live, Live::Info);
        held.clear();
        assert_eq!(realtime.connections(), 1);
    }
}
