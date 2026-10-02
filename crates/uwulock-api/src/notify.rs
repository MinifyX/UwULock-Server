//! Telling the clients what changed: every connection of the account on Bitwarden's hub and on
//! UwULock's own realtime channel at once. Bitwarden's push relay is not used: its phone apps
//! sync when they are opened.
//!
//! Called where things change, after they changed. It never fails a request: a client that
//! misses a message syncs on its next look anyway.

use crate::AppState;
use crate::auth::Session;
use uwulock_notify::realtime::{Event, Live};
use uwulock_notify::{Kind, Subject, Update};
use uwulock_store::Cipher;

/// Hand `update` to the hub and to the realtime channel.
pub(crate) fn publish(state: &AppState, update: Update) {
    if let Some(live) = Live::from_update(&update) {
        state.realtime.publish(&update.user_id, Event::new(live, update.acting_device.clone()));
    }
    publish_bitwarden(state, update);
}

/// Only Bitwarden's side: the SignalR hub.
fn publish_bitwarden(state: &AppState, update: Update) {
    state.hub.publish(&update);
}

fn acting(session: Option<&Session>) -> Option<String> {
    session.map(|session| session.device.clone())
}

pub(crate) fn cipher(state: &AppState, session: &Session, kind: Kind, cipher: &Cipher) {
    publish(
        state,
        Update {
            kind,
            user_id: session.user.id.clone(),
            subject: Subject::Cipher {
                id: cipher.id.clone(),
                organization_id: None,
                collection_ids: None,
                revision: cipher.revision.clone(),
            },
            acting_device: acting(Some(session)),
        },
    );
}

pub(crate) fn folder(state: &AppState, session: &Session, kind: Kind, id: &str, revision: &str) {
    publish(
        state,
        Update {
            kind,
            user_id: session.user.id.clone(),
            subject: Subject::Folder { id: id.to_string(), revision: revision.to_string() },
            acting_device: acting(Some(session)),
        },
    );
}

/// A Send changed; `session` is none when somebody with the link opened it.
pub(crate) fn send(state: &AppState, user_id: &str, session: Option<&Session>, kind: Kind, id: &str, revision: &str) {
    publish(
        state,
        Update {
            kind,
            user_id: user_id.to_string(),
            subject: Subject::Send { id: id.to_string(), revision: revision.to_string() },
            acting_device: acting(session),
        },
    );
}

/// Something of the whole account: sync everything (`Vault`, `Ciphers`), the settings, or log
/// out — which every device does that hears it.
pub(crate) fn user(state: &AppState, user_id: &str, session: Option<&Session>, kind: Kind) {
    publish(
        state,
        Update {
            kind,
            user_id: user_id.to_string(),
            subject: Subject::User { date: uwulock_store::clock::now() },
            acting_device: acting(session),
        },
    );
}

/// The session of every device of the account ended, and why (docs/uwu-api.md §5.2:
/// `securityStamp`, `disabled`, `keysRotated`): Bitwarden's `LogOut` and the realtime `logout`.
pub(crate) fn logout(state: &AppState, user_id: &str, session: Option<&Session>, reason: &'static str) {
    let update = Update {
        kind: Kind::LogOut,
        user_id: user_id.to_string(),
        subject: Subject::User { date: uwulock_store::clock::now() },
        acting_device: acting(session),
    };
    state.realtime.publish(user_id, Event::new(Live::Logout { reason }, update.acting_device.clone()));
    publish_bitwarden(state, update);
}

/// Something only UwULock's clients care about, on the realtime channel alone: their extras
/// (`uwu`), a suite space, a notice.
pub(crate) fn live(state: &AppState, user_id: &str, session: Option<&Session>, live: Live) {
    state.realtime.publish(user_id, Event::new(live, acting(session)));
}

/// A message for one device of the account only.
pub(crate) fn live_to_device(state: &AppState, user_id: &str, device: &str, live: Live) {
    state.realtime.publish(user_id, Event { live, acting_device: None, only_device: Some(device.to_string()) });
}

/// A device asks to be let in: every device of the account hears it.
pub(crate) fn auth_request(state: &AppState, user_id: &str, id: &str) {
    publish(
        state,
        Update {
            kind: Kind::AuthRequest,
            user_id: user_id.to_string(),
            subject: Subject::AuthRequest { id: id.to_string() },
            acting_device: None,
        },
    );
}

/// A request was answered: the account's devices hear it, and so does the one that asked.
pub(crate) fn auth_response(state: &AppState, session: &Session, id: &str) {
    let update = Update {
        kind: Kind::AuthRequestResponse,
        user_id: session.user.id.clone(),
        subject: Subject::AuthRequest { id: id.to_string() },
        acting_device: acting(Some(session)),
    };
    state.hub.publish_anonymous(id, &update);
    publish(state, update);
}
