//! Telling the clients what changed: every connection of the account on the hub at once, and
//! its phones through the push relay when an admin set that up.
//!
//! Called where things change, after they changed. It never fails a request: a client that
//! misses a message syncs on its next look anyway.

use crate::AppState;
use crate::auth::Session;
use uwulock_notify::realtime::{Event, Live};
use uwulock_notify::{Kind, Subject, Update};
use uwulock_store::Cipher;

/// Hand `update` to the hub, to the realtime channel, and to the relay in the background.
pub(crate) fn publish(state: &AppState, update: Update) {
    if let Some(live) = Live::from_update(&update) {
        state.realtime.publish(&update.user_id, Event::new(live, update.acting_device.clone()));
    }
    publish_bitwarden(state, update);
}

/// Only Bitwarden's side: the SignalR hub and the push relay.
fn publish_bitwarden(state: &AppState, update: Update) {
    state.hub.publish(&update);
    let Some(settings) = state.settings().push.clone() else { return };
    let state = state.clone();
    tokio::spawn(async move {
        let phones = state.store.push_devices(&update.user_id).await.unwrap_or_default();
        if phones.is_empty() {
            return;
        }
        let acting = update
            .acting_device
            .as_ref()
            .and_then(|acting| phones.iter().find(|(device, _)| device == acting))
            .map(|(_, push_id)| push_id.clone());
        if let Err(error) = state.relay.send(&settings, &update, acting.as_deref()).await {
            tracing::warn!(%error, "the push relay did not take an update");
        }
    });
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

/// Register a phone's push token with the relay, when an admin set it up; the relay's id for the
/// device is kept. Failures go to the log: the phone syncs when it is opened anyway.
pub(crate) async fn register_phone(state: &AppState, session: &Session, token: &str) {
    let Some(settings) = state.settings().push else { return };
    let device = match state.store.device(&session.user.id, &session.device).await {
        Ok(Some(device)) => device,
        _ => return,
    };
    let push_id = match state.store.push_id(&session.user.id, &session.device).await {
        Ok(Some(id)) => id,
        _ => uuid::Uuid::new_v4().to_string(),
    };
    match state.relay.register(&settings, &push_id, token, &session.user.id, device.kind, &device.id).await {
        Ok(()) => {
            if let Err(error) = state.store.set_push_id(&session.user.id, &session.device, Some(push_id)).await {
                tracing::warn!(%error, "could not keep the push relay's id of a device");
            }
        }
        Err(error) => tracing::warn!(%error, "the push relay did not register a phone"),
    }
}

/// Take a device off the relay, before it is forgotten or logged out for good.
pub(crate) async fn forget_phone(state: &AppState, user_id: &str, device_id: &str) {
    let Ok(Some(push_id)) = state.store.push_id(user_id, device_id).await else { return };
    if let Some(settings) = state.settings().push
        && let Err(error) = state.relay.unregister(&settings, &push_id).await
    {
        tracing::warn!(%error, "the push relay did not take a phone off");
    }
    let _ = state.store.set_push_id(user_id, device_id, None).await;
}
