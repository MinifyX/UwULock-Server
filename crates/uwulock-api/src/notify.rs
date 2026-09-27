//! Telling the clients what changed: every connection of the account on the hub at once, and
//! its phones through the push relay when an admin set that up.
//!
//! Called where things change, after they changed. It never fails a request: a client that
//! misses a message syncs on its next look anyway.

use crate::AppState;
use crate::auth::Session;
use uwulock_notify::{Kind, Subject, Update};
use uwulock_store::Cipher;

/// Hand `update` to the hub, and to the relay in the background.
pub(crate) fn publish(state: &AppState, update: Update) {
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
