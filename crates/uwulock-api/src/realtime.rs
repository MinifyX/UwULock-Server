//! `/uwu/v1/realtime` (docs/uwu-api.md §5): UwULock's own WebSocket, one per device, that says
//! *that* something changed. The token comes in the first message, a fresh one later on the
//! same connection; the server pings, checks the session again at every ping, and closes with
//! the codes of §5.3.
//!
//! What goes out comes from [`uwulock_notify::realtime::Realtime`], which the SignalR hub's
//! updates are handed to as well ([`crate::notify::publish`]).

use crate::AppState;
use crate::auth::Session;
use crate::sync::{Areas, Cursor};
use axum::Router;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use serde_json::json;
use std::time::{Duration, Instant};
use uwulock_notify::realtime::Live;

pub(crate) const PROTOCOL: &str = "uwu.realtime.v1";
/// How often the server pings, and checks the session again.
#[cfg(not(test))]
const HEARTBEAT: Duration = Duration::from_secs(25);
#[cfg(test)]
const HEARTBEAT: Duration = Duration::from_millis(150);
/// How long a new connection has for its `auth`.
#[cfg(not(test))]
const AUTH_WITHIN: Duration = Duration::from_secs(10);
#[cfg(test)]
const AUTH_WITHIN: Duration = Duration::from_millis(300);
/// The most a client message may be.
const MOST_MESSAGE: usize = 4096;
/// Client messages: one a second on average, ten at once.
const BURST: f64 = 10.0;
const PER_SECOND: f64 = 1.0;

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/realtime", get(connect))
}

async fn connect(State(state): State<AppState>, headers: HeaderMap, upgrade: WebSocketUpgrade) -> Response {
    let offered = headers
        .get_all("sec-websocket-protocol")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|protocol| protocol.trim() == PROTOCOL);
    if !offered {
        return (StatusCode::BAD_REQUEST, "The realtime channel speaks uwu.realtime.v1 only.").into_response();
    }
    upgrade
        .protocols([PROTOCOL])
        .read_buffer_size(MOST_MESSAGE)
        .max_message_size(MOST_MESSAGE)
        .max_frame_size(MOST_MESSAGE)
        .on_upgrade(move |socket| serve(state, socket))
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum ClientMessage {
    Auth {
        token: String,
        #[serde(default)]
        cursor: Option<String>,
    },
    Ping,
}

/// How a connection ends.
fn close(code: u16, reason: &'static str) -> Message {
    Message::Close(Some(CloseFrame { code, reason: reason.into() }))
}

/// Why a session that was good is no more; nothing while it still is.
async fn gone(state: &AppState, session: &Session) -> Option<&'static str> {
    match state.store.session_user(&session.user.id).await {
        Ok(Some(now)) if now.user.disabled => Some("disabled"),
        Ok(Some(now)) if now.user.security_stamp != session.user.security_stamp => Some("securityStamp"),
        Ok(Some(now)) if !now.devices.contains(&session.device) => Some("deviceRemoved"),
        Ok(Some(_)) => None,
        // Gone, or the store did not answer: the client comes back and finds out.
        Ok(None) => Some("disabled"),
        Err(_) => None,
    }
}

/// The areas the device follows, for a resume: a suite app its space, an account's client what
/// its cursor was made for.
fn areas_of(session: &Session, cursor: &Cursor) -> Areas {
    let include = cursor.areas().split(':').next().unwrap_or_default().to_string();
    Areas::parse(Some(&include), session.space).unwrap_or(Areas {
        vault: true,
        suite: false,
        uwu: true,
        space: session.space,
    })
}

/// `changed` for a device whose cursor is behind, right after `ready`.
async fn resume(state: &AppState, session: &Session, cursor: Option<&str>) -> Option<Live> {
    let cursor = cursor.map(str::trim).filter(|text| !text.is_empty())?;
    let counters = state.store.sync_counters(&session.user.id).await.ok()??;
    let spaces: Vec<String> = match session.space {
        Some(space) => vec![space.to_string()],
        None => counters.spaces.iter().map(|(space, _)| space.clone()).collect(),
    };
    let everything = || {
        let areas: Vec<&'static str> = if session.is_suite() { vec!["suite"] } else { vec!["vault", "uwu"] };
        let spaces = if session.is_suite() { spaces.clone() } else { Vec::new() };
        Live::Changed { areas, spaces }
    };
    let Some(cursor) = Cursor::decode(cursor) else { return Some(everything()) };
    let areas = areas_of(session, &cursor);
    if !cursor.behind(&counters, &areas) {
        return None;
    }
    let names = areas.names();
    if names.is_empty() {
        return None;
    }
    let spaces = if areas.suite { spaces } else { Vec::new() };
    Some(Live::Changed { areas: names, spaces })
}

async fn send(socket: &mut WebSocket, text: String) -> bool {
    socket.send(Message::Text(text.into())).await.is_ok()
}

fn ready(connection_id: &str, session: &Session) -> String {
    json!({
        "type": "ready",
        "connectionId": connection_id,
        "expires": session.expires,
        "heartbeat": HEARTBEAT.as_secs().max(1),
    })
    .to_string()
}

/// A token of the first or a later `auth`: the session, or the close code.
async fn authenticate(state: &AppState, token: &str) -> Result<Session, Message> {
    let session = Session::from_any_token(state, token)
        .await
        .map_err(|_| close(4401, "The token is not (or no longer) valid."))?;
    if session.is_suite() && !state.feature(crate::Feature::Suite) {
        return Err(close(4403, "The suite vault is switched off."));
    }
    Ok(session)
}

/// Reads the next client message, keeping to the rate: the message, or how to close.
struct Rate {
    tokens: f64,
    at: Instant,
}

impl Rate {
    fn new() -> Self {
        Rate { tokens: BURST, at: Instant::now() }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * PER_SECOND).min(BURST);
        self.at = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

async fn serve(state: AppState, mut socket: WebSocket) {
    // ── `auth` first ──
    let first = tokio::time::timeout(AUTH_WITHIN, socket.recv()).await;
    let text = match first {
        Err(_) => {
            let _ = socket.send(close(4408, "No auth in time.")).await;
            return;
        }
        Ok(Some(Ok(Message::Text(text)))) => text,
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => return,
        Ok(Some(Ok(_))) => {
            let _ = socket.send(close(4400, "Text frames with JSON only.")).await;
            return;
        }
    };
    let Ok(ClientMessage::Auth { token, cursor }) = serde_json::from_str::<ClientMessage>(&text) else {
        let _ = socket.send(close(4401, "The first message is auth.")).await;
        return;
    };
    let mut session = match authenticate(&state, &token).await {
        Ok(session) => session,
        Err(message) => {
            let _ = socket.send(message).await;
            return;
        }
    };
    let Some(mut connection) = state.realtime.join(&session.user.id) else {
        let _ = socket.send(close(4429, "This account has too many connections open.")).await;
        return;
    };
    let connection_id = uuid::Uuid::new_v4().simple().to_string();
    if !send(&mut socket, ready(&connection_id, &session)).await {
        return;
    }
    if let Some(live) = resume(&state, &session, cursor.as_deref()).await
        && !send(&mut socket, live.to_json()).await
    {
        return;
    }

    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let mut rate = Rate::new();
    loop {
        let left = Duration::from_secs(u64::try_from(session.expires - crate::auth::now_seconds()).unwrap_or(0));
        tokio::select! {
            () = tokio::time::sleep(left) => {
                let _ = socket.send(close(4401, "The token ran out.")).await;
                break;
            }
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    if !rate.take() {
                        let _ = socket.send(close(4429, "Too many messages.")).await;
                        break;
                    }
                    match serde_json::from_str::<ClientMessage>(&text) {
                        Ok(ClientMessage::Ping) => {
                            if !send(&mut socket, json!({ "type": "pong" }).to_string()).await {
                                break;
                            }
                        }
                        Ok(ClientMessage::Auth { token, cursor }) => {
                            let renewed = match authenticate(&state, &token).await {
                                Ok(renewed) if renewed.user.id == session.user.id && renewed.space == session.space => renewed,
                                Ok(_) => {
                                    let _ = socket.send(close(4400, "A new token is for the same account and app.")).await;
                                    break;
                                }
                                Err(message) => {
                                    let _ = socket.send(message).await;
                                    break;
                                }
                            };
                            session = renewed;
                            if !send(&mut socket, ready(&connection_id, &session)).await {
                                break;
                            }
                            if let Some(live) = resume(&state, &session, cursor.as_deref()).await
                                && !send(&mut socket, live.to_json()).await
                            {
                                break;
                            }
                        }
                        Err(_) => {
                            let _ = socket.send(close(4400, "That is no message of uwu.realtime.v1.")).await;
                            break;
                        }
                    }
                }
                Some(Ok(Message::Binary(_))) => {
                    let _ = socket.send(close(4400, "Text frames with JSON only.")).await;
                    break;
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                // Pings are answered by the socket itself; pongs need nothing.
                Some(Ok(_)) => {}
            },
            event = connection.events.recv() => {
                let Some(event) = event else { break };
                if !event.is_for(&session.device) {
                    continue;
                }
                let live = match session.space {
                    Some(space) => event.live.for_suite(space),
                    None => Some(event.live.clone()),
                };
                let Some(live) = live else { continue };
                if !send(&mut socket, live.to_json()).await {
                    break;
                }
                if matches!(live, Live::Logout { .. }) {
                    let _ = socket.send(close(4401, "The session ended.")).await;
                    break;
                }
            }
            _ = heartbeat.tick() => {
                if let Some(reason) = gone(&state, &session).await {
                    let _ = send(&mut socket, Live::Logout { reason }.to_json()).await;
                    let _ = socket.send(close(4401, "The session ended.")).await;
                    break;
                }
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
