//! `/notifications/hub` and `/notifications/anonymous-hub`: the WebSockets Bitwarden's clients
//! keep open for live updates. SignalR with MessagePack, without the negotiation round trip —
//! the clients skip it.

use crate::AppState;
use crate::auth::ClientIp;
use crate::errors::{ApiError, ApiResult};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use std::time::Duration;
use uwulock_notify::Listening;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/notifications/hub", get(hub))
        .route("/notifications/anonymous-hub", get(anonymous_hub))
}

/// How often the server pings: well inside any proxy's idle timeout, and the server's own.
const PING: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
struct HubQuery {
    #[serde(default)]
    access_token: Option<String>,
}

async fn hub(
    State(state): State<AppState>,
    Query(query): Query<HubQuery>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    let header = headers.get("authorization").and_then(|value| value.to_str().ok()).unwrap_or_default();
    let token = query
        .access_token
        .or_else(|| header.rsplit_once("Bearer ").map(|(_, token)| token.to_string()))
        .ok_or_else(ApiError::unauthorized)?;
    let claims = state.tokens.verify(&token).ok_or_else(ApiError::unauthorized)?;
    let Some(session) = state.store.session_user(&claims.sub).await? else { return Err(ApiError::unauthorized()) };
    if session.user.disabled || session.user.security_stamp != claims.sstamp || !session.devices.contains(&claims.device)
    {
        return Err(ApiError::unauthorized());
    }
    let listening = state
        .hub
        .listen(&claims.sub)
        .ok_or_else(|| ApiError::too_many("This account has too many connections open."))?;
    Ok(upgrade.on_upgrade(move |socket| serve(socket, listening)))
}

#[derive(Deserialize)]
struct AnonymousQuery {
    #[serde(default, alias = "Token")]
    token: Option<String>,
}

async fn anonymous_hub(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Query(query): Query<AnonymousQuery>,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    let token = query.token.filter(|token| !token.is_empty() && token.len() <= 64).ok_or_else(ApiError::unauthorized)?;
    let listening = state
        .hub
        .listen_anonymous(&token, ip)
        .ok_or_else(|| ApiError::too_many("Too many connections from this address."))?;
    Ok(upgrade.on_upgrade(move |socket| serve(socket, listening)))
}

/// One connection: answer the handshake, ping, pass on what the hub has for it, until either
/// side is done.
async fn serve(mut socket: WebSocket, mut listening: Listening) {
    let mut ping = tokio::time::interval(PING);
    ping.tick().await;
    loop {
        tokio::select! {
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    if uwulock_notify::is_handshake(&text)
                        && socket.send(Message::Binary(uwulock_notify::HANDSHAKE_ANSWER.to_vec().into())).await.is_err()
                    {
                        break;
                    }
                }
                Some(Ok(Message::Ping(data))) => {
                    if socket.send(Message::Pong(data)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                // Pongs, and SignalR's own pings and completions: nothing to answer.
                Some(Ok(_)) => {}
            },
            message = listening.messages.recv() => match message {
                Some(message) => {
                    if socket.send(Message::Binary(message.to_vec().into())).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            _ = ping.tick() => {
                if socket.send(Message::Binary(uwulock_notify::ping().into())).await.is_err() {
                    break;
                }
            }
        }
    }
}
