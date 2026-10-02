//! `/notifications/hub` and `/notifications/anonymous-hub`: the WebSockets Bitwarden's clients
//! keep open for live updates. SignalR with MessagePack, without the negotiation round trip —
//! the clients skip it.

use crate::AppState;
use crate::auth::ClientIp;
use crate::errors::{ApiError, ApiResult};
use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use serde::Deserialize;
use std::time::Duration;
use uwulock_notify::Listening;

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/notifications/hub", get(hub)).route("/notifications/anonymous-hub", get(anonymous_hub))
}

/// How often the server pings: well inside any proxy's idle timeout, and the server's own.
/// Every ping also checks the connection's session again.
#[cfg(not(test))]
const PING: Duration = Duration::from_secs(15);
#[cfg(test)]
const PING: Duration = Duration::from_millis(100);
/// How long a new connection has for its handshake.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// The most a client message may be. Clients send a handshake, pings and completions — a few
/// dozen bytes each.
const MOST_MESSAGE: usize = 16 * 1024;

/// A WebSocket that takes only small messages and keeps a small buffer for them.
fn small(upgrade: WebSocketUpgrade) -> WebSocketUpgrade {
    upgrade.read_buffer_size(4096).max_message_size(MOST_MESSAGE).max_frame_size(MOST_MESSAGE)
}

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
    // A suite app's token is for its space and the realtime channel, not for the hub.
    if !claims.scope.iter().any(|scope| scope == "api") {
        return Err(crate::suite::scope_error());
    }
    let check = Recheck {
        state: state.clone(),
        user_id: claims.sub,
        device: claims.device,
        stamp: claims.sstamp,
        expires: claims.exp,
    };
    if !check.still_valid().await {
        return Err(ApiError::unauthorized());
    }
    let listening = state
        .hub
        .listen(&check.user_id)
        .ok_or_else(|| ApiError::too_many("This account has too many connections open."))?;
    Ok(small(upgrade).on_upgrade(move |socket| serve(socket, listening, Some(check))))
}

/// What a connection was opened with, checked again at every ping: once the token runs out,
/// the password changes, the device is logged out or the account is disabled, the connection
/// ends — the clients open a new one with a fresh token, if they still may.
struct Recheck {
    state: AppState,
    user_id: String,
    device: String,
    stamp: String,
    expires: i64,
}

impl Recheck {
    async fn still_valid(&self) -> bool {
        if self.expires <= crate::auth::now_seconds() {
            return false;
        }
        match self.state.store.session_user(&self.user_id).await {
            Ok(Some(session)) => {
                !session.user.disabled
                    && session.user.security_stamp == self.stamp
                    && session.devices.contains(&self.device)
            }
            _ => false,
        }
    }
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
    let token =
        query.token.filter(|token| !token.is_empty() && token.len() <= 64).ok_or_else(ApiError::unauthorized)?;
    // Only for a request that waits for its answer: one for an address without an account
    // waits too, so this says nothing about accounts.
    let waiting = match state.store.auth_request(&token).await? {
        Some(request) => request.approved.is_none() && request.fresh(),
        None => state.unanswerable.contains(&token),
    };
    if !waiting {
        return Err(ApiError::unauthorized());
    }
    let listening = state
        .hub
        .listen_anonymous(&token, ip)
        .ok_or_else(|| ApiError::too_many("Too many connections from this address."))?;
    Ok(small(upgrade).on_upgrade(move |socket| serve(socket, listening, None)))
}

/// One connection: answer the handshake, ping, pass on what the hub has for it, until either
/// side is done.
async fn serve(mut socket: WebSocket, mut listening: Listening, recheck: Option<Recheck>) {
    let mut ping = tokio::time::interval(PING);
    ping.tick().await;
    // Whoever does not say hello in time is not waiting for anything.
    let handshake = tokio::time::sleep(HANDSHAKE);
    tokio::pin!(handshake);
    let mut greeted = false;
    loop {
        tokio::select! {
            () = &mut handshake, if !greeted => break,
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    if uwulock_notify::is_handshake(&text) {
                        greeted = true;
                        if socket.send(Message::Binary(uwulock_notify::HANDSHAKE_ANSWER.to_vec().into())).await.is_err() {
                            break;
                        }
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
                if let Some(recheck) = &recheck
                    && !recheck.still_valid().await
                {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
                if socket.send(Message::Binary(uwulock_notify::ping().into())).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{TestServer, json};
    use axum::http::StatusCode;
    use futures_util::{SinkExt, StreamExt};
    use serde_json::json;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::Message;

    /// The server on a real socket, for WebSockets.
    async fn listen(server: &TestServer) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = server.router.clone().into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        address
    }

    type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

    /// The next message that is not a ping.
    async fn next(socket: &mut Socket) -> Vec<u8> {
        loop {
            let message = tokio::time::timeout(Duration::from_secs(5), socket.next()).await.unwrap().unwrap().unwrap();
            if let Message::Binary(data) = message
                && data.as_ref() != uwulock_notify::ping().as_slice()
            {
                return data.to_vec();
            }
        }
    }

    async fn connect(url: String) -> Socket {
        let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        socket.send(Message::text("{\"protocol\":\"messagepack\",\"version\":1}\u{1e}")).await.unwrap();
        assert_eq!(next(&mut socket).await, uwulock_notify::HANDSHAKE_ANSWER);
        socket
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack.windows(needle.len()).any(|window| window == needle.as_bytes())
    }

    #[tokio::test]
    async fn the_hub_tells_an_account_what_changed_and_nobody_else() {
        let server = TestServer::new().await;
        let nyu = server.account("nyu@example.com").await;
        let other = server.account("other@example.com").await;
        let address = listen(&server).await;

        let refused = tokio_tungstenite::connect_async(format!("ws://{address}/notifications/hub")).await;
        assert!(refused.is_err(), "not without a token");
        let refused =
            tokio_tungstenite::connect_async(format!("ws://{address}/notifications/hub?access_token=nonsense")).await;
        assert!(refused.is_err(), "not with a wrong one");

        let mut socket = connect(format!("ws://{address}/notifications/hub?access_token={}", nyu.token)).await;
        let theirs = server.call("POST", "/api/folders", Some(&other.token), json!({"name": "2.o|o|o"})).await;
        let theirs = json(theirs).await["id"].as_str().unwrap().to_string();
        let mine = server.call("POST", "/api/folders", Some(&nyu.token), json!({"name": "2.f|f|f"})).await;
        let mine = json(mine).await["id"].as_str().unwrap().to_string();

        // Somebody else's folder would have come first.
        let message = next(&mut socket).await;
        assert!(contains(&message, "ReceiveMessage"), "{message:?}");
        assert!(contains(&message, &mine) && !contains(&message, &theirs));
    }

    #[tokio::test]
    async fn a_device_waiting_to_be_let_in_hears_the_answer() {
        let server = TestServer::new().await;
        let nyu = server.account("nyu@example.com").await;
        let address = listen(&server).await;
        let asked = server
            .call(
                "POST",
                "/api/auth-requests",
                None,
                json!({
                    "email": nyu.email, "publicKey": "cHVibGlj", "deviceIdentifier": "5d0e7b43-2a57-4d68-9d1c-0c1f2b3a4d5e",
                    "accessCode": "abcdefghijklmnopqrstu", "type": 0, "fingerprintPhrase": "x"
                }),
            )
            .await;
        assert_eq!(asked.status(), StatusCode::OK);
        let id = json(asked).await["id"].as_str().unwrap().to_string();

        let mut waiting = connect(format!("ws://{address}/notifications/anonymous-hub?Token={id}")).await;
        let answer = json!({"key": "4.a2V5", "masterPasswordHash": null, "deviceIdentifier": nyu.device, "requestApproved": true});
        let response = server.call("PUT", &format!("/api/auth-requests/{id}"), Some(&nyu.token), answer).await;
        assert_eq!(response.status(), StatusCode::OK);
        let message = next(&mut waiting).await;
        assert!(contains(&message, "AuthRequestResponseRecieved") && contains(&message, &id));
    }

    #[tokio::test]
    async fn the_anonymous_hub_is_only_for_requests_that_wait_and_takes_small_messages() {
        let server = TestServer::new().await;
        let address = listen(&server).await;
        let made_up =
            tokio_tungstenite::connect_async(format!("ws://{address}/notifications/anonymous-hub?Token=x")).await;
        assert!(made_up.is_err(), "no request with that id");

        let body = json!({"email": "nobody@example.com", "publicKey": "cHVibGlj", "deviceIdentifier": "d",
            "accessCode": "abcdefghijklmnopqrstu", "type": 0});
        let id =
            json(server.call("POST", "/api/auth-requests", None, body).await).await["id"].as_str().unwrap().to_string();
        let mut waiting = connect(format!("ws://{address}/notifications/anonymous-hub?Token={id}")).await;
        waiting.send(Message::text("x".repeat(64 * 1024))).await.unwrap();
        // Pings may still come; then the server closes the connection.
        while let Some(Ok(Message::Binary(_) | Message::Ping(_))) =
            tokio::time::timeout(Duration::from_secs(5), waiting.next()).await.unwrap()
        {}
    }

    #[tokio::test]
    async fn a_connection_ends_with_its_session() {
        let server = TestServer::new().await;
        let nyu = server.account("nyu@example.com").await;
        let address = listen(&server).await;
        let mut socket = connect(format!("ws://{address}/notifications/hub?access_token={}", nyu.token)).await;
        server.state.store.update_user(&nyu.id, |user| user.security_stamp = "a new one".into()).await.unwrap();
        // Pings may come until the next check; then the server closes the connection.
        while let Some(Ok(Message::Binary(_) | Message::Ping(_))) =
            tokio::time::timeout(Duration::from_secs(5), socket.next()).await.unwrap()
        {}
    }

    /// Bitwarden's phone apps still register their push token: it is taken and dropped, since
    /// there is no push relay (docs/plan.md, Planänderung 0.8).
    #[tokio::test]
    async fn push_tokens_are_taken_and_dropped() {
        let server = TestServer::new().await;
        server.account("nyu@example.com").await;
        let phone = server.login("nyu@example.com", "a3c1e9d4-7b2f-4c5e-8d6a-1f0e2b3c4d5e").await;
        let path = format!("/api/devices/identifier/{}/token", phone.device);
        let response = server.call("PUT", &path, Some(&phone.token), json!({"pushToken": "fcm-1"})).await;
        assert_eq!(response.status(), StatusCode::OK);
        let path = format!("/api/devices/identifier/{}/clear-token", phone.device);
        let response = server.call("PUT", &path, Some(&phone.token), json!({})).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = server.call("PUT", &path, None, json!({})).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
