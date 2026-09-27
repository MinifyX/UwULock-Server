//! Bitwarden's push relay: how a self-hosted server wakes the official phone apps.
//!
//! Apple and Google deliver pushes only for whoever holds the app's keys, which is Bitwarden. So
//! a server registers each phone's push token with Bitwarden's relay, under an installation id
//! and key it got for free at <https://bitwarden.com/host>, and hands the relay what changed; the
//! relay passes it to the phone. What goes there is only which item or folder changed and when —
//! never anything of the vault.

use crate::{Subject, Update};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// Where the relay is: the US or the EU installation of Bitwarden's cloud, or — for tests —
/// somewhere else entirely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelaySettings {
    pub installation_id: String,
    pub installation_key: String,
    /// `us` or `eu`: where the installation id was made.
    #[serde(default = "us")]
    pub region: String,
}

fn us() -> String {
    "us".into()
}

impl RelaySettings {
    /// The relay's address and its identity server's.
    pub fn endpoints(&self) -> (String, String) {
        match self.region.as_str() {
            "eu" => ("https://api.bitwarden.eu".into(), "https://identity.bitwarden.eu".into()),
            other if other.starts_with("http") => {
                // For tests: one address for both.
                (other.trim_end_matches('/').to_string(), other.trim_end_matches('/').to_string())
            }
            _ => ("https://push.bitwarden.com".into(), "https://identity.bitwarden.com".into()),
        }
    }
}

#[derive(Default)]
struct Token {
    value: String,
    until: Option<Instant>,
}

/// Talks to the relay. Cheap to clone.
#[derive(Clone, Default)]
pub struct Relay {
    token: Arc<Mutex<Token>>,
}

fn client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|error| error.to_string())?
                .with_root_certificates(roots)
                .with_no_client_auth();
            reqwest::Client::builder()
                .tls_backend_preconfigured(tls)
                .user_agent("UwULock-Server")
                .timeout(Duration::from_secs(15))
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// A form value, percent-encoded.
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (byte as char).to_string(),
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// The relay's `type`, its payload for an update, with Bitwarden's names.
fn payload(update: &Update) -> Value {
    match &update.subject {
        Subject::Cipher { id, organization_id, collection_ids, revision } => json!({
            "id": id,
            "userId": if organization_id.is_some() { Value::Null } else { update.user_id.clone().into() },
            "organizationId": organization_id,
            "collectionIds": collection_ids,
            "revisionDate": revision,
        }),
        Subject::Folder { id, revision } | Subject::Send { id, revision } => {
            json!({ "id": id, "userId": update.user_id, "revisionDate": revision })
        }
        Subject::User { date } => json!({ "userId": update.user_id, "date": date }),
        Subject::AuthRequest { id } => json!({ "id": id, "userId": update.user_id }),
    }
}

impl Relay {
    /// A token from the relay's identity server, kept for half its life.
    async fn token(&self, settings: &RelaySettings) -> Result<String, String> {
        {
            let token = self.token.lock();
            if token.until.is_some_and(|until| until > Instant::now()) {
                return Ok(token.value.clone());
            }
        }
        #[derive(Deserialize)]
        struct Answer {
            access_token: String,
            expires_in: u64,
        }
        let (_, identity) = settings.endpoints();
        let client_id = format!("installation.{}", settings.installation_id);
        let form = [
            ("grant_type", "client_credentials"),
            ("scope", "api.push"),
            ("client_id", client_id.as_str()),
            ("client_secret", settings.installation_key.as_str()),
        ]
        .iter()
        .map(|(key, value)| format!("{key}={}", encode(value)))
        .collect::<Vec<_>>()
        .join("&");
        let answer: Answer = client()?
            .post(format!("{identity}/connect/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| format!("the relay refused the installation id or key: {error}"))?
            .json()
            .await
            .map_err(|error| error.to_string())?;
        let mut token = self.token.lock();
        token.value = answer.access_token.clone();
        token.until = Some(Instant::now() + Duration::from_secs(answer.expires_in / 2));
        Ok(answer.access_token)
    }

    /// Forget the token, after the settings changed.
    pub fn reset(&self) {
        *self.token.lock() = Token::default();
    }

    async fn post(&self, settings: &RelaySettings, path: &str, body: Option<Value>) -> Result<(), String> {
        let token = self.token(settings).await?;
        let (relay, _) = settings.endpoints();
        let mut request = client()?.post(format!("{relay}{path}")).bearer_auth(token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        request
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Whether the installation id and key work: a token for them.
    pub async fn check(&self, settings: &RelaySettings) -> Result<(), String> {
        self.reset();
        self.token(settings).await.map(drop)
    }

    /// A phone's push token, under `push_id`, the server's own id for this device at the relay.
    pub async fn register(
        &self,
        settings: &RelaySettings,
        push_id: &str,
        push_token: &str,
        user_id: &str,
        device_type: i64,
        device_id: &str,
    ) -> Result<(), String> {
        let body = json!({
            "deviceId": push_id,
            "pushToken": push_token,
            "userId": user_id,
            "type": device_type,
            "identifier": device_id,
            "installationId": settings.installation_id,
        });
        self.post(settings, "/push/register", Some(body)).await
    }

    pub async fn unregister(&self, settings: &RelaySettings, push_id: &str) -> Result<(), String> {
        self.post(settings, &format!("/push/delete/{push_id}"), None).await
    }

    /// Wake the account's phones for an update. `acting_push_id` is the relay's id of the device
    /// the update came from, which it leaves out.
    pub async fn send(
        &self,
        settings: &RelaySettings,
        update: &Update,
        acting_push_id: Option<&str>,
    ) -> Result<(), String> {
        // Always to the one account: the phones are registered with the relay by account, not by
        // organisation, and an organisation's change is published to each member on its own.
        let body = json!({
            "userId": update.user_id,
            "organizationId": null,
            "deviceId": acting_push_id,
            "identifier": update.acting_device,
            "type": update.kind as i64,
            "payload": payload(update),
            "clientType": null,
            "installationId": null,
        });
        self.post(settings, "/push/send", Some(body)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Kind;
    use axum::extract::State;
    use axum::routing::post;
    use std::sync::Arc;

    type Seen = Arc<parking_lot::Mutex<Vec<(String, Value)>>>;

    /// A relay on this machine that keeps what it was told.
    async fn fake() -> (String, Seen) {
        let seen: Seen = Arc::default();
        let app =
            axum::Router::new()
                .route(
                    "/connect/token",
                    post(|body: String| async move {
                        assert!(
                            body.contains("client_id=installation.inst-1") && body.contains("client_secret=secret")
                        );
                        axum::Json(json!({ "access_token": "relay-token", "expires_in": 3600 }))
                    }),
                )
                .route(
                    "/push/{*rest}",
                    post(
                        |State(seen): State<Seen>,
                         uri: axum::http::Uri,
                         headers: axum::http::HeaderMap,
                         body: String| async move {
                            assert_eq!(headers["authorization"], "Bearer relay-token");
                            seen.lock()
                                .push((uri.path().to_string(), serde_json::from_str(&body).unwrap_or(Value::Null)));
                            axum::http::StatusCode::OK
                        },
                    ),
                )
                .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), seen)
    }

    #[tokio::test]
    async fn phones_are_registered_woken_and_forgotten() {
        let (url, seen) = fake().await;
        let settings =
            RelaySettings { installation_id: "inst-1".into(), installation_key: "secret".into(), region: url };
        let relay = Relay::default();
        relay.check(&settings).await.unwrap();
        relay.register(&settings, "push-1", "fcm-token", "u1", 0, "phone-1").await.unwrap();
        let update = Update {
            kind: Kind::CipherUpdate,
            user_id: "u1".into(),
            subject: Subject::Cipher {
                id: "c1".into(),
                organization_id: None,
                collection_ids: None,
                revision: "2026-09-27T12:00:00.000000Z".into(),
            },
            acting_device: Some("laptop".into()),
        };
        relay.send(&settings, &update, None).await.unwrap();
        relay.unregister(&settings, "push-1").await.unwrap();
        let seen = seen.lock();
        assert_eq!(seen[0].0, "/push/register");
        assert_eq!(seen[0].1["pushToken"], "fcm-token");
        assert_eq!(seen[1].0, "/push/send");
        assert_eq!(seen[1].1["payload"]["id"], "c1");
        assert_eq!(seen[1].1["identifier"], "laptop");
        assert_eq!(seen[2].0, "/push/delete/push-1");
    }

    #[test]
    fn the_regions_are_bitwarden_s() {
        let us = RelaySettings { installation_id: String::new(), installation_key: String::new(), region: "us".into() };
        assert_eq!(us.endpoints().0, "https://push.bitwarden.com");
        let eu = RelaySettings { region: "eu".into(), ..us };
        assert_eq!(eu.endpoints().1, "https://identity.bitwarden.eu");
    }
}
