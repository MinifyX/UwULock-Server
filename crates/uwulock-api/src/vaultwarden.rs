//! What is left of Vaultwarden after a move: the public half of its `rsa_key.pem`, which signed
//! the refresh tokens its clients still hold. Such a token is checked with it once, and the
//! device gets one of this server's in its place — so every device stays logged in.

use crate::AppState;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

/// Where the import keeps Vaultwarden's public key (DER, base64).
pub const PUBLIC_KEY: &str = "vaultwarden_rsa_public";

/// The device token inside a refresh token Vaultwarden signed; nothing for anything else.
pub(crate) async fn device_token(state: &AppState, token: &str) -> Option<String> {
    if token.matches('.').count() != 2 {
        return None;
    }
    let key = STANDARD.decode(state.store.setting(PUBLIC_KEY).await.ok()??).ok()?;
    let (signed, signature) = token.rsplit_once('.')?;
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key).verify(signed.as_bytes(), &signature).ok()?;
    let (_, payload) = signed.split_once('.')?;
    let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    let expired =
        claims.get("exp").and_then(serde_json::Value::as_i64).is_some_and(|exp| exp < crate::auth::now_seconds());
    if expired {
        return None;
    }
    claims.get("device_token").and_then(serde_json::Value::as_str).map(str::to_string)
}
