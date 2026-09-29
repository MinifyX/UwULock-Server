//! Travel mode (docs/uwu-api.md §9): folders marked "hide while travelling" disappear, with their
//! items, from everything the account's devices see — and so from the official apps too, at their
//! next sync. Switched on from any device in the web vault; switched off only with the master
//! password and the second step of the login, so a device taken at a border cannot bring them
//! back.
//!
//! The hiding itself happens in the store, in every read of the account's items.

use crate::auth::{ClientIp, Session};
use crate::errors::{ApiError, ApiResult};
use crate::notices::{self, Context};
use crate::two_factor::{AUTHENTICATOR, EMAIL, WEBAUTHN};
use crate::{AppState, auth};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_notify::Kind;
use uwulock_store::{TravelRefusal, TwoFactor, User};

/// What a mailed code for switching travel mode off is kept as.
const TRAVEL_CODE: &str = "travel-disable";

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/travel", get(status))
        .route("/uwu/v1/travel/folders", put(folders))
        .route("/uwu/v1/travel/enable", post(enable))
        .route("/uwu/v1/travel/disable/send-email", post(send_email))
        .route("/uwu/v1/travel/disable/webauthn-challenge", post(webauthn_challenge))
        .route("/uwu/v1/travel/disable", post(disable))
}

/// 400 `travel_active` while travel mode is on: for what needs every item at once, like a key
/// rotation or emptying the vault.
pub(crate) async fn not_while_travelling(state: &AppState, user_id: &str) -> ApiResult<()> {
    if state.store.travelling(user_id).await? {
        return Err(ApiError::bad("Travel mode is on. Switch it off first.").code("travel_active"));
    }
    Ok(())
}

async fn travel_json(state: &AppState, user_id: &str) -> ApiResult<Value> {
    let travel = state.store.travel(user_id).await?;
    Ok(json!({
        "object": "travelMode",
        "enabled": travel.enabled.is_some(),
        "enabledDate": travel.enabled,
        "folderIds": travel.folder_ids,
        "hiddenCount": travel.hidden,
    }))
}

async fn status(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    Ok(Json(travel_json(&state, &session.user.id).await?))
}

/// Every device of the account syncs again, the one that asked included: what is hidden goes,
/// what comes back comes.
fn everyone_syncs(state: &AppState, user_id: &str) {
    crate::notify::user(state, user_id, None, Kind::Vault);
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Folders {
    folder_ids: Vec<String>,
}

async fn folders(State(state): State<AppState>, session: Session, Json(body): Json<Folders>) -> ApiResult<Json<Value>> {
    if body.folder_ids.len() > 1000 {
        return Err(ApiError::bad("That is too many folders.").code("invalid"));
    }
    match state.store.set_travel_folders(&session.user.id, body.folder_ids).await? {
        Ok(grew) => {
            if grew {
                everyone_syncs(&state, &session.user.id);
            }
        }
        Err(TravelRefusal::NotTheirs) => {
            return Err(ApiError::bad("One of these folders is not yours.").code("invalid"));
        }
        Err(TravelRefusal::Active) => {
            return Err(ApiError::bad("While travel mode is on, folders can be added but not taken away.")
                .code("travel_active"));
        }
    }
    Ok(Json(travel_json(&state, &session.user.id).await?))
}

/// The second steps that can switch travel mode off: an authenticator app, a security key, and
/// mail when the server can send it.
fn usable(state: &AppState, factors: &[TwoFactor]) -> Vec<i64> {
    factors
        .iter()
        .filter(|factor| factor.enabled)
        .map(|factor| factor.kind)
        .filter(|kind| *kind == AUTHENTICATOR || *kind == WEBAUTHN || (*kind == EMAIL && state.mailer.enabled()))
        .collect()
}

async fn enable(State(state): State<AppState>, session: Session, ClientIp(ip): ClientIp) -> ApiResult<Json<Value>> {
    let user = &session.user;
    let travel = state.store.travel(&user.id).await?;
    if travel.folder_ids.is_empty() {
        return Err(ApiError::bad("Mark at least one folder to hide first.").code("no_folders"));
    }
    if usable(&state, &state.store.two_factors(&user.id).await?).is_empty() {
        return Err(ApiError::bad("Travel mode needs two-step login: switching it off asks for the second step.")
            .code("two_factor_required"));
    }
    if state.store.set_travelling(&user.id, true).await? {
        let context = Context::of(&state, &session, ip).await;
        notices::record(&state, user, "travelModeEnabled", &context, json!({})).await;
        everyone_syncs(&state, &user.id);
        tracing::info!(user = %user.id, "travel mode on");
    }
    Ok(Json(travel_json(&state, &user.id).await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Password {
    #[serde(default)]
    master_password_hash: String,
}

/// The master password, checked for switching travel mode off. Wrong ones count against the
/// same tries as wrong codes.
async fn password_right(state: &AppState, user: &User, hash: &str) -> bool {
    !hash.is_empty() && auth::verify_password(state.config.hash_cost, Some(&user.password_hash), hash).await
}

/// Takes one of the account's tries to switch travel mode off; 429 when there is none left.
fn take_try(state: &AppState, user: &User) -> ApiResult<()> {
    if !state.limits.travel.take(user.id.clone()) {
        return Err(ApiError::too_many("Too many wrong tries. Wait a few minutes and try again.").code("rate_limited"));
    }
    Ok(())
}

async fn failed(state: &AppState, session: &Session, ip: std::net::IpAddr) -> ApiError {
    let context = Context::of(state, session, ip).await;
    notices::record(state, &session.user, "travelDisableFailed", &context, json!({})).await;
    ApiError::bad("The master password or the code is wrong.").code("invalid")
}

async fn send_email(
    State(state): State<AppState>,
    session: Session,
    ClientIp(ip): ClientIp,
    Json(body): Json<Password>,
) -> ApiResult<StatusCode> {
    let user = &session.user;
    not_travelling_is_fine(&state, user).await?;
    take_try(&state, user)?;
    if !password_right(&state, user, &body.master_password_hash).await {
        return Err(failed(&state, &session, ip).await);
    }
    state.limits.travel.give_back(&user.id);
    let factor = state
        .store
        .two_factors(&user.id)
        .await?
        .into_iter()
        .find(|factor| factor.enabled && factor.kind == EMAIL)
        .filter(|_| state.mailer.enabled())
        .ok_or_else(|| ApiError::bad("Two-step login by mail is not set up.").code("invalid"))?;
    crate::two_factor::send_code_for(&state, user, &factor.data, TRAVEL_CODE).await?;
    Ok(StatusCode::OK)
}

async fn webauthn_challenge(
    State(state): State<AppState>,
    session: Session,
    ClientIp(ip): ClientIp,
    Json(body): Json<Password>,
) -> ApiResult<Json<Value>> {
    let user = &session.user;
    not_travelling_is_fine(&state, user).await?;
    take_try(&state, user)?;
    if !password_right(&state, user, &body.master_password_hash).await {
        return Err(failed(&state, &session, ip).await);
    }
    state.limits.travel.give_back(&user.id);
    let factor = state
        .store
        .two_factors(&user.id)
        .await?
        .into_iter()
        .find(|factor| factor.enabled && factor.kind == WEBAUTHN)
        .ok_or_else(|| ApiError::bad("No security key is set up.").code("invalid"))?;
    Ok(Json(crate::two_factor::webauthn_options(&state, &factor, format!("travel:{}", user.id))))
}

/// Nothing to do while it is off: said, rather than a code sent for nothing.
async fn not_travelling_is_fine(state: &AppState, user: &User) -> ApiResult<()> {
    if !state.store.travelling(&user.id).await? {
        return Err(ApiError::bad("Travel mode is off.").code("invalid"));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Disable {
    #[serde(default)]
    master_password_hash: String,
    #[serde(default)]
    two_factor_provider: i64,
    #[serde(default, deserialize_with = "token_text")]
    two_factor_token: String,
}

/// A code as text, a number, or (a security key's assertion) a JSON object.
fn token_text<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    Ok(match Value::deserialize(deserializer)? {
        Value::String(text) => text,
        Value::Null => String::new(),
        other => other.to_string(),
    })
}

async fn disable(
    State(state): State<AppState>,
    session: Session,
    ClientIp(ip): ClientIp,
    Json(body): Json<Disable>,
) -> ApiResult<Json<Value>> {
    let user = &session.user;
    not_travelling_is_fine(&state, user).await?;
    // Taken first and given back when it was right, so tries sent at once all count.
    take_try(&state, user)?;
    if !password_right(&state, user, &body.master_password_hash).await {
        return Err(failed(&state, &session, ip).await);
    }
    let factors = state.store.two_factors(&user.id).await?;
    let usable = usable(&state, &factors);
    // Two-step login can go after the mode was switched on — the recovery code, an admin, an
    // emergency takeover. Then the master password alone switches it off, or nothing ever would.
    if !usable.is_empty() {
        if !usable.contains(&body.two_factor_provider) {
            return Err(failed(&state, &session, ip).await);
        }
        let checked = crate::two_factor::verify_code(
            &state,
            user,
            &factors,
            body.two_factor_provider,
            body.two_factor_token.trim(),
            &format!("travel:{}", user.id),
            TRAVEL_CODE,
        )
        .await;
        if checked.is_err() {
            return Err(failed(&state, &session, ip).await);
        }
    }
    state.limits.travel.give_back(&user.id);
    if state.store.set_travelling(&user.id, false).await? {
        let context = Context::of(&state, &session, ip).await;
        notices::record(&state, user, "travelModeDisabled", &context, json!({})).await;
        everyone_syncs(&state, &user.id);
        tracing::info!(user = %user.id, "travel mode off");
    }
    Ok(Json(travel_json(&state, &user.id).await?))
}

#[cfg(test)]
mod tests;
