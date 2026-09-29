//! `/uwu/v1`: UwULock's own API, for the web vault and UwULock's clients. The official
//! Bitwarden clients never call it.

use crate::AppState;
use crate::auth::{ClientIp, Session, device_type_name};
use crate::errors::{ApiError, ApiResult};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_mail::Language;
use uwulock_store::clock;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/info", get(info))
        .route("/uwu/v1/invitation", post(invitation))
        .route("/uwu/v1/account", get(account))
        .route("/uwu/v1/account/language", put(set_language))
        .route("/uwu/v1/devices", get(devices))
        .route("/uwu/v1/devices/{id}", delete(forget_device))
}

/// What this server is and can do, for a client that wants to know before it logs in.
async fn info(
    State(state): State<AppState>,
    send_host: Option<axum::Extension<crate::send_hosts::SendHost>>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let settings = state.settings();
    let (loaded, base) = crate::branding::for_request_at(&state, &headers).await;
    let branding = loaded.json(&base);
    if send_host.is_some() {
        // A send domain tells only what its pages need (§2).
        let mut features = vec!["sends"];
        if state.mailer.enabled() {
            features.push("send-emails");
        }
        if settings.file_requests.enabled {
            features.push("file-requests");
        }
        return Json(json!({
            "object": "info",
            "name": "UwULock Server",
            "version": state.version,
            "apiVersion": 1,
            "features": features,
            "branding": branding,
        }));
    }
    let mut features = vec![
        "vault",
        "folders",
        "trash",
        "archive",
        "import",
        "attachments",
        "sends",
        "emergency-access",
        "two-factor-authenticator",
        "two-factor-email",
        "two-factor-webauthn",
        "passkeys",
        "login-with-device",
        "api-key",
        "admin",
        "security-notices",
        "own-icons",
        "travel-mode",
        "reminders",
        "twofa-directory",
        "health-report",
    ];
    if settings.icons.automatic {
        features.push("icons");
    }
    let library = settings.icons.library && !settings.icons.sources.is_empty();
    if library {
        features.push("icon-library");
    }
    if settings.versions.per_item > 0 {
        features.push("versions");
    }
    if settings.hibp {
        features.push("hibp");
    }
    if settings.file_requests.enabled {
        features.push("file-requests");
    }
    if settings.sso.active() {
        features.push("sso");
    }
    if state.mailer.enabled() {
        features.push("send-emails");
    }
    let send_domains = crate::send_domains::for_info(&state);
    if !send_domains.is_empty() {
        features.push("send-domains");
    }
    let rules = &settings.policies.master_password;
    Json(json!({
        "object": "info",
        "name": "UwULock Server",
        "version": state.version,
        "apiVersion": 1,
        "publicUrl": state.config.public,
        "webVault": crate::web::is_built(),
        "mail": state.mailer.enabled(),
        "features": features,
        "sendDomains": send_domains,
        "branding": branding,
        "sso": {
            "enabled": settings.sso.active(),
            "only": settings.sso.active() && settings.sso.only,
            "identifier": settings.sso.identifier,
            "label": settings.sso.label,
        },
        "policies": {
            "masterPassword": {
                "minLength": rules.min_length,
                "minComplexity": rules.min_complexity,
                "enforceOnLogin": rules.enforce_on_login,
            },
        },
        "icons": {
            "automatic": settings.icons.automatic,
            "url": format!("{}/icons", state.config.public.trim_end_matches('/')),
            "ownMaxBytes": crate::icons::OWN_MAX_TEXT,
            "ownPixels": crate::icons::OWN_PIXELS,
            "library": library,
        },
        "limits": {
            "maxFileBytes": u64::from(settings.max_file_mb) * 1024 * 1024,
            "versionsPerItem": settings.versions.per_item,
            "versionDays": settings.versions.days,
            "fileRequestMaxFiles": settings.file_requests.max_files,
            "fileRequestMaxDays": settings.file_requests.max_days,
        },
    }))
}

#[derive(Deserialize)]
struct InvitationQuery {
    token: String,
}

/// Whether an invitation link still works, and for which address: the web vault asks before it
/// shows the form to register. The token comes in the body, not the address, where a proxy's
/// access log would keep it.
async fn invitation(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(query): Json<InvitationQuery>,
) -> ApiResult<Json<Value>> {
    if !state.limits.anonymous.check(ip) {
        return Err(ApiError::too_many("Too many requests. Wait a minute and try again."));
    }
    let invitation = state
        .store
        .invitation_by_token(crate::auth::sha256(query.token.trim().as_bytes()))
        .await?
        .ok_or_else(|| ApiError::not_found("This invitation is not valid (any more). Ask for a new one."))?;
    Ok(Json(json!({ "email": invitation.email, "expires": invitation.expires, "language": invitation.language })))
}

/// What the web vault needs to know about the account beyond Bitwarden's profile.
async fn account(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let settings = state.settings();
    let (factors, unseen, used, travelling, send_domain) = tokio::try_join!(
        state.store.two_factors(&session.user.id),
        state.store.unseen_notices(&session.user.id),
        state.store.storage_used(&session.user.id),
        state.store.travelling(&session.user.id),
        state.store.account_send_domain(&session.user.id),
    )?;
    let require = &settings.policies.require_two_factor;
    let families = crate::families::account_info(&state, &session).await?;
    Ok(Json(json!({
        "object": "account",
        "families": families,
        "policy": {
            "twoFactorRequired": require.enabled,
            "twoFactorDeadline": require.deadline.as_ref().filter(|_| require.enabled),
            "twoFactorEnforced": settings.policies.two_factor_enforced(),
            "kdfBelowMinimum": settings.policies.kdf_below_minimum(&session.user.kdf),
            "minimumKdf": settings.policies.minimum_kdf,
        },
        "securityNoticesUnseen": unseen,
        "travel": { "enabled": travelling },
        "sendDomainId": send_domain,
        "storage": { "usedBytes": used, "limitBytes": settings.storage_limit() },
        "admin": session.user.admin,
        "hasMasterPassword": !session.user.user_key.is_empty(),
        "sso": session.sso,
        "adminNeedsSso": settings.sso.active() && settings.sso.admins_only_with_sso,
        "language": session.user.language,
        "mail": state.mailer.enabled(),
        "passwordHints": settings.password_hints,
        "rememberTwoFactor": settings.remember_two_factor,
        "hibp": settings.hibp,
        "maxFileMb": settings.max_file_mb,
        "mayInvite": settings.users_may_invite || session.user.admin,
        "hasHint": session.user.password_hint.is_some(),
        "twoFactor": factors.iter().filter(|factor| factor.enabled).map(|factor| factor.kind).collect::<Vec<_>>(),
        "created": session.user.created,
        "lastLogin": session.user.last_login,
    })))
}

#[derive(Deserialize)]
struct LanguageData {
    language: String,
}

async fn set_language(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<LanguageData>,
) -> ApiResult<StatusCode> {
    let language = Language::from_code(&data.language).code().to_string();
    state.store.update_user(&session.user.id, move |user| user.language = language).await?;
    Ok(StatusCode::OK)
}

/// The account's devices, with what Bitwarden's list leaves out: when and from where each was
/// last seen, and which one is asking.
async fn devices(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let devices = state.store.devices(&session.user.id).await?;
    let list: Vec<Value> = devices
        .iter()
        .filter(|device| device.logged_in)
        .map(|device| {
            json!({
                "id": device.id,
                "name": device.name,
                "type": device.kind,
                "typeName": device_type_name(device.kind),
                "created": device.created,
                "lastSeen": device.last_seen,
                "lastIp": device.last_ip,
                "current": device.id == session.device,
                "remembered": device.remember_expires.as_deref().is_some_and(|expires| expires > clock::now().as_str()),
            })
        })
        .collect();
    Ok(Json(json!(list)))
}

/// Log a device out, and forget it.
async fn forget_device(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    crate::notify::forget_phone(&state, &session.user.id, &id).await;
    if !state.store.delete_device(&session.user.id, &id).await? {
        return Err(ApiError::not_found("No such device."));
    }
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::http::StatusCode;
    use serde_json::json;

    #[tokio::test]
    async fn an_invitation_link_says_who_it_is_for() {
        let server = TestServer::new().await;
        let token = server.invite("nyu@example.com", false).await;
        let found = json(server.call("POST", "/uwu/v1/invitation", None, json!({ "token": token })).await).await;
        assert_eq!(found["email"], "nyu@example.com");
        let wrong = server.call("POST", "/uwu/v1/invitation", None, json!({ "token": "nope" })).await;
        assert_eq!(wrong.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn devices_can_be_logged_out_from_another() {
        let server = TestServer::new().await;
        let first = server.account("nyu@example.com").await;
        let second = server.login("nyu@example.com", "device-2").await;
        let devices = json(server.get_as(&first.token, "/uwu/v1/devices").await).await;
        assert_eq!(devices.as_array().unwrap().len(), 2);
        assert!(
            devices.as_array().unwrap().iter().any(|device| device["current"] == true && device["id"] == "device-1")
        );
        let response = server.call("DELETE", "/uwu/v1/devices/device-2", Some(&first.token), json!({})).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(server.get_as(&second.token, "/api/sync").await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(server.get_as(&first.token, "/api/sync").await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn the_language_is_the_user_s() {
        let server = TestServer::new().await;
        let account = server.account("nyu@example.com").await;
        let response =
            server.call("PUT", "/uwu/v1/account/language", Some(&account.token), json!({"language": "en-GB"})).await;
        assert_eq!(response.status(), StatusCode::OK);
        let me = json(server.get_as(&account.token, "/uwu/v1/account").await).await;
        assert_eq!(me["language"], "en");
        assert_eq!(me["admin"], false);
    }
}
