//! `/uwu/v1/invitations`: people inviting people. Admins invite in the portal; here every account
//! may, when an admin allows it, up to the quota the settings give — and never as an admin.

use crate::AppState;
use crate::admin::invite;
use crate::auth::Session;
use crate::errors::{ApiError, ApiResult};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_store::{clock, normalize_email};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/invitations", get(mine).post(create))
        .route("/uwu/v1/invitations/{email}", delete(withdraw))
}

/// Whether `session` may invite here, and how many more.
async fn allowance(state: &AppState, session: &Session) -> ApiResult<(bool, i64, i64)> {
    let settings = state.settings();
    let quota = i64::from(settings.invitations_per_user);
    let used = state.store.invitations_used(&session.user.id).await?;
    Ok((settings.users_may_invite || session.user.admin, quota, used))
}

async fn mine(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let (allowed, quota, used) = allowance(&state, &session).await?;
    let now = clock::now();
    let list: Vec<Value> = state
        .store
        .invitations_by(&session.user.id)
        .await?
        .iter()
        .map(|invitation| {
            json!({
                "email": invitation.email,
                "created": invitation.created,
                "expires": invitation.expires,
                "expired": invitation.expires <= now,
            })
        })
        .collect();
    Ok(Json(json!({
        "allowed": allowed,
        // Admins invite without a quota, in the portal as here.
        "quota": if session.user.admin { Value::Null } else { quota.into() },
        "used": used,
        "invitations": list,
    })))
}

#[derive(Deserialize)]
struct NewInvitation {
    email: String,
}

async fn create(
    State(state): State<AppState>,
    session: Session,
    Json(data): Json<NewInvitation>,
) -> ApiResult<Json<Value>> {
    let (allowed, quota, used) = allowance(&state, &session).await?;
    if !allowed {
        return Err(ApiError::forbidden("Only admins invite people to this server."));
    }
    let email = normalize_email(&data.email);
    // Somebody else's invitation stays theirs; one's own goes out again, with a new link.
    let again = match state.store.invitation(&email).await? {
        Some(invitation) if invitation.invited_by.as_deref() != Some(session.user.id.as_str()) => {
            return Err(ApiError::bad("There is an invitation for this address already."));
        }
        Some(invitation) => invitation.expires > clock::now(),
        None => false,
    };
    if !session.user.admin && !again && used >= quota {
        return Err(ApiError::bad(format!("You have invited as many people as you may ({quota}).")));
    }
    crate::identity::mail_allowed(&state, &email, Some(&session.user.id))?;
    let invited = invite(&state, &email, false, Some(session.user.id.clone())).await?;
    tracing::info!(email = %invited.email, by = %session.user.email, "invited");
    Ok(Json(json!({
        "email": invited.email,
        "link": invited.link,
        "mailed": invited.mailed,
        "expires": invited.expires,
    })))
}

async fn withdraw(State(state): State<AppState>, session: Session, Path(email): Path<String>) -> ApiResult<StatusCode> {
    match state.store.invitation(&email).await? {
        Some(invitation) if invitation.invited_by.as_deref() == Some(session.user.id.as_str()) => {
            state.store.uninvite(&email).await?;
            Ok(StatusCode::OK)
        }
        _ => Err(ApiError::not_found("You have no invitation for this address.")),
    }
}

#[cfg(test)]
mod tests {
    use crate::Settings;
    use crate::test_support::*;
    use axum::http::StatusCode;
    use serde_json::json;

    fn open(quota: u32) -> Settings {
        Settings { users_may_invite: true, invitations_per_user: quota, ..Settings::default() }
    }

    #[tokio::test]
    async fn only_when_an_admin_allows_it() {
        let server = TestServer::new().await;
        let nyu = server.account("nyu@example.com").await;
        let body = json!({"email": "friend@example.com"});
        let response = server.call("POST", "/uwu/v1/invitations", Some(&nyu.token), body).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let mine = json(server.get_as(&nyu.token, "/uwu/v1/invitations").await).await;
        assert_eq!(mine["allowed"], false);
    }

    #[tokio::test]
    async fn a_user_invites_up_to_the_quota_and_never_an_admin() {
        let server = TestServer::with_settings(open(2)).await;
        let nyu = server.account("nyu@example.com").await;
        for email in ["a@example.com", "b@example.com"] {
            let response = server.call("POST", "/uwu/v1/invitations", Some(&nyu.token), json!({"email": email})).await;
            assert_eq!(response.status(), StatusCode::OK);
            let link = json(response).await["link"].as_str().unwrap().to_string();
            assert!(link.contains("finish-signup?token="));
        }
        let response =
            server.call("POST", "/uwu/v1/invitations", Some(&nyu.token), json!({"email": "c@example.com"})).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "the quota is used up");
        // Their own again is fine: a new link, not a new person.
        let response =
            server.call("POST", "/uwu/v1/invitations", Some(&nyu.token), json!({"email": "a@example.com"})).await;
        assert_eq!(response.status(), StatusCode::OK);

        let invitation = server.state.store.invitation("a@example.com").await.unwrap().unwrap();
        assert!(!invitation.admin);
        let mine = json(server.get_as(&nyu.token, "/uwu/v1/invitations").await).await;
        assert_eq!((mine["quota"].as_i64(), mine["used"].as_i64()), (Some(2), Some(2)));
        assert_eq!(mine["invitations"].as_array().unwrap().len(), 2);

        // Withdrawn, the place is free again — but only one's own can be withdrawn.
        let other = server.account("other@example.com").await;
        let response =
            server.call("DELETE", "/uwu/v1/invitations/a@example.com", Some(&other.token), json!(null)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = server.call("DELETE", "/uwu/v1/invitations/a@example.com", Some(&nyu.token), json!(null)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response =
            server.call("POST", "/uwu/v1/invitations", Some(&nyu.token), json!({"email": "c@example.com"})).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn somebody_else_s_invitation_stays_theirs() {
        let server = TestServer::with_settings(open(5)).await;
        let nyu = server.account("nyu@example.com").await;
        server.invite("boss@example.com", true).await;
        let response =
            server.call("POST", "/uwu/v1/invitations", Some(&nyu.token), json!({"email": "boss@example.com"})).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(server.state.store.invitation("boss@example.com").await.unwrap().unwrap().admin, "still an admin's");
    }

    #[tokio::test]
    async fn who_registers_counts_for_whoever_invited_them() {
        let server = TestServer::with_settings(open(1)).await;
        let nyu = server.account("nyu@example.com").await;
        let response =
            server.call("POST", "/uwu/v1/invitations", Some(&nyu.token), json!({"email": "a@example.com"})).await;
        let link = json(response).await["link"].as_str().unwrap().to_string();
        let token = link.split("token=").nth(1).unwrap().split('&').next().unwrap().to_string();
        let response = server
            .call("POST", "/identity/accounts/register/finish", None, register_body("a@example.com", &token))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let mine = json(server.get_as(&nyu.token, "/uwu/v1/invitations").await).await;
        assert_eq!(mine["used"], 1, "the account they brought in");
        assert!(mine["invitations"].as_array().unwrap().is_empty());
    }
}
