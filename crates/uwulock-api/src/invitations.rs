//! `/uwu/v1/invitations`: people inviting people. Admins invite in the portal; here every account
//! may, when an admin allows it, up to the quota the settings give — and never as an admin.
//! An admin counts as one here only as in the portal: inside the admin networks, and through SSO
//! where the portal asks for it.

use crate::AppState;
use crate::admin::{invite, invite_as_user};
use crate::auth::{ClientIp, Session};
use crate::errors::{ApiError, ApiResult};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::IpAddr;
use uwulock_store::{clock, normalize_email};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/invitations", get(mine).post(create))
        .route("/uwu/v1/invitations/{email}", delete(withdraw))
}

/// Whether `session` may invite here, and how many more.
/// Whether `session` may invite here, how many, how many it did, and whether as an admin.
async fn allowance(state: &AppState, session: &Session, ip: IpAddr) -> ApiResult<(bool, i64, i64, bool)> {
    let settings = state.settings();
    let quota = i64::from(settings.invitations_per_user);
    let used = state.store.invitations_used(&session.user.id).await?;
    let admin = session.acts_as_admin(state, ip);
    Ok((settings.users_may_invite || admin, quota, used, admin))
}

async fn mine(State(state): State<AppState>, session: Session, ClientIp(ip): ClientIp) -> ApiResult<Json<Value>> {
    let (allowed, quota, used, admin) = allowance(&state, &session, ip).await?;
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
        "quota": if admin { Value::Null } else { quota.into() },
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
    ClientIp(ip): ClientIp,
    Json(data): Json<NewInvitation>,
) -> ApiResult<Json<Value>> {
    let (allowed, quota, _, admin) = allowance(&state, &session, ip).await?;
    if !allowed {
        return Err(ApiError::forbidden("Only admins invite people to this server."));
    }
    let email = normalize_email(&data.email);
    // Somebody else's invitation stays theirs; one's own goes out again, with a new link.
    if let Some(invitation) = state.store.invitation(&email).await?
        && invitation.invited_by.as_deref() != Some(session.user.id.as_str())
    {
        return Err(ApiError::bad("There is an invitation for this address already."));
    }
    crate::identity::mail_allowed(&state, &email, Some(&session.user.id))?;
    let invited = if admin {
        invite(&state, &email, false, Some(session.user.id.clone())).await?
    } else {
        invite_as_user(&state, &email, &session.user, quota).await?
    };
    tracing::info!(email = %invited.email, by = %session.user.email, "invited");
    Ok(Json(json!({
        "email": invited.email,
        // Only when the server cannot mail it: whoever holds it can register the address.
        "link": Some(invited.link).filter(|link| !link.is_empty()),
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
            assert!(json(response).await["link"].is_null(), "the server mails it; the inviter never holds it");
            let mail = server.wait_for_mail(|mail| mail.to == email).await;
            assert!(mail.text.contains("finish-signup?token="));
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
    async fn an_admin_invites_as_one_only_where_the_portal_is_open() {
        let settings = Settings { admin_networks: vec!["192.0.2.0/24".into()], ..Settings::default() };
        let server = TestServer::with_settings(settings).await;
        let boss = server.account("boss@example.com").await;
        server.state.store.update_user(&boss.id, |user| user.admin = true).await.unwrap();
        let body = json!({"email": "friend@example.com"});
        let response = server.call("POST", "/uwu/v1/invitations", Some(&boss.token), body.clone()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "outside the admin networks, an account like any");

        // Inside them it is an admin again; with "admins only with SSO" not without SSO.
        let mut settings = server.state.settings();
        settings.admin_networks = Vec::new();
        server.state.apply_settings(settings.clone());
        let mine = json(server.get_as(&boss.token, "/uwu/v1/invitations").await).await;
        assert!(mine["allowed"] == true && mine["quota"].is_null());
        settings.sso.enabled = true;
        settings.sso.admins_only_with_sso = true;
        server.state.apply_settings(settings);
        let response = server.call("POST", "/uwu/v1/invitations", Some(&boss.token), body).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "a password session of an SSO-only admin");
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
        assert_eq!(response.status(), StatusCode::OK);
        let mail = server.wait_for_mail(|mail| mail.to == "a@example.com").await;
        let token = mail.text.split("token=").nth(1).unwrap().split('&').next().unwrap().to_string();
        let response = server
            .call("POST", "/identity/accounts/register/finish", None, register_body("a@example.com", &token))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let mine = json(server.get_as(&nyu.token, "/uwu/v1/invitations").await).await;
        assert_eq!(mine["used"], 1, "the account they brought in");
        assert!(mine["invitations"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_invitation_says_nothing_about_accounts() {
        let server = TestServer::with_settings(open(5)).await;
        let nyu = server.account("nyu@example.com").await;
        server.account("mio@example.com").await;
        let to_mio = || server.mails().iter().filter(|mail| mail.to == "mio@example.com").count();
        let before = to_mio();
        let mut answers = Vec::new();
        for email in ["mio@example.com", "new@example.com"] {
            let response = server.call("POST", "/uwu/v1/invitations", Some(&nyu.token), json!({"email": email})).await;
            assert_eq!(response.status(), StatusCode::OK, "{email}");
            let mut answer = json(response).await;
            answer["email"] = json!(null);
            answer["expires"] = json!(null);
            answers.push(answer);
        }
        assert_eq!(answers[0], answers[1]);
        server.wait_for_mail(|mail| mail.to == "new@example.com").await;
        assert_eq!(to_mio(), before, "no mail to an account");
    }

    #[tokio::test]
    async fn without_mail_the_inviter_gets_the_link() {
        let mut server = TestServer::with_settings(open(5)).await;
        server.state.mailer = uwulock_mail::Mailer::new(None).unwrap();
        server = server.with_limits(crate::Limits::generous());
        let nyu = server.account("nyu@example.com").await;
        let response =
            server.call("POST", "/uwu/v1/invitations", Some(&nyu.token), json!({"email": "a@example.com"})).await;
        assert!(json(response).await["link"].as_str().unwrap().contains("finish-signup?token="));
    }
}
