//! An organisation's members, as Bitwarden's `OrganizationUsersController` has them: owners
//! invite people by address, the invited accept (with the mail's link, or in the web vault when
//! they are logged in with that address), and an owner confirms them by handing over the
//! organisation key, wrapped for the member's public key.
//!
//! The server never checks that key — it cannot, and must not be able to. Whether it went to
//! the right person is what the fingerprint phrase is for: the owner's web vault shows the
//! phrase of the member's public key, the owner compares it with the member's own, and only then
//! confirms.
//!
//! Somebody without an account is invited the same way. When the inviter may invite people to
//! the server (§21's invitation rules), the invitation to the family also lets them register;
//! otherwise the mail tells them to ask for an account first. Either way the inviter learns
//! nothing about which addresses have an account.

use crate::auth::{self, Session};
use crate::errors::{ApiError, ApiResult};
use crate::families::{Rules, as_member, as_owner, not_found, refused, tell};
use crate::identity::send_later;
use crate::{AppState, json as out};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_mail::{Joining, Language, Mail};
use uwulock_notify::Kind;
use uwulock_store::organizations::{ACCEPTED, CONFIRMED, INVITED, Member, OWNER, Organization};
use uwulock_store::{Access, MemberDetails, OrgRefusal, User, clock, normalize_email};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/organizations/{org}/users", get(list).delete(remove_many))
        .route("/api/organizations/{org}/users/invite", post(invite))
        .route("/api/organizations/{org}/users/reinvite", post(reinvite_many))
        .route("/api/organizations/{org}/users/public-keys", post(public_keys))
        .route("/api/organizations/{org}/users/confirm", post(confirm_many))
        .route("/api/organizations/{org}/users/delete", post(remove_many))
        .route("/api/organizations/{org}/users/{id}", get(one).put(update).post(update).delete(remove_one))
        .route("/api/organizations/{org}/users/{id}/delete", post(remove_one))
        .route("/api/organizations/{org}/users/{id}/reinvite", post(reinvite_one))
        .route("/api/organizations/{org}/users/{id}/accept", post(accept))
        .route("/api/organizations/{org}/users/{id}/confirm", post(confirm_one))
        .route("/api/organizations/{org}/users/{id}/revoke", put(unsupported))
        .route("/api/organizations/{org}/users/{id}/restore", put(unsupported))
}

/// How a person is named in a mail: their name, or their address.
fn called(user: &User) -> String {
    user.name.clone().filter(|name| !name.trim().is_empty()).unwrap_or_else(|| user.email.clone())
}

fn access_json(id: &str, access: &Access) -> Value {
    json!({ "id": id, "readOnly": access.read_only, "hidePasswords": access.hide_passwords, "manage": access.manage })
}

/// `organizationUserUserDetails`. An owner sees everything; a member who else is in it, not
/// what they reach or whether they use two-step login.
fn member_json(details: &MemberDetails, owner: bool, with_collections: bool) -> Value {
    let member = &details.member;
    json!({
        "id": member.id,
        "userId": member.user_id,
        "type": member.kind,
        "status": member.status,
        "externalId": member.external_id,
        "name": details.name,
        "email": details.email,
        "avatarColor": details.avatar_color,
        "twoFactorEnabled": owner && details.two_factor,
        "accessAll": member.access_all,
        "collections": if owner && with_collections {
            details.collections.iter().map(|(id, access)| access_json(id, access)).collect::<Vec<_>>()
        } else {
            Vec::new()
        },
        "groups": [],
        "hasMasterPassword": true,
        "resetPasswordEnrolled": member.reset_password_key.is_some(),
        "ssoBound": false,
        "usesKeyConnector": false,
        "accessSecretsManager": false,
        "managedByOrganization": false,
        "claimedByOrganization": false,
        "permissions": {
            "accessEventLogs": false,
            "accessImportExport": false,
            "accessReports": false,
            "createNewCollections": false,
            "editAnyCollection": false,
            "deleteAnyCollection": false,
            "manageGroups": false,
            "managePolicies": false,
            "manageSso": false,
            "manageUsers": false,
            "manageResetPassword": false,
            "manageScim": false,
        },
        "creationDate": member.created,
        "revisionDate": member.revision,
        "object": "organizationUserUserDetails",
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListQuery {
    #[serde(default)]
    include_collections: Option<bool>,
}

/// Everybody in the organisation. Owners see everything; a member sees who else is in it, as
/// in Bitwarden, but not who reaches which collection.
async fn list(
    State(state): State<AppState>,
    session: Session,
    Path(org): Path<String>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let (org, me) = as_member(&state, &session, &org).await?;
    let owner = me.kind == OWNER;
    let details = state.store.member_details(&org.id).await?;
    let collections = query.include_collections.unwrap_or(false);
    Ok(Json(out::list(details.iter().map(|details| member_json(details, owner, collections)).collect())))
}

async fn one(
    State(state): State<AppState>,
    session: Session,
    Path((org, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (org, _) = as_owner(&state, &session, &org).await?;
    let details = state.store.member_details(&org.id).await?;
    let found = details.iter().find(|details| details.member.id == id).ok_or_else(not_found)?;
    Ok(Json(member_json(found, true, true)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectionAccess {
    id: String,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    hide_passwords: bool,
    #[serde(default)]
    manage: bool,
}

fn accesses(list: Vec<CollectionAccess>) -> Vec<(String, Access)> {
    list.into_iter()
        .map(|access| {
            (
                access.id,
                Access { read_only: access.read_only, hide_passwords: access.hide_passwords, manage: access.manage },
            )
        })
        .collect()
}

/// Refused for member types the organisation does not have, and for groups (Stufe 5).
fn check_type(rules: &Rules, kind: i64, groups: &[Value]) -> ApiResult<()> {
    if !rules.allows_type(kind) {
        return Err(ApiError::bad("A family has owners and members only."));
    }
    if !groups.is_empty() {
        return Err(ApiError::bad("A family has no groups."));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Invite {
    emails: Vec<String>,
    #[serde(rename = "type")]
    kind: i64,
    #[serde(default)]
    collections: Vec<CollectionAccess>,
    #[serde(default)]
    groups: Vec<Value>,
}

async fn invite(
    State(state): State<AppState>,
    session: Session,
    Path(org): Path<String>,
    Json(data): Json<Invite>,
) -> ApiResult<StatusCode> {
    let (org, _) = as_owner(&state, &session, &org).await?;
    let rules = Rules::of(&state, &org);
    check_type(&rules, data.kind, &data.groups)?;
    if data.emails.is_empty() || data.emails.len() > 20 {
        return Err(ApiError::bad("Invite from 1 to 20 addresses at once."));
    }
    let mut emails = Vec::new();
    for email in &data.emails {
        emails.push(crate::admin::checked_address(email)?);
    }
    // Counted before anything is looked up: a list of addresses cannot be tried quickly.
    for _ in &emails {
        if !state.limits.invites.take(session.user.id.clone()) {
            return Err(ApiError::too_many("Too many invitations. Wait a few minutes and try again."));
        }
    }
    let invited = state
        .store
        .invite_members(&org.id, emails, data.kind, accesses(data.collections), rules.seats())
        .await?
        .map_err(refused)?;
    for member in &invited {
        send_invitation(&state, &session.user, &org, member).await?;
    }
    tracing::info!(org = %org.id, count = invited.len(), "invited to an organization");
    Ok(StatusCode::OK)
}

/// The link in an invitation's mail, as Bitwarden's server writes it.
fn invitation_link(state: &AppState, org: &Organization, member: &Member, email: &str, existing: bool) -> String {
    let token = state.tokens.org_invite_token(&member.id, email);
    let encode = |text: &str| url::form_urlencoded::byte_serialize(text.as_bytes()).collect::<String>();
    format!(
        "{}/#/accept-organization?organizationId={}&organizationUserId={}&email={}&organizationName={}&token={}\
         &initOrganization=False&orgUserHasExistingUser={}",
        state.config.public,
        org.id,
        member.id,
        encode(email),
        encode(&org.name),
        encode(&token),
        if existing { "True" } else { "False" },
    )
}

/// Mail the invitation, when the server sends mail and the address had not had enough mails
/// lately. Somebody without an account also gets an invitation to the server when the inviter
/// may give one — then the family's link registers them.
async fn send_invitation(state: &AppState, inviter: &User, org: &Organization, member: &Member) -> ApiResult<()> {
    let email = member.email.clone().unwrap_or_default();
    if !state.mailer.enabled() || crate::identity::mail_allowed(state, &email, None).is_err() {
        return Ok(());
    }
    let settings = state.settings();
    let account = state.store.user_by_email(&email).await?;
    let joining = match &account {
        Some(_) => Joining::Account,
        None if settings.users_may_invite || inviter.admin => {
            if server_invitation(state, inviter, &email).await? {
                Joining::Register
            } else {
                Joining::AskForAccount
            }
        }
        None => Joining::AskForAccount,
    };
    let language = match &account {
        Some(user) => Language::from_code(&user.language),
        None => settings.default_language,
    };
    let mail = Mail::OrgInvited {
        organization: org.name.clone(),
        inviter: called(inviter),
        link: invitation_link(state, org, member, &email, account.is_some()),
        family: org.is_family(),
        joining,
        server: state.host().to_string(),
    };
    send_later(state, &email, mail, language);
    Ok(())
}

/// An invitation to the server for `email`, from `inviter`, within their quota — or the one
/// there is already. Its own link is never sent: the family's link takes its place. Whether
/// there is one.
async fn server_invitation(state: &AppState, inviter: &User, email: &str) -> ApiResult<bool> {
    if state.store.invitation(email).await?.is_some_and(|invitation| invitation.expires > clock::now()) {
        return Ok(true);
    }
    let settings = state.settings();
    let token = auth::sha256(auth::random_token(32).as_bytes());
    let expires = clock::in_seconds(i64::from(settings.invitation_days) * 86_400);
    let language = settings.default_language.code();
    if inviter.admin {
        state.store.invite(email, token, false, Some(inviter.id.clone()), language, expires).await?;
        return Ok(true);
    }
    let quota = i64::from(settings.invitations_per_user);
    Ok(state.store.invite_within(email, token, &inviter.id, language, expires, quota).await?.is_some())
}

/// The bulk answer Bitwarden gives: per member, an error or none.
fn bulk(results: Vec<(String, String)>) -> Value {
    out::list(
        results
            .into_iter()
            .map(|(id, error)| json!({ "object": "OrganizationBulkConfirmResponseModel", "id": id, "error": error }))
            .collect(),
    )
}

#[derive(Deserialize)]
struct Ids {
    ids: Vec<String>,
}

async fn reinvite(state: &AppState, session: &Session, org: &Organization, id: &str) -> ApiResult<()> {
    let member = state.store.org_member(&org.id, id).await?.ok_or_else(not_found)?;
    if member.status != INVITED {
        return Err(ApiError::bad("This member accepted already."));
    }
    if !state.limits.invites.take(session.user.id.clone()) {
        return Err(ApiError::too_many("Too many invitations. Wait a few minutes and try again."));
    }
    send_invitation(state, &session.user, org, &member).await
}

async fn reinvite_one(
    State(state): State<AppState>,
    session: Session,
    Path((org, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let (org, _) = as_owner(&state, &session, &org).await?;
    reinvite(&state, &session, &org, &id).await?;
    Ok(StatusCode::OK)
}

async fn reinvite_many(
    State(state): State<AppState>,
    session: Session,
    Path(org): Path<String>,
    Json(data): Json<Ids>,
) -> ApiResult<Json<Value>> {
    let (org, _) = as_owner(&state, &session, &org).await?;
    let mut results = Vec::new();
    for id in data.ids.into_iter().take(50) {
        let error = reinvite(&state, &session, &org, &id).await.err().map(|error| error.message()).unwrap_or_default();
        results.push((id, error));
    }
    Ok(Json(bulk(results)))
}

#[derive(Deserialize)]
struct Accept {
    #[serde(default)]
    token: Option<String>,
}

/// The invited person accepts: with the token from the mail's link, or — UwULock's addition —
/// in the web vault, logged in with the address the invitation went to.
async fn accept(
    State(state): State<AppState>,
    session: Session,
    Path((org, id)): Path<(String, String)>,
    Json(data): Json<Accept>,
) -> ApiResult<StatusCode> {
    if let Some(token) = data.token.as_deref().map(str::trim).filter(|token| !token.is_empty()) {
        let valid = state
            .tokens
            .check_org_invite_token(token)
            .is_some_and(|(member, email)| member == id && email == session.user.email);
        if !valid {
            return Err(refused(OrgRefusal::State));
        }
    }
    let org = state.store.organization(&org).await?.ok_or_else(not_found)?;
    accept_as(&state, &org, &id, &session.user).await?;
    tell(&state, Some(&session), std::slice::from_ref(&session.user.id), Kind::OrgKeys);
    Ok(StatusCode::OK)
}

/// `user` takes the invitation `id` to `org`; the owners hear that somebody waits.
pub(crate) async fn accept_as(state: &AppState, org: &Organization, id: &str, user: &User) -> ApiResult<Member> {
    let member = state.store.accept_member(&org.id, id, &user.id, &user.email).await?.map_err(refused)?;
    if state.mailer.enabled() {
        for owner in state.store.member_details(&org.id).await? {
            if owner.member.kind != OWNER || owner.member.status != CONFIRMED {
                continue;
            }
            let Some(owner_id) = &owner.member.user_id else { continue };
            if let Some(owner) = state.store.user(owner_id).await? {
                let mail =
                    Mail::OrgAccepted { member: called(user), organization: org.name.clone(), family: org.is_family() };
                send_later(state, &owner.email, mail, Language::from_code(&owner.language));
            }
        }
    }
    tracing::info!(org = %org.id, user = %user.id, "accepted an organization's invitation");
    Ok(member)
}

async fn public_keys(
    State(state): State<AppState>,
    session: Session,
    Path(org): Path<String>,
    Json(data): Json<Ids>,
) -> ApiResult<Json<Value>> {
    let (org, _) = as_owner(&state, &session, &org).await?;
    let keys = state.store.member_public_keys(&org.id, data.ids.into_iter().take(100).collect()).await?;
    Ok(Json(out::list(
        keys.into_iter()
            .map(|(id, user_id, key)| {
                json!({ "object": "organizationUserPublicKeyResponseModel", "id": id, "userId": user_id, "key": key })
            })
            .collect(),
    )))
}

#[derive(Deserialize)]
struct ConfirmOne {
    key: String,
}

/// Confirm an accepted member with the organisation key wrapped for their public key. Only an
/// owner, and only a key of the form an RSA wrap has.
async fn confirm(state: &AppState, session: &Session, org: &Organization, id: &str, key: String) -> ApiResult<()> {
    if !crate::keys::enc_string(&key, 4, 1100) {
        return Err(ApiError::bad("The key has to be wrapped for the member's public key."));
    }
    let most = Rules::of(state, org).per_user();
    let (member, users) =
        state.store.confirm_member(&org.id, id, key, most).await?.map_err(|refusal| match refusal {
            OrgRefusal::State => ApiError::bad("Only a member who accepted can be confirmed."),
            OrgRefusal::Owned => ApiError::bad("This person owns as many families as they may already."),
            other => refused(other),
        })?;
    let Some(user_id) = &member.user_id else { return Ok(()) };
    tell(state, Some(session), std::slice::from_ref(user_id), Kind::OrgKeys);
    tell(state, Some(session), &users.into_iter().filter(|user| user != user_id).collect::<Vec<_>>(), Kind::Vault);
    if let Some(user) = state.store.user(user_id).await? {
        let detail = json!({ "organization": org.name });
        crate::notices::record(state, &user, "organizationJoined", &crate::notices::Context::default(), detail).await;
        if state.mailer.enabled() {
            let mail = Mail::OrgConfirmed { organization: org.name.clone(), family: org.is_family() };
            send_later(state, &user.email, mail, Language::from_code(&user.language));
        }
    }
    tracing::info!(org = %org.id, member = %id, "confirmed a member");
    Ok(())
}

async fn confirm_one(
    State(state): State<AppState>,
    session: Session,
    Path((org, id)): Path<(String, String)>,
    Json(data): Json<ConfirmOne>,
) -> ApiResult<StatusCode> {
    let (org, _) = as_owner(&state, &session, &org).await?;
    confirm(&state, &session, &org, &id, data.key).await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct ConfirmMany {
    keys: Vec<ConfirmKey>,
}

#[derive(Deserialize)]
struct ConfirmKey {
    id: String,
    key: String,
}

async fn confirm_many(
    State(state): State<AppState>,
    session: Session,
    Path(org): Path<String>,
    Json(data): Json<ConfirmMany>,
) -> ApiResult<Json<Value>> {
    let (org, _) = as_owner(&state, &session, &org).await?;
    let mut results = Vec::new();
    for entry in data.keys.into_iter().take(50) {
        let error = confirm(&state, &session, &org, &entry.id, entry.key)
            .await
            .err()
            .map(|error| error.message())
            .unwrap_or_default();
        results.push((entry.id, error));
    }
    Ok(Json(bulk(results)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateMember {
    #[serde(rename = "type")]
    kind: i64,
    #[serde(default)]
    collections: Option<Vec<CollectionAccess>>,
    #[serde(default)]
    groups: Vec<Value>,
}

async fn update(
    State(state): State<AppState>,
    session: Session,
    Path((org, id)): Path<(String, String)>,
    Json(data): Json<UpdateMember>,
) -> ApiResult<StatusCode> {
    let (org, _) = as_owner(&state, &session, &org).await?;
    let rules = Rules::of(&state, &org);
    check_type(&rules, data.kind, &data.groups)?;
    let before = state.store.org_member(&org.id, &id).await?.ok_or_else(not_found)?;
    let collections = data.collections.map(accesses);
    let (member, _) =
        state.store.update_member(&org.id, &id, data.kind, collections, rules.per_user()).await?.map_err(
            |refusal| match refusal {
                OrgRefusal::Owned => ApiError::bad("This person owns as many families as they may already."),
                other => refused(other),
            },
        )?;
    let Some(user_id) = &member.user_id else { return Ok(StatusCode::OK) };
    if member.status == CONFIRMED {
        let kind = if before.kind != member.kind { Kind::OrgKeys } else { Kind::Vault };
        tell(&state, Some(&session), std::slice::from_ref(user_id), kind);
    }
    if before.kind != member.kind
        && member.status >= ACCEPTED
        && let Some(user) = state.store.user(user_id).await?
    {
        let detail = json!({ "organization": org.name, "type": member.kind });
        crate::notices::record(&state, &user, "organizationRoleChanged", &crate::notices::Context::default(), detail)
            .await;
    }
    Ok(StatusCode::OK)
}

/// Take `id` out of `org`: an owner does that to anybody but the last owner.
async fn remove(state: &AppState, session: &Session, org: &Organization, id: &str) -> ApiResult<()> {
    let (member, users) = state.store.remove_member(&org.id, id).await?.map_err(refused)?;
    tell(state, Some(session), &users, Kind::OrgKeys);
    if let Some(user_id) = &member.user_id
        && user_id != &session.user.id
        && let Some(user) = state.store.user(user_id).await?
    {
        crate::families::removed_notice(state, &user, org).await;
    }
    Ok(())
}

async fn remove_one(
    State(state): State<AppState>,
    session: Session,
    Path((org, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let (org, _) = as_owner(&state, &session, &org).await?;
    remove(&state, &session, &org, &id).await?;
    Ok(StatusCode::OK)
}

async fn remove_many(
    State(state): State<AppState>,
    session: Session,
    Path(org): Path<String>,
    Json(data): Json<Ids>,
) -> ApiResult<Json<Value>> {
    let (org, _) = as_owner(&state, &session, &org).await?;
    let mut results = Vec::new();
    for id in data.ids.into_iter().take(50) {
        let error = remove(&state, &session, &org, &id).await.err().map(|error| error.message()).unwrap_or_default();
        results.push((id, error));
    }
    Ok(Json(bulk(results)))
}

/// Revoking and restoring members come with Stufe 5's organisations.
async fn unsupported() -> ApiError {
    ApiError::bad("A family does not revoke members: remove them instead.")
}

/// Registering with an organisation's invitation (`register/finish` with `orgInviteToken`): the
/// membership and address the token is for, if it is still an open invitation.
pub(crate) async fn invitation_for(
    state: &AppState,
    token: &str,
    member_id: &str,
    email: &str,
) -> ApiResult<Option<(Organization, Member)>> {
    let Some((member, address)) = state.tokens.check_org_invite_token(token) else { return Ok(None) };
    if member != member_id || address != normalize_email(email) {
        return Ok(None);
    }
    let found = state.store.org_invitations_for(&address).await?;
    Ok(found.into_iter().find(|(_, member)| member.id == member_id && member.status == INVITED))
}
