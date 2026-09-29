//! Families (Stufe 4d, docs/uwu-api.md §16): organisations made and managed here, the way
//! Bitwarden's organisation API has it, so the official clients see them like any organisation.
//! A family has owners and members, collections, and nothing else: no groups, no policies, no
//! account recovery.
//!
//! This module has the organisation itself (make, read, rename, delete, leave, its keys) and who
//! may do what; members are in `org_members`, collections in `org_collections`. Stufe 5's
//! organisations go through the same endpoints: [`Rules`] is where they differ.

use crate::admin::record;
use crate::auth::{Admin, Session};
use crate::errors::{ApiError, ApiResult};
use crate::settings::OrgSettings;
use crate::{AppState, json as out};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_notify::Kind;
use uwulock_store::organizations::{CONFIRMED, FAMILY, INVITED, Member, ORGANIZATION, OWNER, Organization, USER};
use uwulock_store::{NewOrganization, OrgRefusal};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/organizations", post(create))
        .route("/api/organizations/{id}", get(one).put(rename).post(rename).delete(remove))
        .route("/api/organizations/{id}/delete", post(remove))
        .route("/api/organizations/{id}/leave", post(leave))
        .route("/api/organizations/{id}/keys", get(keys).post(keys))
        .route("/api/organizations/{id}/public-key", get(public_key))
        .route("/uwu/v1/organizations/invitations", get(invitations))
        .route("/uwu/v1/organizations/invitations/{id}", delete(decline))
        .route("/uwu/v1/admin/organizations", get(admin_list))
        .route("/uwu/v1/admin/organizations/{id}", delete(admin_delete))
}

/// What an organisation of one kind allows. A family: owners and members, `readOnly` per
/// collection, seats and owners as the admin set them. Stufe 5 adds organisations here.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Rules {
    pub family: bool,
    pub settings: OrgSettings,
}

impl Rules {
    pub(crate) fn of(state: &AppState, org: &Organization) -> Rules {
        Rules { family: org.is_family(), settings: state.settings().families }
    }

    /// The member types it takes: a family owners and members; an organisation also admins and
    /// custom members (Stufe 5).
    pub(crate) fn allows_type(&self, kind: i64) -> bool {
        if self.family { kind == OWNER || kind == USER } else { matches!(kind, 0 | 1 | 2 | 4) }
    }

    pub(crate) fn seats(&self) -> i64 {
        i64::from(self.settings.max_members)
    }

    pub(crate) fn per_user(&self) -> i64 {
        i64::from(self.settings.per_user)
    }
}

/// Refused unless the organisation can be managed here: families can; Stufe 5 brings the rest.
pub(crate) fn manageable(org: &Organization) -> ApiResult<()> {
    if org.is_family() {
        Ok(())
    } else {
        Err(ApiError::bad(
            "This organisation uses more than a family has (admins, groups or policies). Managing it comes with a later UwULock Server.",
        ))
    }
}

pub(crate) fn not_found() -> ApiError {
    ApiError::not_found("Organization not found.")
}

/// The organisation as a confirmed member of it sees it: refused, as if there were none, for
/// everybody else.
pub(crate) async fn as_member(state: &AppState, session: &Session, org_id: &str) -> ApiResult<(Organization, Member)> {
    match state.store.org_membership(org_id, &session.user.id).await? {
        Some((org, member)) if member.status == CONFIRMED => Ok((org, member)),
        _ => Err(not_found()),
    }
}

/// The organisation as one of its confirmed owners manages it.
pub(crate) async fn as_owner(state: &AppState, session: &Session, org_id: &str) -> ApiResult<(Organization, Member)> {
    let (org, member) = as_member(state, session, org_id).await?;
    if member.kind != OWNER {
        return Err(ApiError::forbidden("Only an owner can do this."));
    }
    manageable(&org)?;
    Ok((org, member))
}

/// What a refusal of the store means for the clients.
pub(crate) fn refused(refusal: OrgRefusal) -> ApiError {
    match refusal {
        OrgRefusal::NotFound => ApiError::not_found("Not found in this organization."),
        OrgRefusal::LastOwner => ApiError::bad("An organization needs an owner. Make somebody else an owner first."),
        OrgRefusal::Seats => ApiError::bad("You have reached the maximum number of users for this organization."),
        OrgRefusal::Owned => ApiError::bad("This account owns as many families as it may."),
        OrgRefusal::Exists(email) => ApiError::bad(format!("{email} is already a member or invited.")),
        OrgRefusal::State => ApiError::bad("This invitation is not valid (any more). Ask for a new one."),
    }
}

/// Tell each of `users` to sync: `kind` is `OrgKeys` when their organisations changed (they
/// sync everything and look at the keys again), `Vault` when only what they see did.
pub(crate) fn tell(state: &AppState, session: Option<&Session>, users: &[String], kind: Kind) {
    for user in users {
        crate::notify::user(state, user, session, kind);
    }
}

/// The plan's switches, the same in the profile and in the organisation's own answer.
fn plan_fields(state: &AppState, org: &Organization, into: &mut serde_json::Map<String, Value>) {
    let family = org.is_family();
    let fields = if family {
        json!({
            "planType": FAMILY,
            "productTierType": 1,
            "seats": state.settings().families.max_members,
            "use2fa": false,
            "useGroups": false,
            "usePolicies": false,
            "useCustomPermissions": false,
        })
    } else {
        json!({
            "planType": ORGANIZATION,
            "productTierType": 3,
            "seats": null,
            "use2fa": true,
            "useGroups": true,
            "usePolicies": true,
            "useCustomPermissions": false,
        })
    };
    if let Value::Object(map) = fields {
        into.extend(map);
    }
}

/// A membership, as the profile lists it (`profileOrganization`).
pub(crate) fn profile_organization(state: &AppState, org: &Organization, member: &Member) -> Value {
    let owner = member.kind == OWNER && org.is_family();
    let mut value = json!({
        "id": org.id,
        "name": org.name,
        "identifier": null,
        "maxCollections": null,
        "usersGetPremium": true,
        "useDirectory": false,
        "useEvents": false,
        "useTotp": true,
        "useScim": false,
        "useApi": false,
        "selfHost": true,
        "hasPublicAndPrivateKeys": org.public_key.is_some() && org.private_key.is_some(),
        "resetPasswordEnrolled": member.reset_password_key.is_some(),
        "useResetPassword": false,
        "ssoBound": false,
        "useSso": false,
        "useKeyConnector": false,
        "useSecretsManager": false,
        "usePasswordManager": true,
        "useActivateAutofillPolicy": false,
        "useRiskInsights": false,
        "useOrganizationDomains": false,
        "useAdminSponsoredFamilies": false,
        "organizationUserId": member.id,
        "providerId": null,
        "providerName": null,
        "providerType": null,
        "familySponsorshipFriendlyName": null,
        "familySponsorshipAvailable": false,
        "keyConnectorEnabled": false,
        "keyConnectorUrl": null,
        "accessSecretsManager": false,
        // Owners make and delete collections; members put items where they may.
        "limitCollectionCreation": true,
        "limitCollectionDeletion": true,
        "limitItemDeletion": false,
        "allowAdminAccessToAllCollectionItems": true,
        "userIsManagedByOrganization": false,
        "userIsClaimedByOrganization": false,
        "permissions": {
            "accessEventLogs": false,
            "accessImportExport": false,
            "accessReports": false,
            "createNewCollections": owner,
            "editAnyCollection": owner,
            "deleteAnyCollection": owner,
            "manageGroups": false,
            "managePolicies": false,
            "manageSso": false,
            "manageUsers": owner,
            "manageResetPassword": false,
            "manageScim": false,
        },
        "maxStorageGb": 32767,
        "userId": member.user_id,
        // Only a confirmed member holds the organisation's key.
        "key": if member.status == CONFIRMED { member.key.clone() } else { None },
        "status": member.status,
        "type": member.kind,
        "enabled": true,
        "object": "profileOrganization",
    });
    if let Value::Object(map) = &mut value {
        plan_fields(state, org, map);
    }
    value
}

/// `OrganizationResponseModel`.
pub(crate) fn organization_json(state: &AppState, org: &Organization) -> Value {
    let family = org.is_family();
    let mut value = json!({
        "id": org.id,
        "identifier": null,
        "name": org.name,
        "businessName": null,
        "businessAddress1": null,
        "businessAddress2": null,
        "businessAddress3": null,
        "businessCountry": null,
        "businessTaxNumber": null,
        "billingEmail": org.billing_email,
        "plan": {
            "type": org.plan_type,
            "productTier": if family { 1 } else { 3 },
            "name": if family { "Families" } else { "Enterprise" },
            "isAnnual": true,
            "object": "plan",
        },
        "maxAutoscaleSeats": null,
        "maxCollections": null,
        "maxStorageGb": 32767,
        "useDirectory": false,
        "useEvents": false,
        "useTotp": true,
        "useScim": false,
        "useSso": false,
        "useKeyConnector": false,
        "useApi": false,
        "useResetPassword": false,
        "useSecretsManager": false,
        "usePasswordManager": true,
        "useRiskInsights": false,
        "useOrganizationDomains": false,
        "useAdminSponsoredFamilies": false,
        "usersGetPremium": true,
        "selfHost": true,
        "hasPublicAndPrivateKeys": org.public_key.is_some() && org.private_key.is_some(),
        "smSeats": null,
        "smServiceAccounts": null,
        "limitCollectionCreation": true,
        "limitCollectionDeletion": true,
        "limitItemDeletion": false,
        "allowAdminAccessToAllCollectionItems": true,
        "creationDate": org.created,
        "object": "organization",
    });
    if let Value::Object(map) = &mut value {
        plan_fields(state, org, map);
    }
    value
}

// ── Making one ────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OrgKeys {
    public_key: String,
    encrypted_private_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewOrg {
    name: String,
    #[serde(default)]
    billing_email: Option<String>,
    #[serde(default)]
    plan_type: Option<i64>,
    key: String,
    #[serde(default)]
    keys: Option<OrgKeys>,
    #[serde(default)]
    collection_name: Option<String>,
}

pub(crate) fn check_name(name: &str) -> ApiResult<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 50 {
        return Err(ApiError::bad("The name is from 1 to 50 characters long."));
    }
    Ok(name.to_string())
}

/// The organisation's key pair as the clients make it: a public key (DER, base64) and the private
/// key under the organisation key.
fn check_keys(keys: &OrgKeys) -> ApiResult<()> {
    use base64::Engine as _;
    let public = base64::engine::general_purpose::STANDARD.decode(keys.public_key.trim()).ok();
    if !public.is_some_and(|der| (100..=2048).contains(&der.len()))
        || !crate::keys::enc_string(&keys.encrypted_private_key, 2, 8192)
    {
        return Err(ApiError::bad("The organization's keys are not in the form the clients make them."));
    }
    Ok(())
}

async fn create(State(state): State<AppState>, session: Session, Json(data): Json<NewOrg>) -> ApiResult<Json<Value>> {
    let settings = state.settings().families;
    match data.plan_type.unwrap_or(FAMILY) {
        FAMILY => {}
        ORGANIZATION => {
            return Err(ApiError::bad("Organizations beyond families come with a later UwULock Server."));
        }
        _ => return Err(ApiError::bad("Invalid plan type: families are type 22.")),
    }
    if !settings.may_create(session.user.admin) {
        return Err(ApiError::forbidden("An admin of this server decides who may make a family, and you may not."));
    }
    let name = check_name(&data.name)?;
    // The organisation key, wrapped for the owner's own public key — the only kind of key the
    // profile hands the clients for an organisation.
    if !crate::keys::enc_string(&data.key, 4, 1100) {
        return Err(ApiError::bad("The organization key has to be wrapped for your public key."));
    }
    if session.user.public_key.is_none() {
        return Err(ApiError::bad("Your account has no key pair yet. Log in to the web vault once, then try again."));
    }
    let keys = data.keys.ok_or_else(|| ApiError::bad("The organization's keys are missing."))?;
    check_keys(&keys)?;
    let collection_name = data.collection_name.filter(|name| !name.is_empty());
    if collection_name.as_ref().is_some_and(|name| !crate::keys::enc_string(name, 2, 1000)) {
        return Err(ApiError::bad("The collection's name has to be encrypted."));
    }
    let new = NewOrganization {
        name,
        billing_email: data.billing_email.unwrap_or_else(|| session.user.email.clone()).trim().to_lowercase(),
        plan_type: FAMILY,
        public_key: keys.public_key.trim().to_string(),
        private_key: keys.encrypted_private_key,
        owner_id: session.user.id.clone(),
        owner_key: data.key,
        collection_name,
    };
    let org =
        state.store.create_organization(new, i64::from(settings.per_user)).await?.map_err(|refusal| match refusal {
            OrgRefusal::Owned if settings.per_user == 0 => {
                ApiError::forbidden("An admin of this server decides who may make a family, and you may not.")
            }
            other => refused(other),
        })?;
    tracing::info!(org = %org.id, user = %session.user.id, "family made");
    tell(&state, Some(&session), std::slice::from_ref(&session.user.id), Kind::OrgKeys);
    Ok(Json(organization_json(&state, &org)))
}

// ── Reading and changing ──────────────────────────────────

async fn one(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let (org, _) = as_member(&state, &session, &id).await?;
    Ok(Json(organization_json(&state, &org)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Rename {
    name: String,
    #[serde(default)]
    billing_email: Option<String>,
}

async fn rename(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(data): Json<Rename>,
) -> ApiResult<Json<Value>> {
    let (org, _) = as_owner(&state, &session, &id).await?;
    let name = check_name(&data.name)?;
    let billing = data.billing_email.map(|email| email.trim().to_lowercase()).unwrap_or(org.billing_email.clone());
    let users = state.store.rename_organization(&org.id, name, billing).await?;
    tell(&state, Some(&session), &users, Kind::OrgKeys);
    let org = state.store.organization(&org.id).await?.ok_or_else(not_found)?;
    Ok(Json(organization_json(&state, &org)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Secret {
    #[serde(default)]
    master_password_hash: Option<String>,
}

/// Tell everybody who was in a deleted organisation, by notice and on their devices.
async fn gone(state: &AppState, session: Option<&Session>, org: &Organization, users: &[String]) {
    tell(state, session, users, Kind::OrgKeys);
    for user in users {
        if session.is_some_and(|session| &session.user.id == user) {
            continue;
        }
        if let Ok(Some(user)) = state.store.user(user).await {
            removed_notice(state, &user, org).await;
        }
    }
}

pub(crate) async fn removed_notice(state: &AppState, user: &uwulock_store::User, org: &Organization) {
    let detail = json!({ "organization": org.name });
    crate::notices::record(state, user, "organizationRemoved", &crate::notices::Context::default(), detail).await;
}

async fn remove(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    body: Option<Json<Secret>>,
) -> ApiResult<StatusCode> {
    let (org, _) = as_owner(&state, &session, &id).await?;
    let hash = body.and_then(|Json(data)| data.master_password_hash);
    crate::accounts::check_password(&state, &session.user, hash.as_deref()).await?;
    let users = state.store.delete_organization(&org.id).await?;
    gone(&state, Some(&session), &org, &users).await;
    tracing::info!(org = %org.id, user = %session.user.id, "organization deleted");
    Ok(StatusCode::OK)
}

async fn leave(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let Some((org, member)) = state.store.org_membership(&id, &session.user.id).await? else {
        return Err(not_found());
    };
    let (_, users) = state.store.remove_member(&org.id, &member.id).await?.map_err(|refusal| match refusal {
        OrgRefusal::LastOwner => {
            ApiError::bad("You are the last owner. Make somebody else an owner first, or delete it.")
        }
        other => refused(other),
    })?;
    tell(&state, Some(&session), &users, Kind::OrgKeys);
    Ok(StatusCode::OK)
}

async fn keys(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let (org, _) = as_member(&state, &session, &id).await?;
    Ok(Json(json!({
        "object": "organizationKeys",
        "publicKey": org.public_key,
        "privateKey": org.private_key,
    })))
}

async fn public_key(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let (org, _) = as_member(&state, &session, &id).await?;
    Ok(Json(json!({ "object": "organizationPublicKey", "publicKey": org.public_key })))
}

// ── Invitations to the account, in the web vault ──────────

/// The organisations that invited the account's address, for accepting without the mail's link.
async fn invitations(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let list = state.store.org_invitations_for(&session.user.email).await?;
    Ok(Json(out::list(
        list.iter()
            .map(|(org, member)| {
                json!({
                    "object": "organizationInvitation",
                    "id": member.id,
                    "organizationId": org.id,
                    "organizationName": org.name,
                    "family": org.is_family(),
                    "type": member.kind,
                    "creationDate": member.created,
                })
            })
            .collect(),
    )))
}

/// Turn an invitation to the account's address down.
async fn decline(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let list = state.store.org_invitations_for(&session.user.email).await?;
    let Some((org, member)) = list.into_iter().find(|(_, member)| member.id == id && member.status == INVITED) else {
        return Err(ApiError::not_found("There is no such invitation for you."));
    };
    state.store.remove_member(&org.id, &member.id).await?.map_err(refused)?;
    Ok(StatusCode::OK)
}

/// What `GET /uwu/v1/account` says about families.
pub(crate) async fn account_info(state: &AppState, session: &Session) -> ApiResult<Value> {
    let settings = state.settings().families;
    let owned = state.store.owned_organizations(&session.user.id, FAMILY).await?;
    Ok(json!({
        "mayCreate": settings.may_create(session.user.admin) && owned < i64::from(settings.per_user),
        "maxMembers": settings.max_members,
        "owned": owned,
        "perUser": settings.per_user,
    }))
}

// ── The admin portal ──────────────────────────────────────

async fn admin_list(State(state): State<AppState>, _admin: Admin) -> ApiResult<Json<Value>> {
    let list = state.store.organization_summaries().await?;
    Ok(Json(json!(
        list.iter()
            .map(|summary| {
                json!({
                    "id": summary.organization.id,
                    "name": summary.organization.name,
                    "kind": if summary.organization.is_family() { "family" } else { "organization" },
                    "members": summary.members,
                    "owners": summary.owners,
                    "secretsManager": false,
                    "creationDate": summary.organization.created,
                })
            })
            .collect::<Vec<_>>()
    )))
}

async fn admin_delete(
    State(state): State<AppState>,
    admin: Admin,
    Path(id): Path<String>,
    body: Option<Json<Secret>>,
) -> ApiResult<StatusCode> {
    let hash = body.and_then(|Json(data)| data.master_password_hash);
    crate::accounts::check_password(&state, &admin.0.user, hash.as_deref()).await?;
    let org = state.store.organization(&id).await?.ok_or_else(not_found)?;
    let users = state.store.delete_organization(&org.id).await?;
    gone(&state, None, &org, &users).await;
    record(&state, &admin, format!("deleted the organization {}", org.name)).await;
    Ok(StatusCode::OK)
}

#[cfg(test)]
#[path = "families/tests.rs"]
mod tests;
