//! WorkOS AuthKit integration for browser sessions and CLI device login.
//!
//! Browser sessions use separate encrypted, HttpOnly cookies for the user and
//! administrator sites. The CLI sends short-lived WorkOS access JWTs, which
//! are verified against WorkOS JWKS on every API request. Every Personal or
//! Organization Account maps to one WorkOS Organization and may own multiple
//! Cats workspaces; organization scope and immutable local IDs are both
//! checked before resource access.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use workos::enums::UserOrganizationMembershipStatus;
use workos::helpers::{
    seal, seal_session, unseal, AuthKitAuthorizationUrlParams, AuthKitPkceCodeExchangeParams,
    SessionData, SessionManager, SessionRefreshOptions, SessionState,
};
use workos::models::{CreateUserInviteOptions, OrganizationInput, RevokeSession};
use workos::resources::organization_membership::{
    CreateOrganizationMembershipParams, CreateOrganizationMembershipParamsBody,
    ListOrganizationMembershipsParams, Role, UpdateOrganizationMembershipParams,
    UpdateOrganizationMembershipParamsBody,
};
use workos::resources::organizations::CreateOrganizationParams;
use workos::resources::user_management::{
    ListInvitationsParams, RevokeSessionParams, SendInvitationParams,
};
use workos::RequestOptions;

use cats_api::auth::{
    Account, AccountInvitation, AccountMember, CliAuthConfigResponse, MeResponse, UserProfile,
    Workspace,
};
use cats_api::error::{ApiError, ErrorCode};

use crate::api::Failure;
use crate::server::AppState;

const USER_SESSION_COOKIE: &str = "cats_user_session";
const USER_CONTEXT_COOKIE: &str = "cats_user_context";
const ADMIN_SESSION_COOKIE: &str = "cats_admin_session";
const USER_FLOW_COOKIE: &str = "cats_user_auth_flow";
const ADMIN_FLOW_COOKIE: &str = "cats_admin_auth_flow";
const SESSION_MAX_AGE_SECONDS: u64 = 30 * 24 * 60 * 60;
const FLOW_MAX_AGE_SECONDS: u64 = 10 * 60;
const FLOW_MAX_AGE_UNIX_SECONDS: i64 = 10 * 60;
const SIGNUP_CAMPAIGN: &str = "signup-2026-10usd";
const SIGNUP_CREDIT_NANOS: i128 = 10_000_000_000;

#[derive(Clone)]
pub struct WorkOsConfig {
    client: workos::Client,
    client_id: String,
    api_base_url: String,
    issuer_url: String,
    jwks: Arc<workos::helpers::JwksHelper>,
    redirect_uri: String,
    cookie_password: String,
    account_organizations: BTreeMap<String, String>,
    admin_organization_id: String,
    admin_permission: String,
    cookie_secure: bool,
    cookie_domain: Option<String>,
    user_site_url: String,
    admin_site_url: String,
    browser_session_heads: Arc<tokio::sync::Mutex<BTreeMap<String, String>>>,
}

pub struct WorkOsConfigParams {
    pub client_id: String,
    pub api_key: String,
    pub api_base_url: String,
    /// Exact `iss` claim published in this WorkOS application's access tokens.
    pub issuer_url: String,
    pub redirect_uri: String,
    pub cookie_password: String,
    /// Cats Account slug -> WorkOS Organization ID.
    pub account_organizations: BTreeMap<String, String>,
    pub admin_organization_id: String,
    pub admin_permission: String,
    pub cookie_secure: bool,
    /// Optional parent domain used when user/admin sites are on subdomains.
    pub cookie_domain: Option<String>,
    /// Login completion destinations. Relative paths preserve local-dev behavior.
    pub user_site_url: Option<String>,
    pub admin_site_url: Option<String>,
}

impl WorkOsConfig {
    pub fn new(params: WorkOsConfigParams) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !params.client_id.is_empty(),
            "WorkOS client ID must not be empty"
        );
        anyhow::ensure!(
            !params.api_key.is_empty(),
            "WorkOS API key must not be empty"
        );
        anyhow::ensure!(
            !params.admin_organization_id.is_empty(),
            "WorkOS admin organization ID must not be empty"
        );
        anyhow::ensure!(
            !params.admin_permission.is_empty(),
            "WorkOS admin permission must not be empty"
        );
        for (account, organization_id) in &params.account_organizations {
            anyhow::ensure!(!account.is_empty(), "Cats account slug must not be empty");
            anyhow::ensure!(
                !organization_id.is_empty(),
                "WorkOS organization ID must not be empty"
            );
        }
        // Exercise the SDK's password validation at startup rather than on
        // the first user login. The sealed value is immediately discarded.
        seal(&"cats-cookie-password-check", &params.cookie_password)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;

        let redirect = reqwest::Url::parse(&params.redirect_uri)
            .map_err(|error| anyhow::anyhow!("invalid WorkOS redirect URI: {error}"))?;
        anyhow::ensure!(
            matches!(redirect.scheme(), "http" | "https"),
            "WorkOS redirect URI must use http or https"
        );
        let issuer = reqwest::Url::parse(&params.issuer_url)
            .map_err(|error| anyhow::anyhow!("invalid WorkOS issuer URL: {error}"))?;
        anyhow::ensure!(
            matches!(issuer.scheme(), "http" | "https")
                && issuer.host_str().is_some()
                && issuer.query().is_none()
                && issuer.fragment().is_none(),
            "WorkOS issuer must be an absolute http(s) URL without a query or fragment"
        );
        if let Some(domain) = &params.cookie_domain {
            anyhow::ensure!(
                !domain.is_empty()
                    && !domain.starts_with('.')
                    && !domain
                        .chars()
                        .any(|ch| ch.is_whitespace() || ch == ';' || ch == '/'),
                "WorkOS cookie domain must be a bare DNS name"
            );
        }
        let user_site_url = params.user_site_url.unwrap_or_else(|| "/user/".into());
        let admin_site_url = params.admin_site_url.unwrap_or_else(|| "/admin/".into());
        validate_site_url(&user_site_url, "user")?;
        validate_site_url(&admin_site_url, "admin")?;

        let client_id = params.client_id.clone();
        let api_base_url = params.api_base_url.trim_end_matches('/').to_string();
        let issuer_url = params.issuer_url;
        let client = workos::Client::builder()
            .client_id(&client_id)
            .api_key(params.api_key)
            .base_url(&api_base_url)
            .try_build()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let jwks = Arc::new(client.jwks());
        Ok(Self {
            client,
            client_id,
            api_base_url,
            issuer_url,
            jwks,
            redirect_uri: params.redirect_uri,
            cookie_password: params.cookie_password,
            account_organizations: params.account_organizations,
            admin_organization_id: params.admin_organization_id,
            admin_permission: params.admin_permission,
            cookie_secure: params.cookie_secure,
            cookie_domain: params.cookie_domain,
            user_site_url,
            admin_site_url,
            browser_session_heads: Arc::new(tokio::sync::Mutex::new(BTreeMap::new())),
        })
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn api_base_url(&self) -> &str {
        &self.api_base_url
    }

    pub fn account_organizations(&self) -> &BTreeMap<String, String> {
        &self.account_organizations
    }

    async fn ensure_personal_organization(
        &self,
        user_id: &str,
        display_name: &str,
    ) -> Result<String, ApiError> {
        let external_id = format!("cats-personal:{user_id}");
        let organization = match self
            .client
            .organizations()
            .get_organization_by_external_id(&external_id)
            .await
        {
            Ok(organization) => organization,
            Err(error) if error.is_not_found() => self
                .client
                .organizations()
                .create_organization(CreateOrganizationParams::new(OrganizationInput {
                    name: format!("{display_name}'s Personal Account"),
                    allow_profiles_outside_organization: Some(false),
                    domains: None,
                    domain_data: None,
                    metadata: Some(std::collections::HashMap::from([(
                        "cats_account_kind".to_string(),
                        "personal".to_string(),
                    )])),
                    external_id: Some(external_id),
                }))
                .await
                .map_err(|error| {
                    tracing::warn!(error = %error, user_id, "WorkOS personal organization create failed");
                    ApiError::unavailable(
                        "personal account provisioning is temporarily unavailable",
                    )
                })?,
            Err(error) => {
                tracing::warn!(error = %error, user_id, "WorkOS personal organization lookup failed");
                return Err(ApiError::unavailable(
                    "personal account provisioning is temporarily unavailable",
                ));
            }
        };
        if !self
            .user_has_active_membership(user_id, &organization.id)
            .await?
        {
            let mut body =
                CreateOrganizationMembershipParamsBody::new(user_id, organization.id.clone());
            body.role = Some(Role::Single {
                role_slug: "admin".to_string(),
            });
            self.client
                .organization_membership()
                .create_organization_membership(CreateOrganizationMembershipParams::new(body))
                .await
                .map_err(|error| {
                    tracing::warn!(
                        error = %error,
                        user_id,
                        organization_id = organization.id,
                        "WorkOS personal owner membership create failed"
                    );
                    ApiError::unavailable(
                        "personal account provisioning is temporarily unavailable",
                    )
                })?;
        }
        Ok(organization.id)
    }

    pub async fn user_has_active_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<bool, ApiError> {
        let page = self
            .client
            .organization_membership()
            .list_organization_memberships(ListOrganizationMembershipsParams {
                organization_id: Some(organization_id.to_string()),
                user_id: Some(user_id.to_string()),
                limit: Some(100),
                ..Default::default()
            })
            .await
            .map_err(|error| {
                tracing::warn!(
                    error = %error,
                    user_id,
                    organization_id,
                    "WorkOS membership authorization lookup failed"
                );
                ApiError::unavailable("WorkOS membership is temporarily unavailable")
            })?;
        Ok(page.data.into_iter().any(|membership| {
            membership.organization_id == organization_id
                && membership.user_id == user_id
                && membership.status == UserOrganizationMembershipStatus::Active
        }))
    }

    pub async fn send_account_invitation(
        &self,
        account: &crate::store::AccountRecord,
        inviter_user_id: &str,
        email: &str,
        role_slug: &str,
        idempotency_key: &str,
    ) -> Result<AccountInvitation, ApiError> {
        let options = RequestOptions::new().idempotency_key(idempotency_key);
        let invitation = self
            .client
            .user_management()
            .send_invitation_with_options(
                SendInvitationParams::new(CreateUserInviteOptions {
                    email: email.to_string(),
                    organization_id: Some(account.workos_organization_id.clone()),
                    role_slug: Some(role_slug.to_string()),
                    expires_in_days: Some(7),
                    inviter_user_id: Some(inviter_user_id.to_string()),
                    locale: None,
                }),
                Some(&options),
            )
            .await
            .map_err(|error| {
                tracing::warn!(
                    error = %error,
                    account_id = account.id,
                    "WorkOS invitation create failed"
                );
                ApiError::unavailable("WorkOS invitation is temporarily unavailable")
            })?;
        Ok(AccountInvitation {
            id: invitation.id,
            account_id: account.id.clone(),
            email: invitation.email,
            role_slug: invitation
                .role_slug
                .unwrap_or_else(|| role_slug.to_string()),
            state: invitation.state.to_string(),
            expires_at: invitation.expires_at,
        })
    }

    pub async fn list_account_invitations(
        &self,
        account: &crate::store::AccountRecord,
    ) -> Result<Vec<AccountInvitation>, ApiError> {
        let mut result = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .client
                .user_management()
                .list_invitations(ListInvitationsParams {
                    organization_id: Some(account.workos_organization_id.clone()),
                    after: after.clone(),
                    limit: Some(100),
                    ..Default::default()
                })
                .await
                .map_err(|error| {
                    tracing::warn!(
                        error = %error,
                        account_id = account.id,
                        "WorkOS invitation list failed"
                    );
                    ApiError::unavailable("WorkOS invitations are temporarily unavailable")
                })?;
            result.extend(page.data.into_iter().map(|invitation| AccountInvitation {
                id: invitation.id,
                account_id: account.id.clone(),
                email: invitation.email,
                role_slug: invitation.role_slug.unwrap_or_else(|| "member".to_string()),
                state: invitation.state.to_string(),
                expires_at: invitation.expires_at,
            }));
            after = page.list_metadata.after;
            if after.is_none() {
                break;
            }
        }
        Ok(result)
    }

    pub async fn revoke_account_invitation(
        &self,
        account: &crate::store::AccountRecord,
        invitation_id: &str,
    ) -> Result<AccountInvitation, ApiError> {
        let invitation = self
            .client
            .user_management()
            .revoke_invitation(invitation_id)
            .await
            .map_err(|error| {
                tracing::warn!(
                    error = %error,
                    account_id = account.id,
                    invitation_id,
                    "WorkOS invitation revoke failed"
                );
                if error.is_not_found() {
                    ApiError::new(ErrorCode::NotFound, "invitation not found")
                } else {
                    ApiError::unavailable("WorkOS invitation is temporarily unavailable")
                }
            })?;
        if invitation.organization_id.as_deref() != Some(account.workos_organization_id.as_str()) {
            return Err(ApiError::new(
                ErrorCode::PermissionDenied,
                "invitation belongs to another account",
            ));
        }
        Ok(AccountInvitation {
            id: invitation.id,
            account_id: account.id.clone(),
            email: invitation.email,
            role_slug: invitation.role_slug.unwrap_or_else(|| "member".to_string()),
            state: invitation.state.to_string(),
            expires_at: invitation.expires_at,
        })
    }

    pub async fn list_account_members(
        &self,
        account: &crate::store::AccountRecord,
    ) -> Result<Vec<AccountMember>, ApiError> {
        let mut result = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .client
                .organization_membership()
                .list_organization_memberships(ListOrganizationMembershipsParams {
                    organization_id: Some(account.workos_organization_id.clone()),
                    after: after.clone(),
                    limit: Some(100),
                    ..Default::default()
                })
                .await
                .map_err(|error| {
                    tracing::warn!(
                        error = %error,
                        account_id = account.id,
                        "WorkOS member list failed"
                    );
                    ApiError::unavailable("WorkOS members are temporarily unavailable")
                })?;
            result.extend(page.data.into_iter().map(|membership| AccountMember {
                membership_id: membership.id,
                account_id: account.id.clone(),
                user: workos_user_profile(membership.user),
                role_slug: membership.role.slug,
                status: membership.status.to_string(),
            }));
            after = page.list_metadata.after;
            if after.is_none() {
                break;
            }
        }
        Ok(result)
    }

    pub async fn update_account_member(
        &self,
        account: &crate::store::AccountRecord,
        membership_id: &str,
        role_slug: &str,
    ) -> Result<AccountMember, ApiError> {
        let current = self
            .client
            .organization_membership()
            .get_organization_membership(membership_id)
            .await
            .map_err(workos_membership_error)?;
        if current.organization_id != account.workos_organization_id {
            return Err(ApiError::new(
                ErrorCode::PermissionDenied,
                "membership belongs to another account",
            ));
        }
        let mut body = UpdateOrganizationMembershipParamsBody::new();
        body.role = Some(Role::Single {
            role_slug: role_slug.to_string(),
        });
        let membership = self
            .client
            .organization_membership()
            .update_organization_membership(
                membership_id,
                UpdateOrganizationMembershipParams::new(body),
            )
            .await
            .map_err(workos_membership_error)?;
        Ok(AccountMember {
            membership_id: membership.id,
            account_id: account.id.clone(),
            user: workos_user_profile(membership.user),
            role_slug: membership.role.slug,
            status: membership.status.to_string(),
        })
    }

    pub async fn deactivate_account_member(
        &self,
        account: &crate::store::AccountRecord,
        membership_id: &str,
    ) -> Result<(), ApiError> {
        let current = self
            .client
            .organization_membership()
            .get_organization_membership(membership_id)
            .await
            .map_err(workos_membership_error)?;
        if current.organization_id != account.workos_organization_id {
            return Err(ApiError::new(
                ErrorCode::PermissionDenied,
                "membership belongs to another account",
            ));
        }
        self.client
            .organization_membership()
            .deactivate_organization_membership(membership_id)
            .await
            .map_err(workos_membership_error)?;
        Ok(())
    }

    /// Verify a CLI bearer token cryptographically and turn its organization
    /// scope into the Cats Account that owns it. A valid token for an unmapped
    /// organization remains authenticated but has no workspace access.
    pub async fn verify_access_token(&self, token: &str) -> Result<AccessIdentity, ApiError> {
        let header = decode_header(token)
            .map_err(|_| ApiError::unauthenticated("invalid WorkOS access token"))?;
        if header.alg != Algorithm::RS256 {
            return Err(ApiError::unauthenticated(
                "unsupported WorkOS access token algorithm",
            ));
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| ApiError::unauthenticated("WorkOS access token has no key ID"))?;
        let keys = self.jwks.fetch().await.map_err(|error| {
            tracing::warn!(error = %error, "WorkOS JWKS fetch failed");
            ApiError::unavailable("WorkOS signing keys are temporarily unavailable")
        })?;
        let jwk = keys
            .keys
            .iter()
            .find(|key| key.kid.as_deref() == Some(kid))
            .ok_or_else(|| ApiError::unauthenticated("unknown WorkOS signing key"))?;
        if jwk.kty.as_deref() != Some("RSA") || jwk.alg.as_deref() != Some("RS256") {
            return Err(ApiError::unauthenticated("invalid WorkOS signing key"));
        }
        let modulus = jwk
            .other
            .get("n")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ApiError::unauthenticated("invalid WorkOS RSA key"))?;
        let exponent = jwk
            .other
            .get("e")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ApiError::unauthenticated("invalid WorkOS RSA key"))?;
        let key = DecodingKey::from_rsa_components(modulus, exponent)
            .map_err(|_| ApiError::unauthenticated("invalid WorkOS RSA key"))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        validation.set_issuer(&[self.issuer_url.as_str()]);
        let claims = decode::<AccessTokenClaims>(token, &key, &validation)
            .map_err(|error| {
                tracing::warn!(
                    error = %error,
                    kid,
                    "WorkOS access token validation failed"
                );
                ApiError::unauthenticated("invalid or expired WorkOS access token")
            })?
            .claims;
        if claims.client_id != self.client_id || claims.sub.is_empty() || claims.sid.is_empty() {
            return Err(ApiError::unauthenticated(
                "WorkOS access token belongs to another application",
            ));
        }
        let organization_id = claims.org_id.filter(|value| !value.is_empty());
        Ok(AccessIdentity {
            user_id: claims.sub,
            session_id: claims.sid,
            organization_id,
            role: claims.role,
            permissions: claims.permissions,
        })
    }

    pub async fn me(
        &self,
        store: &crate::store::Store,
        identity: &AccessIdentity,
    ) -> Result<MeResponse, ApiError> {
        let user = self
            .client
            .user_management()
            .get_user(&identity.user_id)
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "WorkOS user lookup failed");
                ApiError::unavailable("WorkOS user profile is temporarily unavailable")
            })?;
        let (accounts, workspaces) = self.accounts_and_workspaces_for(store, identity).await?;
        Ok(MeResponse {
            user: UserProfile {
                id: user.id,
                email: user.email,
                name: user.name.or_else(|| {
                    let joined = [user.first_name, user.last_name]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join(" ");
                    (!joined.is_empty()).then_some(joined)
                }),
            },
            accounts,
            workspaces,
        })
    }

    pub async fn workspaces_for(
        &self,
        store: &crate::store::Store,
        identity: &AccessIdentity,
    ) -> Result<Vec<Workspace>, ApiError> {
        self.accounts_and_workspaces_for(store, identity)
            .await
            .map(|(_, workspaces)| workspaces)
    }

    pub async fn accounts_and_workspaces_for(
        &self,
        store: &crate::store::Store,
        identity: &AccessIdentity,
    ) -> Result<(Vec<Account>, Vec<Workspace>), ApiError> {
        let mut accounts = Vec::new();
        let mut workspaces = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .client
                .organization_membership()
                .list_organization_memberships(ListOrganizationMembershipsParams {
                    after: after.clone(),
                    limit: Some(100),
                    user_id: Some(identity.user_id.clone()),
                    ..Default::default()
                })
                .await
                .map_err(|error| {
                    tracing::warn!(error = %error, "WorkOS organization membership lookup failed");
                    ApiError::unavailable(
                        "WorkOS workspace memberships are temporarily unavailable",
                    )
                })?;
            for membership in page.data {
                if membership.status != UserOrganizationMembershipStatus::Active {
                    continue;
                }
                if membership.user_id != identity.user_id {
                    tracing::warn!(
                        expected_user_id = identity.user_id,
                        actual_user_id = membership.user_id,
                        "WorkOS membership list returned another user"
                    );
                    continue;
                }
                let permissions = if identity.organization_id.as_deref()
                    == Some(membership.organization_id.as_str())
                {
                    identity.permissions.as_slice()
                } else {
                    &[]
                };
                let Some((account, mut account_workspaces)) = store.account_and_workspace_views(
                    &membership.organization_id,
                    Some(&membership.role.slug),
                    permissions,
                )?
                else {
                    continue;
                };
                store.upsert_membership_shadow(
                    &membership.id,
                    &account.id,
                    &membership.user_id,
                    &membership.role.slug,
                    "active",
                )?;
                accounts.push(account);
                workspaces.append(&mut account_workspaces);
            }
            after = page.list_metadata.after;
            if after.is_none() {
                break;
            }
        }
        accounts.sort_by(|left, right| left.slug.cmp(&right.slug));
        accounts.dedup_by(|left, right| left.id == right.id);
        workspaces.sort_by(|left, right| left.locator.cmp(&right.locator));
        workspaces.dedup_by(|left, right| left.id == right.id);
        Ok((accounts, workspaces))
    }

    async fn single_mapped_workspace_for_user(
        &self,
        store: &crate::store::Store,
        user_id: &str,
    ) -> Result<Option<(String, String)>, ApiError> {
        let mut candidates = BTreeMap::new();
        let mut after = None;
        loop {
            let page = self
                .client
                .organization_membership()
                .list_organization_memberships(ListOrganizationMembershipsParams {
                    after: after.clone(),
                    limit: Some(100),
                    user_id: Some(user_id.to_string()),
                    ..Default::default()
                })
                .await
                .map_err(|error| {
                    tracing::warn!(error = %error, "WorkOS organization membership lookup failed");
                    ApiError::unavailable(
                        "WorkOS workspace memberships are temporarily unavailable",
                    )
                })?;
            for membership in page.data {
                if membership.status != UserOrganizationMembershipStatus::Active {
                    continue;
                }
                if membership.user_id != user_id {
                    continue;
                }
                let Some(account) = store.account_for_organization(&membership.organization_id)?
                else {
                    continue;
                };
                if account.status != "active" {
                    continue;
                }
                let Some(workspace) = store
                    .workspaces_for_account(&account.id)?
                    .into_iter()
                    .find(|workspace| workspace.is_default)
                else {
                    continue;
                };
                candidates.insert(workspace.id, membership.organization_id);
            }
            after = page.list_metadata.after;
            if after.is_none() {
                break;
            }
        }
        if candidates.len() != 1 {
            return Ok(None);
        }
        Ok(candidates.into_iter().next())
    }

    pub async fn revoke_cli_session(&self, identity: &AccessIdentity) -> Result<(), ApiError> {
        let params = RevokeSessionParams::new(RevokeSession {
            session_id: identity.session_id.clone(),
        });
        self.client
            .user_management()
            .revoke_session(params)
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "WorkOS CLI session revocation failed");
                ApiError::unavailable("WorkOS session could not be revoked")
            })?;
        Ok(())
    }

    pub fn is_fleet_administrator(&self, identity: &AccessIdentity) -> bool {
        identity.organization_id.as_deref() == Some(self.admin_organization_id.as_str())
            && identity
                .permissions
                .iter()
                .any(|permission| permission == &self.admin_permission)
    }

    fn site_url(&self, site: Site) -> &str {
        match site {
            Site::User => &self.user_site_url,
            Site::Admin => &self.admin_site_url,
        }
    }
}

fn workos_membership_error(error: workos::Error) -> ApiError {
    tracing::warn!(error = %error, "WorkOS membership operation failed");
    if error.is_not_found() {
        ApiError::new(ErrorCode::NotFound, "membership not found")
    } else {
        ApiError::unavailable("WorkOS membership is temporarily unavailable")
    }
}

fn workos_user_profile(user: workos::User) -> UserProfile {
    UserProfile {
        id: user.id,
        email: user.email,
        name: user.name.or_else(|| {
            let joined = [user.first_name, user.last_name]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            (!joined.is_empty()).then_some(joined)
        }),
    }
}

#[derive(Debug, Clone)]
pub struct AccessIdentity {
    pub user_id: String,
    pub session_id: String,
    pub organization_id: Option<String>,
    pub role: Option<String>,
    pub permissions: Vec<String>,
}

pub async fn provision_personal_account(
    state: &AppState,
    user_id: &str,
    display_name: &str,
) -> Result<crate::store::AccountRecord, ApiError> {
    let config = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let organization_id = config
        .ensure_personal_organization(user_id, display_name)
        .await?;
    let (account, _workspace) =
        state
            .store
            .ensure_personal_account(user_id, &organization_id, display_name)?;
    let grant_state =
        state
            .store
            .signup_grant_state(user_id, SIGNUP_CAMPAIGN, &account.billing_account_id)?;
    if grant_state == crate::store::SignupGrantState::Pending {
        state
            .credits
            .ensure_account(
                &account.billing_account_id,
                &account.id,
                "USD",
                SIGNUP_CREDIT_NANOS,
                crate::store::now_ms(),
            )
            .await
            .map_err(|error| {
                tracing::warn!(
                    error = %error,
                    user_id,
                    billing_account_id = account.billing_account_id,
                    "personal signup grant failed"
                );
                ApiError::unavailable("personal account credit is temporarily unavailable")
            })?;
        state.store.mark_signup_grant_applied(
            user_id,
            SIGNUP_CAMPAIGN,
            &account.billing_account_id,
        )?;
    }
    state.store.activate_account(&account.id)?;
    state.store.account_by_id(&account.id)
}

#[derive(Debug, Deserialize)]
struct AccessTokenClaims {
    sub: String,
    sid: String,
    client_id: String,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(rename = "exp")]
    _expires_at: u64,
    #[serde(rename = "iss")]
    _issuer: String,
}

fn validate_site_url(value: &str, site: &str) -> anyhow::Result<()> {
    if value.starts_with('/') && !value.starts_with("//") {
        return Ok(());
    }
    let url = reqwest::Url::parse(value)
        .map_err(|error| anyhow::anyhow!("invalid {site} site URL: {error}"))?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.has_host()
            && url.query().is_none()
            && url.fragment().is_none(),
        "{site} site URL must be an absolute HTTP(S) URL without query or fragment"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Site {
    User,
    Admin,
}

impl Site {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    fn root(self) -> &'static str {
        match self {
            Self::User => "/user/",
            Self::Admin => "/admin/",
        }
    }

    fn session_cookie(self) -> &'static str {
        match self {
            Self::User => USER_SESSION_COOKIE,
            Self::Admin => ADMIN_SESSION_COOKIE,
        }
    }

    fn flow_cookie(self) -> &'static str {
        match self {
            Self::User => USER_FLOW_COOKIE,
            Self::Admin => ADMIN_FLOW_COOKIE,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WebIdentity {
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub account_id: Option<String>,
    pub default_workspace_id: Option<String>,
    pub administrator: bool,
    pub permissions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginFlow {
    state: String,
    code_verifier: String,
    site: Site,
    organization_id: Option<String>,
    workspace_id: Option<String>,
    return_to: String,
    created_at_unix: i64,
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    site: String,
    #[serde(default)]
    workspace: Option<String>,
    #[serde(default)]
    return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SiteQuery {
    site: String,
}

#[derive(Debug, Serialize)]
struct SessionUser {
    id: String,
    email: String,
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    authenticated: bool,
    site: Site,
    active_account_id: Option<String>,
    active_workspace_id: Option<String>,
    accounts: Vec<Account>,
    workspaces: Vec<Workspace>,
    role: String,
    permissions: Vec<String>,
    user: Option<SessionUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserContext {
    user_id: String,
    account_id: String,
    workspace_id: String,
}

#[derive(Debug, Deserialize)]
pub struct SwitchWorkspaceRequest {
    workspace_id: String,
}

pub async fn config(State(state): State<AppState>) -> Response {
    let mut response = Json(CliAuthConfigResponse {
        workos_enabled: state.cfg.workos.is_some(),
        workos_client_id: state
            .cfg
            .workos
            .as_ref()
            .map(|config| config.client_id().to_string()),
        workos_api_base_url: state
            .cfg
            .workos
            .as_ref()
            .map(|config| config.api_base_url().to_string()),
    })
    .into_response();
    set_no_store(&mut response);
    response
}

pub async fn login(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, Failure> {
    let config = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let site = Site::parse(&query.site).ok_or_else(|| ApiError::invalid("unknown auth site"))?;
    let (organization_id, workspace_id) = match site {
        Site::User => {
            if let Some(workspace_id) = query.workspace.as_deref() {
                let scope = state.store.workspace_scope(workspace_id)?;
                (
                    Some(scope.account.workos_organization_id),
                    Some(workspace_id.to_string()),
                )
            } else {
                // The public user site does not know which workspace a user
                // owns before authentication. Resolve it from the returned
                // WorkOS identity.
                (None, None)
            }
        }
        Site::Admin => (Some(config.admin_organization_id.clone()), None),
    };
    let return_to = query
        .return_to
        .as_deref()
        .filter(|value| *value == site.root() || *value == config.site_url(site))
        .map(str::to_string)
        .unwrap_or_else(|| config.site_url(site).to_string());
    let authorization = config
        .client
        .authkit()
        .pkce_authorization_url(AuthKitAuthorizationUrlParams {
            redirect_uri: config.redirect_uri.clone(),
            provider: Some("authkit".to_string()),
            organization_id: organization_id.clone(),
            ..Default::default()
        })
        .map_err(|error| ApiError::internal(format!("build WorkOS authorization URL: {error}")))?;
    let flow = LoginFlow {
        state: authorization.state,
        code_verifier: authorization.code_verifier,
        site,
        organization_id,
        workspace_id,
        return_to,
        created_at_unix: crate::store::now_unix(),
    };
    let sealed = seal(&flow, &config.cookie_password)
        .map_err(|error| ApiError::internal(format!("seal WorkOS login state: {error}")))?;
    let mut response = Redirect::to(&authorization.url).into_response();
    append_set_cookie(
        &mut response,
        site.flow_cookie(),
        &sealed,
        FLOW_MAX_AGE_SECONDS,
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    set_no_store(&mut response);
    Ok(response)
}

pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, Failure> {
    let config = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let returned_state = query
        .state
        .ok_or_else(|| ApiError::invalid("missing WorkOS state"))?;
    let flow = [Site::User, Site::Admin]
        .into_iter()
        .filter_map(|site| {
            cookie_value(&headers, site.flow_cookie()).and_then(|sealed| {
                unseal::<LoginFlow>(&sealed, &config.cookie_password)
                    .ok()
                    .filter(|flow| flow.site == site && flow.state == returned_state)
            })
        })
        .next()
        .ok_or_else(|| {
            ApiError::new(
                cats_api::error::ErrorCode::Unauthenticated,
                "invalid or expired WorkOS login state",
            )
        })?;
    if crate::store::now_unix() - flow.created_at_unix > FLOW_MAX_AGE_UNIX_SECONDS {
        return Err(ApiError::new(
            cats_api::error::ErrorCode::Unauthenticated,
            "WorkOS login state expired",
        )
        .into());
    }
    if let Some(error) = query.error {
        tracing::warn!(site = ?flow.site, error, "WorkOS authentication was not completed");
        return auth_error_redirect(config, &flow, "authentication_failed");
    }
    let code = query
        .code
        .ok_or_else(|| ApiError::invalid("missing WorkOS authorization code"))?;

    let auth = config
        .client
        .authkit()
        .pkce_code_exchange(AuthKitPkceCodeExchangeParams {
            code,
            code_verifier: flow.code_verifier.clone(),
        })
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "WorkOS authorization-code exchange failed");
            ApiError::new(
                cats_api::error::ErrorCode::Unauthenticated,
                "WorkOS authentication failed",
            )
        })?;
    if flow
        .organization_id
        .as_deref()
        .is_some_and(|expected| auth.organization_id.as_deref() != Some(expected))
    {
        tracing::warn!(
            site = ?flow.site,
            "WorkOS session organization does not match the requested scope"
        );
        return auth_error_redirect(config, &flow, identity_error_code(flow.site));
    }
    let personal_scope = if flow.site == Site::User && auth.organization_id.is_none() {
        let display_name = auth
            .user
            .name
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(&auth.user.email);
        Some(
            provision_personal_account(&state, &auth.user.id, display_name)
                .await?
                .workos_organization_id,
        )
    } else {
        None
    };
    let sealed_session = seal_session(
        &SessionData {
            access_token: auth.access_token,
            refresh_token: auth.refresh_token,
            user: Some(auth.user),
            impersonator: auth.impersonator,
        },
        &config.cookie_password,
    )
    .map_err(|error| ApiError::internal(format!("seal WorkOS session: {error}")))?;
    let session =
        SessionManager::new(None, &sealed_session, &config.cookie_password).authenticate();
    let (sealed_session, session) = if let Some(organization_id) = personal_scope {
        scope_session_to_organization(
            config,
            sealed_session,
            session,
            &organization_id,
            "personal account",
        )
        .await?
    } else {
        scope_unmapped_user_session(config, &state.store, &flow, sealed_session, session).await
    };
    let identity = match validate_flow_identity(config, &state.store, &flow, &session) {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(
                site = ?flow.site,
                error = %error.0,
                "WorkOS session is not authorized for the requested site"
            );
            return auth_error_redirect(config, &flow, identity_error_code(flow.site));
        }
    };

    let mut response = Redirect::to(&flow.return_to).into_response();
    append_set_cookie(
        &mut response,
        flow.site.session_cookie(),
        &sealed_session,
        SESSION_MAX_AGE_SECONDS,
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    if flow.site == Site::User {
        let workspace = if let Some(workspace_id) = flow.workspace_id.as_deref() {
            state.store.workspace_by_id(workspace_id)?
        } else {
            state.store.workspace_by_id(
                identity
                    .default_workspace_id
                    .as_deref()
                    .ok_or_else(|| ApiError::internal("user login selected no workspace"))?,
            )?
        };
        let user_id = identity
            .user_id
            .as_deref()
            .ok_or_else(|| ApiError::unauthenticated("WorkOS session has no user identity"))?;
        let context = seal(
            &UserContext {
                user_id: user_id.to_string(),
                account_id: workspace.account_id,
                workspace_id: workspace.id,
            },
            &config.cookie_password,
        )
        .map_err(|error| ApiError::internal(format!("seal workspace context: {error}")))?;
        append_set_cookie(
            &mut response,
            USER_CONTEXT_COOKIE,
            &context,
            SESSION_MAX_AGE_SECONDS,
            config.cookie_secure,
            config.cookie_domain.as_deref(),
        )?;
    }
    if !session.session_id.is_empty() {
        config
            .browser_session_heads
            .lock()
            .await
            .insert(session.session_id.clone(), sealed_session);
    }
    append_delete_cookie(
        &mut response,
        flow.site.flow_cookie(),
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    set_no_store(&mut response);
    Ok(response)
}

async fn scope_session_to_organization(
    config: &WorkOsConfig,
    sealed_session: String,
    session: SessionState,
    organization_id: &str,
    label: &str,
) -> Result<(String, SessionState), Failure> {
    let user_id = session
        .user
        .as_ref()
        .map(|user| user.id.clone())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::unauthenticated("WorkOS session has no user identity"))?;
    let manager = SessionManager::new(
        Some(&config.client),
        &sealed_session,
        &config.cookie_password,
    );
    let refreshed = manager
        .refresh(SessionRefreshOptions {
            organization_id: Some(organization_id.to_string()),
        })
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, organization_id, label, "WorkOS organization switch failed");
            ApiError::unavailable("WorkOS organization switch is temporarily unavailable")
        })?;
    if !refreshed.authenticated {
        return Err(ApiError::new(
            cats_api::error::ErrorCode::PermissionDenied,
            format!("WorkOS did not authorize {label}"),
        )
        .into());
    }
    let candidate = SessionManager::new(None, &refreshed.sealed_session, &config.cookie_password)
        .authenticate();
    if !candidate.authenticated
        || candidate.organization_id != organization_id
        || candidate.user.as_ref().map(|user| user.id.as_str()) != Some(user_id.as_str())
    {
        return Err(ApiError::new(
            cats_api::error::ErrorCode::PermissionDenied,
            format!("WorkOS returned an invalid {label} session"),
        )
        .into());
    }
    Ok((refreshed.sealed_session, candidate))
}

async fn scope_unmapped_user_session(
    config: &WorkOsConfig,
    store: &crate::store::Store,
    flow: &LoginFlow,
    sealed_session: String,
    session: SessionState,
) -> (String, SessionState) {
    let should_rescope = flow.site == Site::User
        && flow.organization_id.is_none()
        && flow.workspace_id.is_none()
        && session.authenticated
        && !session.organization_id.is_empty()
        && store
            .account_for_organization(&session.organization_id)
            .ok()
            .flatten()
            .is_none();
    if !should_rescope {
        return (sealed_session, session);
    }
    let Some(user_id) = session
        .user
        .as_ref()
        .map(|user| user.id.clone())
        .filter(|user_id| !user_id.is_empty())
    else {
        return (sealed_session, session);
    };
    let target = match config
        .single_mapped_workspace_for_user(store, &user_id)
        .await
    {
        Ok(Some(target)) => target,
        Ok(None) => return (sealed_session, session),
        Err(error) => {
            tracing::warn!(
                error = %error,
                "WorkOS user workspace resolution failed"
            );
            return (sealed_session, session);
        }
    };
    let (workspace_id, organization_id) = target;
    let manager = SessionManager::new(
        Some(&config.client),
        &sealed_session,
        &config.cookie_password,
    );
    let refreshed = match manager
        .refresh(SessionRefreshOptions {
            organization_id: Some(organization_id.clone()),
        })
        .await
    {
        Ok(refreshed) if refreshed.authenticated => refreshed,
        Ok(refreshed) => {
            tracing::warn!(
                reason = refreshed.reason,
                workspace_id,
                "WorkOS session could not switch to the user's Cats workspace"
            );
            return (sealed_session, session);
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                workspace_id,
                "WorkOS workspace session refresh failed"
            );
            return (sealed_session, session);
        }
    };
    let candidate = SessionManager::new(None, &refreshed.sealed_session, &config.cookie_password)
        .authenticate();
    let same_user = candidate.user.as_ref().map(|user| user.id.as_str()) == Some(user_id.as_str());
    if !candidate.authenticated
        || candidate.organization_id != organization_id
        || !same_user
        || !store
            .workspace_by_id(&workspace_id)
            .and_then(|workspace| store.account_by_id(&workspace.account_id))
            .is_ok_and(|account| account.workos_organization_id == candidate.organization_id)
    {
        tracing::warn!(
            workspace_id,
            "WorkOS returned an invalid workspace-scoped session"
        );
        return (sealed_session, session);
    }
    (refreshed.sealed_session, candidate)
}

fn identity_error_code(site: Site) -> &'static str {
    match site {
        Site::User => "workspace_access_required",
        Site::Admin => "admin_access_required",
    }
}

fn auth_error_redirect(
    config: &WorkOsConfig,
    flow: &LoginFlow,
    error_code: &str,
) -> Result<Response, Failure> {
    let separator = if flow.return_to.contains('?') {
        '&'
    } else {
        '?'
    };
    let location = format!("{}{separator}auth_error={error_code}", flow.return_to);
    let mut response = Redirect::to(&location).into_response();
    append_delete_cookie(
        &mut response,
        flow.site.flow_cookie(),
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    set_no_store(&mut response);
    Ok(response)
}

pub async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SiteQuery>,
) -> Result<Response, Failure> {
    let config = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let site = Site::parse(&query.site).ok_or_else(|| ApiError::invalid("unknown auth site"))?;
    let sealed = cookie_value(&headers, site.session_cookie()).unwrap_or_default();
    let manager = SessionManager::new(Some(&config.client), &sealed, &config.cookie_password);
    let mut session = manager.authenticate();
    let mut replacement_cookie = None;
    if session.needs_refresh {
        let refreshed = manager
            .refresh(SessionRefreshOptions::default())
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "WorkOS session refresh failed");
                ApiError::new(
                    cats_api::error::ErrorCode::Unauthenticated,
                    "WorkOS session expired",
                )
            })?;
        if refreshed.authenticated {
            replacement_cookie = Some(refreshed.sealed_session);
            session = SessionManager::new(
                None,
                replacement_cookie.as_deref().unwrap_or_default(),
                &config.cookie_password,
            )
            .authenticate();
        }
    }
    let (body, replacement_context) =
        session_response(&state, config, site, &session, &headers).await?;
    let mut response = Json(body).into_response();
    if let Some(sealed) = replacement_cookie {
        if !session.session_id.is_empty() {
            config
                .browser_session_heads
                .lock()
                .await
                .insert(session.session_id.clone(), sealed.clone());
        }
        append_set_cookie(
            &mut response,
            site.session_cookie(),
            &sealed,
            SESSION_MAX_AGE_SECONDS,
            config.cookie_secure,
            config.cookie_domain.as_deref(),
        )?;
    }
    if let Some(context) = replacement_context {
        append_set_cookie(
            &mut response,
            USER_CONTEXT_COOKIE,
            &context,
            SESSION_MAX_AGE_SECONDS,
            config.cookie_secure,
            config.cookie_domain.as_deref(),
        )?;
    }
    set_no_store(&mut response);
    Ok(response)
}

pub async fn switch_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SwitchWorkspaceRequest>,
) -> Result<Response, Failure> {
    let config = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let requested_sealed = cookie_value(&headers, USER_SESSION_COOKIE)
        .ok_or_else(|| ApiError::unauthenticated("missing WorkOS user session"))?;
    let requested_session =
        SessionManager::new(None, &requested_sealed, &config.cookie_password).authenticate();
    if !requested_session.authenticated || requested_session.session_id.is_empty() {
        return Err(ApiError::unauthenticated("invalid WorkOS user session").into());
    }
    let requested_user_id = requested_session
        .user
        .as_ref()
        .map(|user| user.id.clone())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::unauthenticated("WorkOS session has no user identity"))?;
    let workspace = state.store.workspace_by_id(&request.workspace_id)?;
    let account = state.store.account_by_id(&workspace.account_id)?;
    if account.status != "active"
        || !config
            .user_has_active_membership(&requested_user_id, &account.workos_organization_id)
            .await?
    {
        return Err(ApiError::new(
            ErrorCode::PermissionDenied,
            "workspace is not available to this user",
        )
        .into());
    }

    // WorkOS refresh tokens rotate. Serialize scope changes and always start
    // from the latest sealed head for this WorkOS session, not the possibly
    // stale cookie carried by a concurrently submitted browser tab.
    let mut heads = config.browser_session_heads.lock().await;
    let current_sealed = heads
        .get(&requested_session.session_id)
        .cloned()
        .unwrap_or(requested_sealed);
    let current_session =
        SessionManager::new(None, &current_sealed, &config.cookie_password).authenticate();
    if !current_session.authenticated
        || current_session.session_id != requested_session.session_id
        || current_session.user.as_ref().map(|user| user.id.as_str())
            != Some(requested_user_id.as_str())
    {
        return Err(ApiError::unauthenticated("WorkOS user session expired").into());
    }
    let (active_sealed, active_session, switched_account) =
        if current_session.organization_id == account.workos_organization_id {
            (current_sealed, current_session, false)
        } else {
            let (sealed, session) = scope_session_to_organization(
                config,
                current_sealed,
                current_session,
                &account.workos_organization_id,
                "account",
            )
            .await?;
            (sealed, session, true)
        };
    heads.insert(active_session.session_id.clone(), active_sealed.clone());
    drop(heads);

    let context = seal(
        &UserContext {
            user_id: requested_user_id,
            account_id: account.id,
            workspace_id: workspace.id,
        },
        &config.cookie_password,
    )
    .map_err(|error| ApiError::internal(format!("seal workspace context: {error}")))?;
    let mut context_headers = HeaderMap::new();
    context_headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("{USER_CONTEXT_COOKIE}={context}"))
            .map_err(|_| ApiError::internal("workspace context cookie is invalid"))?,
    );
    let (body, _) = session_response(
        &state,
        config,
        Site::User,
        &active_session,
        &context_headers,
    )
    .await?;
    let mut response = Json(body).into_response();
    if switched_account {
        append_set_cookie(
            &mut response,
            USER_SESSION_COOKIE,
            &active_sealed,
            SESSION_MAX_AGE_SECONDS,
            config.cookie_secure,
            config.cookie_domain.as_deref(),
        )?;
    }
    append_set_cookie(
        &mut response,
        USER_CONTEXT_COOKIE,
        &context,
        SESSION_MAX_AGE_SECONDS,
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    set_no_store(&mut response);
    Ok(response)
}

async fn session_response(
    state: &AppState,
    config: &WorkOsConfig,
    site: Site,
    session: &SessionState,
    headers: &HeaderMap,
) -> Result<(SessionResponse, Option<String>), Failure> {
    let identity = validate_session_identity(config, &state.store, site, session)?;
    let user = session
        .user
        .clone()
        .map(workos_user_profile)
        .map(|user| SessionUser {
            id: user.id,
            email: user.email,
            name: user.name,
        });
    if site == Site::Admin {
        return Ok((
            SessionResponse {
                authenticated: true,
                site,
                active_account_id: None,
                active_workspace_id: None,
                accounts: Vec::new(),
                workspaces: Vec::new(),
                role: session.role.clone(),
                permissions: session.permissions.clone(),
                user,
            },
            None,
        ));
    }
    let user_id = identity
        .user_id
        .as_deref()
        .ok_or_else(|| ApiError::unauthenticated("WorkOS session has no user identity"))?;
    let organization_id = identity.organization_id.as_deref().ok_or_else(|| {
        ApiError::new(ErrorCode::PermissionDenied, "session has no account scope")
    })?;
    if !config
        .user_has_active_membership(user_id, organization_id)
        .await?
    {
        return Err(ApiError::new(
            ErrorCode::PermissionDenied,
            "WorkOS account membership is not active",
        )
        .into());
    }
    let access = AccessIdentity {
        user_id: user_id.to_string(),
        session_id: session.session_id.clone(),
        organization_id: Some(organization_id.to_string()),
        role: Some(session.role.clone()),
        permissions: session.permissions.clone(),
    };
    let (accounts, workspaces) = config
        .accounts_and_workspaces_for(&state.store, &access)
        .await?;
    let current_account_id = identity
        .account_id
        .as_deref()
        .ok_or_else(|| ApiError::internal("session account resolution failed"))?;
    let sealed_context = cookie_value(headers, USER_CONTEXT_COOKIE);
    let context = sealed_context
        .as_deref()
        .and_then(|sealed| unseal::<UserContext>(sealed, &config.cookie_password).ok())
        .filter(|context| {
            context.user_id == user_id
                && context.account_id == current_account_id
                && workspaces.iter().any(|workspace| {
                    workspace.id == context.workspace_id
                        && workspace.account_id == context.account_id
                })
        });
    let (selected, replacement_context) = if let Some(context) = context {
        let selected = workspaces
            .iter()
            .find(|workspace| workspace.id == context.workspace_id)
            .cloned()
            .ok_or_else(|| ApiError::internal("workspace context validation drifted"))?;
        (selected, None)
    } else {
        let selected = workspaces
            .iter()
            .find(|workspace| workspace.account_id == current_account_id && workspace.is_default)
            .cloned()
            .ok_or_else(|| ApiError::internal("account has no default workspace"))?;
        let sealed = seal(
            &UserContext {
                user_id: user_id.to_string(),
                account_id: selected.account_id.clone(),
                workspace_id: selected.id.clone(),
            },
            &config.cookie_password,
        )
        .map_err(|error| ApiError::internal(format!("seal workspace context: {error}")))?;
        (selected, Some(sealed))
    };
    Ok((
        SessionResponse {
            authenticated: true,
            site,
            active_account_id: Some(selected.account_id.clone()),
            active_workspace_id: Some(selected.id.clone()),
            accounts,
            workspaces,
            role: session.role.clone(),
            permissions: session.permissions.clone(),
            user,
        },
        replacement_context,
    ))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SiteQuery>,
) -> Result<Response, Failure> {
    let config = state
        .cfg
        .workos
        .as_ref()
        .ok_or_else(|| ApiError::failed_precondition("WorkOS AuthKit is not configured"))?;
    let site = Site::parse(&query.site).ok_or_else(|| ApiError::invalid("unknown auth site"))?;
    let sealed = cookie_value(&headers, site.session_cookie()).unwrap_or_default();
    let manager = SessionManager::new(Some(&config.client), sealed, &config.cookie_password);
    let session = manager.authenticate();
    if !session.session_id.is_empty() {
        let params = RevokeSessionParams::new(RevokeSession {
            session_id: session.session_id.clone(),
        });
        if let Err(error) = config.client.user_management().revoke_session(params).await {
            tracing::warn!(error = %error, "WorkOS session revocation failed");
        }
        config
            .browser_session_heads
            .lock()
            .await
            .remove(&session.session_id);
    }
    let mut response = Redirect::to(config.site_url(site)).into_response();
    append_delete_cookie(
        &mut response,
        site.session_cookie(),
        config.cookie_secure,
        config.cookie_domain.as_deref(),
    )?;
    if site == Site::User {
        append_delete_cookie(
            &mut response,
            USER_CONTEXT_COOKIE,
            config.cookie_secure,
            config.cookie_domain.as_deref(),
        )?;
    }
    set_no_store(&mut response);
    Ok(response)
}

fn validate_flow_identity(
    config: &WorkOsConfig,
    store: &crate::store::Store,
    flow: &LoginFlow,
    session: &SessionState,
) -> Result<WebIdentity, Failure> {
    let identity = validate_session_identity(config, store, flow.site, session)?;
    if flow.site == Site::User && flow.organization_id.is_none() && flow.workspace_id.is_none() {
        return Ok(identity);
    }
    let workspace_matches = match flow.workspace_id.as_deref() {
        Some(workspace_id) => {
            store.workspace_belongs_to_organization(workspace_id, &session.organization_id)?
        }
        None => true,
    };
    if Some(session.organization_id.as_str()) != flow.organization_id.as_deref()
        || !workspace_matches
    {
        return Err(ApiError::new(
            cats_api::error::ErrorCode::PermissionDenied,
            "WorkOS session does not match the requested workspace",
        )
        .into());
    }
    Ok(identity)
}

fn validate_session_identity(
    config: &WorkOsConfig,
    store: &crate::store::Store,
    site: Site,
    session: &SessionState,
) -> Result<WebIdentity, Failure> {
    if !session.authenticated {
        return Err(ApiError::new(
            cats_api::error::ErrorCode::Unauthenticated,
            "missing, invalid, or expired WorkOS session",
        )
        .into());
    }
    match site {
        Site::User => {
            if session.organization_id.is_empty() {
                return Err(ApiError::new(
                    cats_api::error::ErrorCode::PermissionDenied,
                    "WorkOS user session is not scoped to an account",
                )
                .into());
            }
            let account = store
                .account_for_organization(&session.organization_id)?
                .ok_or_else(|| {
                    ApiError::new(
                        cats_api::error::ErrorCode::PermissionDenied,
                        "WorkOS organization is not mapped to a Cats account",
                    )
                })?;
            if account.status != "active" {
                return Err(ApiError::new(
                    cats_api::error::ErrorCode::PermissionDenied,
                    "Cats account is not active",
                )
                .into());
            }
            let default_workspace_id = store
                .workspaces_for_account(&account.id)?
                .into_iter()
                .find(|workspace| workspace.is_default)
                .map(|workspace| workspace.id)
                .ok_or_else(|| ApiError::internal("Cats account has no default workspace"))?;
            Ok(WebIdentity {
                user_id: session.user.as_ref().map(|user| user.id.clone()),
                organization_id: Some(session.organization_id.clone()),
                account_id: Some(account.id),
                default_workspace_id: Some(default_workspace_id),
                administrator: false,
                permissions: session.permissions.clone(),
            })
        }
        Site::Admin => {
            if session.organization_id != config.admin_organization_id
                || !session
                    .permissions
                    .iter()
                    .any(|permission| permission == &config.admin_permission)
            {
                return Err(ApiError::new(
                    cats_api::error::ErrorCode::PermissionDenied,
                    "WorkOS session lacks fleet administrator permission",
                )
                .into());
            }
            Ok(WebIdentity {
                user_id: session.user.as_ref().map(|user| user.id.clone()),
                organization_id: Some(session.organization_id.clone()),
                account_id: None,
                default_workspace_id: None,
                administrator: true,
                permissions: session.permissions.clone(),
            })
        }
    }
}

fn identity_from_cookie(state: &AppState, headers: &HeaderMap, site: Site) -> Option<WebIdentity> {
    let config = state.cfg.workos.as_ref()?;
    let sealed = cookie_value(headers, site.session_cookie())?;
    let session = SessionManager::new(None, sealed, &config.cookie_password).authenticate();
    validate_session_identity(config, &state.store, site, &session).ok()
}

pub fn web_user_identity(state: &AppState, headers: &HeaderMap) -> Option<WebIdentity> {
    identity_from_cookie(state, headers, Site::User)
}

pub async fn web_session_allows_workspace(
    state: &AppState,
    headers: &HeaderMap,
    workspace_id: &str,
) -> Result<bool, ApiError> {
    if identity_from_cookie(state, headers, Site::Admin)
        .is_some_and(|identity| identity.administrator)
    {
        return Ok(true);
    }
    let Some(identity) = identity_from_cookie(state, headers, Site::User) else {
        return Ok(false);
    };
    let (Some(user_id), Some(organization_id)) = (
        identity.user_id.as_deref(),
        identity.organization_id.as_deref(),
    ) else {
        return Ok(false);
    };
    if !state
        .store
        .workspace_belongs_to_organization(workspace_id, organization_id)?
    {
        return Ok(false);
    }
    let Some(workos) = state.cfg.workos.as_ref() else {
        return Ok(false);
    };
    workos
        .user_has_active_membership(user_id, organization_id)
        .await
}

pub fn web_session_is_admin(state: &AppState, headers: &HeaderMap) -> bool {
    identity_from_cookie(state, headers, Site::Admin).is_some_and(|identity| identity.administrator)
}

pub fn has_any_web_session(state: &AppState, headers: &HeaderMap) -> bool {
    identity_from_cookie(state, headers, Site::User).is_some()
        || identity_from_cookie(state, headers, Site::Admin).is_some()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(candidate, value)| (candidate == name).then(|| value.to_string()))
}

fn append_set_cookie(
    response: &mut Response,
    name: &str,
    value: &str,
    max_age_seconds: u64,
    secure: bool,
    domain: Option<&str>,
) -> Result<(), Failure> {
    let secure_attribute = if secure { "; Secure" } else { "" };
    let domain_attribute = domain
        .map(|value| format!("; Domain={value}"))
        .unwrap_or_default();
    let cookie = format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_seconds}{secure_attribute}{domain_attribute}"
    );
    let value = HeaderValue::from_str(&cookie)
        .map_err(|_| ApiError::internal("failed to encode session cookie"))?;
    response.headers_mut().append(header::SET_COOKIE, value);
    Ok(())
}

fn append_delete_cookie(
    response: &mut Response,
    name: &str,
    secure: bool,
    domain: Option<&str>,
) -> Result<(), Failure> {
    append_set_cookie(response, name, "", 0, secure, domain)
}

fn set_no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}
