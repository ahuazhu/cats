use super::token::AccessIdentity;
use super::web_flow::{validate_site_url, Site};
use super::*;

#[derive(Clone)]
pub struct WorkOsConfig {
    pub(super) client: workos::Client,
    pub(super) client_id: String,
    pub(super) api_base_url: String,
    pub(super) issuer_url: String,
    pub(super) jwks: Arc<workos::helpers::JwksHelper>,
    pub(super) redirect_uri: String,
    pub(super) cookie_password: String,
    pub(super) account_organizations: BTreeMap<String, String>,
    pub(super) admin_organization_id: String,
    pub(super) admin_permission: String,
    pub(super) cookie_secure: bool,
    pub(super) cookie_domain: Option<String>,
    pub(super) user_site_url: String,
    pub(super) admin_site_url: String,
    pub(super) browser_session_heads: Arc<tokio::sync::Mutex<BTreeMap<String, String>>>,
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

    /// Re-read the candidate's current admin-organization membership and the
    /// permissions of every currently assigned role. Role slugs are lookup
    /// keys only; authorization is the exact permission in the current WorkOS
    /// role objects, never a comparison against a privileged slug.
    pub(crate) async fn current_fleet_administrator_principal(
        &self,
        candidate: &super::FleetAdministratorIdentityCandidate,
    ) -> Result<Option<cats_protocol::runtime_reconciliation::FleetPolicyPrincipal>, ApiError> {
        const FLEET_ADMIN_PERMISSION: &str = "cats:fleet:admin";

        let page = self
            .client
            .organization_membership()
            .list_organization_memberships(ListOrganizationMembershipsParams {
                organization_id: Some(self.admin_organization_id.clone()),
                user_id: Some(candidate.subject.clone()),
                statuses: Some(vec![
                    workos::enums::UserManagementOrganizationMembershipStatuses::Active,
                ]),
                limit: Some(100),
                ..Default::default()
            })
            .await
            .map_err(|error| {
                tracing::warn!(
                    error = %error,
                    subject = candidate.subject,
                    organization_id = self.admin_organization_id,
                    "WorkOS fleet administrator membership lookup failed"
                );
                ApiError::unavailable("WorkOS fleet authorization is temporarily unavailable")
            })?;
        if page.list_metadata.after.is_some() {
            tracing::warn!(
                subject = candidate.subject,
                organization_id = self.admin_organization_id,
                "WorkOS returned more than one page for one subject/organization membership"
            );
            return Err(ApiError::unavailable(
                "WorkOS fleet authorization is temporarily unavailable",
            ));
        }
        let mut matching = page
            .data
            .into_iter()
            .filter(|membership| {
                membership.user_id == candidate.subject
                    && membership.organization_id == self.admin_organization_id
                    && membership.status == UserOrganizationMembershipStatus::Active
            })
            .collect::<Vec<_>>();
        if candidate.organization_id != self.admin_organization_id || matching.len() != 1 {
            return Ok(None);
        }
        let membership = matching.pop().expect("length was checked");
        let mut role_slugs = membership
            .roles
            .into_iter()
            .map(|role| role.slug)
            .collect::<std::collections::BTreeSet<_>>();
        role_slugs.insert(membership.role.slug);
        if role_slugs.is_empty() {
            return Ok(None);
        }
        for role_slug in role_slugs {
            let role = match self
                .client
                .authorization()
                .get_organization_role(&self.admin_organization_id, &role_slug)
                .await
            {
                Ok(role) => role,
                Err(error) if error.is_not_found() => return Ok(None),
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        subject = candidate.subject,
                        organization_id = self.admin_organization_id,
                        "WorkOS fleet administrator role lookup failed"
                    );
                    return Err(ApiError::unavailable(
                        "WorkOS fleet authorization is temporarily unavailable",
                    ));
                }
            };
            if role.slug != role_slug {
                tracing::warn!(
                    requested_role = role_slug,
                    returned_role = role.slug,
                    "WorkOS fleet administrator role response was not self-consistent"
                );
                return Err(ApiError::unavailable(
                    "WorkOS fleet authorization is temporarily unavailable",
                ));
            }
            if role
                .permissions
                .iter()
                .any(|permission| permission == FLEET_ADMIN_PERMISSION)
            {
                return Ok(Some(
                    cats_protocol::runtime_reconciliation::FleetPolicyPrincipal::WorkosFleetAdministrator {
                        subject: cats_protocol::runtime_reconciliation::Id::new(
                            candidate.subject.clone(),
                        )
                        .ok_or_else(|| {
                            ApiError::unauthenticated("WorkOS administrator subject is invalid")
                        })?,
                        organization_id: cats_protocol::runtime_reconciliation::Id::new(
                            self.admin_organization_id.clone(),
                        )
                        .ok_or_else(|| {
                            ApiError::unavailable(
                                "WorkOS fleet authorization is temporarily unavailable",
                            )
                        })?,
                    },
                ));
            }
        }
        Ok(None)
    }

    pub(super) async fn ensure_personal_organization(
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

    pub async fn me(
        &self,
        store: &Arc<crate::store::Store>,
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
        store: &Arc<crate::store::Store>,
        identity: &AccessIdentity,
    ) -> Result<Vec<Workspace>, ApiError> {
        self.accounts_and_workspaces_for(store, identity)
            .await
            .map(|(_, workspaces)| workspaces)
    }

    pub async fn accounts_and_workspaces_for(
        &self,
        store: &Arc<crate::store::Store>,
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
            let memberships = page.data;
            let expected_user_id = identity.user_id.clone();
            let scoped_organization_id = identity.organization_id.clone();
            let scoped_permissions = identity.permissions.clone();
            let (mut page_accounts, mut page_workspaces) = store
                .execute(move |store| {
                    let mut accounts = Vec::new();
                    let mut workspaces = Vec::new();
                    for membership in memberships {
                        if membership.status != UserOrganizationMembershipStatus::Active {
                            continue;
                        }
                        if membership.user_id != expected_user_id {
                            tracing::warn!(
                                expected_user_id,
                                actual_user_id = membership.user_id,
                                "WorkOS membership list returned another user"
                            );
                            continue;
                        }
                        let permissions = if scoped_organization_id.as_deref()
                            == Some(membership.organization_id.as_str())
                        {
                            scoped_permissions.as_slice()
                        } else {
                            &[]
                        };
                        let Some((account, mut account_workspaces)) = store
                            .account_and_workspace_views(
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
                    Ok((accounts, workspaces))
                })
                .await?;
            accounts.append(&mut page_accounts);
            workspaces.append(&mut page_workspaces);
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

    pub(super) async fn single_mapped_workspace_for_user(
        &self,
        store: &Arc<crate::store::Store>,
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
            let memberships = page.data;
            let expected_user_id = user_id.to_string();
            let page_candidates = store
                .execute(move |store| {
                    let mut candidates = Vec::new();
                    for membership in memberships {
                        if membership.status != UserOrganizationMembershipStatus::Active
                            || membership.user_id != expected_user_id
                        {
                            continue;
                        }
                        let Some(account) =
                            store.account_for_organization(&membership.organization_id)?
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
                        candidates.push((workspace.id, membership.organization_id));
                    }
                    Ok(candidates)
                })
                .await?;
            candidates.extend(page_candidates);
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

    pub(super) fn site_url(&self, site: Site) -> &str {
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

pub(super) fn workos_user_profile(user: workos::User) -> UserProfile {
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
