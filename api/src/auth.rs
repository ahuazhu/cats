//! User identity and workspace types shared by the CLI and control plane.

use serde::{Deserialize, Serialize};

/// Public information needed to start an AuthKit device authorization flow.
/// Neither the WorkOS API key nor any session credential is exposed here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliAuthConfigResponse {
    pub workos_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workos_client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workos_api_base_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountKind {
    Personal,
    Organization,
}

/// A tenant and billing owner. Both personal and organization accounts have
/// a WorkOS Organization so switching scopes has one unambiguous protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub slug: String,
    pub display_name: String,
    pub kind: AccountKind,
    pub organization_id: String,
    pub billing_account_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// A user-visible workspace.
///
/// `id` and `account_id` are the authorization identities. `slug` is unique
/// only within the account. `legacy_project` is the stable V1 routing key used
/// by `/v1/projects/{project}` while that compatibility API remains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workspace {
    pub id: String,
    pub account_id: String,
    pub account_slug: String,
    pub account_display_name: String,
    pub slug: String,
    pub locator: String,
    pub legacy_project: String,
    pub display_name: String,
    pub kind: AccountKind,
    pub organization_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub is_default: bool,
}

impl Workspace {
    /// Stable project route used by the V1 resource API.
    pub fn project(&self) -> &str {
        &self.legacy_project
    }

    /// Account-qualified selector accepted by current CLI commands.
    pub fn selector(&self) -> &str {
        &self.locator
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: String,
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeResponse {
    pub user: UserProfile,
    #[serde(default)]
    pub accounts: Vec<Account>,
    pub workspaces: Vec<Workspace>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInvitationRequest {
    pub email: String,
    #[serde(default = "default_member_role")]
    pub role_slug: String,
}

fn default_member_role() -> String {
    "member".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountInvitation {
    pub id: String,
    pub account_id: String,
    pub email: String,
    pub role_slug: String,
    pub state: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountMember {
    pub membership_id: String,
    pub account_id: String,
    pub user: UserProfile,
    pub role_slug: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAccountMemberRequest {
    pub role_slug: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWorkspaceRequest {
    pub slug: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateWorkspaceRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}
