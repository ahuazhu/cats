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
pub enum WorkspaceKind {
    Personal,
    Organization,
}

/// A user-visible workspace. `slug` is the existing Cats project namespace
/// used in resource API paths; `organization_id` is needed only to scope a
/// refreshed WorkOS session when switching organization workspaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workspace {
    pub slug: String,
    pub display_name: String,
    pub kind: WorkspaceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
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
    pub workspaces: Vec<Workspace>,
}
