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

mod cookie;
mod provisioning;
mod session;
mod token;
mod web_flow;
mod workos_client;

pub use provisioning::provision_personal_account;
pub use session::{
    has_any_web_session, logout, session, switch_workspace, web_session_allows_workspace,
    web_session_is_admin, web_session_is_admin_without_store, web_user_identity, SiteQuery,
    SwitchWorkspaceRequest, WebIdentity,
};
pub use token::AccessIdentity;
pub use web_flow::{callback, config, login, CallbackQuery, LoginQuery};
pub use workos_client::{WorkOsConfig, WorkOsConfigParams};

use cookie::*;
