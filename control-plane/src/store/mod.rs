//! Control-plane persistence (SQLite dev implementation of the §17.3 tables).
//!
//! Every user-facing invariant that must hold under concurrency is enforced
//! here with constraints, not in handler code: unique names per workspace,
//! one mount binding per disk (RWO), at most one live attachment per disk,
//! monotonic generations.

mod accounts;
mod cats;
mod disks;
mod endpoints;
mod nodes;
mod oci;
mod operations;
mod rows;
mod schema;
mod work;

#[cfg(test)]
mod tests;

pub use oci::{OciDeploymentClaim, OCI_DEPLOY_OPERATION_KIND};
pub use rows::{parse_desired, parse_observed, parse_wake};
pub use work::WorkLeaseGuard;

use rows::{
    desired_str, disk_state_str, node_state_str, observed_str, row_to_account, row_to_cat,
    row_to_disk, row_to_endpoint, row_to_node, row_to_oci_deployment, row_to_operation,
    row_to_work_lease, row_to_workspace, summarize_node, wake_str, work_kind_str,
};

#[cfg(test)]
use schema::SCHEMA_VERSION;

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use cats_api::auth::{Account, AccountInvitation, AccountKind, Workspace};
use cats_api::error::{ApiError, ErrorBody, ErrorCode};
use cats_api::ids;
use cats_api::oci::OciDeployment;
use cats_api::requests::WorkspaceToken;
use cats_api::resources::*;

pub type Result<T> = std::result::Result<T, ApiError>;

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

pub fn new_id(prefix: &str) -> String {
    ids::make_id(prefix, &Uuid::new_v4().simple().to_string()[..12])
}

pub const DEFAULT_ENDPOINT_NAME: &str = "web";
pub const DEFAULT_ENDPOINT_PORT: u16 = 8080;

fn dns_slug(value: &str, max_len: usize) -> String {
    let mut slug = String::with_capacity(value.len().min(max_len));
    for ch in value.chars() {
        if slug.len() == max_len {
            break;
        }
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if ch == '-' && !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        "cat".to_string()
    } else {
        slug
    }
}

/// Produce the one-label hostname covered by the `*.cats.run` certificate.
///
/// The opaque Cat suffix makes the URL stable across workspace renames and
/// globally unique without exposing a workspace identifier.
pub fn public_endpoint_hostname(cat: &Cat, endpoint_name: &str) -> String {
    let suffix = dns_slug(cat.id.strip_prefix("cat_").unwrap_or(&cat.id), 12);
    let endpoint = dns_slug(endpoint_name, 24);
    let prefix = if endpoint_name == DEFAULT_ENDPOINT_NAME {
        let available = 63usize.saturating_sub(suffix.len() + 1).max(1);
        dns_slug(&cat.name, available)
    } else {
        let fixed = endpoint.len() + suffix.len() + 2;
        let available = 63usize.saturating_sub(fixed).max(1);
        format!("{endpoint}-{}", dns_slug(&cat.name, available))
    };
    format!("{prefix}-{suffix}.cats.run")
}

pub struct Store {
    pub(super) conn: Mutex<Connection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRecord {
    pub id: String,
    pub slug: String,
    pub display_name: String,
    pub kind: AccountKind,
    pub workos_organization_id: String,
    pub billing_account_id: String,
    pub personal_owner_user_id: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRecord {
    pub id: String,
    pub account_id: String,
    pub slug: String,
    pub display_name: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceScope {
    pub account: AccountRecord,
    pub workspace: WorkspaceRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingLedgerRecord {
    pub billing_account_id: String,
    /// Account that owns this Billing Account. Named for what it holds: the
    /// funds side keys on Accounts, never on Workspaces.
    pub account_id: String,
    pub signup_credit_nanos: i128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupGrantState {
    Pending,
    Applied,
}

pub(super) fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e.to_string())
}

pub(super) fn is_constraint(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

impl Store {
    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let conn = self.conn.lock().unwrap();
        f(&conn).map_err(|e| {
            if is_constraint(&e) {
                ApiError::conflict(format!("constraint violation: {e}"))
            } else {
                internal(e)
            }
        })
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64
}
