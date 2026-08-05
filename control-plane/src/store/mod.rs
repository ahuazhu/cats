//! Control-plane persistence (PostgreSQL implementation of the §17.3 tables).
//!
//! Every user-facing invariant that must hold under concurrency is enforced
//! here with constraints, not in handler code: unique names per workspace,
//! one mount binding per disk (RWO), at most one live attachment per disk,
//! monotonic generations.
//!
//! The store shares one database with the storage MetadataStore (its tables
//! are prefixed `cats_storage_`); ownership of the control tables stays here.
//! Tests isolate through a per-test schema selected via the DSN's
//! `options=-csearch_path=...` parameter.

mod accounts;
mod cats;
mod disks;
mod endpoints;
mod leadership;
mod nodes;
mod oci;
mod operations;
mod rows;
mod schema;
mod work;

#[cfg(test)]
mod tests;

pub use leadership::{OciDeploymentLease, SingletonRole};
pub use oci::{OciDeploymentClaim, OCI_DEPLOY_OPERATION_KIND};
pub use rows::{parse_desired, parse_observed, parse_wake};
pub use work::WorkLeaseGuard;

use rows::{
    desired_str, node_state_str, observed_str, row_to_account, row_to_cat, row_to_disk,
    row_to_endpoint, row_to_node, row_to_oci_deployment, row_to_operation, row_to_work_lease,
    row_to_workspace, summarize_node, wake_str, work_kind_str,
};

#[cfg(test)]
use schema::SCHEMA_VERSION;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use postgres::Client;
use uuid::Uuid;

use cats_api::auth::{Account, AccountInvitation, AccountKind, Workspace};
use cats_api::error::{ApiError, ErrorBody, ErrorCode};
use cats_api::ids;
use cats_api::oci::OciDeployment;
use cats_api::requests::{HeartbeatCat, WorkspaceToken};
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
    /// One serialized connection, the same concurrency shape the SQLite
    /// implementation had. `with` reconnects lazily after the server drops
    /// it. Option only so `Drop` can move the client onto a non-runtime
    /// thread — it is `Some` for the store's whole life.
    pub(super) client: Mutex<Option<Client>>,
    dsn: DsnSource,
    ca_file: Option<String>,
}

/// Where the control store obtains its PostgreSQL DSN on each connect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DsnSource {
    /// A fixed development credential.
    Literal(String),
    /// A file kept current by the platform and re-read after a disconnect.
    File(PathBuf),
}

impl DsnSource {
    /// Resolve without ever including the credential-bearing contents in an
    /// error message.
    fn resolve(&self) -> Result<String> {
        match self {
            Self::Literal(url) => Ok(url.clone()),
            Self::File(path) => {
                let contents = fs::read_to_string(path).map_err(|error| {
                    internal(format!(
                        "read control-store PostgreSQL DSN from {}: {error}",
                        path.display()
                    ))
                })?;
                let url = contents.trim();
                if url.is_empty() {
                    return Err(internal(format!(
                        "control-store PostgreSQL DSN file {} is empty",
                        path.display()
                    )));
                }
                Ok(url.to_string())
            }
        }
    }
}

/// Tearing down the client blocks on its internal runtime, which panics on a
/// tokio worker thread just like queries do.
impl Drop for Store {
    fn drop(&mut self) {
        if let Ok(guard) = self.client.get_mut() {
            if let Some(client) = guard.take() {
                off_runtime(move || drop(client));
            }
        }
    }
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

/// Constraint violations (SQLSTATE class 23) and the store's own immutability
/// triggers (raised as P0001) both surface as conflicts, mirroring what the
/// SQLite implementation reported for its CHECK/UNIQUE/trigger aborts.
pub(super) fn is_constraint(e: &postgres::Error) -> bool {
    e.code().is_some_and(|state| {
        state.code().starts_with("23") || state == &postgres::error::SqlState::RAISE_EXCEPTION
    })
}

/// Run `f` on a thread that is not driving an async runtime.
///
/// The sync `postgres` client owns an internal runtime and panics when used
/// on a tokio worker thread ("cannot start a runtime from within a runtime").
/// The store is called from both plain threads (tests) and async handlers, so
/// database work hops to a scoped helper thread exactly when an ambient
/// runtime exists. The caller blocks for the duration either way — the same
/// serialization the SQLite implementation had behind its connection mutex.
pub(crate) fn off_runtime<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::scope(|scope| {
            scope
                .spawn(f)
                .join()
                .expect("control-store operation panicked")
        })
    } else {
        f()
    }
}

impl Store {
    /// Lock the connection and run `f` off-runtime. The server closing the
    /// connection (restart, failover, idle timeout) must cost one reconnect,
    /// not a wedged store, so `f` receives the reconnect outcome instead of a
    /// guaranteed client.
    fn enter<T: Send>(
        &self,
        f: impl FnOnce(std::result::Result<&mut Client, ApiError>) -> T + Send,
    ) -> T {
        let mut guard = self.client.lock().unwrap();
        let client: &mut Option<Client> = &mut guard;
        off_runtime(move || {
            if client.as_ref().is_none_or(Client::is_closed) {
                match schema::connect_client(&self.dsn, self.ca_file.as_deref()) {
                    Ok(fresh) => *client = Some(fresh),
                    Err(error) => return f(Err(error)),
                }
            }
            f(Ok(client.as_mut().expect("client was just ensured")))
        })
    }

    fn with<T: Send>(
        &self,
        f: impl FnOnce(&mut Client) -> std::result::Result<T, postgres::Error> + Send,
    ) -> Result<T> {
        self.enter(|client| {
            f(client?).map_err(|e| {
                if is_constraint(&e) {
                    ApiError::conflict(format!("constraint violation: {e}"))
                } else {
                    internal(e)
                }
            })
        })
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64
}
