//! Control-plane persistence (SQLite dev implementation of the §17.3 tables).
//!
//! Every user-facing invariant that must hold under concurrency is enforced
//! here with constraints, not in handler code: unique names per project,
//! one mount binding per disk (RWO), at most one live attachment per disk,
//! monotonic generations.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use cats_api::auth::{Account, AccountInvitation, AccountKind, Workspace};
use cats_api::error::{ApiError, ErrorBody, ErrorCode};
use cats_api::ids;
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
    conn: Mutex<Connection>,
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
    pub legacy_project: String,
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
    pub owner_id: String,
    pub signup_credit_nanos: i128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupGrantState {
    Pending,
    Applied,
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e.to_string())
}

fn is_constraint(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

fn ensure_column(conn: &Connection, table: &str, column: &str, definition: &str) -> Result<()> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(internal)?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(internal)?;
    if !names.iter().any(|name| name == column) {
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
            [],
        )
        .map_err(internal)?;
    }
    Ok(())
}

fn backfill_public_endpoints(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction().map_err(internal)?;
    let cats = {
        let mut stmt = tx.prepare("SELECT * FROM cats").map_err(internal)?;
        let rows = stmt
            .query_map([], row_to_cat)
            .map_err(internal)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(internal)?;
        rows
    };
    let cats_by_id = cats
        .iter()
        .map(|cat| (cat.id.as_str(), cat))
        .collect::<HashMap<_, _>>();
    let existing = {
        let mut stmt = tx
            .prepare("SELECT id, cat_id, name, hostname FROM endpoints")
            .map_err(internal)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(internal)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(internal)?;
        rows
    };

    // Databases created by the local-only prototype used `.cats.local`.
    // Move every endpoint to the public one-label namespace atomically while
    // preserving route state and epoch.
    for (endpoint_id, cat_id, name, old_hostname) in existing {
        let Some(cat) = cats_by_id.get(cat_id.as_str()) else {
            continue;
        };
        let hostname = public_endpoint_hostname(cat, &name);
        if hostname == old_hostname {
            continue;
        }
        tx.execute(
            "UPDATE routes SET hostname=?2 WHERE hostname=?1",
            params![old_hostname, hostname],
        )
        .map_err(internal)?;
        tx.execute(
            "UPDATE endpoints SET hostname=?2 WHERE id=?1",
            params![endpoint_id, hostname],
        )
        .map_err(internal)?;
    }

    // Every Cat owns a default wake-on-request endpoint. Existing Cats get
    // the same contract during control-plane startup.
    for cat in cats {
        let has_default: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM endpoints WHERE cat_id=?1 AND name=?2
                 )",
                params![cat.id, DEFAULT_ENDPOINT_NAME],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if has_default {
            continue;
        }
        let endpoint_id = new_id(ids::ENDPOINT_PREFIX);
        let hostname = public_endpoint_hostname(&cat, DEFAULT_ENDPOINT_NAME);
        tx.execute(
            "INSERT INTO endpoints
                (id, cat_id, name, hostname, target_port, protocol, wake_policy)
             VALUES (?1,?2,?3,?4,?5,'http','wake_on_request')",
            params![
                endpoint_id,
                cat.id,
                DEFAULT_ENDPOINT_NAME,
                hostname,
                DEFAULT_ENDPOINT_PORT
            ],
        )
        .map_err(internal)?;

        let gateway_url = match (
            cat.observed_state == ObservedState::Running,
            cat.node_id.as_deref(),
        ) {
            (true, Some(node_id)) => tx
                .query_row(
                    "SELECT gateway_url FROM nodes WHERE id=?1",
                    params![node_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(internal)?,
            _ => None,
        };
        let (node_id, epoch, state) = match (cat.node_id.as_deref(), gateway_url.as_deref()) {
            (Some(node_id), Some(_)) if cat.observed_state == ObservedState::Running => {
                (Some(node_id), 1, "active")
            }
            _ => (None, 0, "unbound"),
        };
        tx.execute(
            "INSERT INTO routes
                (hostname, cat_id, node_id, gateway_url, target_port, epoch, state)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                hostname,
                cat.id,
                node_id,
                gateway_url,
                DEFAULT_ENDPOINT_PORT,
                epoch,
                state
            ],
        )
        .map_err(internal)?;
    }
    tx.commit().map_err(internal)
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(internal)?;
        conn.busy_timeout(std::time::Duration::from_secs(10))
            .map_err(internal)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(internal)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(internal)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(internal)?;
        conn.execute_batch(SCHEMA).map_err(internal)?;
        ensure_column(&conn, "operations", "project", "TEXT NOT NULL DEFAULT ''")?;
        ensure_column(
            &conn,
            "cats",
            "workspace_id",
            "TEXT REFERENCES workspaces(id)",
        )?;
        ensure_column(
            &conn,
            "disks",
            "workspace_id",
            "TEXT REFERENCES workspaces(id)",
        )?;
        ensure_column(
            &conn,
            "operations",
            "workspace_id",
            "TEXT REFERENCES workspaces(id)",
        )?;
        ensure_column(&conn, "nodes", "telemetry_json", "TEXT")?;
        ensure_column(
            &conn,
            "nodes",
            "scheduling_disabled",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(&conn, "cats", "auto_suspend", "INTEGER NOT NULL DEFAULT 1")?;
        ensure_column(&conn, "cats", "work_version", "INTEGER NOT NULL DEFAULT 0")?;
        ensure_column(
            &conn,
            "cats",
            "observed_state_since_ms",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        // Backfill ownership for databases created before operations carried
        // their project explicitly. Deleted resources cannot be recovered and
        // remain admin-only (empty project).
        conn.execute_batch(
            "UPDATE operations
                SET project = COALESCE(
                    (SELECT project FROM cats WHERE cats.id = operations.resource_id),
                    (SELECT project FROM disks WHERE disks.id = operations.resource_id),
                    project)
              WHERE project = '';
             UPDATE nodes
                SET scheduling_disabled = 1
              WHERE state IN ('cordoned', 'draining');",
        )
        .map_err(internal)?;
        // Databases upgraded from a release without a persisted state clock
        // start their automatic tier timers at migration time. Using the Cat
        // creation time here could immediately demote an old but recently
        // suspended Cat.
        conn.execute(
            "UPDATE cats
                SET observed_state_since_ms=?1
              WHERE observed_state_since_ms=0",
            params![now_ms()],
        )
        .map_err(internal)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

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

    // ------------------------------------------------------------------
    // Accounts and workspaces
    // ------------------------------------------------------------------

    /// Backfill the V1 project namespace into immutable Account/Workspace
    /// identities. Re-running this migration is safe.
    pub fn reconcile_legacy_projects(
        &self,
        project_organizations: &BTreeMap<String, String>,
    ) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let projects = {
            let mut stmt = tx
                .prepare(
                    "SELECT project FROM cats
                     UNION SELECT project FROM disks
                     UNION SELECT project FROM operations
                     ORDER BY project",
                )
                .map_err(internal)?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(internal)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(internal)?;
            rows
        };
        let mut all_projects = projects;
        all_projects.extend(project_organizations.keys().cloned());
        all_projects.sort();
        all_projects.dedup();
        for project in all_projects
            .into_iter()
            .filter(|project| !project.is_empty())
        {
            let organization_id = project_organizations
                .get(&project)
                .cloned()
                .unwrap_or_else(|| format!("legacy-unmapped:{project}"));
            ensure_legacy_workspace(&tx, &project, &organization_id)?;
        }
        for table in ["cats", "disks", "operations"] {
            tx.execute(
                &format!(
                    "UPDATE {table}
                        SET workspace_id=(
                            SELECT id FROM workspaces
                             WHERE legacy_project={table}.project
                        )
                      WHERE workspace_id IS NULL OR workspace_id=''"
                ),
                [],
            )
            .map_err(internal)?;
            let missing: i64 = tx
                .query_row(
                    &format!(
                        "SELECT COUNT(*) FROM {table}
                          WHERE workspace_id IS NULL OR workspace_id=''"
                    ),
                    [],
                    |row| row.get(0),
                )
                .map_err(internal)?;
            if missing != 0 {
                return Err(ApiError::failed_precondition(format!(
                    "{missing} historical {table} rows have no recoverable workspace owner"
                )));
            }
        }
        tx.execute_batch(
            "CREATE TRIGGER IF NOT EXISTS cats_require_workspace
                BEFORE INSERT ON cats
                WHEN NEW.workspace_id IS NULL OR NEW.workspace_id=''
                BEGIN SELECT RAISE(ABORT, 'cats.workspace_id is required'); END;
             CREATE TRIGGER IF NOT EXISTS disks_require_workspace
                BEFORE INSERT ON disks
                WHEN NEW.workspace_id IS NULL OR NEW.workspace_id=''
                BEGIN SELECT RAISE(ABORT, 'disks.workspace_id is required'); END;
             CREATE TRIGGER IF NOT EXISTS operations_require_workspace
                BEFORE INSERT ON operations
                WHEN NEW.workspace_id IS NULL OR NEW.workspace_id=''
                BEGIN SELECT RAISE(ABORT, 'operations.workspace_id is required'); END;
             CREATE TRIGGER IF NOT EXISTS cats_workspace_matches_project
                BEFORE INSERT ON cats
                WHEN NOT EXISTS(
                    SELECT 1 FROM workspaces
                     WHERE id=NEW.workspace_id AND legacy_project=NEW.project
                )
                BEGIN SELECT RAISE(ABORT, 'cats workspace/project mismatch'); END;
             CREATE TRIGGER IF NOT EXISTS disks_workspace_matches_project
                BEFORE INSERT ON disks
                WHEN NOT EXISTS(
                    SELECT 1 FROM workspaces
                     WHERE id=NEW.workspace_id AND legacy_project=NEW.project
                )
                BEGIN SELECT RAISE(ABORT, 'disks workspace/project mismatch'); END;
             CREATE TRIGGER IF NOT EXISTS operations_workspace_matches_project
                BEFORE INSERT ON operations
                WHEN NOT EXISTS(
                    SELECT 1 FROM workspaces
                     WHERE id=NEW.workspace_id AND legacy_project=NEW.project
                )
                BEGIN SELECT RAISE(ABORT, 'operations workspace/project mismatch'); END;
             CREATE TRIGGER IF NOT EXISTS cats_workspace_owner_is_immutable
                BEFORE UPDATE OF workspace_id, project ON cats
                WHEN NEW.workspace_id != OLD.workspace_id OR NEW.project != OLD.project
                BEGIN SELECT RAISE(ABORT, 'cats workspace owner is immutable'); END;
             CREATE TRIGGER IF NOT EXISTS disks_workspace_owner_is_immutable
                BEFORE UPDATE OF workspace_id, project ON disks
                WHEN NEW.workspace_id != OLD.workspace_id OR NEW.project != OLD.project
                BEGIN SELECT RAISE(ABORT, 'disks workspace owner is immutable'); END;
             CREATE TRIGGER IF NOT EXISTS operations_workspace_owner_is_immutable
                BEFORE UPDATE OF workspace_id, project ON operations
                WHEN NEW.workspace_id != OLD.workspace_id OR NEW.project != OLD.project
                BEGIN SELECT RAISE(ABORT, 'operations workspace owner is immutable'); END;",
        )
        .map_err(internal)?;
        tx.commit().map_err(internal)?;
        backfill_public_endpoints(&mut conn)
    }

    /// Idempotently create the local half of a Personal Account provision.
    /// It remains hidden until the signup grant is durably applied.
    pub fn ensure_personal_account(
        &self,
        workos_user_id: &str,
        workos_organization_id: &str,
        display_name: &str,
    ) -> Result<(AccountRecord, WorkspaceRecord)> {
        if workos_user_id.is_empty() || workos_organization_id.is_empty() {
            return Err(ApiError::invalid(
                "WorkOS user and organization IDs must not be empty",
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        if let Some(account) =
            find_account_by_personal_owner(&tx, workos_user_id).map_err(internal)?
        {
            if account.workos_organization_id != workos_organization_id {
                return Err(ApiError::conflict(
                    "personal account WorkOS organization changed",
                ));
            }
            let workspace = default_workspace_for_account(&tx, &account.id)?;
            tx.commit().map_err(internal)?;
            return Ok((account, workspace));
        }

        if find_account_by_organization(&tx, workos_organization_id)
            .map_err(internal)?
            .is_some()
        {
            return Err(ApiError::conflict(
                "WorkOS organization already belongs to another Cats account",
            ));
        }
        let account_id = new_id(ids::ACCOUNT_PREFIX);
        let workspace_id = new_id(ids::WORKSPACE_PREFIX);
        let requested_slug = dns_slug(
            display_name
                .split('@')
                .next()
                .filter(|value| !value.is_empty())
                .unwrap_or("personal"),
            48,
        );
        let account_slug = unique_account_slug(&tx, &requested_slug)?;
        let legacy_project = unique_legacy_project(&tx, &format!("personal-{workos_user_id}"))?;
        let billing_account_id = format!("billing_account/account/{account_id}");
        let created_at = now_unix();
        tx.execute(
            "INSERT INTO accounts (
                id, slug, display_name, kind, workos_organization_id,
                billing_account_id, personal_owner_user_id, status, created_at
             ) VALUES (?1,?2,?3,'personal',?4,?5,?6,'provisioning',?7)",
            params![
                account_id,
                account_slug,
                display_name,
                workos_organization_id,
                billing_account_id,
                workos_user_id,
                created_at
            ],
        )
        .map_err(internal)?;
        tx.execute(
            "INSERT INTO workspaces (
                id, account_id, slug, display_name, legacy_project,
                is_default, created_at
             ) VALUES (?1,?2,'default','Default',?3,1,?4)",
            params![workspace_id, account_id, legacy_project, created_at],
        )
        .map_err(internal)?;
        tx.execute(
            "INSERT OR REPLACE INTO account_membership_shadow (
                workos_membership_id, account_id, workos_user_id, role_slug,
                status, updated_at
             ) VALUES (?1,?2,?3,'owner','active',?4)",
            params![
                format!("personal-owner:{workos_user_id}"),
                account_id,
                workos_user_id,
                created_at
            ],
        )
        .map_err(internal)?;
        let account = find_account_by_personal_owner(&tx, workos_user_id)
            .map_err(internal)?
            .ok_or_else(|| ApiError::internal("personal account insert was not visible"))?;
        let workspace = default_workspace_for_account(&tx, &account.id)?;
        tx.commit().map_err(internal)?;
        Ok((account, workspace))
    }

    pub fn signup_grant_state(
        &self,
        workos_user_id: &str,
        campaign: &str,
        billing_account_id: &str,
    ) -> Result<SignupGrantState> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO signup_grant_eligibility (
                workos_user_id, campaign, billing_account_id, state, created_at
             ) VALUES (?1,?2,?3,'pending',?4)",
            params![workos_user_id, campaign, billing_account_id, now_unix()],
        )
        .map_err(internal)?;
        let (beneficiary, state): (String, String) = conn
            .query_row(
                "SELECT billing_account_id, state
                   FROM signup_grant_eligibility
                  WHERE workos_user_id=?1 AND campaign=?2",
                params![workos_user_id, campaign],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(internal)?;
        if beneficiary != billing_account_id {
            return Err(ApiError::conflict(
                "signup grant beneficiary cannot be changed",
            ));
        }
        Ok(if state == "applied" {
            SignupGrantState::Applied
        } else {
            SignupGrantState::Pending
        })
    }

    pub fn mark_signup_grant_applied(
        &self,
        workos_user_id: &str,
        campaign: &str,
        billing_account_id: &str,
    ) -> Result<()> {
        self.with(|conn| {
            let changed = conn.execute(
                "UPDATE signup_grant_eligibility
                    SET state='applied', applied_at=?4
                  WHERE workos_user_id=?1 AND campaign=?2
                    AND billing_account_id=?3 AND state IN ('pending','applied')",
                params![workos_user_id, campaign, billing_account_id, now_unix()],
            )?;
            if changed == 0 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            Ok(())
        })
    }

    pub fn activate_account(&self, account_id: &str) -> Result<()> {
        self.with(|conn| {
            let changed = conn.execute(
                "UPDATE accounts SET status='active' WHERE id=?1",
                params![account_id],
            )?;
            if changed == 0 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            Ok(())
        })
    }

    pub fn account_for_organization(&self, organization_id: &str) -> Result<Option<AccountRecord>> {
        self.with(|conn| find_account_by_organization(conn, organization_id))
    }

    pub fn account_for_personal_owner(
        &self,
        workos_user_id: &str,
    ) -> Result<Option<AccountRecord>> {
        self.with(|conn| find_account_by_personal_owner(conn, workos_user_id))
    }

    pub fn account_by_id(&self, account_id: &str) -> Result<AccountRecord> {
        let conn = self.conn.lock().unwrap();
        match conn.query_row(
            "SELECT id, slug, display_name, kind, workos_organization_id,
                        billing_account_id, personal_owner_user_id, status
                   FROM accounts WHERE id=?1",
            params![account_id],
            row_to_account,
        ) {
            Ok(account) => Ok(account),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Err(ApiError::new(ErrorCode::NotFound, "account not found"))
            }
            Err(error) => Err(internal(error)),
        }
    }

    pub fn workspaces_for_account(&self, account_id: &str) -> Result<Vec<WorkspaceRecord>> {
        self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, account_id, slug, display_name, legacy_project, is_default
                   FROM workspaces WHERE account_id=?1
                  ORDER BY is_default DESC, slug",
            )?;
            let rows = stmt
                .query_map(params![account_id], row_to_workspace)?
                .collect();
            rows
        })
    }

    pub fn create_workspace(
        &self,
        account_id: &str,
        slug: &str,
        display_name: &str,
    ) -> Result<WorkspaceRecord> {
        validate_workspace_slug(slug)?;
        if display_name.trim().is_empty() || display_name.len() > 100 {
            return Err(ApiError::invalid(
                "workspace display_name must be 1 to 100 characters",
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let account = tx
            .query_row(
                "SELECT id, slug, display_name, kind, workos_organization_id,
                        billing_account_id, personal_owner_user_id, status
                   FROM accounts WHERE id=?1",
                params![account_id],
                row_to_account,
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => {
                    ApiError::new(ErrorCode::NotFound, "account not found")
                }
                other => internal(other),
            })?;
        if account.status != "active" {
            return Err(ApiError::failed_precondition("account is not active"));
        }
        let workspace_id = new_id(ids::WORKSPACE_PREFIX);
        let legacy_project = unique_legacy_project(&tx, &format!("{}-{slug}", account.slug))?;
        tx.execute(
            "INSERT INTO workspaces (
                id, account_id, slug, display_name, legacy_project,
                is_default, created_at
             ) VALUES (?1,?2,?3,?4,?5,0,?6)",
            params![
                workspace_id,
                account.id,
                slug,
                display_name.trim(),
                legacy_project,
                now_unix()
            ],
        )
        .map_err(|error| {
            if is_constraint(&error) {
                ApiError::conflict("workspace slug already exists in this account")
            } else {
                internal(error)
            }
        })?;
        let workspace = tx
            .query_row(
                "SELECT id, account_id, slug, display_name, legacy_project, is_default
                   FROM workspaces WHERE id=?1",
                params![workspace_id],
                row_to_workspace,
            )
            .map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok(workspace)
    }

    pub fn update_workspace(
        &self,
        workspace_id: &str,
        slug: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<WorkspaceRecord> {
        if slug.is_none() && display_name.is_none() {
            return Err(ApiError::invalid(
                "at least one workspace field must be supplied",
            ));
        }
        if let Some(slug) = slug {
            validate_workspace_slug(slug)?;
        }
        if display_name.is_some_and(|value| value.trim().is_empty() || value.len() > 100) {
            return Err(ApiError::invalid(
                "workspace display_name must be 1 to 100 characters",
            ));
        }
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE workspaces
                    SET slug=COALESCE(?2, slug),
                        display_name=COALESCE(?3, display_name)
                  WHERE id=?1",
                params![workspace_id, slug, display_name.map(str::trim)],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    ApiError::conflict("workspace slug already exists in this account")
                } else {
                    internal(error)
                }
            })?;
        if changed == 0 {
            return Err(ApiError::new(ErrorCode::NotFound, "workspace not found"));
        }
        conn.query_row(
            "SELECT id, account_id, slug, display_name, legacy_project, is_default
               FROM workspaces WHERE id=?1",
            params![workspace_id],
            row_to_workspace,
        )
        .map_err(internal)
    }

    pub fn workspace_for_project(&self, project: &str) -> Result<Option<WorkspaceRecord>> {
        self.with(|conn| {
            conn.query_row(
                "SELECT id, account_id, slug, display_name, legacy_project, is_default
                   FROM workspaces WHERE legacy_project=?1",
                params![project],
                row_to_workspace,
            )
            .optional()
        })
    }

    pub fn workspace_scope_for_project(&self, project: &str) -> Result<WorkspaceScope> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT
                a.id, a.slug, a.display_name, a.kind,
                a.workos_organization_id, a.billing_account_id,
                a.personal_owner_user_id, a.status,
                w.id, w.account_id, w.slug, w.display_name,
                w.legacy_project, w.is_default
               FROM workspaces w
               JOIN accounts a ON a.id=w.account_id
              WHERE w.legacy_project=?1",
            params![project],
            |row| {
                Ok(WorkspaceScope {
                    account: row_to_account(row)?,
                    workspace: WorkspaceRecord {
                        id: row.get(8)?,
                        account_id: row.get(9)?,
                        slug: row.get(10)?,
                        display_name: row.get(11)?,
                        legacy_project: row.get(12)?,
                        is_default: row.get::<_, i64>(13)? != 0,
                    },
                })
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                ApiError::new(ErrorCode::NotFound, format!("workspace route {project}"))
            }
            other => internal(other),
        })
    }

    pub fn workspace_by_id(&self, workspace_id: &str) -> Result<WorkspaceRecord> {
        let conn = self.conn.lock().unwrap();
        match conn.query_row(
            "SELECT id, account_id, slug, display_name, legacy_project, is_default
                   FROM workspaces WHERE id=?1",
            params![workspace_id],
            row_to_workspace,
        ) {
            Ok(workspace) => Ok(workspace),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Err(ApiError::new(ErrorCode::NotFound, "workspace not found"))
            }
            Err(error) => Err(internal(error)),
        }
    }

    pub fn project_belongs_to_organization(
        &self,
        project: &str,
        organization_id: &str,
    ) -> Result<bool> {
        self.with(|conn| {
            conn.query_row(
                "SELECT EXISTS(
                    SELECT 1
                      FROM workspaces w
                      JOIN accounts a ON a.id=w.account_id
                     WHERE w.legacy_project=?1
                       AND a.workos_organization_id=?2
                       AND a.status='active'
                 )",
                params![project, organization_id],
                |row| row.get(0),
            )
        })
    }

    pub fn billing_account_id_for_project(&self, project: &str) -> Result<String> {
        Ok(self
            .workspace_scope_for_project(project)?
            .account
            .billing_account_id)
    }

    /// Return every ledger that contributes to an Account balance. The first
    /// row is the canonical Account ledger used by all new writes; remaining
    /// rows are immutable V1 bindings retained only to aggregate history.
    pub fn billing_ledgers_for_project(&self, project: &str) -> Result<Vec<BillingLedgerRecord>> {
        let scope = self.workspace_scope_for_project(project)?;
        let mut historical = self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT billing_account_id, legacy_project
                   FROM legacy_billing_bindings
                  WHERE account_id=?1
                  ORDER BY legacy_project",
            )?;
            let rows = stmt.query_map(params![scope.account.id], |row| {
                Ok(BillingLedgerRecord {
                    billing_account_id: row.get(0)?,
                    owner_id: row.get(1)?,
                    signup_credit_nanos: 10_000_000_000,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })?;
        // An early account-migration shape reused one V1 project ledger as
        // the Account's canonical ledger. Preserve that immutable ledger's
        // original owner and do not aggregate it twice.
        let canonical = historical
            .iter()
            .position(|ledger| ledger.billing_account_id == scope.account.billing_account_id)
            .map(|index| historical.remove(index))
            .unwrap_or_else(|| BillingLedgerRecord {
                billing_account_id: scope.account.billing_account_id.clone(),
                owner_id: scope.account.id.clone(),
                signup_credit_nanos: if scope.account.kind == AccountKind::Personal {
                    10_000_000_000
                } else {
                    0
                },
            });
        let mut ledgers = vec![canonical];
        ledgers.append(&mut historical);
        Ok(ledgers)
    }

    pub fn account_and_workspace_views(
        &self,
        organization_id: &str,
        role: Option<&str>,
        permissions: &[String],
    ) -> Result<Option<(Account, Vec<Workspace>)>> {
        let Some(account) = self.account_for_organization(organization_id)? else {
            return Ok(None);
        };
        if account.status != "active" {
            return Ok(None);
        }
        let workspaces = self
            .workspaces_for_account(&account.id)?
            .into_iter()
            .map(|workspace| workspace_view(&account, workspace, role))
            .collect();
        Ok(Some((
            Account {
                id: account.id.clone(),
                slug: account.slug.clone(),
                display_name: account.display_name.clone(),
                kind: account.kind,
                organization_id: account.workos_organization_id.clone(),
                billing_account_id: account.billing_account_id.clone(),
                role: role.map(str::to_string),
                permissions: permissions.to_vec(),
            },
            workspaces,
        )))
    }

    pub fn record_invitation(
        &self,
        invitation: &AccountInvitation,
        workos_organization_id: &str,
    ) -> Result<()> {
        self.with(|conn| {
            conn.execute(
                "INSERT INTO account_invitations (
                    workos_invitation_id, account_id, workos_organization_id,
                    email, role_slug, state, expires_at, updated_at
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(workos_invitation_id) DO UPDATE SET
                    email=excluded.email, role_slug=excluded.role_slug,
                    state=excluded.state, expires_at=excluded.expires_at,
                    updated_at=excluded.updated_at",
                params![
                    invitation.id,
                    invitation.account_id,
                    workos_organization_id,
                    invitation.email,
                    invitation.role_slug,
                    invitation.state,
                    invitation.expires_at,
                    now_unix()
                ],
            )?;
            Ok(())
        })
    }

    pub fn upsert_membership_shadow(
        &self,
        membership_id: &str,
        account_id: &str,
        workos_user_id: &str,
        role_slug: &str,
        status: &str,
    ) -> Result<()> {
        self.with(|conn| {
            conn.execute(
                "INSERT INTO account_membership_shadow (
                    workos_membership_id, account_id, workos_user_id,
                    role_slug, status, updated_at
                 ) VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(account_id, workos_user_id) DO UPDATE SET
                    workos_membership_id=excluded.workos_membership_id,
                    role_slug=excluded.role_slug, status=excluded.status,
                    updated_at=excluded.updated_at",
                params![
                    membership_id,
                    account_id,
                    workos_user_id,
                    role_slug,
                    status,
                    now_unix()
                ],
            )?;
            Ok(())
        })
    }

    // ------------------------------------------------------------------
    // Cats
    // ------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn create_cat(
        &self,
        workspace: &WorkspaceRecord,
        name: &str,
        image: &str,
        cpus: u32,
        memory_mib: u64,
        root_disk_size: u64,
        auto_suspend: bool,
        extra_disk: Option<(&str, u64, &str)>, // (name, size, mount_path)
    ) -> Result<(Cat, Vec<Disk>, Operation)> {
        let project = &workspace.legacy_project;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let now = now_unix();
        let cat_id = new_id(ids::CAT_PREFIX);
        let root_disk_id = new_id(ids::DISK_PREFIX);
        let root_volume = new_id(ids::VOLUME_PREFIX);

        let insert_disk = |tx: &rusqlite::Transaction<'_>,
                           id: &str,
                           dname: &str,
                           kind: &str,
                           size: u64,
                           vol: &str,
                           state: &str|
         -> rusqlite::Result<()> {
            tx.execute(
                "INSERT INTO disks (
                    id, workspace_id, project, name, kind, size_bytes,
                    state, volume_id, created_at
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    id,
                    workspace.id,
                    project,
                    dname,
                    kind,
                    size as i64,
                    state,
                    vol,
                    now
                ],
            )?;
            Ok(())
        };

        let result: rusqlite::Result<()> = (|| {
            tx.execute(
                "INSERT INTO cats (
                    id, workspace_id, project, name, image, cpus, memory_mib,
                    root_disk_id, desired_state, observed_state, generation,
                    auto_suspend, created_at, observed_state_since_ms
                 ) VALUES (
                    ?1,?2,?3,?4,?5,?6,?7,?8,
                    'running','creating',1,?9,?10,?11
                 )",
                params![
                    cat_id,
                    workspace.id,
                    project,
                    name,
                    image,
                    cpus,
                    memory_mib as i64,
                    root_disk_id,
                    i64::from(auto_suspend),
                    now,
                    now.saturating_mul(1000)
                ],
            )?;
            let default_endpoint_id = new_id(ids::ENDPOINT_PREFIX);
            let default_hostname = public_endpoint_hostname(
                &Cat {
                    id: cat_id.clone(),
                    workspace_id: workspace.id.clone(),
                    project: project.to_string(),
                    name: name.to_string(),
                    image: image.to_string(),
                    spec: CatSpec { cpus, memory_mib },
                    root_disk_id: root_disk_id.clone(),
                    desired_state: DesiredState::Running,
                    observed_state: ObservedState::Creating,
                    generation: 1,
                    auto_suspend,
                    node_id: None,
                    created_at_unix: now,
                    observed_state_since_unix_ms: now.saturating_mul(1000),
                },
                DEFAULT_ENDPOINT_NAME,
            );
            tx.execute(
                "INSERT INTO endpoints
                    (id, cat_id, name, hostname, target_port, protocol, wake_policy)
                 VALUES (?1,?2,?3,?4,?5,'http','wake_on_request')",
                params![
                    default_endpoint_id,
                    cat_id,
                    DEFAULT_ENDPOINT_NAME,
                    default_hostname,
                    DEFAULT_ENDPOINT_PORT
                ],
            )?;
            tx.execute(
                "INSERT INTO routes
                    (hostname, cat_id, node_id, gateway_url, target_port, epoch, state)
                 VALUES (?1,?2,NULL,NULL,?3,0,'unbound')",
                params![default_hostname, cat_id, DEFAULT_ENDPOINT_PORT],
            )?;
            insert_disk(
                &tx,
                &root_disk_id,
                &format!("{name}-root"),
                "root",
                root_disk_size,
                &root_volume,
                "bound",
            )?;
            tx.execute(
                "INSERT INTO mount_bindings (id, disk_id, cat_id, mount_path)
                 VALUES (?1,?2,?3,'/')",
                params![new_id(ids::MOUNT_PREFIX), root_disk_id, cat_id],
            )?;
            if let Some((dname, dsize, dpath)) = extra_disk {
                let disk_id = new_id(ids::DISK_PREFIX);
                insert_disk(
                    &tx,
                    &disk_id,
                    dname,
                    "persistent",
                    dsize,
                    &new_id(ids::VOLUME_PREFIX),
                    "bound",
                )?;
                tx.execute(
                    "INSERT INTO mount_bindings (id, disk_id, cat_id, mount_path)
                     VALUES (?1,?2,?3,?4)",
                    params![new_id(ids::MOUNT_PREFIX), disk_id, cat_id, dpath],
                )?;
            }
            Ok(())
        })();
        result.map_err(|e| {
            if is_constraint(&e) {
                ApiError::new(
                    ErrorCode::AlreadyExists,
                    format!("cat or disk name in use: {e}"),
                )
            } else {
                internal(e)
            }
        })?;

        let op = Self::insert_operation(&tx, &workspace.id, project, "cat.create", &cat_id, 1)?;
        tx.commit().map_err(internal)?;
        drop(conn);

        let cat = self.must_get_cat_by_id(&cat_id)?;
        let disks = self.list_disks_for_cat(&cat_id)?;
        Ok((cat, disks, op))
    }

    fn insert_operation(
        tx: &rusqlite::Transaction<'_>,
        workspace_id: &str,
        project: &str,
        kind: &str,
        resource_id: &str,
        generation: i64,
    ) -> Result<Operation> {
        let now = now_unix();
        let id = new_id(ids::OPERATION_PREFIX);
        tx.execute(
            "INSERT INTO operations (
                id, workspace_id, project, kind, resource_id,
                resource_generation, phase, created_at, updated_at
             ) VALUES (?1,?2,?3,?4,?5,?6,'pending',?7,?7)",
            params![
                id,
                workspace_id,
                project,
                kind,
                resource_id,
                generation,
                now
            ],
        )
        .map_err(internal)?;
        Ok(Operation {
            id,
            workspace_id: workspace_id.to_string(),
            project: project.to_string(),
            kind: kind.to_string(),
            resource_id: resource_id.to_string(),
            resource_generation: generation,
            phase: OperationPhase::Pending,
            error: None,
            created_at_unix: now,
            updated_at_unix: now,
        })
    }

    fn fail_pending_auto_tier(
        tx: &rusqlite::Transaction<'_>,
        cat_id: &str,
        message: &str,
    ) -> Result<()> {
        let error = serde_json::to_string(&ErrorBody::new(ErrorCode::Conflict, message))
            .map_err(internal)?;
        tx.execute(
            "UPDATE operations SET phase='failed', error_json=?2, updated_at=?3
             WHERE resource_id=?1
               AND kind IN ('cat.auto_suspend','cat.auto_warm','cat.auto_cold')
               AND phase IN ('pending','running')",
            params![cat_id, error, now_unix()],
        )
        .map_err(internal)?;
        Ok(())
    }

    pub fn get_cat(&self, project: &str, name_or_id: &str) -> Result<Cat> {
        self.with(|c| {
            c.query_row(
                "SELECT * FROM cats WHERE project=?1 AND (name=?2 OR id=?2)",
                params![project, name_or_id],
                row_to_cat,
            )
            .optional()
        })?
        .ok_or_else(|| ApiError::not_found(format!("cat {name_or_id}")))
    }

    pub fn must_get_cat_by_id(&self, id: &str) -> Result<Cat> {
        self.with(|c| {
            c.query_row("SELECT * FROM cats WHERE id=?1", params![id], row_to_cat)
                .optional()
        })?
        .ok_or_else(|| ApiError::not_found(format!("cat {id}")))
    }

    pub fn list_cats(&self, project: &str) -> Result<Vec<Cat>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM cats WHERE project=?1 ORDER BY created_at")?;
            let rows = stmt.query_map(params![project], row_to_cat)?;
            rows.collect()
        })
    }

    pub fn list_all_cats(&self) -> Result<Vec<Cat>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM cats ORDER BY created_at")?;
            let rows = stmt.query_map([], row_to_cat)?;
            rows.collect()
        })
    }

    /// Bump generation and set a new desired state; returns the operation.
    pub fn set_desired(
        &self,
        cat_id: &str,
        desired: DesiredState,
        expected_generation: Option<i64>,
        op_kind: &str,
    ) -> Result<Operation> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let current: Option<(i64, String, String)> = tx
            .query_row(
                "SELECT generation, workspace_id, project FROM cats WHERE id=?1",
                params![cat_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(internal)?;
        let (current, workspace_id, project) =
            current.ok_or_else(|| ApiError::not_found(format!("cat {cat_id}")))?;
        if let Some(expected) = expected_generation {
            if expected != current {
                return Err(ApiError::conflict(format!(
                    "generation mismatch: expected {expected}, current {current}"
                )));
            }
        }
        if op_kind != "cat.auto_suspend" {
            Self::fail_pending_auto_tier(&tx, cat_id, "superseded by a newer Cat action")?;
        }
        let new_gen = current + 1;
        tx.execute(
            "UPDATE cats SET desired_state=?2, generation=?3 WHERE id=?1",
            params![cat_id, desired_str(desired), new_gen],
        )
        .map_err(internal)?;
        let op = Self::insert_operation(&tx, &workspace_id, &project, op_kind, cat_id, new_gen)?;
        tx.commit().map_err(internal)?;
        Ok(op)
    }

    /// Atomically request Running only if no other caller has already done
    /// so. Gateway and exec can race on the first request after sleep; one
    /// generation and one wake operation is enough for all of them.
    pub fn ensure_desired_running(&self, cat_id: &str) -> Result<Option<Operation>> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let current: Option<(i64, String, String, String)> = tx
            .query_row(
                "SELECT generation, workspace_id, project, desired_state FROM cats WHERE id=?1",
                params![cat_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(internal)?;
        let (generation, workspace_id, project, desired) =
            current.ok_or_else(|| ApiError::not_found(format!("cat {cat_id}")))?;
        if desired == "running" {
            return Ok(None);
        }
        Self::fail_pending_auto_tier(&tx, cat_id, "superseded by active work")?;
        let next = generation + 1;
        tx.execute(
            "UPDATE cats SET desired_state='running', generation=?2 WHERE id=?1",
            params![cat_id, next],
        )
        .map_err(internal)?;
        let operation =
            Self::insert_operation(&tx, &workspace_id, &project, "cat.wake", cat_id, next)?;
        tx.commit().map_err(internal)?;
        Ok(Some(operation))
    }

    pub fn set_observed(&self, cat_id: &str, observed: ObservedState) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE cats
                    SET observed_state_since_ms = CASE
                            WHEN observed_state=?2 THEN observed_state_since_ms
                            ELSE ?3
                        END,
                        observed_state=?2
                  WHERE id=?1",
                params![cat_id, observed_str(observed), now_ms()],
            )
            .map(|_| ())
        })
    }

    /// Record a physical transition result only while its transitional state
    /// is still current. This lets a stale suspend result describe reality
    /// without overwriting a newer stable generation.
    pub fn finish_transition(
        &self,
        cat_id: &str,
        transitional: ObservedState,
        target: ObservedState,
    ) -> Result<bool> {
        self.with(|c| {
            c.execute(
                "UPDATE cats
                    SET observed_state=?3, observed_state_since_ms=?4
                 WHERE id=?1 AND observed_state=?2",
                params![
                    cat_id,
                    observed_str(transitional),
                    observed_str(target),
                    now_ms()
                ],
            )
            .map(|changed| changed == 1)
        })
    }

    pub fn set_placement(&self, cat_id: &str, node_id: Option<&str>) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE cats SET node_id=?2 WHERE id=?1",
                params![cat_id, node_id],
            )
            .map(|_| ())
        })
    }

    pub fn delete_cat_row(&self, cat_id: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "DELETE FROM cat_work_leases WHERE cat_id=?1",
                params![cat_id],
            )?;
            c.execute(
                "DELETE FROM cat_work_sources WHERE cat_id=?1",
                params![cat_id],
            )?;
            c.execute(
                "DELETE FROM mount_bindings WHERE cat_id=?1",
                params![cat_id],
            )?;
            c.execute("DELETE FROM endpoints WHERE cat_id=?1", params![cat_id])?;
            c.execute("DELETE FROM routes WHERE cat_id=?1", params![cat_id])?;
            c.execute("DELETE FROM cats WHERE id=?1", params![cat_id])
                .map(|_| ())
        })
    }

    // ------------------------------------------------------------------
    // Work-driven auto-suspend
    // ------------------------------------------------------------------

    pub fn set_auto_suspend(&self, cat_id: &str, enabled: bool) -> Result<Cat> {
        self.with(|c| {
            c.execute(
                "UPDATE cats SET auto_suspend=?2 WHERE id=?1",
                params![cat_id, i64::from(enabled)],
            )
            .map(|_| ())
        })?;
        self.must_get_cat_by_id(cat_id)
    }

    pub fn acquire_work(
        &self,
        cat_id: &str,
        kind: WorkKind,
        owner_id: &str,
        label: &str,
        ttl_ms: u64,
    ) -> Result<WorkLease> {
        if owner_id.is_empty() || owner_id.len() > 128 {
            return Err(ApiError::invalid("work owner_id must be 1..128 bytes"));
        }
        if label.len() > 128 {
            return Err(ApiError::invalid("work label exceeds 128 bytes"));
        }
        if ttl_ms == 0 || ttl_ms > cats_api::guest::MAX_WORK_LEASE_TTL_MS {
            return Err(ApiError::invalid("work TTL is outside the allowed range"));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let project_exists: Option<String> = tx
            .query_row(
                "SELECT project FROM cats WHERE id=?1",
                params![cat_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(internal)?;
        project_exists.ok_or_else(|| ApiError::not_found(format!("cat {cat_id}")))?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT id FROM cat_work_leases
                 WHERE cat_id=?1 AND kind=?2 AND owner_id=?3",
                params![cat_id, work_kind_str(kind), owner_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(internal)?;
        let id = existing.unwrap_or_else(|| new_id("work_"));
        let expires_at_ms = now_ms().saturating_add(ttl_ms as i64);
        tx.execute(
            "INSERT INTO cat_work_leases
                (id, cat_id, kind, owner_id, label, expires_at_ms, source_epoch)
             VALUES (?1,?2,?3,?4,?5,?6,NULL)
             ON CONFLICT(cat_id, kind, owner_id) DO UPDATE SET
                label=?5, expires_at_ms=?6",
            params![
                id,
                cat_id,
                work_kind_str(kind),
                owner_id,
                label,
                expires_at_ms
            ],
        )
        .map_err(internal)?;
        tx.execute(
            "UPDATE cats SET work_version=work_version+1 WHERE id=?1",
            params![cat_id],
        )
        .map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok(WorkLease {
            id,
            cat_id: cat_id.to_string(),
            kind,
            owner_id: owner_id.to_string(),
            label: label.to_string(),
            expires_at_unix_ms: expires_at_ms,
        })
    }

    pub fn release_work(&self, lease_id: &str) -> Result<Option<String>> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let cat_id: Option<String> = tx
            .query_row(
                "SELECT cat_id FROM cat_work_leases WHERE id=?1",
                params![lease_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(internal)?;
        if let Some(cat_id) = &cat_id {
            tx.execute("DELETE FROM cat_work_leases WHERE id=?1", params![lease_id])
                .map_err(internal)?;
            tx.execute(
                "UPDATE cats SET work_version=work_version+1 WHERE id=?1",
                params![cat_id],
            )
            .map_err(internal)?;
        }
        tx.commit().map_err(internal)?;
        Ok(cat_id)
    }

    /// Replace the complete set of user-program Guest leases for the current
    /// source epoch/sequence. Returns true when active Guest work must wake a
    /// concurrently auto-suspending Cat.
    pub fn ingest_guest_work(
        &self,
        request: &cats_api::requests::NodeWorkStatusRequest,
    ) -> Result<bool> {
        if request.guest_source_epoch.is_empty()
            || request.guest_source_epoch.len() > 128
            || !request
                .guest_source_epoch
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ApiError::invalid("invalid guest source epoch"));
        }
        if request.leases.len() > cats_api::guest::MAX_WORK_LEASES {
            return Err(ApiError::invalid("too many Guest work leases"));
        }
        for lease in &request.leases {
            if lease.id.is_empty() || lease.id.len() > 128 || lease.label.len() > 128 {
                return Err(ApiError::invalid("invalid Guest work lease"));
            }
        }
        let request_sequence = i64::try_from(request.guest_lease_sequence)
            .map_err(|_| ApiError::invalid("guest lease sequence is too large"))?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let cat: Option<(String, String, i64, String, String, Option<String>)> = tx
            .query_row(
                "SELECT workspace_id, project, generation, desired_state, observed_state, node_id
                 FROM cats WHERE id=?1",
                params![request.cat_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(internal)?;
        let (workspace_id, project, generation, desired, observed, node_id) =
            cat.ok_or_else(|| ApiError::not_found(format!("cat {}", request.cat_id)))?;
        if node_id.as_deref() != Some(request.node_id.as_str()) {
            return Err(ApiError::conflict(
                "work status came from a non-owning node",
            ));
        }
        let current_or_auto_transition = request.generation == generation
            || (request.generation + 1 == generation
                && desired == "suspended"
                && matches!(observed.as_str(), "running" | "suspending"));
        if !current_or_auto_transition {
            return Err(ApiError::conflict("work status generation is stale"));
        }

        let previous: Option<(String, i64)> = tx
            .query_row(
                "SELECT source_epoch, lease_sequence FROM cat_work_sources WHERE cat_id=?1",
                params![request.cat_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(internal)?;
        if let Some((epoch, sequence)) = &previous {
            if epoch == &request.guest_source_epoch && request_sequence < *sequence {
                return Ok(false);
            }
        }

        let now = now_ms();
        let changed = previous.as_ref().is_none_or(|(epoch, sequence)| {
            epoch != &request.guest_source_epoch || *sequence != request_sequence
        });
        tx.execute(
            "INSERT INTO cat_work_sources
                (cat_id, node_id, generation, source_epoch, lease_sequence, seen_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(cat_id) DO UPDATE SET
                node_id=?2, generation=?3, source_epoch=?4,
                lease_sequence=?5, seen_at_ms=?6",
            params![
                request.cat_id,
                request.node_id,
                request.generation,
                request.guest_source_epoch,
                request_sequence,
                now
            ],
        )
        .map_err(internal)?;

        if changed {
            tx.execute(
                "DELETE FROM cat_work_leases WHERE cat_id=?1 AND kind='guest'",
                params![request.cat_id],
            )
            .map_err(internal)?;
            for guest in request.leases.iter().take(cats_api::guest::MAX_WORK_LEASES) {
                if guest.remaining_ttl_ms == 0 {
                    continue;
                }
                let ttl = guest
                    .remaining_ttl_ms
                    .min(cats_api::guest::MAX_WORK_LEASE_TTL_MS);
                let id = format!(
                    "guest_{}_{}",
                    &request.guest_source_epoch[..request.guest_source_epoch.len().min(12)],
                    guest.id
                );
                let owner = format!("{}:{}", request.guest_source_epoch, guest.id);
                tx.execute(
                    "INSERT INTO cat_work_leases
                        (id, cat_id, kind, owner_id, label, expires_at_ms, source_epoch)
                     VALUES (?1,?2,'guest',?3,?4,?5,?6)",
                    params![
                        id,
                        request.cat_id,
                        owner,
                        guest.label.chars().take(128).collect::<String>(),
                        now.saturating_add(ttl as i64),
                        request.guest_source_epoch
                    ],
                )
                .map_err(internal)?;
            }
            tx.execute(
                "UPDATE cats SET work_version=work_version+1 WHERE id=?1",
                params![request.cat_id],
            )
            .map_err(internal)?;
        }

        let has_guest_work = request
            .leases
            .iter()
            .any(|lease| lease.remaining_ttl_ms > 0);
        let cancel_inflight_suspend = has_guest_work
            && desired == "suspended"
            && matches!(observed.as_str(), "running" | "suspending");
        let wake_suspended = has_guest_work && desired != "running" && observed == "suspended";
        let should_wake = cancel_inflight_suspend || wake_suspended;
        if cancel_inflight_suspend {
            Self::fail_pending_auto_tier(&tx, &request.cat_id, "superseded by Guest work")?;
            // The physical suspend for this generation has not committed.
            // Cancel it in-place so the Node and its work watcher can both
            // converge on the job generation after ActivityChanged.
            tx.execute(
                "UPDATE cats SET desired_state='running' WHERE id=?1",
                params![request.cat_id],
            )
            .map_err(internal)?;
        } else if wake_suspended {
            Self::fail_pending_auto_tier(&tx, &request.cat_id, "superseded by Guest work")?;
            let new_generation = generation + 1;
            tx.execute(
                "UPDATE cats SET desired_state='running', generation=?2 WHERE id=?1",
                params![request.cat_id, new_generation],
            )
            .map_err(internal)?;
            Self::insert_operation(
                &tx,
                &workspace_id,
                &project,
                "cat.work_wake",
                &request.cat_id,
                new_generation,
            )?;
        }
        tx.commit().map_err(internal)?;
        Ok(should_wake)
    }

    pub fn work_status(&self, cat_id: &str, signal_stale_ms: i64) -> Result<CatWorkStatus> {
        let cat = self.must_get_cat_by_id(cat_id)?;
        let now = now_ms();
        let leases = self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, cat_id, kind, owner_id, label, expires_at_ms
                 FROM cat_work_leases
                 WHERE cat_id=?1 AND expires_at_ms>?2
                 ORDER BY kind, id",
            )?;
            let rows = stmt.query_map(params![cat_id, now], row_to_work_lease)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })?;
        let source: Option<i64> = self.with(|c| {
            c.query_row(
                "SELECT seen_at_ms FROM cat_work_sources WHERE cat_id=?1",
                params![cat_id],
                |row| row.get(0),
            )
            .optional()
        })?;
        let age = source.map(|seen| now.saturating_sub(seen).max(0) as u64);
        let guest_signal_fresh = age.is_some_and(|age| age <= signal_stale_ms.max(0) as u64);
        let active_work_count = leases.len() as u32;
        let stable_running = cat.desired_state == DesiredState::Running
            && cat.observed_state == ObservedState::Running;
        let can_suspend_now =
            cat.auto_suspend && stable_running && guest_signal_fresh && leases.is_empty();
        let reason = if !cat.auto_suspend {
            "policy_off"
        } else if !stable_running {
            "lifecycle_in_progress"
        } else if !guest_signal_fresh {
            "guest_lease_signal_stale"
        } else if !leases.is_empty() {
            "active_work"
        } else {
            "eligible"
        };
        let work_version = self.with(|c| {
            c.query_row(
                "SELECT work_version FROM cats WHERE id=?1",
                params![cat_id],
                |row| row.get(0),
            )
        })?;
        Ok(CatWorkStatus {
            cat_id: cat_id.to_string(),
            auto_suspend: cat.auto_suspend,
            work_version,
            active_work_count,
            leases,
            guest_signal_fresh,
            guest_signal_age_ms: age,
            can_suspend_now,
            reason: reason.to_string(),
        })
    }

    pub fn suspend_work_fence(&self, cat_id: &str) -> Result<cats_api::nodejob::SuspendWorkFence> {
        self.with(|c| {
            c.query_row(
                "SELECT c.work_version, COALESCE(s.lease_sequence, 0)
                 FROM cats c LEFT JOIN cat_work_sources s ON s.cat_id=c.id
                 WHERE c.id=?1",
                params![cat_id],
                |row| {
                    Ok(cats_api::nodejob::SuspendWorkFence {
                        control_work_version: row.get(0)?,
                        guest_lease_sequence: row.get::<_, i64>(1)? as u64,
                    })
                },
            )
        })
    }

    pub fn auto_suspend_candidates(&self) -> Result<Vec<String>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id FROM cats
                 WHERE auto_suspend=1 AND desired_state='running' AND observed_state='running'",
            )?;
            let rows = stmt.query_map([], |row| row.get(0))?;
            rows.collect()
        })
    }

    pub fn try_auto_suspend(
        &self,
        cat_id: &str,
        signal_stale_ms: i64,
    ) -> Result<Option<Operation>> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let now = now_ms();
        let expired = tx
            .execute(
                "DELETE FROM cat_work_leases WHERE cat_id=?1 AND expires_at_ms<=?2",
                params![cat_id, now],
            )
            .map_err(internal)?;
        if expired > 0 {
            tx.execute(
                "UPDATE cats SET work_version=work_version+1 WHERE id=?1",
                params![cat_id],
            )
            .map_err(internal)?;
        }
        let cat: Option<(String, String, i64, i64, String, String)> = tx
            .query_row(
                "SELECT workspace_id, project, generation, auto_suspend,
                        desired_state, observed_state
                 FROM cats WHERE id=?1",
                params![cat_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(internal)?;
        let Some((workspace_id, project, generation, auto_suspend, desired, observed)) = cat else {
            return Ok(None);
        };
        if auto_suspend == 0 || desired != "running" || observed != "running" {
            return Ok(None);
        }
        let source_seen: Option<i64> = tx
            .query_row(
                "SELECT seen_at_ms FROM cat_work_sources WHERE cat_id=?1",
                params![cat_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(internal)?;
        if !source_seen.is_some_and(|seen| now.saturating_sub(seen) <= signal_stale_ms) {
            return Ok(None);
        }
        let active: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM cat_work_leases
                 WHERE cat_id=?1 AND expires_at_ms>?2",
                params![cat_id, now],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if active != 0 {
            return Ok(None);
        }
        let next = generation + 1;
        let changed = tx
            .execute(
                "UPDATE cats SET desired_state='suspended', generation=?2
                 WHERE id=?1 AND generation=?3 AND desired_state='running'
                   AND observed_state='running' AND auto_suspend=1
                   AND NOT EXISTS (
                     SELECT 1 FROM cat_work_leases
                     WHERE cat_id=?1 AND expires_at_ms>?4)",
                params![cat_id, next, generation, now],
            )
            .map_err(internal)?;
        if changed == 0 {
            return Ok(None);
        }
        let operation = Self::insert_operation(
            &tx,
            &workspace_id,
            &project,
            "cat.auto_suspend",
            cat_id,
            next,
        )?;
        tx.commit().map_err(internal)?;
        Ok(Some(operation))
    }

    /// Stable sleeping Cats whose persisted state age has crossed the next
    /// automatic tier boundary. This is only a scan optimization; the
    /// transaction in `try_auto_tier` is the decision linearization point.
    pub fn auto_tier_candidates(
        &self,
        warm_after_ms: Option<i64>,
        cold_after_ms: Option<i64>,
    ) -> Result<Vec<String>> {
        let now = now_ms();
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, observed_state, observed_state_since_ms
                   FROM cats
                  WHERE auto_suspend=1
                    AND desired_state=observed_state
                    AND observed_state IN ('suspended','warm')",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
            let mut candidates = Vec::new();
            for row in rows {
                let (id, state, since_ms) = row?;
                let threshold = match state.as_str() {
                    "suspended" => warm_after_ms,
                    "warm" => cold_after_ms,
                    _ => None,
                };
                if threshold.is_some_and(|threshold| now.saturating_sub(since_ms) >= threshold) {
                    candidates.push(id);
                }
            }
            Ok(candidates)
        })
    }

    /// Atomically deepen a stable, inactive Cat by one tier:
    /// Suspended -> Warm or Warm -> Cold.
    ///
    /// The elapsed clock is persisted with the observed state, so a control
    /// plane restart neither resets nor accelerates the policy. Any live work
    /// lease wins the race and blocks the transition.
    pub fn try_auto_tier(
        &self,
        cat_id: &str,
        warm_after_ms: Option<i64>,
        cold_after_ms: Option<i64>,
    ) -> Result<Option<Operation>> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let now = now_ms();
        let expired = tx
            .execute(
                "DELETE FROM cat_work_leases WHERE cat_id=?1 AND expires_at_ms<=?2",
                params![cat_id, now],
            )
            .map_err(internal)?;
        if expired > 0 {
            tx.execute(
                "UPDATE cats SET work_version=work_version+1 WHERE id=?1",
                params![cat_id],
            )
            .map_err(internal)?;
        }

        let cat: Option<(String, String, i64, i64, String, String, i64)> = tx
            .query_row(
                "SELECT workspace_id, project, generation, auto_suspend,
                        desired_state, observed_state, observed_state_since_ms
                   FROM cats WHERE id=?1",
                params![cat_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(internal)?;
        let Some((workspace_id, project, generation, auto_suspend, desired, observed, since_ms)) =
            cat
        else {
            return Ok(None);
        };
        if auto_suspend == 0 || desired != observed {
            return Ok(None);
        }
        let (threshold_ms, next_state, operation_kind) = match observed.as_str() {
            "suspended" => (warm_after_ms, "warm", "cat.auto_warm"),
            "warm" => (cold_after_ms, "cold", "cat.auto_cold"),
            _ => return Ok(None),
        };
        let Some(threshold_ms) = threshold_ms else {
            return Ok(None);
        };
        if now.saturating_sub(since_ms) < threshold_ms {
            return Ok(None);
        }
        let active: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM cat_work_leases
                  WHERE cat_id=?1 AND expires_at_ms>?2",
                params![cat_id, now],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if active != 0 {
            return Ok(None);
        }

        let next_generation = generation + 1;
        let changed = tx
            .execute(
                "UPDATE cats
                    SET desired_state=?2, generation=?3
                  WHERE id=?1
                    AND generation=?4
                    AND auto_suspend=1
                    AND desired_state=?5
                    AND observed_state=?5
                    AND observed_state_since_ms=?6
                    AND NOT EXISTS (
                        SELECT 1 FROM cat_work_leases
                         WHERE cat_id=?1 AND expires_at_ms>?7
                    )",
                params![
                    cat_id,
                    next_state,
                    next_generation,
                    generation,
                    observed,
                    since_ms,
                    now
                ],
            )
            .map_err(internal)?;
        if changed == 0 {
            return Ok(None);
        }
        let operation = Self::insert_operation(
            &tx,
            &workspace_id,
            &project,
            operation_kind,
            cat_id,
            next_generation,
        )?;
        tx.commit().map_err(internal)?;
        Ok(Some(operation))
    }

    pub fn cancel_rejected_suspend(&self, cat_id: &str, job_generation: i64) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let current: Option<(i64, String, String)> = tx
            .query_row(
                "SELECT generation, desired_state, observed_state FROM cats WHERE id=?1",
                params![cat_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(internal)?;
        let Some((generation, desired, observed)) = current else {
            return Ok(());
        };
        let error = serde_json::to_string(&ErrorBody::new(
            ErrorCode::Conflict,
            "work arrived while preparing to suspend",
        ))
        .map_err(internal)?;
        tx.execute(
            "UPDATE operations SET phase='failed', error_json=?3, updated_at=?4
             WHERE resource_id=?1 AND resource_generation=?2
               AND phase IN ('pending','running')",
            params![cat_id, job_generation, error, now_unix()],
        )
        .map_err(internal)?;
        if observed == "suspending" {
            tx.execute(
                "UPDATE cats
                    SET observed_state='running', observed_state_since_ms=?2
                  WHERE id=?1",
                params![cat_id, now_ms()],
            )
            .map_err(internal)?;
        }
        if generation == job_generation && desired == "suspended" {
            tx.execute(
                "UPDATE cats SET desired_state='running' WHERE id=?1",
                params![cat_id],
            )
            .map_err(internal)?;
        }
        tx.commit().map_err(internal)?;
        Ok(())
    }

    /// Cats whose desired/observed disagree (work for the reconciler).
    pub fn cats_needing_work(&self) -> Result<Vec<Cat>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT * FROM cats WHERE
                   (desired_state='running'   AND observed_state NOT IN ('running'))
                OR (desired_state='suspended' AND observed_state NOT IN ('suspended'))
                OR (desired_state='warm'      AND observed_state NOT IN ('warm'))
                OR (desired_state='cold'      AND observed_state NOT IN ('cold'))
                OR (desired_state='deleted'   AND observed_state NOT IN ('deleted'))
                ORDER BY created_at",
            )?;
            let rows = stmt.query_map([], row_to_cat)?;
            rows.collect()
        })
    }

    // ------------------------------------------------------------------
    // Disks / bindings / attachments
    // ------------------------------------------------------------------

    pub fn create_disk(
        &self,
        workspace: &WorkspaceRecord,
        name: &str,
        size_bytes: u64,
    ) -> Result<Disk> {
        let id = new_id(ids::DISK_PREFIX);
        let vol = new_id(ids::VOLUME_PREFIX);
        let now = now_unix();
        self.with(|c| {
            c.execute(
                "INSERT INTO disks (
                    id, workspace_id, project, name, kind, size_bytes,
                    state, volume_id, created_at
                 ) VALUES (?1,?2,?3,?4,'persistent',?5,'available',?6,?7)",
                params![
                    id,
                    workspace.id,
                    workspace.legacy_project,
                    name,
                    size_bytes as i64,
                    vol,
                    now
                ],
            )
            .map(|_| ())
        })
        .map_err(|e| {
            if e.code == ErrorCode::Conflict {
                ApiError::new(ErrorCode::AlreadyExists, format!("disk name {name} in use"))
            } else {
                e
            }
        })?;
        self.get_disk(&workspace.legacy_project, &id)
    }

    pub fn get_disk(&self, project: &str, name_or_id: &str) -> Result<Disk> {
        let mut disk = self
            .with(|c| {
                c.query_row(
                    "SELECT * FROM disks WHERE project=?1 AND (name=?2 OR id=?2)",
                    params![project, name_or_id],
                    row_to_disk,
                )
                .optional()
            })?
            .ok_or_else(|| ApiError::not_found(format!("disk {name_or_id}")))?;
        disk.bound_cat_id = self.with(|c| {
            c.query_row(
                "SELECT cat_id FROM mount_bindings WHERE disk_id=?1",
                params![disk.id],
                |r| r.get(0),
            )
            .optional()
        })?;
        Ok(disk)
    }

    pub fn list_disks(&self, project: &str) -> Result<Vec<Disk>> {
        let mut disks = self.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM disks WHERE project=?1 ORDER BY created_at")?;
            let rows = stmt.query_map(params![project], row_to_disk)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })?;
        for d in &mut disks {
            d.bound_cat_id = self.with(|c| {
                c.query_row(
                    "SELECT cat_id FROM mount_bindings WHERE disk_id=?1",
                    params![d.id],
                    |r| r.get(0),
                )
                .optional()
            })?;
        }
        Ok(disks)
    }

    pub fn list_disks_for_cat(&self, cat_id: &str) -> Result<Vec<Disk>> {
        let ids: Vec<String> = self.with(|c| {
            let mut stmt =
                c.prepare("SELECT disk_id FROM mount_bindings WHERE cat_id=?1 ORDER BY id")?;
            let rows = stmt.query_map(params![cat_id], |r| r.get(0))?;
            rows.collect()
        })?;
        let mut out = Vec::new();
        for id in ids {
            let d = self.with(|c| {
                c.query_row("SELECT * FROM disks WHERE id=?1", params![id], row_to_disk)
                    .optional()
            })?;
            if let Some(mut d) = d {
                d.bound_cat_id = Some(cat_id.to_string());
                out.push(d);
            }
        }
        Ok(out)
    }

    pub fn get_binding(&self, disk_id: &str) -> Result<Option<MountBinding>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, disk_id, cat_id, mount_path FROM mount_bindings WHERE disk_id=?1",
                params![disk_id],
                |r| {
                    Ok(MountBinding {
                        id: r.get(0)?,
                        disk_id: r.get(1)?,
                        cat_id: r.get(2)?,
                        mount_path: r.get(3)?,
                    })
                },
            )
            .optional()
        })
    }

    pub fn bindings_for_cat(&self, cat_id: &str) -> Result<Vec<MountBinding>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, disk_id, cat_id, mount_path FROM mount_bindings WHERE cat_id=?1 ORDER BY id",
            )?;
            let rows = stmt.query_map(params![cat_id], |r| {
                Ok(MountBinding {
                    id: r.get(0)?,
                    disk_id: r.get(1)?,
                    cat_id: r.get(2)?,
                    mount_path: r.get(3)?,
                })
            })?;
            rows.collect()
        })
    }

    /// RWO: unique index on mount_bindings.disk_id makes a second bind fail.
    pub fn bind_disk(&self, disk_id: &str, cat_id: &str, mount_path: &str) -> Result<MountBinding> {
        let id = new_id(ids::MOUNT_PREFIX);
        self.with(|c| {
            c.execute(
                "INSERT INTO mount_bindings (id, disk_id, cat_id, mount_path) VALUES (?1,?2,?3,?4)",
                params![id, disk_id, cat_id, mount_path],
            )?;
            c.execute(
                "UPDATE disks SET state='bound' WHERE id=?1",
                params![disk_id],
            )?;
            Ok(())
        })
        .map_err(|e| {
            if e.code == ErrorCode::Conflict {
                ApiError::conflict("disk is already bound (RWO)")
            } else {
                e
            }
        })?;
        Ok(MountBinding {
            id,
            disk_id: disk_id.to_string(),
            cat_id: cat_id.to_string(),
            mount_path: mount_path.to_string(),
        })
    }

    pub fn unbind_disk(&self, disk_id: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "DELETE FROM mount_bindings WHERE disk_id=?1",
                params![disk_id],
            )?;
            c.execute(
                "UPDATE disks SET state='available' WHERE id=?1 AND kind='persistent'",
                params![disk_id],
            )
            .map(|_| ())
        })
    }

    pub fn set_disk_state(&self, disk_id: &str, state: DiskState) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE disks SET state=?2 WHERE id=?1",
                params![disk_id, disk_state_str(state)],
            )
            .map(|_| ())
        })
    }

    pub fn set_disk_size(&self, disk_id: &str, size: u64) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE disks SET size_bytes=?2 WHERE id=?1",
                params![disk_id, size as i64],
            )
            .map(|_| ())
        })
    }

    pub fn delete_disk_row(&self, disk_id: &str) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM disks WHERE id=?1", params![disk_id])
                .map(|_| ())
        })
    }

    // ------------------------------------------------------------------
    // Nodes
    // ------------------------------------------------------------------

    pub fn register_node(
        &self,
        node_id: &str,
        agent_url: &str,
        gateway_url: &str,
        cpus: u32,
        memory_mib: u64,
    ) -> Result<()> {
        let now = now_ms();
        self.with(|c| {
            c.execute(
                "INSERT INTO nodes (id, agent_url, gateway_url, state, cpus, memory_mib,
                                    last_heartbeat_ms, scheduling_disabled)
                 VALUES (?1,?2,?3,'ready',?4,?5,?6,0)
                 ON CONFLICT(id) DO UPDATE SET
                   agent_url=?2, gateway_url=?3,
                   state=CASE
                       WHEN nodes.state='draining' THEN 'draining'
                       WHEN nodes.scheduling_disabled=1 THEN 'cordoned'
                       ELSE 'ready'
                   END,
                   cpus=?4, memory_mib=?5, last_heartbeat_ms=?6",
                params![
                    node_id,
                    agent_url,
                    gateway_url,
                    cpus,
                    memory_mib as i64,
                    now
                ],
            )
            .map(|_| ())
        })
    }

    pub fn heartbeat_node(&self, node_id: &str, telemetry: Option<&NodeTelemetry>) -> Result<()> {
        let telemetry_json = telemetry
            .map(|value| serde_json::to_string(value).expect("node telemetry must serialize"));
        let n = self.with(|c| {
            c.execute(
                "UPDATE nodes SET last_heartbeat_ms=?2, telemetry_json=?3,
                                  state=CASE
                                      WHEN state='lost' AND scheduling_disabled=1 THEN 'cordoned'
                                      WHEN state='lost' THEN 'ready'
                                      ELSE state
                                  END
                 WHERE id=?1",
                params![node_id, now_ms(), telemetry_json],
            )
        })?;
        if n == 0 {
            return Err(ApiError::not_found(format!("node {node_id}")));
        }
        Ok(())
    }

    pub fn list_nodes(&self) -> Result<Vec<Node>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM nodes ORDER BY id")?;
            let rows = stmt.query_map([], row_to_node)?;
            rows.collect()
        })
    }

    pub fn get_node(&self, node_id: &str) -> Result<Node> {
        self.with(|c| {
            c.query_row(
                "SELECT * FROM nodes WHERE id=?1",
                params![node_id],
                row_to_node,
            )
            .optional()
        })?
        .ok_or_else(|| ApiError::not_found(format!("node {node_id}")))
    }

    pub fn set_node_state(&self, node_id: &str, state: NodeState) -> Result<()> {
        let state = node_state_str(state);
        let n = self.with(|c| {
            c.execute(
                "UPDATE nodes
                    SET state=CASE
                            WHEN ?2='cordoned' AND state='lost' THEN state
                            ELSE ?2
                        END,
                        scheduling_disabled=CASE
                            WHEN ?2='ready' THEN 0
                            WHEN ?2 IN ('cordoned','draining') THEN 1
                            ELSE scheduling_disabled
                        END
                  WHERE id=?1",
                params![node_id, state],
            )
        })?;
        if n == 0 {
            return Err(ApiError::not_found(format!("node {node_id}")));
        }
        Ok(())
    }

    pub fn cats_on_node(&self, node_id: &str) -> Result<Vec<Cat>> {
        self.with(|c| {
            let mut stmt =
                c.prepare("SELECT * FROM cats WHERE node_id=?1 ORDER BY project, name")?;
            let rows = stmt.query_map(params![node_id], row_to_cat)?;
            rows.collect()
        })
    }

    pub fn node_summary(&self, node_id: &str) -> Result<NodeSummary> {
        let node = self.get_node(node_id)?;
        let cats = self.cats_on_node(node_id)?;
        Ok(summarize_node(node, &cats))
    }

    pub fn list_node_summaries(&self) -> Result<Vec<NodeSummary>> {
        self.list_nodes()?
            .into_iter()
            .map(|node| {
                let cats = self.cats_on_node(&node.id)?;
                Ok(summarize_node(node, &cats))
            })
            .collect()
    }

    pub fn node_cat_summaries(&self, node_id: &str) -> Result<Vec<NodeCatSummary>> {
        let node = self.get_node(node_id)?;
        let mut actual_by_cat: HashMap<String, CatResourceTelemetry> = node
            .telemetry
            .map(|telemetry| {
                telemetry
                    .cat_resources
                    .into_iter()
                    .map(|actual| (actual.cat_id.clone(), actual))
                    .collect()
            })
            .unwrap_or_default();
        self.cats_on_node(node_id)?
            .into_iter()
            .map(|cat| {
                let requested_disk_bytes = self
                    .list_disks_for_cat(&cat.id)?
                    .into_iter()
                    .fold(0_u64, |total, disk| total.saturating_add(disk.size_bytes));
                let actual = actual_by_cat.remove(&cat.id);
                Ok(NodeCatSummary {
                    cat,
                    requested_disk_bytes,
                    actual,
                })
            })
            .collect()
    }

    pub fn delete_node(&self, node_id: &str) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(internal)?;
        let assigned: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM cats WHERE node_id=?1",
                params![node_id],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if assigned != 0 {
            return Err(ApiError::failed_precondition(
                "node still owns Cats; drain it before deletion",
            ));
        }
        let state: Option<String> = tx
            .query_row(
                "SELECT state FROM nodes WHERE id=?1",
                params![node_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(internal)?;
        let state = state.ok_or_else(|| ApiError::not_found(format!("node {node_id}")))?;
        if state == "ready" || state == "draining" {
            return Err(ApiError::failed_precondition(
                "only cordoned or lost nodes can be deleted",
            ));
        }
        tx.execute("DELETE FROM nodes WHERE id=?1", params![node_id])
            .map_err(internal)?;
        tx.commit().map_err(internal)
    }

    // ------------------------------------------------------------------
    // Operations / idempotency
    // ------------------------------------------------------------------

    pub fn get_operation(&self, id: &str) -> Result<Operation> {
        self.with(|c| {
            c.query_row(
                "SELECT * FROM operations WHERE id=?1",
                params![id],
                row_to_operation,
            )
            .optional()
        })?
        .ok_or_else(|| ApiError::not_found(format!("operation {id}")))
    }

    pub fn list_operations(&self, project: &str) -> Result<Vec<Operation>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT * FROM operations WHERE project=?1 ORDER BY created_at DESC, id DESC",
            )?;
            let rows = stmt.query_map(params![project], row_to_operation)?;
            rows.collect()
        })
    }

    pub fn operation_counts(&self) -> Result<OperationCounts> {
        self.with(|c| {
            c.query_row(
                "SELECT
                    SUM(CASE WHEN phase='pending' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN phase='running' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN phase='succeeded' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN phase='failed' THEN 1 ELSE 0 END)
                 FROM operations",
                [],
                |row| {
                    Ok(OperationCounts {
                        pending: row.get::<_, Option<i64>>(0)?.unwrap_or(0) as u64,
                        running: row.get::<_, Option<i64>>(1)?.unwrap_or(0) as u64,
                        succeeded: row.get::<_, Option<i64>>(2)?.unwrap_or(0) as u64,
                        failed: row.get::<_, Option<i64>>(3)?.unwrap_or(0) as u64,
                    })
                },
            )
        })
    }

    pub fn pending_operations_for(&self, resource_id: &str) -> Result<Vec<Operation>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT * FROM operations WHERE resource_id=?1 AND phase IN ('pending','running')",
            )?;
            let rows = stmt.query_map(params![resource_id], row_to_operation)?;
            rows.collect()
        })
    }

    pub fn finish_operation(&self, op_id: &str, error: Option<&ErrorBody>) -> Result<()> {
        let phase = if error.is_some() {
            "failed"
        } else {
            "succeeded"
        };
        let err_json = error.map(|e| serde_json::to_string(e).expect("error serializes"));
        self.with(|c| {
            c.execute(
                "UPDATE operations SET phase=?2, error_json=?3, updated_at=?4
                 WHERE id=?1 AND phase IN ('pending','running')",
                params![op_id, phase, err_json, now_unix()],
            )
            .map(|_| ())
        })
    }

    /// Returns the previously stored operation id for this idempotency key.
    pub fn idempotency_lookup(&self, key: &str, route: &str) -> Result<Option<String>> {
        self.with(|c| {
            c.query_row(
                "SELECT operation_id FROM idempotency WHERE key=?1 AND route=?2",
                params![key, route],
                |r| r.get(0),
            )
            .optional()
        })
    }

    pub fn idempotency_store(&self, key: &str, route: &str, operation_id: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT OR IGNORE INTO idempotency (key, route, operation_id) VALUES (?1,?2,?3)",
                params![key, route, operation_id],
            )
            .map(|_| ())
        })
    }

    // ------------------------------------------------------------------
    // Endpoints / routes
    // ------------------------------------------------------------------

    pub fn create_endpoint(
        &self,
        cat: &Cat,
        name: &str,
        target_port: u16,
        protocol: &str,
        wake: WakePolicy,
    ) -> Result<Endpoint> {
        if let Some(mut endpoint) = self
            .endpoints_for_cat(&cat.id)?
            .into_iter()
            .find(|endpoint| endpoint.name == name)
        {
            if name != DEFAULT_ENDPOINT_NAME {
                return Err(ApiError::new(
                    ErrorCode::AlreadyExists,
                    "endpoint name in use",
                ));
            }
            self.with(|connection| {
                connection.execute(
                    "UPDATE endpoints
                        SET target_port=?2, protocol=?3, wake_policy=?4
                      WHERE id=?1",
                    params![endpoint.id, target_port, protocol, wake_str(wake)],
                )?;
                connection.execute(
                    "UPDATE routes
                        SET target_port=?2, epoch=epoch+1
                      WHERE hostname=?1",
                    params![endpoint.hostname, target_port],
                )?;
                Ok(())
            })?;
            endpoint.target_port = target_port;
            endpoint.protocol = protocol.to_string();
            endpoint.wake_policy = wake;
            return Ok(endpoint);
        }
        let id = new_id(ids::ENDPOINT_PREFIX);
        let hostname = public_endpoint_hostname(cat, name);
        self.with(|c| {
            c.execute(
                "INSERT INTO endpoints (id, cat_id, name, hostname, target_port, protocol, wake_policy)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    id,
                    cat.id,
                    name,
                    hostname,
                    target_port,
                    protocol,
                    wake_str(wake)
                ],
            )?;
            c.execute(
                "INSERT INTO routes (hostname, cat_id, node_id, gateway_url, target_port, epoch, state)
                 VALUES (?1,?2,NULL,NULL,?3,0,'unbound')",
                params![hostname, cat.id, target_port],
            )
            .map(|_| ())
        })
        .map_err(|e| {
            if e.code == ErrorCode::Conflict {
                ApiError::new(ErrorCode::AlreadyExists, "endpoint name in use")
            } else {
                e
            }
        })?;
        Ok(Endpoint {
            id,
            cat_id: cat.id.clone(),
            name: name.to_string(),
            hostname,
            target_port,
            protocol: protocol.to_string(),
            wake_policy: wake,
        })
    }

    pub fn endpoints_for_cat(&self, cat_id: &str) -> Result<Vec<Endpoint>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM endpoints WHERE cat_id=?1 ORDER BY id")?;
            let rows = stmt.query_map(params![cat_id], row_to_endpoint)?;
            rows.collect()
        })
    }

    /// Publish routes for a cat now running on `node`; bumps each epoch.
    pub fn publish_routes(&self, cat_id: &str, node_id: &str, gateway_url: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE routes SET node_id=?2, gateway_url=?3, epoch=epoch+1, state='active'
                 WHERE cat_id=?1",
                params![cat_id, node_id, gateway_url],
            )
            .map(|_| ())
        })
    }

    pub fn unbind_routes(&self, cat_id: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE routes SET node_id=NULL, gateway_url=NULL, epoch=epoch+1, state='unbound'
                 WHERE cat_id=?1",
                params![cat_id],
            )
            .map(|_| ())
        })
    }

    pub fn resolve_route(&self, hostname: &str) -> Result<(RouteBinding, String)> {
        let row = self
            .with(|c| {
                c.query_row(
                    "SELECT r.hostname, r.cat_id, r.node_id, r.gateway_url, r.target_port, r.epoch,
                            r.state, e.wake_policy, c.project
                       FROM routes r
                       JOIN endpoints e ON e.hostname = r.hostname
                       JOIN cats c ON c.id = r.cat_id
                      WHERE r.hostname = ?1",
                    params![hostname],
                    |r| {
                        Ok((
                            RouteBinding {
                                hostname: r.get(0)?,
                                cat_id: r.get(1)?,
                                node_id: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                                gateway_url: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                                target_port: r.get::<_, u16>(4)?,
                                epoch: r.get(5)?,
                                wake_policy: parse_wake(&r.get::<_, String>(7)?),
                                project: r.get(8)?,
                            },
                            r.get::<_, String>(6)?,
                        ))
                    },
                )
                .optional()
            })?
            .ok_or_else(|| ApiError::not_found(format!("route {hostname}")))?;
        Ok(row)
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64
}

// ---------------------------------------------------------------------------
// Row mappers and enum codecs
// ---------------------------------------------------------------------------

fn desired_str(d: DesiredState) -> &'static str {
    match d {
        DesiredState::Running => "running",
        DesiredState::Suspended => "suspended",
        DesiredState::Warm => "warm",
        DesiredState::Cold => "cold",
        DesiredState::Deleted => "deleted",
    }
}

pub fn parse_desired(s: &str) -> DesiredState {
    match s {
        "running" => DesiredState::Running,
        "suspended" => DesiredState::Suspended,
        "warm" => DesiredState::Warm,
        "deleted" => DesiredState::Deleted,
        _ => DesiredState::Cold,
    }
}

fn observed_str(o: ObservedState) -> &'static str {
    match o {
        ObservedState::Creating => "creating",
        ObservedState::Starting => "starting",
        ObservedState::Running => "running",
        ObservedState::Suspending => "suspending",
        ObservedState::Suspended => "suspended",
        ObservedState::Warming => "warming",
        ObservedState::Warm => "warm",
        ObservedState::Stopping => "stopping",
        ObservedState::Cold => "cold",
        ObservedState::Failed => "failed",
        ObservedState::Deleted => "deleted",
        ObservedState::Unknown => "unknown",
    }
}

pub fn parse_observed(s: &str) -> ObservedState {
    match s {
        "creating" => ObservedState::Creating,
        "starting" => ObservedState::Starting,
        "running" => ObservedState::Running,
        "suspending" => ObservedState::Suspending,
        "suspended" => ObservedState::Suspended,
        "warming" => ObservedState::Warming,
        "warm" => ObservedState::Warm,
        "stopping" => ObservedState::Stopping,
        "failed" => ObservedState::Failed,
        "deleted" => ObservedState::Deleted,
        "unknown" => ObservedState::Unknown,
        _ => ObservedState::Cold,
    }
}

fn disk_state_str(s: DiskState) -> &'static str {
    match s {
        DiskState::Creating => "creating",
        DiskState::Available => "available",
        DiskState::Bound => "bound",
        DiskState::Deleting => "deleting",
        DiskState::Deleted => "deleted",
    }
}

fn node_state_str(s: NodeState) -> &'static str {
    match s {
        NodeState::Ready => "ready",
        NodeState::Cordoned => "cordoned",
        NodeState::Draining => "draining",
        NodeState::Lost => "lost",
    }
}

fn wake_str(w: WakePolicy) -> &'static str {
    match w {
        WakePolicy::WakeOnRequest => "wake_on_request",
        WakePolicy::NoWake => "no_wake",
    }
}

pub fn parse_wake(s: &str) -> WakePolicy {
    if s == "no_wake" {
        WakePolicy::NoWake
    } else {
        WakePolicy::WakeOnRequest
    }
}

fn row_to_cat(r: &rusqlite::Row<'_>) -> rusqlite::Result<Cat> {
    Ok(Cat {
        id: r.get("id")?,
        workspace_id: r.get("workspace_id")?,
        project: r.get("project")?,
        name: r.get("name")?,
        image: r.get("image")?,
        spec: CatSpec {
            cpus: r.get("cpus")?,
            memory_mib: r.get::<_, i64>("memory_mib")? as u64,
        },
        root_disk_id: r.get("root_disk_id")?,
        desired_state: parse_desired(&r.get::<_, String>("desired_state")?),
        observed_state: parse_observed(&r.get::<_, String>("observed_state")?),
        generation: r.get("generation")?,
        auto_suspend: r.get::<_, i64>("auto_suspend")? != 0,
        node_id: r.get("node_id")?,
        created_at_unix: r.get("created_at")?,
        observed_state_since_unix_ms: r.get("observed_state_since_ms")?,
    })
}

fn row_to_work_lease(r: &rusqlite::Row<'_>) -> rusqlite::Result<WorkLease> {
    Ok(WorkLease {
        id: r.get(0)?,
        cat_id: r.get(1)?,
        kind: parse_work_kind(&r.get::<_, String>(2)?),
        owner_id: r.get(3)?,
        label: r.get(4)?,
        expires_at_unix_ms: r.get(5)?,
    })
}

fn work_kind_str(kind: WorkKind) -> &'static str {
    match kind {
        WorkKind::Gateway => "gateway",
        WorkKind::Exec => "exec",
        WorkKind::Guest => "guest",
        WorkKind::Pin => "pin",
        WorkKind::Control => "control",
    }
}

fn parse_work_kind(kind: &str) -> WorkKind {
    match kind {
        "gateway" => WorkKind::Gateway,
        "exec" => WorkKind::Exec,
        "guest" => WorkKind::Guest,
        "pin" => WorkKind::Pin,
        _ => WorkKind::Control,
    }
}

fn row_to_disk(r: &rusqlite::Row<'_>) -> rusqlite::Result<Disk> {
    let kind: String = r.get("kind")?;
    let state: String = r.get("state")?;
    Ok(Disk {
        id: r.get("id")?,
        workspace_id: r.get("workspace_id")?,
        project: r.get("project")?,
        name: r.get("name")?,
        kind: if kind == "root" {
            DiskKind::Root
        } else {
            DiskKind::Persistent
        },
        size_bytes: r.get::<_, i64>("size_bytes")? as u64,
        state: match state.as_str() {
            "creating" => DiskState::Creating,
            "bound" => DiskState::Bound,
            "deleting" => DiskState::Deleting,
            "deleted" => DiskState::Deleted,
            _ => DiskState::Available,
        },
        volume_id: r.get("volume_id")?,
        bound_cat_id: None,
        created_at_unix: r.get("created_at")?,
    })
}

fn row_to_node(r: &rusqlite::Row<'_>) -> rusqlite::Result<Node> {
    let state: String = r.get("state")?;
    let telemetry_json: Option<String> = r.get("telemetry_json")?;
    Ok(Node {
        id: r.get("id")?,
        agent_url: r.get("agent_url")?,
        gateway_url: r.get("gateway_url")?,
        state: match state.as_str() {
            "cordoned" => NodeState::Cordoned,
            "draining" => NodeState::Draining,
            "lost" => NodeState::Lost,
            _ => NodeState::Ready,
        },
        capacity: NodeCapacity {
            cpus: r.get("cpus")?,
            memory_mib: r.get::<_, i64>("memory_mib")? as u64,
        },
        last_heartbeat_unix: r.get::<_, i64>("last_heartbeat_ms")? / 1000,
        telemetry: telemetry_json.and_then(|json| serde_json::from_str(&json).ok()),
    })
}

fn summarize_node(node: Node, cats: &[Cat]) -> NodeSummary {
    let assigned_cpus = cats.iter().map(|cat| cat.spec.cpus).sum();
    let assigned_memory_mib = cats.iter().map(|cat| cat.spec.memory_mib).sum();
    NodeSummary {
        heartbeat_age_seconds: now_unix()
            .saturating_sub(node.last_heartbeat_unix)
            .try_into()
            .unwrap_or(0),
        node,
        assigned_cats: cats.len() as u64,
        assigned_cpus,
        assigned_memory_mib,
    }
}

fn row_to_operation(r: &rusqlite::Row<'_>) -> rusqlite::Result<Operation> {
    let phase: String = r.get("phase")?;
    let err_json: Option<String> = r.get("error_json")?;
    Ok(Operation {
        id: r.get("id")?,
        workspace_id: r.get("workspace_id")?,
        project: r.get("project")?,
        kind: r.get("kind")?,
        resource_id: r.get("resource_id")?,
        resource_generation: r.get("resource_generation")?,
        phase: match phase.as_str() {
            "running" => OperationPhase::Running,
            "succeeded" => OperationPhase::Succeeded,
            "failed" => OperationPhase::Failed,
            _ => OperationPhase::Pending,
        },
        error: err_json.and_then(|j| serde_json::from_str(&j).ok()),
        created_at_unix: r.get("created_at")?,
        updated_at_unix: r.get("updated_at")?,
    })
}

fn row_to_endpoint(r: &rusqlite::Row<'_>) -> rusqlite::Result<Endpoint> {
    Ok(Endpoint {
        id: r.get("id")?,
        cat_id: r.get("cat_id")?,
        name: r.get("name")?,
        hostname: r.get("hostname")?,
        target_port: r.get("target_port")?,
        protocol: r.get("protocol")?,
        wake_policy: parse_wake(&r.get::<_, String>("wake_policy")?),
    })
}

fn row_to_account(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountRecord> {
    let kind = match row.get::<_, String>(3)?.as_str() {
        "personal" => AccountKind::Personal,
        _ => AccountKind::Organization,
    };
    Ok(AccountRecord {
        id: row.get(0)?,
        slug: row.get(1)?,
        display_name: row.get(2)?,
        kind,
        workos_organization_id: row.get(4)?,
        billing_account_id: row.get(5)?,
        personal_owner_user_id: row.get(6)?,
        status: row.get(7)?,
    })
}

fn row_to_workspace(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkspaceRecord> {
    Ok(WorkspaceRecord {
        id: row.get(0)?,
        account_id: row.get(1)?,
        slug: row.get(2)?,
        display_name: row.get(3)?,
        legacy_project: row.get(4)?,
        is_default: row.get(5)?,
    })
}

fn find_account_by_organization(
    conn: &Connection,
    organization_id: &str,
) -> rusqlite::Result<Option<AccountRecord>> {
    conn.query_row(
        "SELECT id, slug, display_name, kind, workos_organization_id,
                billing_account_id, personal_owner_user_id, status
           FROM accounts WHERE workos_organization_id=?1",
        params![organization_id],
        row_to_account,
    )
    .optional()
}

fn find_account_by_personal_owner(
    conn: &Connection,
    workos_user_id: &str,
) -> rusqlite::Result<Option<AccountRecord>> {
    conn.query_row(
        "SELECT id, slug, display_name, kind, workos_organization_id,
                billing_account_id, personal_owner_user_id, status
           FROM accounts WHERE personal_owner_user_id=?1",
        params![workos_user_id],
        row_to_account,
    )
    .optional()
}

fn default_workspace_for_account(conn: &Connection, account_id: &str) -> Result<WorkspaceRecord> {
    conn.query_row(
        "SELECT id, account_id, slug, display_name, legacy_project, is_default
           FROM workspaces WHERE account_id=?1 AND is_default=1",
        params![account_id],
        row_to_workspace,
    )
    .map_err(internal)
}

fn unique_account_slug(conn: &Connection, requested: &str) -> Result<String> {
    for suffix in 0..10_000_u32 {
        let candidate = if suffix == 0 {
            requested.to_string()
        } else {
            format!("{requested}-{suffix}")
        };
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE slug=?1)",
                params![candidate],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if !exists {
            return Ok(candidate);
        }
    }
    Err(ApiError::conflict(
        "could not allocate a unique account slug",
    ))
}

fn unique_legacy_project(conn: &Connection, requested: &str) -> Result<String> {
    for suffix in 0..10_000_u32 {
        let candidate = if suffix == 0 {
            requested.to_string()
        } else {
            format!("{requested}-{suffix}")
        };
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM workspaces WHERE legacy_project=?1)",
                params![candidate],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if !exists {
            return Ok(candidate);
        }
    }
    Err(ApiError::conflict(
        "could not allocate a unique legacy project route",
    ))
}

fn ensure_legacy_workspace(conn: &Connection, project: &str, organization_id: &str) -> Result<()> {
    let existing: Option<(String, String, String)> = conn
        .query_row(
            "SELECT w.account_id, a.workos_organization_id, a.status
               FROM workspaces w JOIN accounts a ON a.id=w.account_id
              WHERE w.legacy_project=?1",
            params![project],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(internal)?;
    if let Some((mut account_id, old_organization_id, old_status)) = existing {
        if old_organization_id.starts_with("legacy-unmapped:")
            && !organization_id.starts_with("legacy-unmapped:")
        {
            if let Some(other) =
                find_account_by_organization(conn, organization_id).map_err(internal)?
            {
                if other.id != account_id {
                    if old_status != "pending_mapping" {
                        return Err(ApiError::conflict(format!(
                            "project {project} cannot move between active accounts"
                        )));
                    }
                    let workspace_slug: String = conn
                        .query_row(
                            "SELECT slug FROM workspaces WHERE legacy_project=?1",
                            params![project],
                            |row| row.get(0),
                        )
                        .map_err(internal)?;
                    let workspace_slug = unique_workspace_slug(conn, &other.id, &workspace_slug)?;
                    let target_has_default: bool = conn
                        .query_row(
                            "SELECT EXISTS(
                                SELECT 1 FROM workspaces
                                 WHERE account_id=?1 AND is_default=1
                             )",
                            params![other.id],
                            |row| row.get(0),
                        )
                        .map_err(internal)?;
                    conn.execute(
                        "UPDATE workspaces
                            SET account_id=?2, slug=?3,
                                is_default=CASE WHEN ?4 THEN 0 ELSE is_default END
                          WHERE legacy_project=?1",
                        params![project, other.id, workspace_slug, target_has_default],
                    )
                    .map_err(internal)?;
                    conn.execute(
                        "UPDATE legacy_billing_bindings SET account_id=?2
                          WHERE legacy_project=?1",
                        params![project, other.id],
                    )
                    .map_err(internal)?;
                    conn.execute(
                        "DELETE FROM accounts
                          WHERE id=?1
                            AND status='pending_mapping'
                            AND NOT EXISTS(
                                SELECT 1 FROM workspaces WHERE account_id=?1
                            )",
                        params![account_id],
                    )
                    .map_err(internal)?;
                    account_id = other.id;
                }
            } else {
                conn.execute(
                    "UPDATE accounts
                        SET workos_organization_id=?2, status='active'
                      WHERE id=?1",
                    params![account_id, organization_id],
                )
                .map_err(internal)?;
            }
        }
        conn.execute(
            "INSERT OR IGNORE INTO legacy_billing_bindings (
                legacy_project, account_id, billing_account_id, created_at
             ) VALUES (?1,?2,?3,?4)",
            params![
                project,
                account_id,
                format!("billing_account/project/{project}"),
                now_unix()
            ],
        )
        .map_err(internal)?;
        return Ok(());
    }

    let account = find_account_by_organization(conn, organization_id).map_err(internal)?;
    let (account_id, is_default) = if let Some(account) = account {
        (account.id, false)
    } else {
        let account_id = new_id(ids::ACCOUNT_PREFIX);
        let account_slug = unique_account_slug(conn, &dns_slug(project, 48))?;
        let billing_account_id = format!("billing_account/account/{account_id}");
        let status = if organization_id.starts_with("legacy-unmapped:") {
            "pending_mapping"
        } else {
            "active"
        };
        conn.execute(
            "INSERT INTO accounts (
                id, slug, display_name, kind, workos_organization_id,
                billing_account_id, status, created_at
             ) VALUES (?1,?2,?3,'organization',?4,?5,?6,?7)",
            params![
                account_id,
                account_slug,
                project,
                organization_id,
                billing_account_id,
                status,
                now_unix()
            ],
        )
        .map_err(internal)?;
        (account_id, true)
    };
    let workspace_slug = unique_workspace_slug(conn, &account_id, &dns_slug(project, 48))?;
    let workspace_id = new_id(ids::WORKSPACE_PREFIX);
    conn.execute(
        "INSERT INTO workspaces (
            id, account_id, slug, display_name, legacy_project,
            is_default, created_at
         ) VALUES (?1,?2,?3,?4,?4,?5,?6)",
        params![
            workspace_id,
            account_id,
            workspace_slug,
            project,
            is_default,
            now_unix()
        ],
    )
    .map_err(internal)?;
    conn.execute(
        "INSERT INTO legacy_billing_bindings (
            legacy_project, account_id, billing_account_id, created_at
         ) VALUES (?1,?2,?3,?4)",
        params![
            project,
            account_id,
            format!("billing_account/project/{project}"),
            now_unix()
        ],
    )
    .map_err(internal)?;
    Ok(())
}

fn unique_workspace_slug(conn: &Connection, account_id: &str, requested: &str) -> Result<String> {
    for suffix in 0..10_000_u32 {
        let candidate = if suffix == 0 {
            requested.to_string()
        } else {
            format!("{requested}-{suffix}")
        };
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM workspaces WHERE account_id=?1 AND slug=?2
                 )",
                params![account_id, candidate],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if !exists {
            return Ok(candidate);
        }
    }
    Err(ApiError::conflict(
        "could not allocate a unique workspace slug",
    ))
}

fn validate_workspace_slug(slug: &str) -> Result<()> {
    if slug.is_empty() || slug.len() > 48 || dns_slug(slug, 48) != slug || slug.starts_with('-') {
        return Err(ApiError::invalid(
            "workspace slug must be a lowercase DNS label up to 48 characters",
        ));
    }
    Ok(())
}

fn workspace_view(
    account: &AccountRecord,
    workspace: WorkspaceRecord,
    role: Option<&str>,
) -> Workspace {
    let locator = format!("{}/{}", account.slug, workspace.slug);
    Workspace {
        id: workspace.id,
        account_id: account.id.clone(),
        account_slug: account.slug.clone(),
        account_display_name: account.display_name.clone(),
        slug: workspace.slug,
        locator,
        legacy_project: workspace.legacy_project,
        display_name: workspace.display_name,
        kind: account.kind,
        organization_id: account.workos_organization_id.clone(),
        role: role.map(str::to_string),
        is_default: workspace.is_default,
    }
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('personal','organization')),
    workos_organization_id TEXT NOT NULL UNIQUE,
    billing_account_id TEXT NOT NULL UNIQUE,
    personal_owner_user_id TEXT UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('provisioning','active','pending_mapping','disabled')),
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    slug TEXT NOT NULL,
    display_name TEXT NOT NULL,
    legacy_project TEXT NOT NULL UNIQUE,
    is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0,1)),
    created_at INTEGER NOT NULL,
    UNIQUE (account_id, slug)
);
CREATE UNIQUE INDEX IF NOT EXISTS workspaces_one_default
ON workspaces(account_id) WHERE is_default=1;
CREATE TABLE IF NOT EXISTS legacy_billing_bindings (
    legacy_project TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    billing_account_id TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS account_membership_shadow (
    workos_membership_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    workos_user_id TEXT NOT NULL,
    role_slug TEXT NOT NULL,
    status TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (account_id, workos_user_id)
);
CREATE TABLE IF NOT EXISTS workspace_grants (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    workos_user_id TEXT NOT NULL,
    access_level TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, workos_user_id)
);
CREATE TABLE IF NOT EXISTS signup_grant_eligibility (
    workos_user_id TEXT NOT NULL,
    campaign TEXT NOT NULL,
    billing_account_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('pending','applied')),
    created_at INTEGER NOT NULL,
    applied_at INTEGER,
    PRIMARY KEY (workos_user_id, campaign)
);
CREATE TABLE IF NOT EXISTS account_invitations (
    workos_invitation_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    workos_organization_id TEXT NOT NULL,
    email TEXT NOT NULL,
    role_slug TEXT NOT NULL,
    state TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS workos_event_receipts (
    workos_event_id TEXT PRIMARY KEY,
    event_name TEXT NOT NULL,
    processed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cats (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    project TEXT NOT NULL,
    name TEXT NOT NULL,
    image TEXT NOT NULL,
    cpus INTEGER NOT NULL,
    memory_mib INTEGER NOT NULL,
    root_disk_id TEXT NOT NULL,
    desired_state TEXT NOT NULL,
    observed_state TEXT NOT NULL,
    generation INTEGER NOT NULL,
    auto_suspend INTEGER NOT NULL DEFAULT 1,
    work_version INTEGER NOT NULL DEFAULT 0,
    observed_state_since_ms INTEGER NOT NULL,
    node_id TEXT,
    created_at INTEGER NOT NULL,
    UNIQUE (project, name)
);
CREATE TABLE IF NOT EXISTS disks (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    project TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    state TEXT NOT NULL,
    volume_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (project, name)
);
CREATE TABLE IF NOT EXISTS mount_bindings (
    id TEXT PRIMARY KEY,
    disk_id TEXT NOT NULL UNIQUE,
    cat_id TEXT NOT NULL,
    mount_path TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    agent_url TEXT NOT NULL,
    gateway_url TEXT NOT NULL,
    state TEXT NOT NULL,
    cpus INTEGER NOT NULL,
    memory_mib INTEGER NOT NULL,
    last_heartbeat_ms INTEGER NOT NULL,
    telemetry_json TEXT,
    scheduling_disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    project TEXT NOT NULL,
    kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_generation INTEGER NOT NULL,
    phase TEXT NOT NULL,
    error_json TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
    key TEXT NOT NULL,
    route TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    PRIMARY KEY (key, route)
);
CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    cat_id TEXT NOT NULL,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL UNIQUE,
    target_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    wake_policy TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS routes (
    hostname TEXT PRIMARY KEY,
    cat_id TEXT NOT NULL,
    node_id TEXT,
    gateway_url TEXT,
    target_port INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cat_work_sources (
    cat_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    source_epoch TEXT NOT NULL,
    lease_sequence INTEGER NOT NULL,
    seen_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cat_work_leases (
    id TEXT PRIMARY KEY,
    cat_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    label TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    source_epoch TEXT,
    UNIQUE (cat_id, kind, owner_id)
);
CREATE INDEX IF NOT EXISTS cat_work_leases_live
ON cat_work_leases(cat_id, expires_at_ms);
";

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::guest::GuestWorkLease;
    use cats_api::requests::NodeWorkStatusRequest;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    fn legacy_workspace(store: &Store, project: &str) -> WorkspaceRecord {
        store
            .reconcile_legacy_projects(&BTreeMap::from([(
                project.to_string(),
                format!("org_{project}"),
            )]))
            .unwrap();
        store.workspace_for_project(project).unwrap().unwrap()
    }

    #[test]
    fn legacy_projects_share_canonical_billing_and_retain_history_bindings() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("control.db")).unwrap();
        let mappings = BTreeMap::from([
            ("default".to_string(), "org_acme".to_string()),
            ("sibling".to_string(), "org_acme".to_string()),
            ("other".to_string(), "org_other".to_string()),
        ]);
        store.reconcile_legacy_projects(&mappings).unwrap();
        store.reconcile_legacy_projects(&mappings).unwrap();

        let default = store.workspace_for_project("default").unwrap().unwrap();
        let sibling = store.workspace_for_project("sibling").unwrap().unwrap();
        let other = store.workspace_for_project("other").unwrap().unwrap();
        assert_eq!(default.account_id, sibling.account_id);
        assert_ne!(default.account_id, other.account_id);
        assert!(default.is_default);
        assert!(!sibling.is_default);
        assert_eq!(
            store.billing_account_id_for_project("default").unwrap(),
            store.billing_account_id_for_project("sibling").unwrap()
        );
        assert!(store
            .billing_account_id_for_project("default")
            .unwrap()
            .starts_with("billing_account/account/"));
        assert_eq!(
            store
                .billing_ledgers_for_project("default")
                .unwrap()
                .into_iter()
                .map(|ledger| ledger.billing_account_id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                store.billing_account_id_for_project("default").unwrap(),
                "billing_account/project/default".to_string(),
                "billing_account/project/sibling".to_string(),
            ])
        );
        assert_eq!(
            store
                .workspaces_for_account(&default.account_id)
                .unwrap()
                .len(),
            2
        );

        let (cat, disks, operation) = store
            .create_cat(
                &default,
                "stable-owner",
                "test",
                1,
                256,
                1 << 20,
                true,
                None,
            )
            .unwrap();
        let renamed = store
            .update_workspace(&default.id, Some("renamed"), None)
            .unwrap();
        assert_eq!(renamed.id, default.id);
        assert_eq!(renamed.legacy_project, "default");
        assert_eq!(
            store.get_cat("default", &cat.id).unwrap().workspace_id,
            default.id
        );
        assert!(disks.iter().all(|disk| disk.workspace_id == default.id));
        assert_eq!(operation.workspace_id, default.id);
        assert!(store
            .with(|conn| {
                conn.execute(
                    "UPDATE cats SET workspace_id=?2 WHERE id=?1",
                    params![cat.id, sibling.id],
                )
                .map(|_| ())
            })
            .is_err());
    }

    #[test]
    fn pending_legacy_accounts_merge_when_authoritative_mapping_arrives() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("control.db")).unwrap();
        store
            .reconcile_legacy_projects(&BTreeMap::from([
                ("first".to_string(), "legacy-unmapped:first".to_string()),
                ("second".to_string(), "legacy-unmapped:second".to_string()),
            ]))
            .unwrap();
        let first_before = store.workspace_for_project("first").unwrap().unwrap();
        let second_before = store.workspace_for_project("second").unwrap().unwrap();
        assert_ne!(first_before.account_id, second_before.account_id);

        store
            .reconcile_legacy_projects(&BTreeMap::from([
                ("first".to_string(), "org_grouped".to_string()),
                ("second".to_string(), "org_grouped".to_string()),
            ]))
            .unwrap();
        let first_after = store.workspace_for_project("first").unwrap().unwrap();
        let second_after = store.workspace_for_project("second").unwrap().unwrap();
        assert_eq!(first_after.id, first_before.id);
        assert_eq!(second_after.id, second_before.id);
        assert_eq!(first_after.account_id, second_after.account_id);
        assert_eq!(
            store
                .account_by_id(&first_after.account_id)
                .unwrap()
                .workos_organization_id,
            "org_grouped"
        );
    }

    #[test]
    fn legacy_canonical_billing_alias_keeps_its_original_owner_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("control.db")).unwrap();
        let mappings = BTreeMap::from([
            ("default".to_string(), "org_acme".to_string()),
            ("sibling".to_string(), "org_acme".to_string()),
        ]);
        store.reconcile_legacy_projects(&mappings).unwrap();
        let account_id = store
            .workspace_for_project("default")
            .unwrap()
            .unwrap()
            .account_id;
        store
            .with(|conn| {
                conn.execute(
                    "UPDATE accounts SET billing_account_id=?2 WHERE id=?1",
                    params![account_id, "billing_account/project/default"],
                )?;
                Ok(())
            })
            .unwrap();

        assert_eq!(
            store.billing_ledgers_for_project("sibling").unwrap(),
            vec![
                BillingLedgerRecord {
                    billing_account_id: "billing_account/project/default".to_string(),
                    owner_id: "default".to_string(),
                    signup_credit_nanos: 10_000_000_000,
                },
                BillingLedgerRecord {
                    billing_account_id: "billing_account/project/sibling".to_string(),
                    owner_id: "sibling".to_string(),
                    signup_credit_nanos: 10_000_000_000,
                },
            ]
        );
    }

    #[test]
    fn concurrent_personal_provision_has_one_identity_and_grant_claim() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("control.db")).unwrap());
        let mut threads = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            threads.push(std::thread::spawn(move || {
                store
                    .ensure_personal_account("user_one", "org_personal_one", "one@example.com")
                    .unwrap()
            }));
        }
        let rows = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert!(
            rows.iter()
                .all(|(account, workspace)| account.id == rows[0].0.id
                    && workspace.id == rows[0].1.id)
        );
        let account = &rows[0].0;
        assert_eq!(
            store
                .signup_grant_state("user_one", "signup-2026-10usd", &account.billing_account_id,)
                .unwrap(),
            SignupGrantState::Pending
        );
        store
            .mark_signup_grant_applied("user_one", "signup-2026-10usd", &account.billing_account_id)
            .unwrap();
        assert_eq!(
            store
                .signup_grant_state("user_one", "signup-2026-10usd", &account.billing_account_id,)
                .unwrap(),
            SignupGrantState::Applied
        );
        assert!(store
            .signup_grant_state(
                "user_one",
                "signup-2026-10usd",
                "billing_account/account/another",
            )
            .is_err());
    }

    #[test]
    fn opens_and_backfills_the_pre_project_operation_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE cats (
                    id TEXT PRIMARY KEY, project TEXT NOT NULL, name TEXT NOT NULL,
                    image TEXT NOT NULL, cpus INTEGER NOT NULL, memory_mib INTEGER NOT NULL,
                    root_disk_id TEXT NOT NULL, desired_state TEXT NOT NULL,
                    observed_state TEXT NOT NULL, generation INTEGER NOT NULL,
                    node_id TEXT, created_at INTEGER NOT NULL, UNIQUE (project, name)
                 );
                 CREATE TABLE operations (
                    id TEXT PRIMARY KEY, kind TEXT NOT NULL, resource_id TEXT NOT NULL,
                    resource_generation INTEGER NOT NULL, phase TEXT NOT NULL,
                    error_json TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
                 );
                 CREATE TABLE nodes (
                    id TEXT PRIMARY KEY, agent_url TEXT NOT NULL, gateway_url TEXT NOT NULL,
                    state TEXT NOT NULL, cpus INTEGER NOT NULL, memory_mib INTEGER NOT NULL,
                    last_heartbeat_ms INTEGER NOT NULL
                 );
                 INSERT INTO cats VALUES
                    ('cat_old', 'alpha', 'legacy', 'ubuntu', 1, 512, 'disk_old',
                     'running', 'cold', 1, NULL, 1);
                 INSERT INTO operations VALUES
                    ('op_old', 'cat.create', 'cat_old', 1, 'pending', NULL, 1, 1);
                 INSERT INTO nodes VALUES
                    ('node_old', 'http://node', 'http://gateway', 'cordoned', 4, 8192, 1);",
            )
            .unwrap();
        }

        let migration_started_ms = now_ms();
        let store = Store::open(&path).unwrap();
        store
            .reconcile_legacy_projects(&BTreeMap::from([(
                "alpha".to_string(),
                "org_alpha".to_string(),
            )]))
            .unwrap();
        assert_eq!(store.get_operation("op_old").unwrap().project, "alpha");
        let upgraded_cat = store.must_get_cat_by_id("cat_old").unwrap();
        assert_eq!(
            upgraded_cat.workspace_id,
            store.workspace_for_project("alpha").unwrap().unwrap().id
        );
        assert!(upgraded_cat.auto_suspend);
        assert!(
            upgraded_cat.observed_state_since_unix_ms >= migration_started_ms,
            "an upgraded Cat must begin its tier clock at migration time"
        );
        let endpoints = store.endpoints_for_cat("cat_old").unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].name, DEFAULT_ENDPOINT_NAME);
        assert_eq!(endpoints[0].hostname, "legacy-old.cats.run");
        assert_eq!(endpoints[0].target_port, DEFAULT_ENDPOINT_PORT);
        let node = store.get_node("node_old").unwrap();
        assert_eq!(node.state, NodeState::Cordoned);
        assert!(node.telemetry.is_none());

        // An upgraded cordoned node remains unschedulable after a Lost ->
        // register/heartbeat recovery cycle.
        store.set_node_state("node_old", NodeState::Lost).unwrap();
        store
            .register_node("node_old", "http://node-new", "http://gateway", 4, 8192)
            .unwrap();
        assert_eq!(
            store.get_node("node_old").unwrap().state,
            NodeState::Cordoned
        );

        let telemetry = NodeTelemetry {
            observed_cats: 2,
            allocated_cpus: 3,
            allocated_memory_mib: 2048,
            ..NodeTelemetry::default()
        };
        store.heartbeat_node("node_old", Some(&telemetry)).unwrap();
        let stored = store.get_node("node_old").unwrap().telemetry.unwrap();
        assert_eq!(stored.observed_cats, 2);
        assert_eq!(stored.allocated_cpus, 3);
        assert_eq!(stored.allocated_memory_mib, 2048);
    }

    #[test]
    fn last_guest_work_release_is_immediately_suspend_eligible() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("control.db")).unwrap();
        let workspace = legacy_workspace(&store, "alpha");
        let (cat, _, _) = store
            .create_cat(
                &workspace,
                "worker",
                "test",
                1,
                256,
                1024 * 1024,
                true,
                None,
            )
            .unwrap();
        assert!(cat.auto_suspend);
        let endpoints = store.endpoints_for_cat(&cat.id).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].name, DEFAULT_ENDPOINT_NAME);
        assert_eq!(endpoints[0].target_port, DEFAULT_ENDPOINT_PORT);
        assert!(endpoints[0].hostname.starts_with("worker-"));
        assert!(endpoints[0].hostname.ends_with(".cats.run"));
        let default_id = endpoints[0].id.clone();
        let updated = store
            .create_endpoint(
                &cat,
                DEFAULT_ENDPOINT_NAME,
                3000,
                "http",
                WakePolicy::NoWake,
            )
            .unwrap();
        assert_eq!(updated.id, default_id);
        assert_eq!(updated.target_port, 3000);
        assert_eq!(updated.wake_policy, WakePolicy::NoWake);
        assert_eq!(store.endpoints_for_cat(&cat.id).unwrap().len(), 1);
        let (route, _) = store.resolve_route(&updated.hostname).unwrap();
        assert_eq!(route.target_port, 3000);
        assert_eq!(route.epoch, 1);
        store
            .register_node("node-1", "http://node", "http://gateway", 4, 8192)
            .unwrap();
        store.set_placement(&cat.id, Some("node-1")).unwrap();
        store.set_observed(&cat.id, ObservedState::Running).unwrap();
        let status = |sequence, leases| NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: cat.id.clone(),
            generation: 1,
            guest_source_epoch: "guest-boot-1".into(),
            guest_lease_sequence: sequence,
            leases,
        };
        store
            .ingest_guest_work(&status(
                1,
                vec![GuestWorkLease {
                    id: "lease-1".into(),
                    label: "user-job".into(),
                    remaining_ttl_ms: 5_000,
                }],
            ))
            .unwrap();
        assert!(store.try_auto_suspend(&cat.id, 5_000).unwrap().is_none());
        assert_eq!(
            store.work_status(&cat.id, 5_000).unwrap().reason,
            "active_work"
        );

        store.ingest_guest_work(&status(2, vec![])).unwrap();
        let operation = store
            .try_auto_suspend(&cat.id, 5_000)
            .unwrap()
            .expect("last release should trigger suspend without an idle timer");
        assert_eq!(operation.kind, "cat.auto_suspend");
        let sleeping = store.must_get_cat_by_id(&cat.id).unwrap();
        assert_eq!(sleeping.desired_state, DesiredState::Suspended);
        assert_eq!(sleeping.generation, 2);
    }

    #[test]
    fn gateway_work_blocks_auto_suspend_and_wake_is_singleflight() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("control.db")).unwrap();
        let workspace = legacy_workspace(&store, "alpha");
        let (cat, _, _) = store
            .create_cat(&workspace, "web", "test", 1, 256, 1024 * 1024, true, None)
            .unwrap();
        store
            .register_node("node-1", "http://node", "http://gateway", 4, 8192)
            .unwrap();
        store.set_placement(&cat.id, Some("node-1")).unwrap();
        store.set_observed(&cat.id, ObservedState::Running).unwrap();
        store.set_auto_suspend(&cat.id, true).unwrap();
        store
            .ingest_guest_work(&NodeWorkStatusRequest {
                node_id: "node-1".into(),
                cat_id: cat.id.clone(),
                generation: 1,
                guest_source_epoch: "guest-boot-1".into(),
                guest_lease_sequence: 0,
                leases: vec![],
            })
            .unwrap();
        let lease = store
            .acquire_work(&cat.id, WorkKind::Gateway, "request-1", "GET /", 5_000)
            .unwrap();
        assert!(store.try_auto_suspend(&cat.id, 5_000).unwrap().is_none());
        store.release_work(&lease.id).unwrap();
        store.try_auto_suspend(&cat.id, 5_000).unwrap().unwrap();

        let first = store.ensure_desired_running(&cat.id).unwrap();
        let second = store.ensure_desired_running(&cat.id).unwrap();
        assert!(first.is_some());
        assert!(second.is_none());
        assert_eq!(store.must_get_cat_by_id(&cat.id).unwrap().generation, 3);
    }

    #[test]
    fn guest_work_cancels_an_inflight_suspend_without_generation_drift() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("control.db")).unwrap();
        let workspace = legacy_workspace(&store, "alpha");
        let (cat, _, _) = store
            .create_cat(&workspace, "racer", "test", 1, 256, 1024 * 1024, true, None)
            .unwrap();
        store
            .register_node("node-1", "http://node", "http://gateway", 4, 8192)
            .unwrap();
        store.set_placement(&cat.id, Some("node-1")).unwrap();
        store.set_observed(&cat.id, ObservedState::Running).unwrap();
        store.set_auto_suspend(&cat.id, true).unwrap();
        let report = |sequence, leases| NodeWorkStatusRequest {
            node_id: "node-1".into(),
            cat_id: cat.id.clone(),
            generation: 1,
            guest_source_epoch: "guest-boot-1".into(),
            guest_lease_sequence: sequence,
            leases,
        };
        store.ingest_guest_work(&report(0, vec![])).unwrap();
        let auto = store.try_auto_suspend(&cat.id, 5_000).unwrap().unwrap();
        assert_eq!(auto.resource_generation, 2);
        store
            .set_observed(&cat.id, ObservedState::Suspending)
            .unwrap();

        assert!(store
            .ingest_guest_work(&report(
                1,
                vec![GuestWorkLease {
                    id: "late-job".into(),
                    label: "late-job".into(),
                    remaining_ttl_ms: 5_000,
                }],
            ))
            .unwrap());
        store.cancel_rejected_suspend(&cat.id, 2).unwrap();
        let running = store.must_get_cat_by_id(&cat.id).unwrap();
        assert_eq!(running.desired_state, DesiredState::Running);
        assert_eq!(running.observed_state, ObservedState::Running);
        assert_eq!(running.generation, 2);
        assert_eq!(
            store.get_operation(&auto.id).unwrap().phase,
            OperationPhase::Failed
        );
    }

    #[test]
    fn automatic_deeper_tiers_use_persisted_state_age_and_respect_work() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.db");
        let cat_id;
        {
            let store = Store::open(&path).unwrap();
            let workspace = legacy_workspace(&store, "alpha");
            let (cat, _, _) = store
                .create_cat(
                    &workspace,
                    "sleeper",
                    "test",
                    1,
                    256,
                    1024 * 1024,
                    true,
                    None,
                )
                .unwrap();
            cat_id = cat.id.clone();
            let suspend = store
                .set_desired(&cat.id, DesiredState::Suspended, None, "cat.suspend")
                .unwrap();
            store
                .set_observed(&cat.id, ObservedState::Suspended)
                .unwrap();
            store.finish_operation(&suspend.id, None).unwrap();
            store
                .with(|conn| {
                    conn.execute(
                        "UPDATE cats SET observed_state_since_ms=?2 WHERE id=?1",
                        params![cat.id, now_ms() - 2_000],
                    )
                    .map(|_| ())
                })
                .unwrap();

            let candidates = store
                .auto_tier_candidates(Some(1_000), Some(1_000))
                .unwrap();
            assert_eq!(candidates, vec![cat.id.clone()]);
            let warm = store
                .try_auto_tier(&cat.id, Some(1_000), Some(1_000))
                .unwrap()
                .expect("an old Suspended Cat should move toward Warm");
            assert_eq!(warm.kind, "cat.auto_warm");
            assert_eq!(
                store.must_get_cat_by_id(&cat.id).unwrap().desired_state,
                DesiredState::Warm
            );
            store.set_observed(&cat.id, ObservedState::Warm).unwrap();
            store.finish_operation(&warm.id, None).unwrap();
            store
                .with(|conn| {
                    conn.execute(
                        "UPDATE cats SET observed_state_since_ms=?2 WHERE id=?1",
                        params![cat.id, now_ms() - 2_000],
                    )
                    .map(|_| ())
                })
                .unwrap();
        }

        // Reopening the control-plane database must not reset the Warm timer.
        let store = Store::open(&path).unwrap();
        let lease = store
            .acquire_work(&cat_id, WorkKind::Gateway, "request-1", "GET /", 5_000)
            .unwrap();
        assert!(store
            .try_auto_tier(&cat_id, Some(1_000), Some(1_000))
            .unwrap()
            .is_none());
        store.release_work(&lease.id).unwrap();
        let cold = store
            .try_auto_tier(&cat_id, Some(1_000), Some(1_000))
            .unwrap()
            .expect("an old inactive Warm Cat should move toward Cold");
        assert_eq!(cold.kind, "cat.auto_cold");
        let cat = store.must_get_cat_by_id(&cat_id).unwrap();
        assert_eq!(cat.desired_state, DesiredState::Cold);
        assert_eq!(cat.observed_state, ObservedState::Warm);
    }
}
