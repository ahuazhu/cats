use super::*;

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
        let stamped: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(internal)?;
        // Key the gate on a control-plane table, not on "any table": the
        // credential-free dev shape points the usage store at this same SQLite
        // file, and its tables must not read as a stale control-plane schema.
        let control_plane_schema_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type='table' AND name='cats'",
                [],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if control_plane_schema_exists > 0
            && !(OLDEST_MIGRATABLE_SCHEMA_VERSION..=SCHEMA_VERSION).contains(&stamped)
        {
            return Err(ApiError::failed_precondition(format!(
                "control-plane database {} is at schema version {stamped}, this build \
                 requires {SCHEMA_VERSION} (migratable from \
                 {OLDEST_MIGRATABLE_SCHEMA_VERSION}); recreate it",
                path.display()
            )));
        }
        if control_plane_schema_exists > 0 && stamped < 2 {
            // v1 -> v2: absolute Cat expiry. ALTER is idempotent-by-guard: it
            // only runs while the stamp is below 2, and the stamp update below
            // commits in the same process before any caller can observe v2.
            conn.execute_batch("ALTER TABLE cats ADD COLUMN expires_at_unix INTEGER")
                .map_err(internal)?;
        }
        if control_plane_schema_exists > 0 && stamped < 3 {
            // v2 -> v3: per-disk durability tier (ADR-0021). Existing disks
            // keep the semantics they were created under: strict.
            conn.execute_batch(
                "ALTER TABLE disks ADD COLUMN durability TEXT NOT NULL DEFAULT 'strict'",
            )
            .map_err(internal)?;
        }
        conn.execute_batch(SCHEMA).map_err(internal)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(internal)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

/// Bumped on every schema change. `Store::open` upgrades a database stamped
/// inside `[OLDEST_MIGRATABLE_SCHEMA_VERSION, SCHEMA_VERSION]` in place and
/// refuses anything else: production now carries control-plane state that has
/// to survive (workspaces, tokens), so each release keeps exactly the ladder
/// the live fleet needs and deletes rungs once no deployment is below them.
/// Deployment automation reads both constants and refuses to replace a live
/// Pod whose database this build can neither run nor migrate.
pub(super) const SCHEMA_VERSION: i64 = 3;

/// The oldest stamped version `Store::open` can still upgrade in place.
const OLDEST_MIGRATABLE_SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('personal','organization')),
    workos_organization_id TEXT NOT NULL UNIQUE,
    billing_account_id TEXT NOT NULL UNIQUE,
    personal_owner_user_id TEXT UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('provisioning','active','disabled')),
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    slug TEXT NOT NULL,
    display_name TEXT NOT NULL,
    is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0,1)),
    created_at INTEGER NOT NULL,
    UNIQUE (account_id, slug)
);
CREATE UNIQUE INDEX IF NOT EXISTS workspaces_one_default
ON workspaces(account_id) WHERE is_default=1;
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
CREATE TABLE IF NOT EXISTS workspace_tokens (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    label TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS workspace_tokens_active
ON workspace_tokens(token_hash) WHERE revoked_at IS NULL;
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
    expires_at_unix INTEGER,
    UNIQUE (workspace_id, name)
);
CREATE TABLE IF NOT EXISTS disks (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    state TEXT NOT NULL,
    volume_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    durability TEXT NOT NULL DEFAULT 'strict',
    UNIQUE (workspace_id, name)
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
CREATE TRIGGER IF NOT EXISTS cats_workspace_owner_is_immutable
   BEFORE UPDATE OF workspace_id ON cats
   WHEN NEW.workspace_id != OLD.workspace_id
   BEGIN SELECT RAISE(ABORT, 'cats workspace owner is immutable'); END;
CREATE TRIGGER IF NOT EXISTS disks_workspace_owner_is_immutable
   BEFORE UPDATE OF workspace_id ON disks
   WHEN NEW.workspace_id != OLD.workspace_id
   BEGIN SELECT RAISE(ABORT, 'disks workspace owner is immutable'); END;
CREATE TRIGGER IF NOT EXISTS operations_workspace_owner_is_immutable
   BEFORE UPDATE OF workspace_id ON operations
   WHEN NEW.workspace_id != OLD.workspace_id
   BEGIN SELECT RAISE(ABORT, 'operations workspace owner is immutable'); END;
";
