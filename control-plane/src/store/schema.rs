use super::*;

use native_tls::{Certificate, TlsConnector};
use postgres_native_tls::MakeTlsConnector;
use std::time::Duration;

impl Store {
    /// Connect to the control database and bring its schema to this build's
    /// version. The URL may carry `options=-csearch_path=...` so tests can
    /// isolate in a per-test schema; reconnects preserve it because they
    /// re-parse the same URL.
    pub fn connect(url: &str, ca_file: Option<&str>) -> Result<Self> {
        Self::connect_from(&DsnSource::Literal(url.to_string()), ca_file)
    }

    /// Connect from a source that is consulted again after every disconnect.
    pub fn connect_from(dsn: &DsnSource, ca_file: Option<&str>) -> Result<Self> {
        let client = off_runtime(|| {
            let mut client = connect_client(dsn, ca_file)?;
            ensure_schema(&mut client)?;
            Ok::<_, ApiError>(client)
        })?;
        Ok(Self {
            client: Mutex::new(Some(client)),
            dsn: dsn.clone(),
            ca_file: ca_file.map(str::to_string),
        })
    }
}

pub(super) fn connect_client(dsn: &DsnSource, ca_file: Option<&str>) -> Result<Client> {
    let mut builder = TlsConnector::builder();
    if let Some(path) = ca_file {
        let pem = std::fs::read(path)
            .map_err(|error| internal(format!("read control-store CA file: {error}")))?;
        let certificates = pem_certificates(&pem)?;
        if certificates.is_empty() {
            return Err(internal(format!(
                "control-store CA file {path:?} contains no certificates"
            )));
        }
        for certificate in certificates {
            builder.add_root_certificate(certificate);
        }
    }
    let connector = builder
        .build()
        .map_err(|error| internal(format!("build control-store TLS client: {error}")))?;
    let url = dsn.resolve()?;
    let mut config: postgres::Config = url
        .parse()
        .map_err(|error| internal(format!("parse control-store URL: {error}")))?;
    config.connect_timeout(Duration::from_secs(5));
    let client = config
        .connect(MakeTlsConnector::new(connector))
        .map_err(|error| internal(connect_failure(error)))?;
    Ok(client)
}

/// Describe a failed connect using the server's own words. `postgres::Error`
/// renders a server-side failure as just "db error"; the reason is only
/// reachable through `as_db_error`, and losing it has cost real diagnosis
/// time before (a rotated password surfacing as an unexplained "db error").
fn connect_failure(error: postgres::Error) -> String {
    match error.as_db_error() {
        Some(database_error) => {
            let detail = database_error
                .detail()
                .map(|value| format!("; {value}"))
                .unwrap_or_default();
            format!(
                "connect control store: {}{detail}",
                database_error.message()
            )
        }
        None => format!("connect control store: {error}"),
    }
}

fn pem_certificates(pem: &[u8]) -> Result<Vec<Certificate>> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let mut certificates = Vec::new();
    let mut rest = pem;
    while let Some(start) = find_bytes(rest, BEGIN) {
        let candidate = &rest[start..];
        let Some(end) = find_bytes(candidate, END) else {
            return Err(internal(
                "control-store CA file has an unterminated certificate",
            ));
        };
        let end = end + END.len();
        certificates.push(
            Certificate::from_pem(&candidate[..end]).map_err(|error| {
                internal(format!("parse control-store CA certificate: {error}"))
            })?,
        );
        rest = &candidate[end..];
    }
    Ok(certificates)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn ensure_schema(client: &mut Client) -> Result<()> {
    client
        .batch_execute("SET statement_timeout = '5s'; SET lock_timeout = '2s'")
        .map_err(internal)?;
    // Two replicas racing this DDL on the same empty schema must converge, not
    // fail each other: IF NOT EXISTS everywhere, and the whole batch behind an
    // advisory lock so concurrent CREATEs cannot deadlock mid-batch. The lock
    // is keyed on the schema, not the database: per-test schemas must not
    // queue behind each other (lock_timeout would fail the stragglers).
    client
        .batch_execute("SELECT pg_advisory_lock(hashtext(current_schema()), 420103)")
        .map_err(internal)?;
    let ensure = (|| -> Result<()> {
        let stamped: Option<i64> = match client.query_opt(
            "SELECT version FROM control_schema_version WHERE singleton",
            &[],
        ) {
            Ok(row) => row.map(|row| row.get(0)),
            Err(error) if error.code() == Some(&postgres::error::SqlState::UNDEFINED_TABLE) => None,
            Err(error) => return Err(internal(error)),
        };
        if let Some(stamped) = stamped {
            if !(OLDEST_MIGRATABLE_SCHEMA_VERSION..=SCHEMA_VERSION).contains(&stamped) {
                return Err(ApiError::failed_precondition(format!(
                    "control-plane database is at schema version {stamped}, this build \
                     requires {SCHEMA_VERSION} (migratable from \
                     {OLDEST_MIGRATABLE_SCHEMA_VERSION}); recreate it"
                )));
            }
        }
        client.batch_execute(SCHEMA).map_err(internal)?;
        client
            .execute(
                "INSERT INTO control_schema_version (singleton, version) VALUES (TRUE, $1)
                 ON CONFLICT (singleton) DO UPDATE SET version = EXCLUDED.version",
                &[&SCHEMA_VERSION],
            )
            .map_err(internal)?;
        Ok(())
    })();
    let unlock =
        client.batch_execute("SELECT pg_advisory_unlock(hashtext(current_schema()), 420103)");
    ensure?;
    unlock.map_err(internal)?;
    Ok(())
}

/// Bumped on every incompatible schema change. The PostgreSQL store starts its own ladder:
/// version 1 is the v5 SQLite layout re-expressed in PostgreSQL, and there is
/// deliberately no SQLite import path (decided with #103: the pre-cutover data
/// is not carried over). `connect` upgrades a database stamped inside
/// `[OLDEST_MIGRATABLE_SCHEMA_VERSION, SCHEMA_VERSION]` in place and refuses
/// anything else.
// Route Grant rollout metadata is an expand-only addition: the v1 binary
// ignores the nullable Node column and the new table, so retaining stamp 1 is
// what keeps an application rollback startable during the mixed-version
// rollout. A future contract migration must bump this value.
pub(super) const SCHEMA_VERSION: i64 = 1;

/// The oldest stamped version `Store::connect` can still upgrade in place.
const OLDEST_MIGRATABLE_SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS control_schema_version (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS route_grant_rollout_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    legacy_admission_open BOOLEAN NOT NULL
);
INSERT INTO route_grant_rollout_state (singleton, legacy_admission_open)
VALUES (TRUE, TRUE)
ON CONFLICT (singleton) DO NOTHING;
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('personal','organization')),
    workos_organization_id TEXT NOT NULL UNIQUE,
    billing_account_id TEXT NOT NULL UNIQUE,
    personal_owner_user_id TEXT UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('provisioning','active','disabled')),
    created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    slug TEXT NOT NULL,
    display_name TEXT NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT NOT NULL,
    UNIQUE (account_id, slug)
);
CREATE UNIQUE INDEX IF NOT EXISTS workspaces_one_default
ON workspaces(account_id) WHERE is_default;
CREATE TABLE IF NOT EXISTS account_membership_shadow (
    workos_membership_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    workos_user_id TEXT NOT NULL,
    role_slug TEXT NOT NULL,
    status TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (account_id, workos_user_id)
);
CREATE TABLE IF NOT EXISTS workspace_grants (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    workos_user_id TEXT NOT NULL,
    access_level TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (workspace_id, workos_user_id)
);
CREATE TABLE IF NOT EXISTS workspace_tokens (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    label TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL,
    revoked_at BIGINT
);
CREATE INDEX IF NOT EXISTS workspace_tokens_active
ON workspace_tokens(token_hash) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS signup_grant_eligibility (
    workos_user_id TEXT NOT NULL,
    campaign TEXT NOT NULL,
    billing_account_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('pending','applied')),
    created_at BIGINT NOT NULL,
    applied_at BIGINT,
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
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS workos_event_receipts (
    workos_event_id TEXT PRIMARY KEY,
    event_name TEXT NOT NULL,
    processed_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS cats (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    image TEXT NOT NULL,
    cpus BIGINT NOT NULL,
    memory_mib BIGINT NOT NULL,
    root_disk_id TEXT NOT NULL,
    desired_state TEXT NOT NULL,
    observed_state TEXT NOT NULL,
    generation BIGINT NOT NULL,
    auto_suspend BOOLEAN NOT NULL DEFAULT TRUE,
    work_version BIGINT NOT NULL DEFAULT 0,
    observed_state_since_ms BIGINT NOT NULL,
    node_id TEXT,
    created_at BIGINT NOT NULL,
    expires_at_unix BIGINT,
    UNIQUE (workspace_id, name)
);
CREATE TABLE IF NOT EXISTS disks (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    state TEXT NOT NULL,
    volume_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
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
    cpus BIGINT NOT NULL,
    memory_mib BIGINT NOT NULL,
    last_heartbeat_ms BIGINT NOT NULL,
    telemetry_json TEXT,
    scheduling_disabled BOOLEAN NOT NULL DEFAULT FALSE,
    reported_cats_json TEXT,
    route_grant_public_key_sha256 TEXT
);
ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS route_grant_public_key_sha256 TEXT;
CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_generation BIGINT NOT NULL,
    phase TEXT NOT NULL,
    error_json TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS operations_active_resource_generation
ON operations(resource_id, resource_generation)
WHERE phase IN ('pending','running');
CREATE TABLE IF NOT EXISTS idempotency (
    key TEXT NOT NULL,
    route TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    PRIMARY KEY (key, route)
);
-- One row per (cat, app, pinned digest): the deployment's identity, so a
-- retried request finds the first attempt instead of starting a second one.
-- The UNIQUE constraint is the idempotency mechanism; handler code only reads
-- what the constraint decided. Registry credentials are deliberately absent --
-- they are transient pull credentials and must never be persisted, which is
-- also why an interrupted deploy cannot be resumed after a restart and is
-- converged to 'failed' instead.
--
-- 'superseded' is what a succeeded row becomes when a later digest is
-- activated for the same app. It matters because a Cat runs exactly one image
-- per app: without it, re-requesting an older digest would replay a record for
-- something no longer running, reporting success while the Guest kept serving
-- the newer image.
CREATE TABLE IF NOT EXISTS oci_deployments (
    id TEXT PRIMARY KEY,
    cat_id TEXT NOT NULL,
    app TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    phase TEXT NOT NULL
        CHECK (phase IN ('running','succeeded','failed','superseded')),
    manifest_digest TEXT,
    service TEXT,
    active BOOLEAN NOT NULL DEFAULT FALSE,
    error_json TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (cat_id, app, image_digest)
);
-- At most one activated deployment per (cat, app), enforced rather than
-- maintained by convention: a Cat has one `current` symlink and one systemd
-- unit per app, so two 'succeeded' rows for one app would describe a state the
-- Guest cannot be in. This also removes any need to order or de-duplicate when
-- reading what is deployed.
CREATE UNIQUE INDEX IF NOT EXISTS oci_deployments_one_current_per_app
    ON oci_deployments (cat_id, app) WHERE phase='succeeded';
CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    cat_id TEXT NOT NULL,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL UNIQUE,
    target_port BIGINT NOT NULL,
    protocol TEXT NOT NULL,
    wake_policy TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS routes (
    hostname TEXT PRIMARY KEY,
    cat_id TEXT NOT NULL,
    node_id TEXT,
    gateway_url TEXT,
    target_port BIGINT NOT NULL,
    epoch BIGINT NOT NULL,
    state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cat_work_sources (
    cat_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    source_epoch TEXT NOT NULL,
    lease_sequence BIGINT NOT NULL,
    seen_at_ms BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS cat_work_leases (
    id TEXT PRIMARY KEY,
    cat_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    label TEXT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    source_epoch TEXT,
    UNIQUE (cat_id, kind, owner_id)
);
CREATE INDEX IF NOT EXISTS cat_work_leases_live
ON cat_work_leases(cat_id, expires_at_ms);
-- Workspace ownership is immutable, enforced in the database exactly as the
-- SQLite triggers did. Raised as an ordinary exception; the store maps it to
-- a conflict.
CREATE OR REPLACE FUNCTION control_workspace_owner_is_immutable() RETURNS trigger AS $$
BEGIN
    IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id THEN
        RAISE EXCEPTION '% workspace owner is immutable', TG_TABLE_NAME;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger t
         JOIN pg_class c ON c.oid = t.tgrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE t.tgname = 'cats_workspace_owner_is_immutable'
          AND n.nspname = current_schema()
    ) THEN
        CREATE TRIGGER cats_workspace_owner_is_immutable
            BEFORE UPDATE OF workspace_id ON cats
            FOR EACH ROW EXECUTE FUNCTION control_workspace_owner_is_immutable();
        CREATE TRIGGER disks_workspace_owner_is_immutable
            BEFORE UPDATE OF workspace_id ON disks
            FOR EACH ROW EXECUTE FUNCTION control_workspace_owner_is_immutable();
        CREATE TRIGGER operations_workspace_owner_is_immutable
            BEFORE UPDATE OF workspace_id ON operations
            FOR EACH ROW EXECUTE FUNCTION control_workspace_owner_is_immutable();
    END IF;
END;
$$;
";
