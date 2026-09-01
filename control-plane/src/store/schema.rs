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
            #[cfg(test)]
            commit_response_loss_once: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            request_commit_response_loss_once: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            commit_response_loss_delay_ms: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Verify a pre-existing Control schema without installing or repairing
    /// any object. Reset and release preflight callers must bind the DSN's
    /// search path to the exact explicit target and use this read-only path;
    /// ordinary `connect_from` remains the sole fresh-schema installer.
    pub fn verify_existing_schema(
        dsn: &DsnSource,
        ca_file: Option<&str>,
        expected_schema: &str,
    ) -> Result<()> {
        let mut schema_characters = expected_schema.chars();
        if expected_schema.len() > 63
            || !schema_characters
                .next()
                .is_some_and(|value| value == '_' || value.is_ascii_lowercase())
            || !schema_characters
                .all(|value| value == '_' || value.is_ascii_lowercase() || value.is_ascii_digit())
        {
            return Err(ApiError::invalid(
                "expected Control schema must match [a-z_][a-z0-9_]{0,62}",
            ));
        }
        off_runtime(|| {
            let mut client = connect_client(dsn, ca_file)?;
            client
                .batch_execute("SET statement_timeout = '5s'; SET lock_timeout = '2s'")
                .map_err(internal)?;
            let mut transaction = client.transaction().map_err(internal)?;
            transaction
                .batch_execute("SET TRANSACTION READ ONLY")
                .map_err(internal)?;
            let actual_schema: String = transaction
                .query_one("SELECT COALESCE(current_schema(), '')", &[])
                .map_err(internal)?
                .get(0);
            if actual_schema != expected_schema {
                return Err(ApiError::failed_precondition(format!(
                    "Control DSN selects schema {actual_schema}, expected exact schema {expected_schema}"
                )));
            }
            transaction
                .query_one(
                    "SELECT pg_advisory_xact_lock_shared(hashtext(current_schema()), 420103)",
                    &[],
                )
                .map_err(internal)?;
            if !relation_exists(&mut transaction, "control_schema_version")? {
                return Err(ApiError::failed_precondition(format!(
                    "Control schema {expected_schema} has no release stamp; refusing installation"
                )));
            }
            let stamped = transaction
                .query_opt(
                    "SELECT version FROM control_schema_version WHERE singleton",
                    &[],
                )
                .map_err(internal)?
                .ok_or_else(|| {
                    ApiError::failed_precondition(
                        "control-plane schema stamp is missing its singleton row; recreate it",
                    )
                })?
                .get::<_, i64>(0);
            if stamped != SCHEMA_VERSION {
                return Err(ApiError::failed_precondition(format!(
                    "control-plane database is at schema version {stamped}, this build requires exact clean-slate version {SCHEMA_VERSION}; recreate it"
                )));
            }
            verify_current_schema(&mut transaction)?;
            transaction.commit().map_err(internal)
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
        .map_err(|error| ApiError::unavailable(connect_failure(error)))?;
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
    let isolated_test_bootstrap: bool = client
        .query_one(
            "SELECT COALESCE(
                current_setting('cats.test_schema_bootstrap', TRUE) = 'on',
                FALSE
             )",
            &[],
        )
        .map_err(internal)?
        .get(0);
    // The clean-slate cutover has one schema shape. DDL and its stamp commit in
    // the same transaction; a current stamp is verified but never repaired.
    // The xact-scoped lock lets two first replicas converge without leaving a
    // session lock behind after any error.
    let mut transaction = client.transaction().map_err(internal)?;
    // Integration tests link the ordinary library, so the isolated-schema
    // helper carries an exact custom GUC instead of relying on cfg(test).
    // SET LOCAL restores the production 5s/2s session limits at transaction
    // end, and no other marker value changes production behavior. Four
    // workspace test threads can queue behind the intentionally global DDL
    // lock while a concurrent Linux gate loads the host, so the test-only
    // budget covers the complete bounded queue rather than one schema install.
    if isolated_test_bootstrap {
        transaction
            .batch_execute(
                "SET LOCAL statement_timeout = '120s'; \
                 SET LOCAL lock_timeout = '120s'",
            )
            .map_err(internal)?;
    }
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtext(current_schema()), 420103)",
            &[],
        )
        .map_err(internal)?;

    if relation_exists(&mut transaction, "control_schema_version")? {
        let stamped = transaction
            .query_opt(
                "SELECT version FROM control_schema_version WHERE singleton",
                &[],
            )
            .map_err(|error| internal(format!("verify authority foreign key catalog: {error:?}")))?
            .ok_or_else(|| {
                ApiError::failed_precondition(
                    "control-plane schema stamp is missing its singleton row; recreate it",
                )
            })?
            .get::<_, i64>(0);
        if stamped != SCHEMA_VERSION {
            return Err(ApiError::failed_precondition(format!(
                "control-plane database is at schema version {stamped}, this build requires exact clean-slate version {SCHEMA_VERSION}; recreate it"
            )));
        }
        verify_current_schema(&mut transaction)?;
    } else {
        if CONTROL_TABLES.iter().try_fold(false, |found, table| {
            relation_exists(&mut transaction, table).map(|exists| found || exists)
        })? {
            return Err(ApiError::failed_precondition(
                "control-plane schema is nonempty but unstamped; recreate it",
            ));
        }
        // Different isolated test schemas do not share the production
        // per-schema lock, so serialize only their catalog-heavy initial DDL.
        if isolated_test_bootstrap {
            transaction
                .query_one("SELECT pg_advisory_xact_lock(420111, 1)", &[])
                .map_err(internal)?;
        }
        transaction.batch_execute(SCHEMA).map_err(internal)?;
        transaction
            .execute(
                "INSERT INTO control_schema_version (singleton, version) VALUES (TRUE, $1)",
                &[&SCHEMA_VERSION],
            )
            .map_err(internal)?;
        verify_current_schema(&mut transaction)?;
    }
    transaction.commit().map_err(internal)
}

fn relation_exists(transaction: &mut postgres::Transaction<'_>, relation: &str) -> Result<bool> {
    transaction
        .query_one(
            "SELECT EXISTS (
                SELECT 1
                  FROM pg_class c
                  JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = current_schema()
                   AND c.relname = $1
                   AND c.relkind IN ('r', 'p')
             )",
            &[&relation],
        )
        .map(|row| row.get(0))
        .map_err(internal)
}

fn column_exists(
    transaction: &mut postgres::Transaction<'_>,
    relation: &str,
    column: &str,
) -> Result<bool> {
    transaction
        .query_one(
            "SELECT EXISTS (
                SELECT 1
                  FROM information_schema.columns
                 WHERE table_schema=current_schema()
                   AND table_name=$1
                   AND column_name=$2
             )",
            &[&relation, &column],
        )
        .map(|row| row.get(0))
        .map_err(internal)
}

fn verify_current_schema(transaction: &mut postgres::Transaction<'_>) -> Result<()> {
    for table in CONTROL_TABLES {
        if !relation_exists(transaction, table)? {
            return Err(ApiError::failed_precondition(format!(
                "control-plane schema version {SCHEMA_VERSION} is partial: missing table {table}; recreate it"
            )));
        }
    }
    for table in FORBIDDEN_LEGACY_CONTROL_TABLES {
        if relation_exists(transaction, table)? {
            return Err(ApiError::failed_precondition(format!(
                "control-plane schema version {SCHEMA_VERSION} still contains legacy authority table {table}; recreate it"
            )));
        }
    }
    for (table, column) in FORBIDDEN_LEGACY_CONTROL_COLUMNS {
        if column_exists(transaction, table, column)? {
            return Err(ApiError::failed_precondition(format!(
                "control-plane schema version {SCHEMA_VERSION} still contains legacy authority column {table}.{column}; recreate it"
            )));
        }
    }

    // These probes also make a manually stamped shape with a missing authority
    // projection fail at startup instead of being repaired or discovered by a
    // writer later.
    for probe in AUTHORITY_SCHEMA_PROBES {
        transaction.query(*probe, &[]).map_err(|error| {
            ApiError::failed_precondition(format!(
                "control-plane schema version {SCHEMA_VERSION} does not match this build: {error}; recreate it"
            ))
        })?;
    }
    Ok(())
}

/// The Control Store owns the exact clean-slate release stamp. Version 20 has
/// no migration or compatibility reader/writer for an earlier authority shape.
pub(super) const SCHEMA_VERSION: i64 = 20;

const CONTROL_TABLES: &[&str] = &[
    "control_schema_version",
    "accounts",
    "workspaces",
    "nodes",
    "node_heartbeats",
    "cats",
    "cat_ingress_targets",
    "persistent_disks",
    "disk_bindings",
    "account_membership_shadow",
    "workspace_tokens",
    "signup_grant_eligibility",
    "account_invitations",
    "workos_event_receipts",
    "volume_records",
    "disk_records",
    "disk_snapshots",
    "disk_snapshot_records",
    "production_mutation_admission_commands",
    "production_mutation_admission",
    "node_identities",
    "runtime_node_placement_policies",
    "runtime_node_authority_apply_records",
    "runtime_node_credential_lineage",
    "runtime_provisioner_deployment_identity",
    "runtime_provisioner_trust_revisions",
    "runtime_provisioner_credential_lineage",
];

// Version 20 is an empty-database cutover, not an additive migration. A
// manually stamped database that still exposes any former product or Desired
// authority must fail closed instead of letting old and atomic writers coexist.
const FORBIDDEN_LEGACY_CONTROL_TABLES: &[&str] = &[
    "oci_deployments",
    "cat_records",
    "endpoint_records",
    "cat_runtime_configs",
    "hostname_endpoint_lookups",
    "runtime_operations",
    "lifecycle_volume_receipts",
    "route_operations",
    "api_idempotency_results",
    "agent_registration_attempts",
    "current_agent_sessions",
    "route_node_ring_acks",
    "runtime_inventory_receive_states",
    "runtime_full_inventory_attestations",
    "runtime_current_cat_telemetry",
    "route_v2_gateway_identity_authority",
    "route_v2_gateway_identity_revisions",
    "route_v2_gateway_credential_lineage",
    "route_v2_gateway_current_credentials",
    "route_v2_signing_authority",
    "route_v2_signer_revisions",
    "route_v2_signer_key_lineage",
    "route_v2_public_key_ring_revisions",
    "route_v2_signer_retirements",
    "route_v2_rotation_operator_authority",
    "route_v2_rotation_operator_credentials",
    "route_v2_signing_command_receipts",
    "route_v2_public_ring_deliveries",
    "route_grant_rollout_state",
    "disks",
    "mount_bindings",
    "operations",
    "idempotency",
    "endpoints",
    "routes",
    "cat_work_sources",
    "cat_work_leases",
    "desired_runtime_specs",
    "hostname_desired_lookups",
    "runtime_desired_read_states",
    "runtime_observation_receive_states",
    "runtime_current_cat_observations",
    "runtime_admission_inventory_states",
    "trusted_host_fence_recovery_attempts_v1",
    "trusted_host_fence_recovery_attempt_cats_v1",
    "host_fence_events",
    "volume_authorizations",
    "delete_completion_receipts",
];

const FORBIDDEN_LEGACY_CONTROL_COLUMNS: &[(&str, &str)] =
    &[("volume_records", "transition_desired_revision")];

// Startup probes bind the columns used by the active semantic protocol.
const AUTHORITY_SCHEMA_PROBES: &[&str] = &[
    "SELECT node_id, node_name, control_endpoint, vendor, region, zone,
            instance_id, machine_type, node_version, status, created_at, updated_at
       FROM nodes WHERE FALSE",
    "SELECT node_id, last_heartbeat_at, node_reported_at, reported_status,
            total_cpu, cpu_utilized, total_memory, memory_utilized,
            running_cat_count, suspended_cat_count, warm_cat_count
       FROM node_heartbeats WHERE FALSE",
    "SELECT cat_id, workspace_id, cat_slug, state, current_action,
            current_action_started_at, current_action_recovery_started_at,
            current_action_node_id, node_id,
            cpu_count, memory_bytes, boot_image, last_error_code,
            last_error_message, created_at, updated_at, destroyed_at,
            last_running_at
       FROM cats WHERE FALSE",
    "SELECT disk_id, workspace_id, disk_slug, size_bytes, status,
            created_at, deleted_at
       FROM persistent_disks WHERE FALSE",
    "SELECT binding_id, workspace_id, disk_id, cat_id, mount_path, created_at
       FROM disk_bindings WHERE FALSE",
    "SELECT volume_id, record, size_bytes, durability, admin_state, delete_id,
            gc_required, gc_id, gc_roots_digest, gc_started_at,
            head_generation, head_root_hash, head_root_object_id, lease_owner,
            lease_epoch, lease_expires_at, last_transition_kind,
            last_transition_id, transition_placement_epoch,
            transition_lease_duration_ms, owner_binding, owner_node_id
       FROM volume_records WHERE FALSE",
    "SELECT disk_id, record, workspace_id, name, volume_id, size_bytes,
            durability, created_at, admin_state, delete_id, role_kind,
            root_cat_id, initialization_kind, initialization_token,
            filesystem_uuid, expected_blank_generation,
            expected_blank_root_hash, expected_blank_root_object_id,
            initialized_generation, initialized_root_hash,
            initialized_root_object_id, initialized_at,
            initialization_commit_receipt_bytes,
            initialization_commit_receipt_digest
       FROM disk_records WHERE FALSE",
    "SELECT snapshot_id, workspace_id, snapshot_slug, disk_id, disk_slug,
            volume_id, size_bytes, captured_generation,
            deleted_head_generation, created_at, deleted_at
       FROM disk_snapshots WHERE FALSE",
    "SELECT snapshot_id, record, disk_id, volume_id, size_bytes,
            head_generation, head_root_hash, head_root_object_id, created_at
       FROM disk_snapshot_records WHERE FALSE",
];

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS control_schema_version (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version BIGINT NOT NULL
);
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
-- The semantic Control/Node protocol is the only lifecycle product model.
-- The former runtime Operation, AgentSession, Route and inventory settlement
-- projections are deliberately absent from this clean schema.
CREATE TABLE IF NOT EXISTS nodes (
    node_id TEXT PRIMARY KEY,
    node_name TEXT NOT NULL CHECK (length(node_name) BETWEEN 1 AND 255),
    control_endpoint TEXT NOT NULL CHECK (length(control_endpoint) BETWEEN 1 AND 2048),
    vendor TEXT NOT NULL CHECK (length(vendor) BETWEEN 1 AND 63),
    region TEXT NOT NULL CHECK (length(region) BETWEEN 1 AND 127),
    zone TEXT NOT NULL CHECK (length(zone) BETWEEN 1 AND 127),
    instance_id TEXT NOT NULL CHECK (length(instance_id) BETWEEN 1 AND 255),
    machine_type TEXT NOT NULL CHECK (length(machine_type) BETWEEN 1 AND 127),
    node_version TEXT NOT NULL CHECK (length(node_version) BETWEEN 1 AND 127),
    status TEXT NOT NULL
        CHECK (status IN ('running','draining','offline','reset_required','deleted')),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at),
    CONSTRAINT nodes_cloud_instance_unique UNIQUE (vendor, instance_id)
);
CREATE TABLE IF NOT EXISTS node_heartbeats (
    node_id TEXT PRIMARY KEY REFERENCES nodes(node_id),
    -- Written from clock_timestamp() by the heartbeat upsert.  Node time is
    -- retained separately and must never decide liveness.
    last_heartbeat_at BIGINT NOT NULL CHECK (last_heartbeat_at >= 0),
    node_reported_at BIGINT CHECK (node_reported_at >= 0),
    reported_status TEXT NOT NULL
        CHECK (reported_status IN ('running','draining','offline','reset_required','deleted')),
    -- Zero means the Node has registered but has not delivered its first
    -- telemetry heartbeat yet. Registration still creates the DB-time row so
    -- a never-heartbeating Node participates in stale detection.
    total_cpu BIGINT NOT NULL CHECK (total_cpu >= 0),
    cpu_utilized DOUBLE PRECISION NOT NULL
        CHECK (cpu_utilized >= 0 AND cpu_utilized <= total_cpu),
    total_memory BIGINT NOT NULL CHECK (total_memory >= 0),
    memory_utilized BIGINT NOT NULL
        CHECK (memory_utilized >= 0 AND memory_utilized <= total_memory),
    running_cat_count BIGINT NOT NULL CHECK (running_cat_count >= 0),
    suspended_cat_count BIGINT NOT NULL CHECK (suspended_cat_count >= 0),
    warm_cat_count BIGINT NOT NULL CHECK (warm_cat_count >= 0)
);
CREATE TABLE IF NOT EXISTS cats (
    cat_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    cat_slug TEXT NOT NULL
        CHECK (cat_slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    state TEXT CHECK (state IN ('running','suspended','warm','cold','failure','destroyed')),
    current_action TEXT
        CHECK (current_action IN ('create','run','suspend','warm','cold','destroy')),
    current_action_started_at BIGINT CHECK (current_action_started_at >= 0),
    current_action_recovery_started_at BIGINT
        CHECK (current_action_recovery_started_at >= current_action_started_at),
    current_action_node_id TEXT REFERENCES nodes(node_id),
    node_id TEXT REFERENCES nodes(node_id),
    cpu_count BIGINT NOT NULL CHECK (cpu_count > 0),
    memory_bytes BIGINT NOT NULL CHECK (memory_bytes > 0),
    boot_image TEXT NOT NULL CHECK (length(boot_image) > 0),
    last_error_code TEXT,
    last_error_message TEXT,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at),
    destroyed_at BIGINT CHECK (destroyed_at >= created_at),
    -- Newest DB time at which this Cat was recorded settled in Running. NULL
    -- means it has never run. Every settle whose resulting *or* previous state
    -- is Running writes it, so a Cat that moved running -> suspended -> warm
    -- still reports when it actually stopped running -- which `updated_at`
    -- cannot, because that is the last change of any kind and, while an action
    -- is in flight, an activity clock.
    last_running_at BIGINT CHECK (last_running_at >= created_at),
    CONSTRAINT cats_workspace_identity_unique UNIQUE (workspace_id, cat_id),
    -- A settled Running Cat has, by definition, been recorded running. The
    -- constraint makes a missed write site fail at the write instead of
    -- silently projecting NULL for a Cat that is demonstrably running.
    CONSTRAINT cats_running_records_its_run_check CHECK (
        state IS DISTINCT FROM 'running' OR last_running_at IS NOT NULL
    ),
    CONSTRAINT cats_destroyed_shape_check CHECK (
        ((state = 'destroyed') IS TRUE) = (destroyed_at IS NOT NULL)
    ),
    CONSTRAINT cats_initial_create_shape_check CHECK (
        state IS NOT NULL OR current_action = 'create'
    ),
    CONSTRAINT cats_current_action_shape_check CHECK (
        (current_action IS NULL
            AND current_action_started_at IS NULL
            AND current_action_recovery_started_at IS NULL
            AND current_action_node_id IS NULL) OR
        (current_action IS NOT NULL
            AND current_action_started_at IS NOT NULL
            AND (current_action_node_id IS NOT NULL OR
                 (current_action = 'destroy' AND node_id IS NULL))
            AND state IS DISTINCT FROM 'destroyed')
    ),
    CONSTRAINT cats_placement_shape_check CHECK (
        (state IN ('running','suspended','warm') AND node_id IS NOT NULL) OR
        (state IN ('cold','destroyed') AND node_id IS NULL) OR
        state IN ('failure') OR
        state IS NULL
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS cats_current_slug_unique
ON cats(workspace_id, cat_slug) WHERE destroyed_at IS NULL;
CREATE INDEX IF NOT EXISTS cats_current_action_scan
ON cats(updated_at, current_action_recovery_started_at)
WHERE current_action IS NOT NULL;
CREATE INDEX IF NOT EXISTS cats_node_placement
ON cats(node_id) WHERE node_id IS NOT NULL;
-- One row is the complete serving target for new traffic to a Cat. Absence
-- means withdrawn. Lifecycle state and heartbeat remain separate concerns.
CREATE TABLE IF NOT EXISTS cat_ingress_targets (
    cat_id TEXT PRIMARY KEY REFERENCES cats(cat_id),
    node_id TEXT NOT NULL REFERENCES nodes(node_id),
    updated_at BIGINT NOT NULL CHECK (updated_at >= 0)
);
CREATE INDEX IF NOT EXISTS cat_ingress_targets_node
ON cat_ingress_targets(node_id);
CREATE TABLE IF NOT EXISTS persistent_disks (
    disk_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    disk_slug TEXT NOT NULL
        CHECK (disk_slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    volume_id TEXT NOT NULL UNIQUE,
    filesystem_uuid TEXT NOT NULL UNIQUE
        CHECK (filesystem_uuid ~ '^[0-9a-f]{32}$'),
    disk_format TEXT NOT NULL CHECK (disk_format = 'ext4'),
    status TEXT NOT NULL
        CHECK (status IN ('provisioning','normal','deleting','deleted')),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    deleted_at BIGINT CHECK (deleted_at >= created_at),
    CONSTRAINT persistent_disks_workspace_identity_unique
        UNIQUE (workspace_id, disk_id),
    CONSTRAINT persistent_disks_deleted_shape_check CHECK (
        (status = 'deleted') IS NOT DISTINCT FROM (deleted_at IS NOT NULL)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS disks_current_slug_unique
ON persistent_disks(workspace_id, disk_slug) WHERE deleted_at IS NULL;
CREATE TABLE IF NOT EXISTS disk_bindings (
    binding_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    disk_id TEXT NOT NULL,
    cat_id TEXT NOT NULL,
    mount_path TEXT NOT NULL CHECK (
        mount_path LIKE '/%' AND
        mount_path NOT IN ('/','/boot','/proc','/sys','/dev','/run')
    ),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    CONSTRAINT disk_bindings_disk_unique UNIQUE (disk_id),
    CONSTRAINT disk_bindings_cat_mount_unique UNIQUE (cat_id, mount_path),
    CONSTRAINT disk_bindings_disk_workspace_fkey
        FOREIGN KEY (workspace_id, disk_id)
        REFERENCES persistent_disks(workspace_id, disk_id),
    CONSTRAINT disk_bindings_cat_workspace_fkey
        FOREIGN KEY (workspace_id, cat_id)
        REFERENCES cats(workspace_id, cat_id)
);
CREATE TABLE IF NOT EXISTS account_membership_shadow (
    workos_membership_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    workos_user_id TEXT NOT NULL,
    role_slug TEXT NOT NULL,
    status TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (account_id, workos_user_id)
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
CREATE TABLE IF NOT EXISTS volume_records (
    volume_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    durability TEXT NOT NULL CHECK (durability IN ('strict', 'relaxed')),
    admin_state TEXT NOT NULL
        CHECK (admin_state IN ('active', 'deleting', 'garbage_collecting')),
    delete_id TEXT,
    gc_required BOOLEAN NOT NULL DEFAULT FALSE,
    gc_id TEXT,
    gc_roots_digest TEXT CHECK (
        gc_roots_digest IS NULL OR gc_roots_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    gc_started_at BIGINT CHECK (gc_started_at IS NULL OR gc_started_at >= 0),
    head_generation BIGINT NOT NULL CHECK (head_generation >= 0),
    head_root_hash TEXT,
    head_root_object_id TEXT,
    lease_owner TEXT,
    lease_epoch BIGINT NOT NULL CHECK (lease_epoch >= 0),
    lease_expires_at BIGINT,
    last_transition_kind TEXT CHECK (
        last_transition_kind IN (
            'normal_acquire', 'release', 'begin_delete', 'snapshot_restore'
        )
    ),
    last_transition_id TEXT,
    transition_placement_epoch BIGINT,
    transition_lease_duration_ms BIGINT,
    owner_binding JSONB,
    owner_node_id TEXT,
    CHECK (
        (admin_state = 'active' AND delete_id IS NULL
            AND gc_id IS NULL AND gc_roots_digest IS NULL AND gc_started_at IS NULL) OR
        (admin_state = 'deleting' AND delete_id IS NOT NULL
            AND gc_id IS NULL AND gc_roots_digest IS NULL AND gc_started_at IS NULL) OR
        (admin_state = 'garbage_collecting' AND delete_id IS NULL
            AND gc_required AND gc_id IS NOT NULL
            AND gc_roots_digest IS NOT NULL AND gc_started_at IS NOT NULL)
    ),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
    CHECK (lease_owner IS NULL OR admin_state = 'active'),
    CHECK (lease_owner IS NULL OR (lease_epoch > 0 AND lease_expires_at > 0)),
    CONSTRAINT volume_records_owner_present_check
        CHECK ((lease_owner IS NULL) = (owner_binding IS NULL)),
    CONSTRAINT volume_records_owner_node_present_check
        CHECK ((owner_binding IS NULL) = (owner_node_id IS NULL)),
    CONSTRAINT volume_records_owner_binding_check CHECK (
        owner_binding IS NULL OR owner_binding = jsonb_build_object(
            'volume_id', volume_id,
            'owner_node_id', owner_node_id,
            'attachment_id', lease_owner,
            'attachment_epoch', lease_epoch
        )
    ),
    CHECK (admin_state <> 'deleting' OR (lease_owner IS NULL AND lease_epoch > 0)),
    CHECK (
        (head_generation = 0 AND head_root_hash IS NULL AND head_root_object_id IS NULL) OR
        (head_generation > 0 AND head_root_hash IS NOT NULL AND head_root_object_id IS NOT NULL)
    ),
    CONSTRAINT volume_records_transition_shape_check CHECK ((
        (last_transition_kind IS NULL AND last_transition_id IS NULL
            AND transition_placement_epoch IS NULL
            AND transition_lease_duration_ms IS NULL) OR
        (last_transition_kind = 'normal_acquire' AND last_transition_id IS NOT NULL
            AND transition_placement_epoch > 0
            AND transition_lease_duration_ms > 0) OR
        (last_transition_kind IN ('release', 'begin_delete', 'snapshot_restore')
            AND last_transition_id IS NOT NULL
            AND transition_placement_epoch IS NULL
            AND transition_lease_duration_ms IS NULL)
    ) IS TRUE)
);
CREATE INDEX IF NOT EXISTS volume_records_owner_node
ON volume_records(owner_node_id, volume_id COLLATE \"C\")
WHERE owner_node_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS volume_records_owner_binding_node
ON volume_records((owner_binding->>'owner_node_id'), volume_id COLLATE \"C\")
WHERE owner_binding IS NOT NULL;
CREATE INDEX IF NOT EXISTS volume_records_record_volume
ON volume_records((record->>'volume_id'));
CREATE INDEX IF NOT EXISTS volume_records_delete
ON volume_records((COALESCE(delete_id, '')));
CREATE INDEX IF NOT EXISTS volume_records_record_delete
ON volume_records((record->'admin_state'->>'delete_id'));
CREATE TABLE IF NOT EXISTS disk_records (
    disk_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    volume_id TEXT NOT NULL UNIQUE REFERENCES volume_records(volume_id),
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    durability TEXT NOT NULL CHECK (durability IN ('strict', 'relaxed')),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    admin_state TEXT NOT NULL CHECK (admin_state IN ('active', 'deleting')),
    delete_id TEXT,
    role_kind TEXT NOT NULL CHECK (role_kind IN ('root', 'persistent')),
    root_cat_id TEXT,
    initialization_kind TEXT CHECK (initialization_kind IN ('uninitialized', 'initialized')),
    initialization_token TEXT,
    filesystem_uuid TEXT,
    expected_blank_generation BIGINT,
    expected_blank_root_hash TEXT,
    expected_blank_root_object_id TEXT,
    initialized_generation BIGINT,
    initialized_root_hash TEXT,
    initialized_root_object_id TEXT,
    initialized_at BIGINT,
    initialization_commit_receipt_bytes BYTEA
        CONSTRAINT disk_records_initialization_commit_receipt_bytes_check
        CHECK (initialization_commit_receipt_bytes IS NULL OR
               octet_length(initialization_commit_receipt_bytes) BETWEEN 1 AND 2097152),
    initialization_commit_receipt_digest TEXT
        CONSTRAINT disk_records_initialization_commit_receipt_digest_check
        CHECK (initialization_commit_receipt_digest IS NULL OR
               initialization_commit_receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    UNIQUE (workspace_id, name),
    FOREIGN KEY (workspace_id, root_cat_id)
        REFERENCES cats(workspace_id, cat_id),
    CHECK (
        (admin_state = 'active' AND delete_id IS NULL) OR
        (admin_state = 'deleting' AND delete_id IS NOT NULL)
    ),
    CHECK ((
        (role_kind = 'root'
            AND name = disk_id
            AND root_cat_id IS NOT NULL
            AND initialization_kind IS NULL
            AND initialization_token IS NULL
            AND filesystem_uuid IS NULL
            AND expected_blank_generation IS NULL
            AND expected_blank_root_hash IS NULL
            AND expected_blank_root_object_id IS NULL
            AND initialized_generation IS NULL
            AND initialized_root_hash IS NULL
            AND initialized_root_object_id IS NULL
            AND initialized_at IS NULL
            AND initialization_commit_receipt_bytes IS NULL
            AND initialization_commit_receipt_digest IS NULL) OR
        (role_kind = 'persistent'
            AND root_cat_id IS NULL
            AND initialization_kind = 'uninitialized'
            AND initialization_token IS NOT NULL
            AND filesystem_uuid IS NOT NULL
            AND expected_blank_generation = 0
            AND expected_blank_root_hash IS NULL
            AND expected_blank_root_object_id IS NULL
            AND initialized_generation IS NULL
            AND initialized_root_hash IS NULL
            AND initialized_root_object_id IS NULL
            AND initialized_at IS NULL
            AND initialization_commit_receipt_bytes IS NULL
            AND initialization_commit_receipt_digest IS NULL) OR
        (role_kind = 'persistent'
            AND root_cat_id IS NULL
            AND initialization_kind = 'initialized'
            AND initialization_token IS NOT NULL
            AND filesystem_uuid IS NOT NULL
            AND expected_blank_generation = 0
            AND expected_blank_root_hash IS NULL
            AND expected_blank_root_object_id IS NULL
            AND initialized_generation > 0
            AND initialized_root_hash IS NOT NULL
            AND initialized_root_object_id IS NOT NULL
            AND initialized_at >= 0
            AND initialization_commit_receipt_bytes IS NOT NULL
            AND initialization_commit_receipt_digest IS NOT NULL)
    ) IS TRUE)
);
CREATE UNIQUE INDEX IF NOT EXISTS disk_records_one_root_per_cat
ON disk_records(root_cat_id) WHERE role_kind = 'root';
CREATE UNIQUE INDEX IF NOT EXISTS disk_records_initialization_token_unique
ON disk_records(initialization_token) WHERE role_kind = 'persistent';
CREATE UNIQUE INDEX IF NOT EXISTS disk_records_filesystem_uuid_unique
ON disk_records(filesystem_uuid) WHERE role_kind = 'persistent';
CREATE INDEX IF NOT EXISTS disk_records_record_root_cat
ON disk_records((record->'role'->>'cat_id'));
CREATE INDEX IF NOT EXISTS disk_records_record_volume
ON disk_records((record->>'volume_id'));
CREATE INDEX IF NOT EXISTS disk_records_lookup_scalar_scalar
ON disk_records(workspace_id COLLATE \"C\", disk_id COLLATE \"C\");
CREATE INDEX IF NOT EXISTS disk_records_lookup_scalar_record
ON disk_records(workspace_id COLLATE \"C\", (record->>'disk_id') COLLATE \"C\")
WHERE disk_id COLLATE \"C\" IS DISTINCT FROM (record->>'disk_id') COLLATE \"C\";
CREATE INDEX IF NOT EXISTS disk_records_lookup_record_scalar
ON disk_records((record->>'workspace_id') COLLATE \"C\", disk_id COLLATE \"C\")
WHERE workspace_id COLLATE \"C\" IS DISTINCT FROM (record->>'workspace_id') COLLATE \"C\";
CREATE INDEX IF NOT EXISTS disk_records_lookup_record_record
ON disk_records((record->>'workspace_id') COLLATE \"C\", (record->>'disk_id') COLLATE \"C\")
WHERE workspace_id COLLATE \"C\" IS DISTINCT FROM (record->>'workspace_id') COLLATE \"C\"
  AND disk_id COLLATE \"C\" IS DISTINCT FROM (record->>'disk_id') COLLATE \"C\";
-- Product identity/tombstone is retained after deletion so snapshot IDs are
-- never reused while the workspace slug is immediately reusable. It does not
-- reference the parent Disk/Volume because those rows may be removed after
-- the live root is released.
CREATE TABLE IF NOT EXISTS disk_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    snapshot_slug TEXT NOT NULL
        CHECK (snapshot_slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    disk_id TEXT NOT NULL,
    disk_slug TEXT NOT NULL
        CHECK (disk_slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    volume_id TEXT NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    captured_generation BIGINT NOT NULL CHECK (captured_generation > 0),
    deleted_head_generation BIGINT CHECK (deleted_head_generation > 0),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    deleted_at BIGINT CHECK (deleted_at >= created_at),
    CONSTRAINT disk_snapshots_deleted_result_exact
        CHECK ((deleted_at IS NULL) = (deleted_head_generation IS NULL)),
    CONSTRAINT disk_snapshots_deleted_generation_monotonic
        CHECK (deleted_head_generation IS NULL OR
               deleted_head_generation >= captured_generation),
    CONSTRAINT disk_snapshots_workspace_identity_unique
        UNIQUE (workspace_id, snapshot_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS disk_snapshots_current_slug_unique
ON disk_snapshots(workspace_id, snapshot_slug) WHERE deleted_at IS NULL;
-- Only this row is a live GC root. Keeping the parent FKs makes an accidental
-- Disk/Volume metadata deletion fail at PostgreSQL while the pin exists.
CREATE TABLE IF NOT EXISTS disk_snapshot_records (
    snapshot_id TEXT PRIMARY KEY,
    CONSTRAINT disk_snapshot_records_product_fkey
        FOREIGN KEY (snapshot_id) REFERENCES disk_snapshots(snapshot_id),
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    disk_id TEXT NOT NULL REFERENCES disk_records(disk_id),
    volume_id TEXT NOT NULL REFERENCES volume_records(volume_id),
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    head_generation BIGINT NOT NULL CHECK (head_generation >= 0),
    head_root_hash TEXT,
    head_root_object_id TEXT,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    CHECK (
        (head_generation = 0 AND head_root_hash IS NULL AND head_root_object_id IS NULL) OR
        (head_generation > 0 AND head_root_hash IS NOT NULL AND head_root_object_id IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS disk_snapshot_records_disk
ON disk_snapshot_records(disk_id, snapshot_id);
CREATE INDEX IF NOT EXISTS disk_snapshot_records_volume
ON disk_snapshot_records(volume_id, snapshot_id);
CREATE INDEX IF NOT EXISTS disk_snapshot_records_record_disk
ON disk_snapshot_records((record->>'disk_id'), snapshot_id);
CREATE INDEX IF NOT EXISTS disk_snapshot_records_record_volume
ON disk_snapshot_records((record->>'volume_id'), snapshot_id);
CREATE TABLE IF NOT EXISTS production_mutation_admission_commands (
    command_id TEXT PRIMARY KEY
        CONSTRAINT production_mutation_admission_commands_id_ck
        CHECK (command_id ~ '^[0-9a-f]{32}$'),
    command JSONB NOT NULL
        CONSTRAINT production_mutation_admission_commands_command_ck
        CHECK (jsonb_typeof(command) = 'object'),
    request_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_request_digest_ck
        CHECK (request_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    principal JSONB NOT NULL
        CONSTRAINT production_mutation_admission_commands_principal_ck
        CHECK (jsonb_typeof(principal) = 'object'),
    principal_kind TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_principal_kind_ck
        CHECK (principal_kind = 'production_cutover_operator'),
    operator_credential_id TEXT NOT NULL,
    operator_public_key_spki_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_operator_key_ck
        CHECK (operator_public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    operator_trust_bundle_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_operator_trust_ck
        CHECK (operator_trust_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    operator_aws_partition TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_operator_partition_ck
        CHECK (operator_aws_partition IN ('aws', 'aws-us-gov', 'aws-cn')),
    operator_account_id TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_operator_account_ck
        CHECK (operator_account_id ~ '^[0-9]{12}$'),
    operator_role_arn TEXT NOT NULL,
    operator_principal_arn TEXT NOT NULL,
    issued_at_unix_ms BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_commands_issued_time_ck
        CHECK (issued_at_unix_ms >= 0),
    expires_at_unix_ms BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_commands_expiry_time_ck
        CHECK (expires_at_unix_ms > issued_at_unix_ms),
    expected_revision BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_commands_expected_revision_ck
        CHECK (expected_revision > 0),
    mutation_kind TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_mutation_kind_ck
        CHECK (mutation_kind IN (
            'begin_qualification', 'end_qualification', 'emergency_close'
        )),
    target_mode TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_target_mode_ck
        CHECK (target_mode IN ('closed', 'qualification')),
    binding_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_binding_digest_ck
        CHECK (binding_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    release_id TEXT NOT NULL,
    source_commit_sha TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_source_commit_ck
        CHECK (source_commit_sha ~ '^[0-9a-f]{40}$'),
    control_schema_version BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_commands_schema_ck
        CHECK (control_schema_version = 20),
    source_manifest_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_source_manifest_ck
        CHECK (source_manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    source_bundle_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_source_bundle_ck
        CHECK (source_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    build_receipt_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_build_receipt_ck
        CHECK (build_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    release_manifest_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_release_manifest_ck
        CHECK (release_manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    worker_bundle_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_worker_bundle_ck
        CHECK (worker_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_catalog_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_catalog_ck
        CHECK (qualification_catalog_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_cell_manifest_sha256 TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_cell_manifest_ck
        CHECK (qualification_cell_manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_aws_partition TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_partition_ck
        CHECK (qualification_aws_partition IN ('aws', 'aws-us-gov', 'aws-cn')),
    qualification_aws_account_id TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_aws_account_ck
        CHECK (qualification_aws_account_id ~ '^[0-9]{12}$'),
    qualification_aws_region TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_region_ck
        CHECK (qualification_aws_region ~ '^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$'),
    qualification_cell_id TEXT NOT NULL,
    qualification_cell_namespace TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_namespace_ck
        CHECK (qualification_cell_namespace ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    qualification_cats_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    qualification_workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    qualification_mutation_classes JSONB NOT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_classes_ck
        CHECK (jsonb_typeof(qualification_mutation_classes) = 'array'
            AND qualification_mutation_classes =
                '[\"cat_create\",\"disk_create\",\"disk_delete\",\"runtime_mutation\"]'::jsonb),
    qualification_expires_at_unix_ms BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_commands_qualification_expiry_ck
        CHECK (qualification_expires_at_unix_ms > 0),
    outcome JSONB NOT NULL
        CONSTRAINT production_mutation_admission_commands_outcome_ck
        CHECK (jsonb_typeof(outcome) = 'object'),
    outcome_kind TEXT NOT NULL
        CONSTRAINT production_mutation_admission_commands_outcome_kind_ck
        CHECK (outcome_kind IN ('applied', 'authority_precondition_failed')),
    resulting_revision BIGINT NULL
        CONSTRAINT production_mutation_admission_commands_result_revision_ck
        CHECK (resulting_revision > 0),
    resulting_mode TEXT NULL
        CONSTRAINT production_mutation_admission_commands_result_mode_ck
        CHECK (resulting_mode IN ('closed', 'qualification')),
    committed_at_unix_ms BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_commands_time_ck
        CHECK (committed_at_unix_ms >= 0),
    CONSTRAINT production_mutation_admission_commands_terminal_ck CHECK (
        (outcome_kind = 'applied'
            AND resulting_revision = expected_revision + 1
            AND resulting_mode = target_mode) OR
        (outcome_kind = 'authority_precondition_failed'
            AND resulting_revision IS NULL AND resulting_mode IS NULL)
    ),
    CONSTRAINT production_mutation_admission_commands_mutation_target_ck CHECK (
        (mutation_kind = 'begin_qualification' AND target_mode = 'qualification') OR
        (mutation_kind IN ('end_qualification', 'emergency_close')
            AND target_mode = 'closed')
    ),
    CONSTRAINT production_mutation_admission_commands_state_key
        UNIQUE (command_id, resulting_revision, resulting_mode, binding_sha256)
);
CREATE TABLE IF NOT EXISTS production_mutation_admission (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE
        CONSTRAINT production_mutation_admission_singleton_ck CHECK (singleton),
    revision BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_revision_ck CHECK (revision > 0),
    mode TEXT NOT NULL
        CONSTRAINT production_mutation_admission_mode_ck
        CHECK (mode IN ('closed', 'qualification')),
    binding JSONB NULL
        CONSTRAINT production_mutation_admission_binding_json_ck
        CHECK (jsonb_typeof(binding) = 'object'),
    binding_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_binding_digest_ck
        CHECK (binding_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_id TEXT NULL,
    deployment_id TEXT NULL,
    release_id TEXT NULL,
    source_commit_sha TEXT NULL
        CONSTRAINT production_mutation_admission_source_commit_ck
        CHECK (source_commit_sha ~ '^[0-9a-f]{40}$'),
    control_schema_version BIGINT NULL
        CONSTRAINT production_mutation_admission_schema_ck
        CHECK (control_schema_version = 20),
    source_manifest_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_source_manifest_ck
        CHECK (source_manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    source_bundle_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_source_bundle_ck
        CHECK (source_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    build_receipt_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_build_receipt_ck
        CHECK (build_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    release_manifest_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_release_manifest_ck
        CHECK (release_manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    worker_bundle_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_worker_bundle_ck
        CHECK (worker_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_catalog_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_qualification_catalog_ck
        CHECK (qualification_catalog_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_cell_manifest_sha256 TEXT NULL
        CONSTRAINT production_mutation_admission_qualification_cell_manifest_ck
        CHECK (qualification_cell_manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    qualification_aws_partition TEXT NULL
        CONSTRAINT production_mutation_admission_qualification_partition_ck
        CHECK (qualification_aws_partition IN ('aws', 'aws-us-gov', 'aws-cn')),
    qualification_aws_account_id TEXT NULL
        CONSTRAINT production_mutation_admission_qualification_aws_account_ck
        CHECK (qualification_aws_account_id ~ '^[0-9]{12}$'),
    qualification_aws_region TEXT NULL
        CONSTRAINT production_mutation_admission_qualification_region_ck
        CHECK (qualification_aws_region ~ '^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$'),
    qualification_cell_id TEXT NULL,
    qualification_cell_namespace TEXT NULL
        CONSTRAINT production_mutation_admission_qualification_namespace_ck
        CHECK (qualification_cell_namespace ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    qualification_cats_account_id TEXT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    qualification_workspace_id TEXT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    qualification_mutation_classes JSONB NULL
        CONSTRAINT production_mutation_admission_qualification_classes_ck
        CHECK (jsonb_typeof(qualification_mutation_classes) = 'array'
            AND qualification_mutation_classes =
                '[\"cat_create\",\"disk_create\",\"disk_delete\",\"runtime_mutation\"]'::jsonb),
    qualification_expires_at_unix_ms BIGINT NULL
        CONSTRAINT production_mutation_admission_qualification_expiry_ck
        CHECK (qualification_expires_at_unix_ms > 0),
    last_command_id TEXT NULL
        CONSTRAINT production_mutation_admission_last_command_key UNIQUE,
    updated_at_unix_ms BIGINT NOT NULL
        CONSTRAINT production_mutation_admission_time_ck
        CHECK (updated_at_unix_ms >= 0),
    CONSTRAINT production_mutation_admission_initial_or_bound_ck CHECK (
        (binding IS NULL AND binding_sha256 IS NULL
            AND qualification_id IS NULL AND deployment_id IS NULL
            AND release_id IS NULL AND source_commit_sha IS NULL
            AND control_schema_version IS NULL
            AND source_manifest_sha256 IS NULL AND source_bundle_sha256 IS NULL
            AND build_receipt_sha256 IS NULL AND release_manifest_sha256 IS NULL
            AND worker_bundle_sha256 IS NULL AND qualification_catalog_sha256 IS NULL
            AND qualification_cell_manifest_sha256 IS NULL
            AND qualification_aws_partition IS NULL
            AND qualification_aws_account_id IS NULL
            AND qualification_aws_region IS NULL AND qualification_cell_id IS NULL
            AND qualification_cell_namespace IS NULL
            AND qualification_cats_account_id IS NULL
            AND qualification_workspace_id IS NULL
            AND qualification_mutation_classes IS NULL
            AND qualification_expires_at_unix_ms IS NULL
            AND mode = 'closed' AND revision = 1
            AND last_command_id IS NULL AND updated_at_unix_ms = 0) OR
        (binding IS NOT NULL AND binding_sha256 IS NOT NULL
            AND qualification_id IS NOT NULL AND deployment_id IS NOT NULL
            AND release_id IS NOT NULL AND source_commit_sha IS NOT NULL
            AND control_schema_version IS NOT NULL
            AND source_manifest_sha256 IS NOT NULL AND source_bundle_sha256 IS NOT NULL
            AND build_receipt_sha256 IS NOT NULL AND release_manifest_sha256 IS NOT NULL
            AND worker_bundle_sha256 IS NOT NULL
            AND qualification_catalog_sha256 IS NOT NULL
            AND qualification_cell_manifest_sha256 IS NOT NULL
            AND qualification_aws_partition IS NOT NULL
            AND qualification_aws_account_id IS NOT NULL
            AND qualification_aws_region IS NOT NULL
            AND qualification_cell_id IS NOT NULL
            AND qualification_cell_namespace IS NOT NULL
            AND qualification_cats_account_id IS NOT NULL
            AND qualification_workspace_id IS NOT NULL
            AND qualification_mutation_classes IS NOT NULL
            AND qualification_expires_at_unix_ms IS NOT NULL
            AND mode IN ('closed', 'qualification')
            AND last_command_id IS NOT NULL)
    ),
    CONSTRAINT production_mutation_admission_exact_command_fkey
        FOREIGN KEY (last_command_id, revision, mode, binding_sha256)
        REFERENCES production_mutation_admission_commands(
            command_id, resulting_revision, resulting_mode, binding_sha256)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
INSERT INTO production_mutation_admission (singleton, revision, mode, updated_at_unix_ms)
VALUES (TRUE, 1, 'closed', 0);
CREATE TABLE IF NOT EXISTS node_identities (
    node_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    host_provider TEXT NOT NULL CHECK (
        octet_length(host_provider) BETWEEN 1 AND 128
        AND host_provider ~ '^[A-Za-z0-9._:-]+$'
    ),
    host_partition TEXT NOT NULL CHECK (
        octet_length(host_partition) BETWEEN 1 AND 128
        AND host_partition ~ '^[A-Za-z0-9._:-]+$'
    ),
    host_account_id TEXT NOT NULL CHECK (
        octet_length(host_account_id) BETWEEN 1 AND 128
        AND host_account_id ~ '^[A-Za-z0-9._:-]+$'
    ),
    host_region TEXT NOT NULL CHECK (
        octet_length(host_region) BETWEEN 1 AND 128
        AND host_region ~ '^[A-Za-z0-9._:-]+$'
    ),
    immutable_host_id TEXT NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    credential_kind TEXT NOT NULL
        CHECK (credential_kind IN ('public_key', 'provider_principal')),
    credential_public_key_spki_sha256 TEXT,
    credential_provider TEXT,
    credential_principal TEXT,
    credential_lineage_state TEXT
        CHECK (credential_lineage_state IN ('active', 'retired')),
    state_path_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('provisioned', 'retired')),
    UNIQUE (
        host_provider, host_partition, host_account_id, host_region,
        immutable_host_id, state_path_id
    ),
    UNIQUE (
        node_id, host_provider, host_partition, host_account_id, host_region,
        immutable_host_id
    ),
    CHECK ((
        (credential_kind = 'public_key'
            AND credential_public_key_spki_sha256 IS NOT NULL
            AND credential_public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'
            AND credential_provider IS NULL
            AND credential_principal IS NULL
            AND credential_lineage_state IS NOT NULL
            AND ((state = 'provisioned' AND credential_lineage_state = 'active') OR
                 (state = 'retired' AND credential_lineage_state = 'retired'))) OR
        (credential_kind = 'provider_principal'
            AND credential_public_key_spki_sha256 IS NULL
            AND credential_provider IS NOT NULL
            AND credential_principal IS NOT NULL
            AND credential_lineage_state IS NULL)
    ) IS TRUE)
);
CREATE UNIQUE INDEX IF NOT EXISTS node_identity_one_provisioned_per_host
    ON node_identities(
        host_provider, host_partition, host_account_id, host_region,
        immutable_host_id
    ) WHERE state = 'provisioned';
CREATE TABLE IF NOT EXISTS runtime_node_credential_lineage (
    credential_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES node_identities(node_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    public_key_spki_sha256 TEXT NOT NULL UNIQUE
        CHECK (public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('active', 'retired')),
    first_committed_at_unix_ms BIGINT NOT NULL CHECK (first_committed_at_unix_ms >= 0),
    retired_at_unix_ms BIGINT NULL CHECK (
        retired_at_unix_ms IS NULL OR
        retired_at_unix_ms >= first_committed_at_unix_ms),
    CHECK ((state = 'active' AND retired_at_unix_ms IS NULL) OR
           (state = 'retired' AND retired_at_unix_ms IS NOT NULL)),
    UNIQUE (node_id, credential_id),
    UNIQUE (node_id, credential_id, public_key_spki_sha256, state)
);
CREATE UNIQUE INDEX IF NOT EXISTS runtime_node_one_active_credential
    ON runtime_node_credential_lineage(node_id) WHERE state = 'active';
ALTER TABLE node_identities
    ADD CONSTRAINT node_identity_current_public_key_lineage
    FOREIGN KEY (
        node_id, credential_id, credential_public_key_spki_sha256,
        credential_lineage_state)
    REFERENCES runtime_node_credential_lineage(
        node_id, credential_id, public_key_spki_sha256, state)
    ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE IF NOT EXISTS runtime_node_placement_policies (
    node_id TEXT PRIMARY KEY REFERENCES node_identities(node_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    scheduling_state TEXT NOT NULL CHECK (scheduling_state IN ('cordoned', 'schedulable')),
    allocatable_vcpus BIGINT NOT NULL
        CHECK (allocatable_vcpus BETWEEN 1 AND 4294967295),
    allocatable_memory_bytes BIGINT NOT NULL CHECK (allocatable_memory_bytes > 0),
    guest_config_digest TEXT NOT NULL
        CHECK (guest_config_digest ~ '^sha256:[0-9a-f]{64}$'),
    block_frontend TEXT NOT NULL CHECK (block_frontend IN ('kernel_nbd', 'vhost_user_blk')),
    guest_ipv4_network_address TEXT NOT NULL
        CHECK (guest_ipv4_network_address ~ '^[0-9]{1,3}([.][0-9]{1,3}){3}$')
);
CREATE TABLE IF NOT EXISTS runtime_node_authority_apply_records (
    apply_id TEXT PRIMARY KEY,
    request JSONB NOT NULL CHECK (jsonb_typeof(request) = 'object'),
    request_sha256 TEXT NOT NULL CHECK (request_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    principal JSONB NOT NULL CHECK (jsonb_typeof(principal) = 'object'),
    principal_kind TEXT NOT NULL
        CHECK (principal_kind IN ('deployment_provisioner', 'workos_fleet_administrator')),
    node_id TEXT NOT NULL,
    outcome JSONB NOT NULL CHECK (jsonb_typeof(outcome) = 'object'),
    outcome_kind TEXT NOT NULL CHECK (outcome_kind IN ('applied', 'authority_precondition_failed')),
    committed_at_unix_ms BIGINT NOT NULL CHECK (committed_at_unix_ms >= 0)
);
CREATE TABLE IF NOT EXISTS runtime_provisioner_deployment_identity (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    deployment_id TEXT NOT NULL UNIQUE,
    current_trust_revision BIGINT NOT NULL CHECK (current_trust_revision > 0),
    current_active_set_sha256 TEXT NOT NULL
        CHECK (current_active_set_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    first_committed_at_unix_ms BIGINT NOT NULL CHECK (first_committed_at_unix_ms >= 0)
);
CREATE TABLE IF NOT EXISTS runtime_provisioner_trust_revisions (
    deployment_id TEXT NOT NULL
        REFERENCES runtime_provisioner_deployment_identity(deployment_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    trust_revision BIGINT NOT NULL CHECK (trust_revision > 0),
    active_set_sha256 TEXT NOT NULL
        CHECK (active_set_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    expected_previous_trust_revision BIGINT NULL
        CHECK (expected_previous_trust_revision > 0),
    expected_previous_active_set_sha256 TEXT NULL
        CHECK (expected_previous_active_set_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    committed_at_unix_ms BIGINT NOT NULL CHECK (committed_at_unix_ms >= 0),
    PRIMARY KEY (deployment_id, trust_revision),
    UNIQUE (deployment_id, trust_revision, active_set_sha256),
    CHECK (
        (trust_revision = 1 AND expected_previous_trust_revision IS NULL
            AND expected_previous_active_set_sha256 IS NULL) OR
        (trust_revision > 1
            AND expected_previous_trust_revision = trust_revision - 1
            AND expected_previous_active_set_sha256 IS NOT NULL)
    )
);
ALTER TABLE runtime_provisioner_deployment_identity
    ADD CONSTRAINT runtime_provisioner_current_trust_revision
    FOREIGN KEY (deployment_id, current_trust_revision, current_active_set_sha256)
    REFERENCES runtime_provisioner_trust_revisions(
        deployment_id, trust_revision, active_set_sha256)
    ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE IF NOT EXISTS runtime_provisioner_credential_lineage (
    credential_id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL
        REFERENCES runtime_provisioner_deployment_identity(deployment_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    public_key_spki TEXT NOT NULL UNIQUE,
    public_key_spki_sha256 TEXT NOT NULL UNIQUE
        CHECK (public_key_spki_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('active', 'retired')),
    first_committed_at_unix_ms BIGINT NOT NULL CHECK (first_committed_at_unix_ms >= 0),
    retired_at_unix_ms BIGINT NULL CHECK (
        retired_at_unix_ms IS NULL OR
        retired_at_unix_ms >= first_committed_at_unix_ms),
    CHECK ((state = 'active' AND retired_at_unix_ms IS NULL) OR
           (state = 'retired' AND retired_at_unix_ms IS NOT NULL))
);
CREATE OR REPLACE FUNCTION control_runtime_node_credential_lineage_update()
RETURNS trigger AS $$
BEGIN
    IF NEW.credential_id IS DISTINCT FROM OLD.credential_id
       OR NEW.node_id IS DISTINCT FROM OLD.node_id
       OR NEW.public_key_spki_sha256 IS DISTINCT FROM OLD.public_key_spki_sha256
       OR NEW.first_committed_at_unix_ms IS DISTINCT FROM OLD.first_committed_at_unix_ms
       OR OLD.state = 'retired'
       OR OLD.state <> 'active'
       OR NEW.state <> 'retired'
       OR OLD.retired_at_unix_ms IS NOT NULL
       OR NEW.retired_at_unix_ms IS NULL THEN
        RAISE EXCEPTION 'runtime Node credential lineage is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_runtime_node_credential_lineage_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'runtime Node credential lineage cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER runtime_node_credential_lineage_update
    BEFORE UPDATE ON runtime_node_credential_lineage
    FOR EACH ROW EXECUTE FUNCTION control_runtime_node_credential_lineage_update();
CREATE TRIGGER runtime_node_credential_lineage_cannot_delete
    BEFORE DELETE ON runtime_node_credential_lineage
    FOR EACH ROW EXECUTE FUNCTION control_runtime_node_credential_lineage_cannot_delete();
CREATE OR REPLACE FUNCTION control_runtime_node_policy_update()
RETURNS trigger AS $$
BEGIN
    IF NEW.node_id IS DISTINCT FROM OLD.node_id
       OR NEW.policy_revision <> OLD.policy_revision + 1 THEN
        RAISE EXCEPTION 'runtime Node placement policy revision is not a successor';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_runtime_node_policy_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'runtime Node placement policy cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER runtime_node_policy_update
    BEFORE UPDATE ON runtime_node_placement_policies
    FOR EACH ROW EXECUTE FUNCTION control_runtime_node_policy_update();
CREATE TRIGGER runtime_node_policy_cannot_delete
    BEFORE DELETE ON runtime_node_placement_policies
    FOR EACH ROW EXECUTE FUNCTION control_runtime_node_policy_cannot_delete();
CREATE OR REPLACE FUNCTION control_runtime_node_apply_is_immutable()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'runtime Node authority apply result is immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER runtime_node_apply_is_immutable
    BEFORE UPDATE OR DELETE ON runtime_node_authority_apply_records
    FOR EACH ROW EXECUTE FUNCTION control_runtime_node_apply_is_immutable();
CREATE OR REPLACE FUNCTION control_runtime_provisioner_revision_is_immutable()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'runtime provisioner trust revision is immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER runtime_provisioner_revision_is_immutable
    BEFORE UPDATE OR DELETE ON runtime_provisioner_trust_revisions
    FOR EACH ROW EXECUTE FUNCTION control_runtime_provisioner_revision_is_immutable();
CREATE OR REPLACE FUNCTION control_runtime_provisioner_credential_update()
RETURNS trigger AS $$
BEGIN
    IF NEW.credential_id IS DISTINCT FROM OLD.credential_id
       OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
       OR NEW.public_key_spki IS DISTINCT FROM OLD.public_key_spki
       OR NEW.public_key_spki_sha256 IS DISTINCT FROM OLD.public_key_spki_sha256
       OR NEW.first_committed_at_unix_ms IS DISTINCT FROM OLD.first_committed_at_unix_ms
       OR OLD.state = 'retired'
       OR OLD.state <> 'active'
       OR NEW.state <> 'retired'
       OR OLD.retired_at_unix_ms IS NOT NULL
       OR NEW.retired_at_unix_ms IS NULL THEN
        RAISE EXCEPTION 'runtime provisioner credential lineage is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_runtime_provisioner_credential_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'runtime provisioner credential lineage cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER runtime_provisioner_credential_update
    BEFORE UPDATE ON runtime_provisioner_credential_lineage
    FOR EACH ROW EXECUTE FUNCTION control_runtime_provisioner_credential_update();
CREATE TRIGGER runtime_provisioner_credential_cannot_delete
    BEFORE DELETE ON runtime_provisioner_credential_lineage
    FOR EACH ROW EXECUTE FUNCTION control_runtime_provisioner_credential_cannot_delete();
CREATE OR REPLACE FUNCTION control_runtime_provisioner_pointer_update()
RETURNS trigger AS $$
BEGIN
    IF NEW.singleton IS DISTINCT FROM OLD.singleton
       OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
       OR NEW.first_committed_at_unix_ms IS DISTINCT FROM OLD.first_committed_at_unix_ms
       OR NEW.current_trust_revision <> OLD.current_trust_revision + 1
       OR NEW.current_active_set_sha256 = OLD.current_active_set_sha256 THEN
        RAISE EXCEPTION 'runtime provisioner trust pointer is not a successor';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_runtime_provisioner_pointer_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'runtime provisioner deployment identity cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER runtime_provisioner_pointer_update
    BEFORE UPDATE ON runtime_provisioner_deployment_identity
    FOR EACH ROW EXECUTE FUNCTION control_runtime_provisioner_pointer_update();
CREATE TRIGGER runtime_provisioner_pointer_cannot_delete
    BEFORE DELETE ON runtime_provisioner_deployment_identity
    FOR EACH ROW EXECUTE FUNCTION control_runtime_provisioner_pointer_cannot_delete();
CREATE OR REPLACE FUNCTION control_node_identity_lineage_is_immutable()
RETURNS trigger AS $$
BEGIN
    IF NEW.node_id IS DISTINCT FROM OLD.node_id
       OR NEW.host_provider IS DISTINCT FROM OLD.host_provider
       OR NEW.host_partition IS DISTINCT FROM OLD.host_partition
       OR NEW.host_account_id IS DISTINCT FROM OLD.host_account_id
       OR NEW.host_region IS DISTINCT FROM OLD.host_region
       OR NEW.immutable_host_id IS DISTINCT FROM OLD.immutable_host_id
       OR NEW.state_path_id IS DISTINCT FROM OLD.state_path_id THEN
        RAISE EXCEPTION 'NodeIdentity lineage is immutable';
    END IF;
    IF OLD.state = 'retired' AND NEW.state <> 'retired' THEN
        RAISE EXCEPTION 'retired NodeIdentity cannot be reprovisioned';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_node_identity_cannot_be_deleted()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'NodeIdentity lineage cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER node_identity_lineage_is_immutable
    BEFORE UPDATE ON node_identities
    FOR EACH ROW EXECUTE FUNCTION control_node_identity_lineage_is_immutable();
CREATE TRIGGER node_identity_cannot_be_deleted
    BEFORE DELETE ON node_identities
    FOR EACH ROW EXECUTE FUNCTION control_node_identity_cannot_be_deleted();
CREATE OR REPLACE FUNCTION control_production_mutation_admission_command_is_immutable()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'production mutation admission command receipts are immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER production_mutation_admission_command_is_immutable
    BEFORE UPDATE OR DELETE ON production_mutation_admission_commands
    FOR EACH ROW EXECUTE FUNCTION
        control_production_mutation_admission_command_is_immutable();
CREATE OR REPLACE FUNCTION control_production_mutation_admission_successor()
RETURNS trigger AS $$
BEGIN
    IF NEW.singleton IS DISTINCT FROM OLD.singleton
       OR NEW.revision <> OLD.revision + 1
       OR NEW.mode = OLD.mode
       OR NEW.last_command_id IS NULL
       OR NEW.last_command_id IS NOT DISTINCT FROM OLD.last_command_id
       OR NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
       OR NOT (
            (OLD.binding IS NULL AND OLD.mode = 'closed'
                AND OLD.revision = 1
                AND NEW.mode = 'qualification'
                AND NEW.binding IS NOT NULL) OR
            (OLD.mode = 'closed' AND OLD.binding IS NOT NULL
                AND NEW.mode = 'qualification'
                AND NEW.binding IS NOT NULL) OR
            (OLD.mode = 'qualification' AND NEW.mode = 'closed'
                AND NEW.binding = OLD.binding
                AND NEW.binding_sha256 = OLD.binding_sha256)
       ) THEN
        RAISE EXCEPTION 'production mutation admission pointer is not an exact successor';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION control_production_mutation_admission_cannot_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'production mutation admission singleton cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER production_mutation_admission_successor
    BEFORE UPDATE ON production_mutation_admission
    FOR EACH ROW EXECUTE FUNCTION control_production_mutation_admission_successor();
CREATE TRIGGER production_mutation_admission_cannot_delete
    BEFORE DELETE ON production_mutation_admission
    FOR EACH ROW EXECUTE FUNCTION control_production_mutation_admission_cannot_delete();
";

#[cfg(test)]
mod semantic_protocol_schema_tests {
    use super::{CONTROL_TABLES, FORBIDDEN_LEGACY_CONTROL_TABLES, SCHEMA, SCHEMA_VERSION};

    #[test]
    fn v20_contains_current_resource_uniqueness_and_rwo_binding_constraints() {
        assert_eq!(SCHEMA_VERSION, 20);
        for table in [
            "cats",
            "nodes",
            "node_heartbeats",
            "cat_ingress_targets",
            "persistent_disks",
            "disk_bindings",
        ] {
            assert!(CONTROL_TABLES.contains(&table));
            assert!(SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {table} (")));
        }
        assert!(SCHEMA.contains(
            "CREATE UNIQUE INDEX IF NOT EXISTS cats_current_slug_unique\nON cats(workspace_id, cat_slug) WHERE destroyed_at IS NULL"
        ));
        assert!(SCHEMA.contains(
            "CREATE UNIQUE INDEX IF NOT EXISTS disks_current_slug_unique\nON persistent_disks(workspace_id, disk_slug) WHERE deleted_at IS NULL"
        ));
        assert!(SCHEMA.contains(
            "CREATE UNIQUE INDEX IF NOT EXISTS disk_snapshots_current_slug_unique\nON disk_snapshots(workspace_id, snapshot_slug) WHERE deleted_at IS NULL"
        ));
        assert!(SCHEMA.contains("CONSTRAINT disk_bindings_disk_unique UNIQUE (disk_id)"));
        assert!(SCHEMA.contains("control_endpoint TEXT NOT NULL"));
        assert!(SCHEMA.contains("last_heartbeat_at BIGINT NOT NULL"));
        assert!(SCHEMA.contains("current_action_recovery_started_at BIGINT"));
        assert!(SCHEMA.contains("cat_id TEXT PRIMARY KEY REFERENCES cats(cat_id)"));
    }

    #[test]
    fn v20_rejects_retired_protocol_catalogs_but_keeps_snapshot_live_roots() {
        for retired in [
            "runtime_operations",
            "route_operations",
            "agent_registration_attempts",
            "current_agent_sessions",
            "runtime_inventory_receive_states",
            "runtime_full_inventory_attestations",
            "runtime_current_cat_telemetry",
        ] {
            assert!(FORBIDDEN_LEGACY_CONTROL_TABLES.contains(&retired));
            assert!(!CONTROL_TABLES.contains(&retired));
            assert!(!SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {retired} (")));
        }

        for retained in [
            "volume_records",
            "disk_records",
            "disk_snapshots",
            "disk_snapshot_records",
        ] {
            assert!(CONTROL_TABLES.contains(&retained));
            assert!(SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {retained} (")));
        }
        assert!(SCHEMA.contains("REFERENCES cats(workspace_id, cat_id)"));
        assert!(SCHEMA.contains("FOREIGN KEY (snapshot_id) REFERENCES disk_snapshots(snapshot_id)"));
        assert!(SCHEMA.contains("disk_id TEXT NOT NULL REFERENCES disk_records(disk_id)"));
        assert!(SCHEMA.contains("volume_id TEXT NOT NULL REFERENCES volume_records(volume_id)"));
        assert!(!SCHEMA.contains("REFERENCES cat_records"));
    }
}
