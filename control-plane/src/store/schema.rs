use super::*;

use cats_storage::authority::AUTHORITY_RELEASE_SCHEMA_VERSION;
use native_tls::{Certificate, TlsConnector};
use postgres_native_tls::MakeTlsConnector;
use sha2::{Digest as _, Sha256};
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
    // The clean-slate cutover has one schema shape. DDL and its stamp commit in
    // the same transaction; a current stamp is verified but never repaired.
    // The xact-scoped lock lets two first replicas converge without leaving a
    // session lock behind after any error.
    let mut transaction = client.transaction().map_err(internal)?;
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

fn verify_current_schema(transaction: &mut postgres::Transaction<'_>) -> Result<()> {
    for table in CONTROL_TABLES {
        if !relation_exists(transaction, table)? {
            return Err(ApiError::failed_precondition(format!(
                "control-plane schema version {SCHEMA_VERSION} is partial: missing table {table}; recreate it"
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
    verify_authority_catalog(transaction)?;
    Ok(())
}

/// Column probes cannot detect a stamped schema whose database-enforced
/// lineage/immutability barriers were dropped. Verify the A23 catalog objects
/// structurally at every startup; a current stamp is never permission to
/// recreate or repair one of them.
fn verify_authority_catalog(transaction: &mut postgres::Transaction<'_>) -> Result<()> {
    for (table, constraint, target, source_columns, target_columns, update_action, delete_action) in
        REQUIRED_DEFERRED_FOREIGN_KEYS
    {
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_constraint c
                      JOIN pg_class source ON source.oid=c.conrelid
                      JOIN pg_namespace n ON n.oid=source.relnamespace
                      JOIN pg_class target ON target.oid=c.confrelid
                      JOIN pg_namespace target_namespace
                        ON target_namespace.oid=target.relnamespace
                     WHERE n.nspname=current_schema()
                       AND source.relname=$1 AND c.conname=$2
                       AND target_namespace.nspname=current_schema()
                       AND target.relname=$3 AND c.contype='f'
                       AND c.condeferrable AND c.condeferred AND c.convalidated
                       AND ARRAY(
                           SELECT attribute.attname::TEXT
                             FROM unnest(c.conkey) WITH ORDINALITY AS key(attnum, ordinal)
                             JOIN pg_attribute attribute
                               ON attribute.attrelid=c.conrelid
                              AND attribute.attnum=key.attnum
                            ORDER BY key.ordinal
                       ) = string_to_array($4, ',')
                       AND ARRAY(
                           SELECT attribute.attname::TEXT
                             FROM unnest(c.confkey) WITH ORDINALITY AS key(attnum, ordinal)
                             JOIN pg_attribute attribute
                               ON attribute.attrelid=c.confrelid
                              AND attribute.attnum=key.attnum
                            ORDER BY key.ordinal
                       ) = string_to_array($5, ',')
                       AND c.confupdtype::TEXT=$6 AND c.confdeltype::TEXT=$7
                 )",
                &[
                    table,
                    constraint,
                    target,
                    source_columns,
                    target_columns,
                    update_action,
                    delete_action,
                ],
            )
            .map_err(|error| internal(format!("verify authority index catalog: {error:?}")))?
            .get(0);
        if !present {
            return Err(partial_catalog_object(constraint));
        }
    }
    for (table, index, columns, predicate) in REQUIRED_UNIQUE_INDEXES {
        let present: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM pg_index i
                      JOIN pg_class source ON source.oid=i.indrelid
                      JOIN pg_namespace n ON n.oid=source.relnamespace
                      JOIN pg_class index_relation ON index_relation.oid=i.indexrelid
                     WHERE n.nspname=current_schema()
                       AND source.relname=$1 AND index_relation.relname=$2
                       AND i.indisunique AND i.indisvalid AND i.indisready
                       AND ARRAY(
                           SELECT attribute.attname::TEXT
                             FROM unnest(i.indkey) WITH ORDINALITY AS key(attnum, ordinal)
                             JOIN pg_attribute attribute
                               ON attribute.attrelid=i.indrelid
                              AND attribute.attnum=key.attnum
                            WHERE key.ordinal <= i.indnkeyatts
                            ORDER BY key.ordinal
                       ) = string_to_array($3, ',')
                       AND (($4::TEXT IS NULL AND i.indpred IS NULL)
                            OR pg_get_expr(i.indpred, i.indrelid)=$4)
                 )",
                &[table, index, columns, predicate],
            )
            .map_err(|error| internal(format!("verify authority trigger catalog: {error:?}")))?
            .get(0);
        if !present {
            return Err(partial_catalog_object(index));
        }
    }
    for (table, trigger, function, trigger_type, body_sha256) in REQUIRED_IMMUTABILITY_TRIGGERS {
        let body = transaction
            .query_opt(
                "SELECT function.prosrc
                   FROM pg_trigger trigger
                   JOIN pg_class source ON source.oid=trigger.tgrelid
                   JOIN pg_namespace source_namespace
                     ON source_namespace.oid=source.relnamespace
                   JOIN pg_proc function ON function.oid=trigger.tgfoid
                   JOIN pg_namespace function_namespace
                     ON function_namespace.oid=function.pronamespace
                   JOIN pg_language language ON language.oid=function.prolang
                  WHERE source_namespace.nspname=current_schema()
                    AND function_namespace.nspname=current_schema()
                    AND source.relname=$1 AND trigger.tgname=$2
                    AND function.proname=$3 AND NOT trigger.tgisinternal
                    AND trigger.tgenabled='O' AND trigger.tgtype=$4
                    AND trigger.tgattr::TEXT='' AND trigger.tgqual IS NULL
                    AND trigger.tgnargs=0 AND function.pronargs=0
                    AND function.prorettype='trigger'::regtype
                    AND language.lanname='plpgsql'",
                &[table, trigger, function, trigger_type],
            )
            .map_err(internal)?
            .map(|row| row.get::<_, String>(0));
        let actual_body_sha256 = body.map(|body| hex::encode(Sha256::digest(body.as_bytes())));
        if actual_body_sha256.as_deref() != Some(*body_sha256) {
            return Err(partial_catalog_object(trigger));
        }
    }
    Ok(())
}

fn partial_catalog_object(name: &str) -> ApiError {
    ApiError::failed_precondition(format!(
        "control-plane schema version {SCHEMA_VERSION} is missing or changed authority catalog object {name}; recreate it"
    ))
}

/// The Control Store owns the full release stamp. Its authority tables share
/// the one compatibility number consumed by the target data-plane adapter.
pub(super) const SCHEMA_VERSION: i64 = AUTHORITY_RELEASE_SCHEMA_VERSION;

const CONTROL_TABLES: &[&str] = &[
    "control_schema_version",
    "route_grant_rollout_state",
    "accounts",
    "workspaces",
    "account_membership_shadow",
    "workspace_grants",
    "workspace_tokens",
    "signup_grant_eligibility",
    "account_invitations",
    "workos_event_receipts",
    "cats",
    "disks",
    "mount_bindings",
    "nodes",
    "operations",
    "idempotency",
    "oci_deployments",
    "endpoints",
    "routes",
    "cat_work_sources",
    "cat_work_leases",
    "volume_records",
    "host_fence_events",
    "volume_authorizations",
    "delete_completion_receipts",
    "cat_records",
    "endpoint_records",
    "disk_records",
    "disk_snapshot_records",
    "desired_runtime_specs",
    "hostname_desired_lookups",
    "runtime_operations",
    "api_idempotency_results",
    "node_identities",
    "agent_registration_attempts",
    "current_agent_sessions",
    "runtime_desired_read_states",
    "runtime_observation_receive_states",
    "runtime_admission_inventory_states",
    "runtime_current_cat_observations",
    "runtime_node_placement_policies",
    "runtime_node_authority_apply_records",
    "runtime_node_credential_lineage",
    "runtime_provisioner_deployment_identity",
    "runtime_provisioner_trust_revisions",
    "runtime_provisioner_credential_lineage",
];

type RequiredDeferredForeignKey = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

const REQUIRED_DEFERRED_FOREIGN_KEYS: &[RequiredDeferredForeignKey] = &[
    (
        "node_identities",
        "node_identity_current_public_key_lineage",
        "runtime_node_credential_lineage",
        "node_id,credential_id,credential_public_key_spki_sha256,credential_lineage_state",
        "node_id,credential_id,public_key_spki_sha256,state",
        "a",
        "a",
    ),
    (
        "runtime_node_credential_lineage",
        "runtime_node_credential_lineage_node_id_fkey",
        "node_identities",
        "node_id",
        "node_id",
        "r",
        "r",
    ),
    (
        "runtime_provisioner_deployment_identity",
        "runtime_provisioner_current_trust_revision",
        "runtime_provisioner_trust_revisions",
        "deployment_id,current_trust_revision,current_active_set_sha256",
        "deployment_id,trust_revision,active_set_sha256",
        "r",
        "r",
    ),
    (
        "runtime_provisioner_trust_revisions",
        "runtime_provisioner_trust_revisions_deployment_id_fkey",
        "runtime_provisioner_deployment_identity",
        "deployment_id",
        "deployment_id",
        "r",
        "r",
    ),
];

const REQUIRED_UNIQUE_INDEXES: &[(&str, &str, &str, Option<&str>)] = &[
    (
        "host_fence_events",
        "runtime_node_one_active_host_fence_event",
        "node_id",
        Some("(state = 'active'::text)"),
    ),
    (
        "runtime_node_credential_lineage",
        "runtime_node_one_active_credential",
        "node_id",
        Some("(state = 'active'::text)"),
    ),
    (
        "runtime_node_credential_lineage",
        "runtime_node_credential_lineage_public_key_spki_sha256_key",
        "public_key_spki_sha256",
        None,
    ),
    (
        "runtime_node_authority_apply_records",
        "runtime_node_authority_apply_records_pkey",
        "apply_id",
        None,
    ),
    (
        "runtime_provisioner_credential_lineage",
        "runtime_provisioner_credential_lineage_public_key_spki_key",
        "public_key_spki",
        None,
    ),
    (
        "runtime_provisioner_credential_lineage",
        "runtime_provisioner_credential_linea_public_key_spki_sha256_key",
        "public_key_spki_sha256",
        None,
    ),
    (
        "runtime_provisioner_trust_revisions",
        "runtime_provisioner_trust_revisions_pkey",
        "deployment_id,trust_revision",
        None,
    ),
];

// PostgreSQL `pg_trigger.tgtype` bits: ROW=1, BEFORE=2, DELETE=8,
// UPDATE=16. Exact masks reject statement-level, AFTER, extra-event and
// `UPDATE OF`/WHEN weakened variants even when their names/functions match.
const BEFORE_ROW_DELETE: i16 = 1 | 2 | 8;
const BEFORE_ROW_UPDATE: i16 = 1 | 2 | 16;
const BEFORE_ROW_UPDATE_DELETE: i16 = 1 | 2 | 8 | 16;
const REQUIRED_IMMUTABILITY_TRIGGERS: &[(&str, &str, &str, i16, &str)] = &[
    (
        "runtime_node_credential_lineage",
        "runtime_node_credential_lineage_update",
        "control_runtime_node_credential_lineage_update",
        BEFORE_ROW_UPDATE,
        "b59ca8cd4bb9bd032340d29c9c230f4ba5f1957089bcc0be7d3b16d1530a9fbf",
    ),
    (
        "runtime_node_credential_lineage",
        "runtime_node_credential_lineage_cannot_delete",
        "control_runtime_node_credential_lineage_cannot_delete",
        BEFORE_ROW_DELETE,
        "47aadab1d6b9584e1a8313d38655be3eaee3ec5865e64938f5ebf20c3c02f205",
    ),
    (
        "runtime_node_placement_policies",
        "runtime_node_policy_update",
        "control_runtime_node_policy_update",
        BEFORE_ROW_UPDATE,
        "e5aecb0d77f3125308bf95f772cfab57b03ddce8d8c9859a69f88003ac7b30a7",
    ),
    (
        "runtime_node_placement_policies",
        "runtime_node_policy_cannot_delete",
        "control_runtime_node_policy_cannot_delete",
        BEFORE_ROW_DELETE,
        "8eeafd5c331ab500bda261e135b6c061f13987386898edde3f74c3c4dc009a2c",
    ),
    (
        "runtime_node_authority_apply_records",
        "runtime_node_apply_is_immutable",
        "control_runtime_node_apply_is_immutable",
        BEFORE_ROW_UPDATE_DELETE,
        "31366c6d9612212b3e9fae15ec31c217c3708c5fb166431980e3f60fd28f80d8",
    ),
    (
        "runtime_provisioner_trust_revisions",
        "runtime_provisioner_revision_is_immutable",
        "control_runtime_provisioner_revision_is_immutable",
        BEFORE_ROW_UPDATE_DELETE,
        "28c3a0a59fed38ccb79d2ce366bde142919d64eaa4164e2ffc6e2a5250313431",
    ),
    (
        "runtime_provisioner_credential_lineage",
        "runtime_provisioner_credential_update",
        "control_runtime_provisioner_credential_update",
        BEFORE_ROW_UPDATE,
        "297646e468dd86f20c46c4212f47b5bbe94c99288ee34c87a301e06308367a9a",
    ),
    (
        "runtime_provisioner_credential_lineage",
        "runtime_provisioner_credential_cannot_delete",
        "control_runtime_provisioner_credential_cannot_delete",
        BEFORE_ROW_DELETE,
        "4f3a0c1a80e7678486cad830a1be9427fb8e546c47ff21f4c387e9817f0bf4b6",
    ),
    (
        "runtime_provisioner_deployment_identity",
        "runtime_provisioner_pointer_update",
        "control_runtime_provisioner_pointer_update",
        BEFORE_ROW_UPDATE,
        "883fd6c3ff7394370a112afc7292e2e64503f37c05ec452c382f0e97ae45b24c",
    ),
    (
        "runtime_provisioner_deployment_identity",
        "runtime_provisioner_pointer_cannot_delete",
        "control_runtime_provisioner_pointer_cannot_delete",
        BEFORE_ROW_DELETE,
        "3ba58cdd898c1ded0023c8732a3ca155cc17caf6bba93d8346dcc43c2dbd9e76",
    ),
    (
        "node_identities",
        "node_identity_lineage_is_immutable",
        "control_node_identity_lineage_is_immutable",
        BEFORE_ROW_UPDATE,
        "474f612481baad907dbb4697502dcf7e187ed2ae06594e361be6bedf2ba9e43a",
    ),
    (
        "node_identities",
        "node_identity_cannot_be_deleted",
        "control_node_identity_cannot_be_deleted",
        BEFORE_ROW_DELETE,
        "3930793dad74a3088892fdf5b2391255f8ebd1b2b675e21369cbda0543bef264",
    ),
];

const AUTHORITY_SCHEMA_PROBES: &[&str] = &[
    "SELECT volume_id, record, size_bytes, durability, admin_state, delete_id,
            head_generation, head_root_hash, head_root_object_id, lease_owner,
            lease_epoch, lease_expires_at, last_transition_kind,
            last_transition_id, transition_desired_revision,
            transition_placement_epoch, transition_lease_duration_ms
       FROM volume_records WHERE FALSE",
    "SELECT event_id, record, provider, immutable_host_id, node_id,
            expected_node_boot_id, expected_agent_session_epoch,
            fence_attempt_id, isolation_state, observed_at, state,
            destroyed_at
       FROM host_fence_events WHERE FALSE",
    "SELECT authorization_id, record, kind, authorized_node_id,
            host_fence_event_id, volume_id,
            state, desired_revision, placement_epoch, lease_duration_ms,
            not_after, consumed_at
       FROM volume_authorizations WHERE FALSE",
    "SELECT delete_id, record, kind, disk_id, volume_id, authorization_id,
            prior_attachment_id, deleting_epoch, head_generation,
            head_root_hash, head_root_object_id, completed_at
       FROM delete_completion_receipts WHERE FALSE",
    "SELECT cat_id, record, workspace_id, name, created_at
       FROM cat_records WHERE FALSE",
    "SELECT endpoint_id, record, workspace_id, cat_id, name, created_at
       FROM endpoint_records WHERE FALSE",
    "SELECT disk_id, record, workspace_id, name, volume_id, size_bytes,
            durability, created_at, admin_state, delete_id, role_kind,
            root_cat_id, initialization_kind, initialization_token,
            filesystem_uuid, expected_blank_generation,
            expected_blank_root_hash, expected_blank_root_object_id,
            initialized_generation, initialized_root_hash,
            initialized_root_object_id, initialized_at
       FROM disk_records WHERE FALSE",
    "SELECT snapshot_id, record, disk_id, volume_id, size_bytes,
            head_generation, head_root_hash, head_root_object_id, created_at
       FROM disk_snapshot_records WHERE FALSE",
    "SELECT cat_id, record, workspace_id, desired_revision, spec_digest,
            target, node_id, placement_epoch
       FROM desired_runtime_specs WHERE FALSE",
    "SELECT hostname, record, workspace_id, cat_id, endpoint_id,
            desired_revision
       FROM hostname_desired_lookups WHERE FALSE",
    "SELECT operation_id, record, workspace_id, cat_id, desired_revision,
            desired_spec_digest, node_id, placement_epoch, target, phase,
            terminal_kind, created_at, updated_at
       FROM runtime_operations WHERE FALSE",
    "SELECT authenticated_workspace_id, canonical_route, idempotency_key,
            request_fingerprint, http_status, content_type, response_body,
            created_at
       FROM api_idempotency_results WHERE FALSE",
    "SELECT node_id, record, immutable_host_id, credential_id,
            credential_kind, credential_public_key_spki_sha256,
            credential_provider, credential_principal,
            credential_lineage_state, state_path_id, state
       FROM node_identities WHERE FALSE",
    "SELECT node_id, registration_attempt_id, attempt_record,
            immutable_host_id, node_boot_id, agent_instance_id,
            guest_config_digest, expected_agent_session_epoch,
            session_record, agent_session_epoch, lease_deadline_unix_ms
       FROM agent_registration_attempts WHERE FALSE",
    "SELECT node_id, record, immutable_host_id, node_boot_id,
            agent_instance_id, agent_session_epoch, registration_attempt_id,
            guest_config_digest, lease_deadline_unix_ms
       FROM current_agent_sessions WHERE FALSE",
    "SELECT node_id, response, node_boot_id, agent_instance_id,
            agent_session_epoch, last_request_sequence,
            read_position_high_water, issued_at_unix_ms,
            expires_at_unix_ms, consumed_observation_id,
            consumed_heartbeat_sequence
       FROM runtime_desired_read_states WHERE FALSE",
    "SELECT node_id, observation, acceptance, node_boot_id,
            agent_instance_id, agent_session_epoch, heartbeat_sequence,
            observation_id, accepted_at_unix_ms
       FROM runtime_observation_receive_states WHERE FALSE",
    "SELECT node_id, attestation, full_observation, assigned_snapshot,
            node_boot_id, agent_instance_id, agent_session_epoch,
            inventory_epoch, inventory_digest, inventory_read_position,
            accepted_at_unix_ms
       FROM runtime_admission_inventory_states WHERE FALSE",
    "SELECT node_id, cat_id, runtime_record, node_boot_id,
            agent_instance_id, agent_session_epoch, inventory_epoch,
            source_observation_id, heartbeat_sequence, accepted_at_unix_ms,
            source_kind
       FROM runtime_current_cat_observations WHERE FALSE",
    "SELECT node_id, record, policy_revision, scheduling_state,
            allocatable_vcpus, allocatable_memory_bytes,
            guest_config_digest, block_frontend, guest_ipv4_network_address
       FROM runtime_node_placement_policies WHERE FALSE",
    "SELECT apply_id, request, request_sha256, principal, principal_kind,
            node_id, outcome, outcome_kind, committed_at_unix_ms
       FROM runtime_node_authority_apply_records WHERE FALSE",
    "SELECT credential_id, node_id, public_key_spki_sha256, state,
            first_committed_at_unix_ms, retired_at_unix_ms
       FROM runtime_node_credential_lineage WHERE FALSE",
    "SELECT singleton, deployment_id, current_trust_revision,
            current_active_set_sha256, first_committed_at_unix_ms
       FROM runtime_provisioner_deployment_identity WHERE FALSE",
    "SELECT deployment_id, trust_revision, active_set_sha256,
            expected_previous_trust_revision,
            expected_previous_active_set_sha256, committed_at_unix_ms
       FROM runtime_provisioner_trust_revisions WHERE FALSE",
    "SELECT credential_id, deployment_id, public_key_spki,
            public_key_spki_sha256, state, first_committed_at_unix_ms,
            retired_at_unix_ms
       FROM runtime_provisioner_credential_lineage WHERE FALSE",
];

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
CREATE TABLE IF NOT EXISTS volume_records (
    volume_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    durability TEXT NOT NULL CHECK (durability IN ('strict', 'relaxed')),
    admin_state TEXT NOT NULL CHECK (admin_state IN ('active', 'deleting')),
    delete_id TEXT,
    head_generation BIGINT NOT NULL CHECK (head_generation >= 0),
    head_root_hash TEXT,
    head_root_object_id TEXT,
    lease_owner TEXT,
    lease_epoch BIGINT NOT NULL CHECK (lease_epoch >= 0),
    lease_expires_at BIGINT,
    last_transition_kind TEXT CHECK (
        last_transition_kind IN (
            'normal_acquire', 'release', 'takeover', 'begin_delete',
            'begin_disposable_delete'
        )
    ),
    last_transition_id TEXT,
    transition_desired_revision BIGINT,
    transition_placement_epoch BIGINT,
    transition_lease_duration_ms BIGINT,
    CHECK (
        (admin_state = 'active' AND delete_id IS NULL) OR
        (admin_state = 'deleting' AND delete_id IS NOT NULL)
    ),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
    CHECK (lease_owner IS NULL OR admin_state = 'active'),
    CHECK (lease_owner IS NULL OR (lease_epoch > 0 AND lease_expires_at > 0)),
    CHECK (admin_state <> 'deleting' OR (lease_owner IS NULL AND lease_epoch > 0)),
    CHECK (
        (head_generation = 0 AND head_root_hash IS NULL AND head_root_object_id IS NULL) OR
        (head_generation > 0 AND head_root_hash IS NOT NULL AND head_root_object_id IS NOT NULL)
    ),
    CHECK (
        (last_transition_kind IS NULL AND last_transition_id IS NULL
            AND transition_desired_revision IS NULL
            AND transition_placement_epoch IS NULL
            AND transition_lease_duration_ms IS NULL) OR
        (last_transition_kind = 'normal_acquire' AND last_transition_id IS NOT NULL
            AND transition_desired_revision > 0
            AND transition_placement_epoch > 0
            AND transition_lease_duration_ms > 0) OR
        (last_transition_kind IN (
                'release', 'takeover', 'begin_delete', 'begin_disposable_delete'
            ) AND last_transition_id IS NOT NULL
            AND transition_desired_revision IS NULL
            AND transition_placement_epoch IS NULL
            AND transition_lease_duration_ms IS NULL)
    )
);
CREATE TABLE IF NOT EXISTS host_fence_events (
    event_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    provider TEXT NOT NULL,
    immutable_host_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    expected_node_boot_id TEXT NOT NULL,
    expected_agent_session_epoch BIGINT NOT NULL CHECK (expected_agent_session_epoch > 0),
    fence_attempt_id TEXT NOT NULL,
    isolation_state TEXT NOT NULL CHECK (isolation_state IN ('isolated', 'host_destroyed')),
    observed_at BIGINT NOT NULL CHECK (observed_at >= 0),
    state TEXT NOT NULL CHECK (state IN ('active', 'rejoined')),
    destroyed_at BIGINT,
    CHECK (
        (isolation_state = 'isolated' AND destroyed_at IS NULL) OR
        (isolation_state = 'host_destroyed' AND destroyed_at IS NOT NULL)
    ),
    CHECK (isolation_state <> 'host_destroyed' OR state = 'active')
);
CREATE UNIQUE INDEX IF NOT EXISTS runtime_node_one_active_host_fence_event
    ON host_fence_events(node_id) WHERE state = 'active';
CREATE TABLE IF NOT EXISTS volume_authorizations (
    authorization_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    kind TEXT NOT NULL CHECK (kind IN ('takeover', 'disposable_root_delete')),
    authorized_node_id TEXT NOT NULL,
    host_fence_event_id TEXT REFERENCES host_fence_events(event_id),
    volume_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('unconsumed', 'consumed')),
    desired_revision BIGINT NOT NULL CHECK (desired_revision > 0),
    placement_epoch BIGINT NOT NULL CHECK (placement_epoch > 0),
    lease_duration_ms BIGINT,
    not_after BIGINT NOT NULL CHECK (not_after >= 0),
    consumed_at BIGINT,
    CHECK (
        (kind = 'takeover' AND host_fence_event_id IS NOT NULL AND lease_duration_ms > 0) OR
        (kind = 'disposable_root_delete' AND lease_duration_ms IS NULL)
    ),
    CHECK ((state = 'consumed') = (consumed_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS volume_authorizations_event
ON volume_authorizations(host_fence_event_id) WHERE host_fence_event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS volume_authorizations_volume
ON volume_authorizations(volume_id);
CREATE TABLE IF NOT EXISTS delete_completion_receipts (
    delete_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    kind TEXT NOT NULL CHECK (kind IN ('normal', 'disposable_root')),
    disk_id TEXT NOT NULL,
    volume_id TEXT NOT NULL UNIQUE,
    authorization_id TEXT,
    prior_attachment_id TEXT,
    deleting_epoch BIGINT NOT NULL CHECK (deleting_epoch > 0),
    head_generation BIGINT NOT NULL CHECK (head_generation >= 0),
    head_root_hash TEXT,
    head_root_object_id TEXT,
    completed_at BIGINT NOT NULL CHECK (completed_at >= 0),
    CHECK (
        (kind = 'normal' AND authorization_id IS NULL AND prior_attachment_id IS NULL) OR
        (kind = 'disposable_root' AND authorization_id IS NOT NULL AND prior_attachment_id IS NOT NULL)
    ),
    CHECK (
        (head_generation = 0 AND head_root_hash IS NULL AND head_root_object_id IS NULL) OR
        (head_generation > 0 AND head_root_hash IS NOT NULL AND head_root_object_id IS NOT NULL)
    )
);
CREATE TABLE IF NOT EXISTS cat_records (
    cat_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    UNIQUE (workspace_id, name),
    UNIQUE (workspace_id, cat_id)
);
CREATE TABLE IF NOT EXISTS endpoint_records (
    endpoint_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    workspace_id TEXT NOT NULL,
    cat_id TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    UNIQUE (cat_id, name),
    UNIQUE (workspace_id, cat_id, endpoint_id),
    FOREIGN KEY (workspace_id, cat_id)
        REFERENCES cat_records(workspace_id, cat_id)
);
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
    UNIQUE (workspace_id, name),
    FOREIGN KEY (workspace_id, root_cat_id)
        REFERENCES cat_records(workspace_id, cat_id),
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
            AND initialized_at IS NULL) OR
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
            AND initialized_at IS NULL) OR
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
            AND initialized_at >= 0)
    ) IS TRUE)
);
CREATE UNIQUE INDEX IF NOT EXISTS disk_records_one_root_per_cat
ON disk_records(root_cat_id) WHERE role_kind = 'root';
CREATE TABLE IF NOT EXISTS disk_snapshot_records (
    snapshot_id TEXT PRIMARY KEY,
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
CREATE TABLE IF NOT EXISTS desired_runtime_specs (
    cat_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    workspace_id TEXT NOT NULL,
    desired_revision BIGINT NOT NULL CHECK (desired_revision > 0),
    spec_digest TEXT NOT NULL CHECK (spec_digest ~ '^sha256:[0-9a-f]{64}$'),
    target TEXT NOT NULL CHECK (target IN ('running', 'suspended', 'warm', 'cold', 'deleted')),
    node_id TEXT NOT NULL,
    placement_epoch BIGINT NOT NULL CHECK (placement_epoch > 0),
    UNIQUE (workspace_id, cat_id, desired_revision),
    FOREIGN KEY (workspace_id, cat_id)
        REFERENCES cat_records(workspace_id, cat_id)
);
CREATE TABLE IF NOT EXISTS hostname_desired_lookups (
    hostname TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    workspace_id TEXT NOT NULL,
    cat_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL UNIQUE,
    desired_revision BIGINT NOT NULL CHECK (desired_revision > 0),
    FOREIGN KEY (workspace_id, cat_id, endpoint_id)
        REFERENCES endpoint_records(workspace_id, cat_id, endpoint_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (workspace_id, cat_id, desired_revision)
        REFERENCES desired_runtime_specs(workspace_id, cat_id, desired_revision)
        DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE IF NOT EXISTS runtime_operations (
    operation_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    workspace_id TEXT NOT NULL,
    cat_id TEXT NOT NULL,
    desired_revision BIGINT NOT NULL CHECK (desired_revision > 0),
    desired_spec_digest TEXT NOT NULL CHECK (desired_spec_digest ~ '^sha256:[0-9a-f]{64}$'),
    node_id TEXT NOT NULL,
    placement_epoch BIGINT NOT NULL CHECK (placement_epoch > 0),
    target TEXT NOT NULL CHECK (target IN ('running', 'suspended', 'warm', 'cold', 'deleted')),
    phase TEXT NOT NULL CHECK (phase IN ('pending', 'succeeded', 'failed', 'superseded')),
    terminal_kind TEXT CHECK (terminal_kind IN ('succeeded', 'failed', 'superseded')),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at),
    UNIQUE (cat_id, desired_revision),
    FOREIGN KEY (workspace_id, cat_id)
        REFERENCES cat_records(workspace_id, cat_id),
    CHECK ((
        (phase = 'pending' AND terminal_kind IS NULL) OR
        (phase <> 'pending' AND terminal_kind = phase)
    ) IS TRUE)
);
CREATE UNIQUE INDEX IF NOT EXISTS runtime_operations_one_pending_per_cat
ON runtime_operations(cat_id) WHERE phase = 'pending';
CREATE TABLE IF NOT EXISTS api_idempotency_results (
    authenticated_workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    canonical_route TEXT NOT NULL CHECK (
        octet_length(canonical_route) BETWEEN 1 AND 512
        AND canonical_route ~ '^[ -~]+$'
    ),
    idempotency_key TEXT NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 512
        AND idempotency_key ~ '^[ -~]+$'
    ),
    request_fingerprint TEXT NOT NULL
        CHECK (request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    http_status SMALLINT NOT NULL CHECK (http_status BETWEEN 200 AND 599),
    content_type TEXT CHECK (content_type = 'application/json'),
    response_body BYTEA NOT NULL CHECK (octet_length(response_body) <= 1048576),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (authenticated_workspace_id, canonical_route, idempotency_key)
);
CREATE TABLE IF NOT EXISTS node_identities (
    node_id TEXT PRIMARY KEY,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
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
    UNIQUE (immutable_host_id, state_path_id),
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
CREATE TABLE IF NOT EXISTS agent_registration_attempts (
    node_id TEXT NOT NULL REFERENCES node_identities(node_id),
    registration_attempt_id TEXT NOT NULL,
    attempt_record JSONB NOT NULL CHECK (jsonb_typeof(attempt_record) = 'object'),
    immutable_host_id TEXT NOT NULL,
    node_boot_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    guest_config_digest TEXT NOT NULL
        CHECK (guest_config_digest ~ '^sha256:[0-9a-f]{64}$'),
    expected_agent_session_epoch BIGINT CHECK (expected_agent_session_epoch > 0),
    session_record JSONB NOT NULL CHECK (jsonb_typeof(session_record) = 'object'),
    agent_session_epoch BIGINT NOT NULL CHECK (agent_session_epoch > 0),
    lease_deadline_unix_ms BIGINT NOT NULL CHECK (lease_deadline_unix_ms >= 0),
    PRIMARY KEY (node_id, registration_attempt_id),
    UNIQUE (node_id, agent_session_epoch),
    UNIQUE (node_id, registration_attempt_id, agent_session_epoch)
);
CREATE TABLE IF NOT EXISTS current_agent_sessions (
    node_id TEXT PRIMARY KEY REFERENCES node_identities(node_id),
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    immutable_host_id TEXT NOT NULL,
    node_boot_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    agent_session_epoch BIGINT NOT NULL CHECK (agent_session_epoch > 0),
    registration_attempt_id TEXT NOT NULL,
    guest_config_digest TEXT NOT NULL
        CHECK (guest_config_digest ~ '^sha256:[0-9a-f]{64}$'),
    lease_deadline_unix_ms BIGINT NOT NULL CHECK (lease_deadline_unix_ms >= 0),
    FOREIGN KEY (node_id, registration_attempt_id, agent_session_epoch)
        REFERENCES agent_registration_attempts(
            node_id, registration_attempt_id, agent_session_epoch
        )
);
CREATE TABLE IF NOT EXISTS runtime_desired_read_states (
    node_id TEXT PRIMARY KEY REFERENCES node_identities(node_id),
    response JSONB NOT NULL CHECK (jsonb_typeof(response) = 'object'),
    node_boot_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    agent_session_epoch BIGINT NOT NULL CHECK (agent_session_epoch > 0),
    last_request_sequence BIGINT NOT NULL CHECK (last_request_sequence > 0),
    read_position_high_water BIGINT NOT NULL CHECK (read_position_high_water > 0),
    issued_at_unix_ms BIGINT NOT NULL CHECK (issued_at_unix_ms >= 0),
    expires_at_unix_ms BIGINT NOT NULL CHECK (expires_at_unix_ms > issued_at_unix_ms),
    consumed_observation_id TEXT,
    consumed_heartbeat_sequence BIGINT CHECK (consumed_heartbeat_sequence > 0),
    CHECK ((consumed_observation_id IS NULL) = (consumed_heartbeat_sequence IS NULL))
);
CREATE TABLE IF NOT EXISTS runtime_observation_receive_states (
    node_id TEXT PRIMARY KEY REFERENCES node_identities(node_id),
    observation JSONB NOT NULL CHECK (jsonb_typeof(observation) = 'object'),
    acceptance JSONB NOT NULL CHECK (jsonb_typeof(acceptance) = 'object'),
    node_boot_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    agent_session_epoch BIGINT NOT NULL CHECK (agent_session_epoch > 0),
    heartbeat_sequence BIGINT NOT NULL CHECK (heartbeat_sequence > 0),
    observation_id TEXT NOT NULL,
    accepted_at_unix_ms BIGINT NOT NULL CHECK (accepted_at_unix_ms >= 0)
);
CREATE TABLE IF NOT EXISTS runtime_admission_inventory_states (
    node_id TEXT PRIMARY KEY REFERENCES node_identities(node_id),
    attestation JSONB NOT NULL CHECK (jsonb_typeof(attestation) = 'object'),
    full_observation JSONB NOT NULL CHECK (jsonb_typeof(full_observation) = 'object'),
    assigned_snapshot JSONB NOT NULL CHECK (jsonb_typeof(assigned_snapshot) = 'object'),
    node_boot_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    agent_session_epoch BIGINT NOT NULL CHECK (agent_session_epoch > 0),
    inventory_epoch BIGINT NOT NULL CHECK (inventory_epoch > 0),
    inventory_digest TEXT NOT NULL CHECK (inventory_digest ~ '^sha256:[0-9a-f]{64}$'),
    inventory_read_position BIGINT NOT NULL CHECK (inventory_read_position > 0),
    accepted_at_unix_ms BIGINT NOT NULL CHECK (accepted_at_unix_ms >= 0)
);
CREATE TABLE IF NOT EXISTS runtime_current_cat_observations (
    node_id TEXT NOT NULL REFERENCES node_identities(node_id),
    cat_id TEXT NOT NULL,
    runtime_record JSONB NOT NULL CHECK (jsonb_typeof(runtime_record) = 'object'),
    node_boot_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    agent_session_epoch BIGINT NOT NULL CHECK (agent_session_epoch > 0),
    inventory_epoch BIGINT NOT NULL CHECK (inventory_epoch > 0),
    source_observation_id TEXT NOT NULL,
    heartbeat_sequence BIGINT NOT NULL CHECK (heartbeat_sequence > 0),
    accepted_at_unix_ms BIGINT NOT NULL CHECK (accepted_at_unix_ms >= 0),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('full', 'partial')),
    PRIMARY KEY (node_id, cat_id)
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
CREATE OR REPLACE FUNCTION control_agent_registration_attempt_is_immutable()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'AgentRegistrationAttempt and its first result are immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER agent_registration_attempt_is_immutable
    BEFORE UPDATE OR DELETE ON agent_registration_attempts
    FOR EACH ROW EXECUTE FUNCTION control_agent_registration_attempt_is_immutable();
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
