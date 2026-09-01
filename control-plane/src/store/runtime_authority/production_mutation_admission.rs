//! Bounded production qualification mutation authority.
//!
//! Qualification product transactions take a shared lock on the singleton
//! only after their exact API replay lookup. End/emergency-close commands take
//! the same row for update, so PostgreSQL drains every admitted write before
//! the qualification returns to Closed.

use cats_protocol::production_mutation_admission::{
    encode_production_mutation_admission_command,
    encode_production_mutation_admission_command_receipt,
    encode_production_mutation_admission_state,
    encode_production_qualification_product_inventory_receipt,
    production_mutation_admission_binding_sha256,
    production_mutation_admission_command_receipt_sha256,
    production_mutation_admission_command_sha256, ProductionCutoverOperatorPrincipal,
    ProductionMutationAdmissionBinding, ProductionMutationAdmissionCommand,
    ProductionMutationAdmissionCommandReceipt, ProductionMutationAdmissionMode,
    ProductionMutationAdmissionMutation, ProductionMutationAdmissionState,
    ProductionMutationAdmissionStoredOutcome, ProductionQualificationAdmissionBinding,
    ProductionQualificationCloseKind, ProductionQualificationMutationClass,
    ProductionQualificationProductInventoryCounts, ProductionQualificationProductInventoryReceipt,
    PRODUCTION_CUTOVER_CLOCK_SKEW_MS, PRODUCTION_MUTATION_ADMISSION_SCHEMA_VERSION,
    PRODUCTION_QUALIFICATION_MAX_LIFETIME_MS,
    PRODUCTION_QUALIFICATION_PRODUCT_INVENTORY_RECEIPT_KIND,
};
use cats_protocol::runtime_reconciliation::{
    ContractVersion, Epoch, RandomId128, Sha256Digest, UnixMillis, WireU64,
};
use cats_storage::authority::AuthorityError;
use postgres::{Row, Transaction};
use serde::{de::DeserializeOwned, Serialize};

use super::pg_codec::PgBigInt;
use super::rows::database_now;
use crate::store::transaction::{
    AuthorityRequestDisposition, AuthorityTransactionError, AuthorityTxResult,
};
use crate::store::{ApiError, AuthorityRequestContext, Result, Store};

const STATE_COLUMNS: &str = "
    revision, mode, binding::text AS binding_json, binding_sha256,
    qualification_id, deployment_id, release_id, source_commit_sha,
    control_schema_version, source_manifest_sha256, source_bundle_sha256,
    build_receipt_sha256, release_manifest_sha256, worker_bundle_sha256,
    qualification_catalog_sha256,
    qualification_cell_manifest_sha256, qualification_aws_partition,
    qualification_aws_account_id, qualification_aws_region,
    qualification_cell_id, qualification_cell_namespace,
    qualification_cats_account_id, qualification_workspace_id,
    qualification_mutation_classes::text AS qualification_mutation_classes_json,
    qualification_expires_at_unix_ms, last_command_id,
    updated_at_unix_ms";

const COMMAND_COLUMNS: &str = "
    command_id, command::text AS command_json, request_sha256,
    principal::text AS principal_json, principal_kind, operator_credential_id,
    operator_public_key_spki_sha256, operator_trust_bundle_sha256, operator_aws_partition,
    operator_account_id, operator_role_arn, operator_principal_arn,
    issued_at_unix_ms, expires_at_unix_ms, expected_revision,
    mutation_kind, target_mode, binding_sha256,
    qualification_id, deployment_id, release_id,
    source_commit_sha, control_schema_version, source_manifest_sha256,
    source_bundle_sha256, build_receipt_sha256, release_manifest_sha256,
    worker_bundle_sha256, qualification_catalog_sha256,
    qualification_cell_manifest_sha256, qualification_aws_partition,
    qualification_aws_account_id, qualification_aws_region,
    qualification_cell_id, qualification_cell_namespace,
    qualification_cats_account_id, qualification_workspace_id,
    qualification_mutation_classes::text AS qualification_mutation_classes_json,
    qualification_expires_at_unix_ms, outcome::text AS outcome_json,
    outcome_kind, resulting_revision, resulting_mode, committed_at_unix_ms";

// Cold-path admission store outcomes: constructed once per operator command,
// sized by the receipt's fixed digest set. Indirection buys nothing here.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProductionMutationAdmissionCommandStoreOutcome {
    Stored(ProductionMutationAdmissionCommandReceipt),
    CommandIdConflict,
    AuthenticationFailed,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProductionQualificationProductInventoryStoreOutcome {
    Found(ProductionQualificationProductInventoryReceipt),
    CommandIdConflict,
    NotFound,
    AuthenticationFailed,
}

impl Store {
    pub(crate) fn production_mutation_admission_state(
        &self,
    ) -> Result<ProductionMutationAdmissionState> {
        self.authority_transaction(load_state)
    }

    pub(crate) fn apply_production_mutation_admission_command_request(
        &self,
        principal: &ProductionCutoverOperatorPrincipal,
        command: &ProductionMutationAdmissionCommand,
        request: &AuthorityRequestContext,
    ) -> Result<ProductionMutationAdmissionCommandStoreOutcome> {
        encode_production_mutation_admission_command(command)
            .map_err(|_| ApiError::invalid("production mutation admission command is invalid"))?;
        if principal.sts != command.operator {
            return Ok(ProductionMutationAdmissionCommandStoreOutcome::AuthenticationFailed);
        }
        self.authority_request_transaction(request, |transaction| {
            let outcome = apply_command_in(transaction, principal, command)?;
            Ok(match outcome {
                ProductionMutationAdmissionCommandStoreOutcome::Stored(_) => {
                    AuthorityRequestDisposition::Commit(outcome)
                }
                ProductionMutationAdmissionCommandStoreOutcome::CommandIdConflict
                | ProductionMutationAdmissionCommandStoreOutcome::AuthenticationFailed => {
                    AuthorityRequestDisposition::Reject(outcome)
                }
            })
        })
    }

    /// Serialize ambiguous COMMIT discovery behind the original command ID.
    pub(crate) fn resolve_production_mutation_admission_command(
        &self,
        command: &ProductionMutationAdmissionCommand,
    ) -> Result<Option<ProductionMutationAdmissionCommandStoreOutcome>> {
        encode_production_mutation_admission_command(command)
            .map_err(|_| ApiError::invalid("production mutation admission command is invalid"))?;
        let command = command.clone();
        self.authority_transaction(move |transaction| {
            lock_command_id(transaction, command.command_id.as_str())?;
            Ok(
                load_command_receipt(transaction, command.command_id.as_str())?.map(|stored| {
                    if stored.command == command {
                        ProductionMutationAdmissionCommandStoreOutcome::Stored(stored)
                    } else {
                        ProductionMutationAdmissionCommandStoreOutcome::CommandIdConflict
                    }
                }),
            )
        })
    }

    pub(crate) fn production_qualification_product_inventory(
        &self,
        principal: &ProductionCutoverOperatorPrincipal,
        command: &ProductionMutationAdmissionCommand,
        request: &AuthorityRequestContext,
    ) -> Result<ProductionQualificationProductInventoryStoreOutcome> {
        encode_production_mutation_admission_command(command)
            .map_err(|_| ApiError::invalid("production qualification close command is invalid"))?;
        if principal.sts != command.operator {
            return Ok(ProductionQualificationProductInventoryStoreOutcome::AuthenticationFailed);
        }
        let principal = principal.clone();
        let command = command.clone();
        self.authority_request_locking_read_snapshot(request, move |transaction| {
            qualification_product_inventory_in(transaction, &principal, &command)
        })
    }
}

fn qualification_product_inventory_in(
    transaction: &mut Transaction<'_>,
    principal: &ProductionCutoverOperatorPrincipal,
    command: &ProductionMutationAdmissionCommand,
) -> AuthorityTxResult<ProductionQualificationProductInventoryStoreOutcome> {
    let (binding, close_kind) = match &command.mutation {
        ProductionMutationAdmissionMutation::EndQualification { binding } => {
            (binding, ProductionQualificationCloseKind::EndQualification)
        }
        ProductionMutationAdmissionMutation::EmergencyClose {
            binding: ProductionMutationAdmissionBinding::Qualification(binding),
        } => (binding, ProductionQualificationCloseKind::EmergencyClose),
        _ => {
            return Ok(ProductionQualificationProductInventoryStoreOutcome::NotFound);
        }
    };
    let state = load_state_locked(transaction, "FOR SHARE")?;
    let Some(expected_closed_revision) = command.expected_revision.get().checked_add(1) else {
        return Err(corrupt("qualification close revision overflowed"));
    };
    if state.mode != ProductionMutationAdmissionMode::Closed
        || state.revision.get() != expected_closed_revision
        || state.last_command_id.as_ref() != Some(&command.command_id)
        || state.binding.as_ref()
            != Some(&ProductionMutationAdmissionBinding::Qualification(
                binding.clone(),
            ))
    {
        return Ok(ProductionQualificationProductInventoryStoreOutcome::NotFound);
    }
    let Some(stored) = load_command_receipt(transaction, command.command_id.as_str())? else {
        return Err(corrupt(
            "Closed qualification state lost its immutable close command",
        ));
    };
    if stored.command != *command {
        return Ok(ProductionQualificationProductInventoryStoreOutcome::CommandIdConflict);
    }
    if stored.principal != *principal {
        return Ok(ProductionQualificationProductInventoryStoreOutcome::AuthenticationFailed);
    }
    if !matches!(
        &stored.outcome,
        ProductionMutationAdmissionStoredOutcome::Applied { state: applied } if applied == &state
    ) {
        return Err(corrupt(
            "qualification close command is not the current applied Closed state",
        ));
    }
    if qualified_release_commit() != Some(binding.source_commit_sha.as_str()) {
        return Err(corrupt(
            "qualification inventory binding does not match this Control release",
        ));
    }

    let counts = semantic_product_inventory_counts(transaction, &binding.workspace_id)?;
    let product_resource_count = [
        counts.current_cat_count,
        counts.root_disk_count,
        counts.persistent_disk_count,
        counts.disk_snapshot_count,
        counts.endpoint_count,
        counts.hostname_endpoint_lookup_count,
    ]
    .into_iter()
    .try_fold(0_u64, |total, count| total.checked_add(count.get()))
    .and_then(WireU64::new)
    .ok_or_else(|| corrupt("qualification product inventory count overflowed"))?;
    let receipt = ProductionQualificationProductInventoryReceipt {
        kind: PRODUCTION_QUALIFICATION_PRODUCT_INVENTORY_RECEIPT_KIND.to_owned(),
        version: ContractVersion::V1,
        qualification_id: binding.qualification_id.clone(),
        workspace_id: binding.workspace_id.clone(),
        release_id: binding.release_id.clone(),
        source_commit_sha: binding.source_commit_sha.clone(),
        qualification_catalog_sha256: binding.qualification_catalog_sha256.clone(),
        binding_sha256: production_mutation_admission_binding_sha256(
            &ProductionMutationAdmissionBinding::Qualification(binding.clone()),
        )
        .map_err(corrupt)?,
        close_kind,
        close_command_id: command.command_id.clone(),
        close_request_sha256: production_mutation_admission_command_sha256(command)
            .map_err(corrupt)?,
        close_command_receipt_sha256: production_mutation_admission_command_receipt_sha256(&stored)
            .map_err(corrupt)?,
        closed_revision: state.revision,
        evaluated_at_unix_ms: database_now(transaction)?,
        complete: true,
        counts,
        product_resource_count,
    };
    encode_production_qualification_product_inventory_receipt(&receipt).map_err(corrupt)?;
    Ok(ProductionQualificationProductInventoryStoreOutcome::Found(
        receipt,
    ))
}

fn semantic_product_inventory_counts(
    transaction: &mut Transaction<'_>,
    workspace_id: &cats_protocol::runtime_reconciliation::Id,
) -> AuthorityTxResult<ProductionQualificationProductInventoryCounts> {
    let row = transaction.query_one(
        "SELECT
            (SELECT count(*) FROM cats
              WHERE workspace_id=$1 AND destroyed_at IS NULL) AS current_cats,
            (SELECT count(*) FROM cats
              WHERE workspace_id=$1 AND destroyed_at IS NOT NULL) AS destroyed_cats,
            (SELECT count(*) FROM persistent_disks
              WHERE workspace_id=$1 AND deleted_at IS NULL) AS current_disks,
            (SELECT count(*) FROM disk_snapshots
              WHERE workspace_id=$1 AND deleted_at IS NULL) AS current_snapshots",
        &[&workspace_id.as_str()],
    )?;
    let count = |name| -> AuthorityTxResult<WireU64> {
        let value: i64 = row.try_get(name)?;
        let value = u64::try_from(value)
            .map_err(|_| corrupt("semantic product inventory count is negative"))?;
        WireU64::new(value)
            .ok_or_else(|| corrupt("semantic product inventory count exceeds the wire range"))
    };
    let zero = WireU64::new(0).expect("zero is wire-safe");
    Ok(ProductionQualificationProductInventoryCounts {
        current_cat_count: count("current_cats")?,
        root_disk_count: zero,
        persistent_disk_count: count("current_disks")?,
        disk_snapshot_count: count("current_snapshots")?,
        endpoint_count: zero,
        hostname_endpoint_lookup_count: zero,
        deleted_cat_tombstone_count: count("destroyed_cats")?,
        api_idempotency_receipt_count: zero,
    })
}

/// Gate a new product mutation in the same transaction as its business write.
/// Exact API replays call this only after finding no stored result.
#[allow(
    dead_code,
    reason = "the semantic resource adapter has not yet composed the release mutation gate"
)]
pub(in crate::store) fn require_production_product_mutation_admitted(
    transaction: &mut Transaction<'_>,
    authenticated_workspace_id: &cats_protocol::runtime_reconciliation::Id,
    mutation_class: ProductionQualificationMutationClass,
) -> AuthorityTxResult<ProductionMutationAdmissionBinding> {
    let state = load_state_locked(transaction, "FOR SHARE")?;
    let Some(binding) = state.binding else {
        return Err(closed());
    };
    let Some(release_commit) = qualified_release_commit() else {
        return Err(AuthorityTransactionError::Application(ApiError::unavailable(
            "this Control build has no qualified release commit; product mutations remain Closed",
        )));
    };
    if binding.source_commit_sha() != release_commit
        || binding.control_schema_version().get() != PRODUCTION_MUTATION_ADMISSION_SCHEMA_VERSION
    {
        return Err(corrupt(
            "production mutation admission binding does not match this exact release/schema",
        ));
    }
    match (&state.mode, &binding) {
        (
            ProductionMutationAdmissionMode::Qualification,
            ProductionMutationAdmissionBinding::Qualification(qualification),
        ) => {
            let now = database_now(transaction)?;
            if qualification.workspace_id != *authenticated_workspace_id
                || qualification.qualification_expires_at_unix_ms <= now
                || qualification
                    .allowed_mutation_classes
                    .binary_search(&mutation_class)
                    .is_err()
            {
                return Err(closed());
            }
        }
        _ => return Err(closed()),
    }
    Ok(binding)
}

fn apply_command_in(
    transaction: &mut Transaction<'_>,
    principal: &ProductionCutoverOperatorPrincipal,
    command: &ProductionMutationAdmissionCommand,
) -> AuthorityTxResult<ProductionMutationAdmissionCommandStoreOutcome> {
    if principal.sts != command.operator {
        return Ok(ProductionMutationAdmissionCommandStoreOutcome::AuthenticationFailed);
    }
    lock_command_id(transaction, command.command_id.as_str())?;
    if let Some(stored) = load_command_receipt(transaction, command.command_id.as_str())? {
        return Ok(if stored.command == *command {
            ProductionMutationAdmissionCommandStoreOutcome::Stored(stored)
        } else {
            ProductionMutationAdmissionCommandStoreOutcome::CommandIdConflict
        });
    }

    let current = load_state_locked(transaction, "FOR UPDATE")?;
    let binding = command.mutation.state_binding();
    let qualified_release = qualified_release_commit();
    let now = database_now(transaction)?;
    let transition_matches = current.revision == command.expected_revision
        && qualified_release == Some(binding.source_commit_sha())
        && command.issued_at_unix_ms.get()
            <= now.get().saturating_add(PRODUCTION_CUTOVER_CLOCK_SKEW_MS)
        && command.expires_at_unix_ms > now
        && match &command.mutation {
            ProductionMutationAdmissionMutation::BeginQualification {
                binding: qualification,
            } => {
                current.mode == ProductionMutationAdmissionMode::Closed
                    && qualification.qualification_expires_at_unix_ms > now
                    && qualification
                        .qualification_expires_at_unix_ms
                        .get()
                        .saturating_sub(now.get())
                        <= PRODUCTION_QUALIFICATION_MAX_LIFETIME_MS
                    && qualification_scope_exists(transaction, qualification)?
            }
            ProductionMutationAdmissionMutation::EndQualification { .. } => {
                current.mode == ProductionMutationAdmissionMode::Qualification
                    && current.binding.as_ref() == Some(&binding)
            }
            ProductionMutationAdmissionMutation::EmergencyClose { .. } => {
                current.mode == ProductionMutationAdmissionMode::Qualification
                    && current.binding.as_ref() == Some(&binding)
            }
        };
    let outcome = if transition_matches {
        let revision = current
            .revision
            .get()
            .checked_add(1)
            .and_then(Epoch::new)
            .ok_or_else(|| corrupt("production mutation admission revision exhausted"))?;
        let mode = match &command.mutation {
            ProductionMutationAdmissionMutation::BeginQualification { .. } => {
                ProductionMutationAdmissionMode::Qualification
            }
            ProductionMutationAdmissionMutation::EndQualification { .. }
            | ProductionMutationAdmissionMutation::EmergencyClose { .. } => {
                ProductionMutationAdmissionMode::Closed
            }
        };
        let state = ProductionMutationAdmissionState {
            version: ContractVersion::V1,
            revision,
            mode,
            binding: Some(binding),
            last_command_id: Some(command.command_id.clone()),
            updated_at_unix_ms: now,
        };
        ProductionMutationAdmissionStoredOutcome::Applied { state }
    } else {
        ProductionMutationAdmissionStoredOutcome::AuthorityPreconditionFailed
    };
    let receipt = ProductionMutationAdmissionCommandReceipt {
        version: ContractVersion::V1,
        command: command.clone(),
        request_sha256: production_mutation_admission_command_sha256(command).map_err(corrupt)?,
        principal: principal.clone(),
        outcome,
        committed_at_unix_ms: now,
    };
    encode_production_mutation_admission_command_receipt(&receipt).map_err(corrupt)?;
    insert_command_receipt(transaction, &receipt)?;
    if let ProductionMutationAdmissionStoredOutcome::Applied { state } = &receipt.outcome {
        update_state(transaction, &current, state)?;
    }
    Ok(ProductionMutationAdmissionCommandStoreOutcome::Stored(
        receipt,
    ))
}

fn lock_command_id(transaction: &mut Transaction<'_>, command_id: &str) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':production-mutation-admission:' || $1, 0::BIGINT))",
        &[&command_id],
    )?;
    Ok(())
}

fn qualification_scope_exists(
    transaction: &mut Transaction<'_>,
    binding: &ProductionQualificationAdmissionBinding,
) -> AuthorityTxResult<bool> {
    Ok(transaction
        .query_opt(
            "SELECT w.id
               FROM accounts a
               JOIN workspaces w ON w.account_id=a.id
              WHERE a.id=$1 AND a.status='active' AND w.id=$2
              FOR KEY SHARE OF a, w",
            &[
                &binding.cats_account_id.as_str(),
                &binding.workspace_id.as_str(),
            ],
        )?
        .is_some())
}

fn load_state(
    transaction: &mut Transaction<'_>,
) -> AuthorityTxResult<ProductionMutationAdmissionState> {
    load_state_locked(transaction, "")
}

fn load_state_locked(
    transaction: &mut Transaction<'_>,
    lock: &str,
) -> AuthorityTxResult<ProductionMutationAdmissionState> {
    let sql = format!(
        "SELECT {STATE_COLUMNS} FROM production_mutation_admission
          WHERE singleton {lock}"
    );
    let row = transaction
        .query_opt(&sql, &[])?
        .ok_or_else(|| corrupt("production mutation admission singleton is missing"))?;
    decode_state(&row)
}

fn decode_state(row: &Row) -> AuthorityTxResult<ProductionMutationAdmissionState> {
    let binding = row
        .try_get::<_, Option<String>>("binding_json")?
        .map(decode_json)
        .transpose()?;
    validate_binding_projection(row, binding.as_ref())?;
    let state = ProductionMutationAdmissionState {
        version: ContractVersion::V1,
        revision: from_pg(row.try_get("revision")?)?,
        mode: parse_mode(row.try_get("mode")?)?,
        binding,
        last_command_id: row
            .try_get::<_, Option<String>>("last_command_id")?
            .map(|value| {
                RandomId128::new(value)
                    .ok_or_else(|| corrupt("stored production command ID is malformed"))
            })
            .transpose()?,
        updated_at_unix_ms: from_pg(row.try_get("updated_at_unix_ms")?)?,
    };
    encode_production_mutation_admission_state(&state).map_err(corrupt)?;
    Ok(state)
}

fn load_command_receipt(
    transaction: &mut Transaction<'_>,
    command_id: &str,
) -> AuthorityTxResult<Option<ProductionMutationAdmissionCommandReceipt>> {
    let sql = format!(
        "SELECT {COMMAND_COLUMNS} FROM production_mutation_admission_commands
          WHERE command_id=$1"
    );
    transaction
        .query_opt(&sql, &[&command_id])?
        .map(|row| decode_command_receipt(&row))
        .transpose()
}

fn decode_command_receipt(
    row: &Row,
) -> AuthorityTxResult<ProductionMutationAdmissionCommandReceipt> {
    let command: ProductionMutationAdmissionCommand = decode_json(row.try_get("command_json")?)?;
    let principal: ProductionCutoverOperatorPrincipal =
        decode_json(row.try_get("principal_json")?)?;
    let outcome: ProductionMutationAdmissionStoredOutcome =
        decode_json(row.try_get("outcome_json")?)?;
    let receipt = ProductionMutationAdmissionCommandReceipt {
        version: ContractVersion::V1,
        command,
        request_sha256: parse_digest(row.try_get("request_sha256")?)?,
        principal,
        outcome,
        committed_at_unix_ms: from_pg(row.try_get("committed_at_unix_ms")?)?,
    };
    encode_production_mutation_admission_command_receipt(&receipt).map_err(corrupt)?;
    let binding = receipt.command.mutation.state_binding();
    validate_binding_projection(row, Some(&binding))?;
    let (mutation_kind, target_mode, outcome_kind, resulting_revision, resulting_mode) =
        receipt_projection(&receipt);
    if row.try_get::<_, String>("command_id")? != receipt.command.command_id.as_str()
        || from_pg::<Epoch>(row.try_get("expected_revision")?)? != receipt.command.expected_revision
        || row.try_get::<_, String>("principal_kind")? != "production_cutover_operator"
        || row.try_get::<_, String>("operator_credential_id")?
            != receipt.principal.credential_id.as_str()
        || parse_digest(row.try_get("operator_public_key_spki_sha256")?)?
            != receipt.principal.public_key_spki_sha256
        || parse_digest(row.try_get("operator_trust_bundle_sha256")?)?
            != receipt.principal.trust_bundle_sha256
        || row.try_get::<_, String>("operator_aws_partition")?
            != receipt.principal.sts.aws_partition.as_str()
        || row.try_get::<_, String>("operator_account_id")?.as_str()
            != receipt.principal.sts.account_id.as_str()
        || row.try_get::<_, String>("operator_role_arn")?.as_str()
            != receipt.principal.sts.role_arn.as_str()
        || row.try_get::<_, String>("operator_principal_arn")?.as_str()
            != receipt.principal.sts.principal_arn.as_str()
        || from_pg::<UnixMillis>(row.try_get("issued_at_unix_ms")?)?
            != receipt.command.issued_at_unix_ms
        || from_pg::<UnixMillis>(row.try_get("expires_at_unix_ms")?)?
            != receipt.command.expires_at_unix_ms
        || parse_digest(row.try_get("request_sha256")?)?
            != production_mutation_admission_command_sha256(&receipt.command).map_err(corrupt)?
        || parse_digest(row.try_get("binding_sha256")?)?
            != production_mutation_admission_binding_sha256(&binding).map_err(corrupt)?
        || row.try_get::<_, String>("mutation_kind")? != mutation_kind
        || row.try_get::<_, String>("target_mode")? != target_mode
        || row.try_get::<_, String>("outcome_kind")? != outcome_kind
        || row.try_get::<_, Option<i64>>("resulting_revision")?
            != resulting_revision
                .map(|value| value.to_pg())
                .transpose()
                .map_err(corrupt)?
        || row
            .try_get::<_, Option<String>>("resulting_mode")?
            .as_deref()
            != resulting_mode
    {
        return Err(corrupt(
            "production mutation admission command projection diverged",
        ));
    }
    Ok(receipt)
}

fn receipt_projection(
    receipt: &ProductionMutationAdmissionCommandReceipt,
) -> (
    &'static str,
    &'static str,
    &'static str,
    Option<Epoch>,
    Option<&'static str>,
) {
    let (mutation_kind, target) = match &receipt.command.mutation {
        ProductionMutationAdmissionMutation::BeginQualification { .. } => {
            ("begin_qualification", "qualification")
        }
        ProductionMutationAdmissionMutation::EndQualification { .. } => {
            ("end_qualification", "closed")
        }
        ProductionMutationAdmissionMutation::EmergencyClose { .. } => ("emergency_close", "closed"),
    };
    match &receipt.outcome {
        ProductionMutationAdmissionStoredOutcome::Applied { state } => (
            mutation_kind,
            target,
            "applied",
            Some(state.revision),
            Some(mode_text(state.mode)),
        ),
        ProductionMutationAdmissionStoredOutcome::AuthorityPreconditionFailed => (
            mutation_kind,
            target,
            "authority_precondition_failed",
            None,
            None,
        ),
    }
}

fn insert_command_receipt(
    transaction: &mut Transaction<'_>,
    receipt: &ProductionMutationAdmissionCommandReceipt,
) -> AuthorityTxResult<()> {
    let command_bytes =
        encode_production_mutation_admission_command(&receipt.command).map_err(corrupt)?;
    let command_json = String::from_utf8(command_bytes).map_err(corrupt)?;
    let principal_json = encode_json(&receipt.principal)?;
    let outcome_json = encode_json(&receipt.outcome)?;
    let binding = receipt.command.mutation.state_binding();
    let binding_json = encode_json(&binding)?;
    let binding_sha256 = production_mutation_admission_binding_sha256(&binding).map_err(corrupt)?;
    let expected_revision = receipt.command.expected_revision.to_pg().map_err(corrupt)?;
    let issued_at = receipt.command.issued_at_unix_ms.to_pg().map_err(corrupt)?;
    let expires_at = receipt
        .command
        .expires_at_unix_ms
        .to_pg()
        .map_err(corrupt)?;
    let committed_at = receipt.committed_at_unix_ms.to_pg().map_err(corrupt)?;
    let (mutation_kind, target_mode, outcome_kind, resulting_revision, resulting_mode) =
        receipt_projection(receipt);
    let resulting_revision = resulting_revision
        .map(PgBigInt::to_pg)
        .transpose()
        .map_err(corrupt)?;
    exactly_one(transaction.execute(
        "INSERT INTO production_mutation_admission_commands (
            command_id, command, request_sha256, principal, principal_kind,
            operator_credential_id, operator_public_key_spki_sha256,
            operator_trust_bundle_sha256, operator_aws_partition,
            operator_account_id, operator_role_arn,
            operator_principal_arn, issued_at_unix_ms, expires_at_unix_ms,
            expected_revision, mutation_kind, target_mode, binding_sha256,
            qualification_id,
            deployment_id, release_id, source_commit_sha, control_schema_version,
            source_manifest_sha256, source_bundle_sha256,
            build_receipt_sha256, release_manifest_sha256, worker_bundle_sha256,
            qualification_catalog_sha256,
            qualification_cell_manifest_sha256, qualification_aws_partition,
            qualification_aws_account_id, qualification_aws_region,
            qualification_cell_id, qualification_cell_namespace,
            qualification_cats_account_id, qualification_workspace_id,
            qualification_mutation_classes, qualification_expires_at_unix_ms,
            outcome, outcome_kind,
            resulting_revision, resulting_mode, committed_at_unix_ms
         ) VALUES (
            $1,$2::TEXT::jsonb,$3,$4::TEXT::jsonb,'production_cutover_operator',
            $5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$18,
            $17::TEXT::jsonb->'binding'->>'qualification_id',
            $17::TEXT::jsonb->'binding'->>'deployment_id',
            $17::TEXT::jsonb->'binding'->>'release_id',
            $17::TEXT::jsonb->'binding'->>'source_commit_sha',
            ($17::TEXT::jsonb->'binding'->>'control_schema_version')::BIGINT,
            $17::TEXT::jsonb->'binding'->>'source_manifest_sha256',
            $17::TEXT::jsonb->'binding'->>'source_bundle_sha256',
            $17::TEXT::jsonb->'binding'->>'build_receipt_sha256',
            $17::TEXT::jsonb->'binding'->>'release_manifest_sha256',
            $17::TEXT::jsonb->'binding'->>'worker_bundle_sha256',
            $17::TEXT::jsonb->'binding'->>'qualification_catalog_sha256',
            $17::TEXT::jsonb->'binding'->>'qualification_cell_manifest_sha256',
            $17::TEXT::jsonb->'binding'->>'aws_partition',
            $17::TEXT::jsonb->'binding'->>'aws_account_id',
            $17::TEXT::jsonb->'binding'->>'aws_region',
            $17::TEXT::jsonb->'binding'->>'cell_id',
            $17::TEXT::jsonb->'binding'->>'cell_namespace',
            $17::TEXT::jsonb->'binding'->>'cats_account_id',
            $17::TEXT::jsonb->'binding'->>'workspace_id',
            $17::TEXT::jsonb->'binding'->'allowed_mutation_classes',
            ($17::TEXT::jsonb->'binding'->>'qualification_expires_at_unix_ms')::BIGINT,
            $19::TEXT::jsonb,$20,$21,$22,$23)",
        &[
            &receipt.command.command_id.as_str(),
            &command_json,
            &receipt.request_sha256.as_str(),
            &principal_json,
            &receipt.principal.credential_id.as_str(),
            &receipt.principal.public_key_spki_sha256.as_str(),
            &receipt.principal.trust_bundle_sha256.as_str(),
            &receipt.principal.sts.aws_partition.as_str(),
            &receipt.principal.sts.account_id,
            &receipt.principal.sts.role_arn,
            &receipt.principal.sts.principal_arn,
            &issued_at,
            &expires_at,
            &expected_revision,
            &mutation_kind,
            &target_mode,
            &binding_json,
            &binding_sha256.as_str(),
            &outcome_json,
            &outcome_kind,
            &resulting_revision,
            &resulting_mode,
            &committed_at,
        ],
    )?)
}

fn update_state(
    transaction: &mut Transaction<'_>,
    current: &ProductionMutationAdmissionState,
    successor: &ProductionMutationAdmissionState,
) -> AuthorityTxResult<()> {
    let binding = successor
        .binding
        .as_ref()
        .ok_or_else(|| corrupt("applied production admission state has no binding"))?;
    let binding_json = encode_json(binding)?;
    let binding_sha256 = production_mutation_admission_binding_sha256(binding).map_err(corrupt)?;
    let current_revision = current.revision.to_pg().map_err(corrupt)?;
    let revision = successor.revision.to_pg().map_err(corrupt)?;
    let updated_at = successor.updated_at_unix_ms.to_pg().map_err(corrupt)?;
    let command_id = successor
        .last_command_id
        .as_ref()
        .ok_or_else(|| corrupt("applied production admission state has no command"))?;
    exactly_one(
        transaction.execute(
            "UPDATE production_mutation_admission SET
            revision=$2, mode=$3, binding=$4::TEXT::jsonb,
            binding_sha256=$5,
            qualification_id=$4::TEXT::jsonb->'binding'->>'qualification_id',
            deployment_id=$4::TEXT::jsonb->'binding'->>'deployment_id',
            release_id=$4::TEXT::jsonb->'binding'->>'release_id',
            source_commit_sha=$4::TEXT::jsonb->'binding'->>'source_commit_sha',
            control_schema_version=($4::TEXT::jsonb->'binding'->>'control_schema_version')::BIGINT,
            source_manifest_sha256=$4::TEXT::jsonb->'binding'->>'source_manifest_sha256',
            source_bundle_sha256=$4::TEXT::jsonb->'binding'->>'source_bundle_sha256',
            build_receipt_sha256=$4::TEXT::jsonb->'binding'->>'build_receipt_sha256',
            release_manifest_sha256=$4::TEXT::jsonb->'binding'->>'release_manifest_sha256',
            worker_bundle_sha256=$4::TEXT::jsonb->'binding'->>'worker_bundle_sha256',
            qualification_catalog_sha256=$4::TEXT::jsonb->'binding'->>'qualification_catalog_sha256',
            qualification_cell_manifest_sha256=$4::TEXT::jsonb->'binding'->>'qualification_cell_manifest_sha256',
            qualification_aws_partition=$4::TEXT::jsonb->'binding'->>'aws_partition',
            qualification_aws_account_id=$4::TEXT::jsonb->'binding'->>'aws_account_id',
            qualification_aws_region=$4::TEXT::jsonb->'binding'->>'aws_region',
            qualification_cell_id=$4::TEXT::jsonb->'binding'->>'cell_id',
            qualification_cell_namespace=$4::TEXT::jsonb->'binding'->>'cell_namespace',
            qualification_cats_account_id=$4::TEXT::jsonb->'binding'->>'cats_account_id',
            qualification_workspace_id=$4::TEXT::jsonb->'binding'->>'workspace_id',
            qualification_mutation_classes=$4::TEXT::jsonb->'binding'->'allowed_mutation_classes',
            qualification_expires_at_unix_ms=($4::TEXT::jsonb->'binding'->>'qualification_expires_at_unix_ms')::BIGINT,
            last_command_id=$6, updated_at_unix_ms=$7
          WHERE singleton AND revision=$1",
            &[
                &current_revision,
                &revision,
                &mode_text(successor.mode),
                &binding_json,
                &binding_sha256.as_str(),
                &command_id.as_str(),
                &updated_at,
            ],
        )?,
    )
}

fn validate_binding_projection(
    row: &Row,
    binding: Option<&ProductionMutationAdmissionBinding>,
) -> AuthorityTxResult<()> {
    let stored_digest = row.try_get::<_, Option<String>>("binding_sha256")?;
    let Some(binding) = binding else {
        if stored_digest.is_some() {
            return Err(corrupt(
                "initial production admission binding projection is partial",
            ));
        }
        return Ok(());
    };
    let schema = row.try_get::<_, Option<i64>>("control_schema_version")?;
    let expected_schema = i64::try_from(binding.control_schema_version().get()).map_err(corrupt)?;
    let digest = production_mutation_admission_binding_sha256(binding).map_err(corrupt)?;
    let projections_match = stored_digest.as_deref() == Some(digest.as_str())
        && text(row, "deployment_id")? == binding.deployment_id().as_str()
        && text(row, "release_id")? == binding.release_id().as_str()
        && text(row, "source_commit_sha")? == binding.source_commit_sha()
        && schema == Some(expected_schema)
        && match binding {
            ProductionMutationAdmissionBinding::Qualification(binding) => {
                qualification_projection_matches(row, binding)?
            }
        };
    if !projections_match {
        return Err(corrupt(
            "production mutation admission binding projection diverged",
        ));
    }
    Ok(())
}

fn qualification_projection_matches(
    row: &Row,
    binding: &ProductionQualificationAdmissionBinding,
) -> AuthorityTxResult<bool> {
    let classes: Vec<ProductionQualificationMutationClass> =
        decode_json(text(row, "qualification_mutation_classes_json")?)?;
    let expires: UnixMillis = from_pg(
        row.try_get::<_, Option<i64>>("qualification_expires_at_unix_ms")?
            .ok_or_else(|| corrupt("qualification expiry projection is missing"))?,
    )?;
    Ok(
        text(row, "qualification_id")? == binding.qualification_id.as_str()
            && text(row, "source_manifest_sha256")? == binding.source_manifest_sha256.as_str()
            && text(row, "source_bundle_sha256")? == binding.source_bundle_sha256.as_str()
            && text(row, "build_receipt_sha256")? == binding.build_receipt_sha256.as_str()
            && text(row, "release_manifest_sha256")? == binding.release_manifest_sha256.as_str()
            && text(row, "worker_bundle_sha256")? == binding.worker_bundle_sha256.as_str()
            && text(row, "qualification_catalog_sha256")?
                == binding.qualification_catalog_sha256.as_str()
            && text(row, "qualification_cell_manifest_sha256")?
                == binding.qualification_cell_manifest_sha256.as_str()
            && text(row, "qualification_aws_partition")? == binding.aws_partition.as_str()
            && text(row, "qualification_aws_account_id")? == binding.aws_account_id
            && text(row, "qualification_aws_region")? == binding.aws_region
            && text(row, "qualification_cell_id")? == binding.cell_id.as_str()
            && text(row, "qualification_cell_namespace")? == binding.cell_namespace
            && text(row, "qualification_cats_account_id")? == binding.cats_account_id.as_str()
            && text(row, "qualification_workspace_id")? == binding.workspace_id.as_str()
            && classes == binding.allowed_mutation_classes
            && expires == binding.qualification_expires_at_unix_ms,
    )
}

fn text(row: &Row, column: &str) -> AuthorityTxResult<String> {
    row.try_get::<_, Option<String>>(column)?
        .ok_or_else(|| corrupt("production mutation admission binding projection is partial"))
}

fn parse_mode(value: String) -> AuthorityTxResult<ProductionMutationAdmissionMode> {
    match value.as_str() {
        "closed" => Ok(ProductionMutationAdmissionMode::Closed),
        "qualification" => Ok(ProductionMutationAdmissionMode::Qualification),
        _ => Err(corrupt(
            "stored production mutation admission mode is unknown",
        )),
    }
}

const fn mode_text(mode: ProductionMutationAdmissionMode) -> &'static str {
    match mode {
        ProductionMutationAdmissionMode::Closed => "closed",
        ProductionMutationAdmissionMode::Qualification => "qualification",
    }
}

fn parse_digest(value: String) -> AuthorityTxResult<Sha256Digest> {
    Sha256Digest::new(value).ok_or_else(|| corrupt("stored digest is malformed"))
}

fn encode_json<T: Serialize>(value: &T) -> AuthorityTxResult<String> {
    serde_json::to_string(value).map_err(corrupt)
}

fn decode_json<T: DeserializeOwned>(value: String) -> AuthorityTxResult<T> {
    serde_json::from_str(&value).map_err(corrupt)
}

fn from_pg<T: PgBigInt>(value: i64) -> AuthorityTxResult<T> {
    T::from_pg(value).map_err(corrupt)
}

fn exactly_one(changed: u64) -> AuthorityTxResult<()> {
    if changed == 1 {
        Ok(())
    } else {
        Err(corrupt("expected exactly one production admission row"))
    }
}

fn closed() -> AuthorityTransactionError {
    AuthorityTransactionError::Application(ApiError::unavailable(
        "production product mutations are Closed",
    ))
}

fn corrupt(_error: impl std::fmt::Debug) -> AuthorityTransactionError {
    AuthorityError::BackendUnknown.into()
}

fn qualified_release_commit() -> Option<&'static str> {
    if let Some(release) = option_env!("CATS_RELEASE_COMMIT_SHA") {
        return Some(release);
    }
    #[cfg(any(test, debug_assertions, feature = "test-support"))]
    {
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    }
    #[cfg(not(any(test, debug_assertions, feature = "test-support")))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_protocol::production_mutation_admission::{
        ProductionCutoverAwsPartition, ProductionCutoverStsPrincipal,
    };
    use cats_protocol::runtime_reconciliation::{Id, WireU64};
    use postgres::NoTls;
    use std::sync::mpsc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn qualification_binding(
        cats_account_id: Id,
        workspace_id: Id,
        expires_at_unix_ms: UnixMillis,
    ) -> ProductionQualificationAdmissionBinding {
        ProductionQualificationAdmissionBinding {
            qualification_id: Id::new("qualification_a").unwrap(),
            deployment_id: Id::new("deployment_a").unwrap(),
            release_id: Id::new("release_a").unwrap(),
            source_commit_sha: "a".repeat(40),
            control_schema_version: WireU64::new(PRODUCTION_MUTATION_ADMISSION_SCHEMA_VERSION)
                .unwrap(),
            source_manifest_sha256: digest('0'),
            source_bundle_sha256: digest('1'),
            build_receipt_sha256: digest('2'),
            release_manifest_sha256: digest('3'),
            worker_bundle_sha256: digest('4'),
            qualification_catalog_sha256: digest('5'),
            qualification_cell_manifest_sha256: digest('6'),
            aws_partition: ProductionCutoverAwsPartition::Aws,
            aws_account_id: "123456789012".to_owned(),
            aws_region: "us-east-1".to_owned(),
            cell_id: Id::new("qualification-cell-a").unwrap(),
            cell_namespace: "cats-qualification".to_owned(),
            cats_account_id,
            workspace_id,
            allowed_mutation_classes: vec![
                ProductionQualificationMutationClass::CatCreate,
                ProductionQualificationMutationClass::DiskCreate,
                ProductionQualificationMutationClass::DiskDelete,
                ProductionQualificationMutationClass::RuntimeMutation,
            ],
            qualification_expires_at_unix_ms: expires_at_unix_ms,
        }
    }

    fn sts() -> ProductionCutoverStsPrincipal {
        ProductionCutoverStsPrincipal {
            aws_partition: ProductionCutoverAwsPartition::Aws,
            account_id: "123456789012".to_owned(),
            role_arn: "arn:aws:iam::123456789012:role/cats-production-cutover".to_owned(),
            principal_arn:
                "arn:aws:sts::123456789012:assumed-role/cats-production-cutover/session-a"
                    .to_owned(),
        }
    }

    fn principal() -> ProductionCutoverOperatorPrincipal {
        ProductionCutoverOperatorPrincipal {
            credential_id: Id::new("cutover_a").unwrap(),
            public_key_spki_sha256: digest('d'),
            trust_bundle_sha256: digest('e'),
            sts: sts(),
        }
    }

    fn command(
        id: char,
        expected_revision: u64,
        mutation: ProductionMutationAdmissionMutation,
    ) -> ProductionMutationAdmissionCommand {
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        ProductionMutationAdmissionCommand {
            version: ContractVersion::V1,
            command_id: RandomId128::new(id.to_string().repeat(32)).unwrap(),
            issued_at_unix_ms: UnixMillis::new(now).unwrap(),
            expires_at_unix_ms: UnixMillis::new(now + 60_000).unwrap(),
            operator: sts(),
            expected_revision: Epoch::new(expected_revision).unwrap(),
            mutation,
        }
    }

    fn apply(
        store: &Store,
        command: &ProductionMutationAdmissionCommand,
    ) -> ProductionMutationAdmissionCommandReceipt {
        let request = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(5));
        match store
            .apply_production_mutation_admission_command_request(&principal(), command, &request)
            .unwrap()
        {
            ProductionMutationAdmissionCommandStoreOutcome::Stored(receipt) => receipt,
            other => panic!("unexpected production admission outcome: {other:?}"),
        }
    }

    #[test]
    fn qualification_is_exact_workspace_scoped_replayable_and_end_drains_writers() {
        let dsn = crate::testsupport::isolated_control_store_url();
        let store = Store::connect(&dsn, None).unwrap();
        store
            .ensure_configured_accounts(&std::collections::BTreeMap::from([(
                "qualification".to_owned(),
                "org_qualification".to_owned(),
            )]))
            .unwrap();
        let (cats_account_id, workspace_id): (String, String) = store
            .with(|client| {
                client
                    .query_one(
                        "SELECT a.id, w.id
                           FROM accounts a JOIN workspaces w ON w.account_id=a.id
                          WHERE a.slug='qualification' AND w.is_default",
                        &[],
                    )
                    .map(|row| (row.get(0), row.get(1)))
            })
            .unwrap();
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let binding = qualification_binding(
            Id::new(cats_account_id).unwrap(),
            Id::new(workspace_id).unwrap(),
            UnixMillis::new(now + 600_000).unwrap(),
        );
        let begin = command(
            '4',
            1,
            ProductionMutationAdmissionMutation::BeginQualification {
                binding: binding.clone(),
            },
        );
        let begun = apply(&store, &begin);
        assert!(matches!(
            begun.outcome,
            ProductionMutationAdmissionStoredOutcome::Applied { ref state }
                if state.mode == ProductionMutationAdmissionMode::Qualification
                    && state.revision.get() == 2
        ));
        assert_eq!(apply(&store, &begin), begun);

        let mut product_client = postgres::Client::connect(&dsn, NoTls).unwrap();
        let mut product_transaction = product_client.transaction().unwrap();
        assert_eq!(
            require_production_product_mutation_admitted(
                &mut product_transaction,
                &binding.workspace_id,
                ProductionQualificationMutationClass::DiskCreate,
            )
            .unwrap(),
            ProductionMutationAdmissionBinding::Qualification(binding.clone())
        );
        let foreign = Id::new("workspace_foreign").unwrap();
        assert!(require_production_product_mutation_admitted(
            &mut product_transaction,
            &foreign,
            ProductionQualificationMutationClass::DiskCreate,
        )
        .is_err());

        let end = command(
            '5',
            2,
            ProductionMutationAdmissionMutation::EndQualification {
                binding: binding.clone(),
            },
        );
        let (done_tx, done_rx) = mpsc::channel();
        let end_dsn = dsn.clone();
        let worker = std::thread::spawn(move || {
            let end_store = Store::connect(&end_dsn, None).unwrap();
            done_tx.send(apply(&end_store, &end)).unwrap();
        });
        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        product_transaction.commit().unwrap();
        let ended = done_rx
            .recv_timeout(cats_test_support::poll_bound())
            .unwrap();
        worker.join().unwrap();
        assert!(matches!(
            ended.outcome,
            ProductionMutationAdmissionStoredOutcome::Applied { ref state }
                if state.mode == ProductionMutationAdmissionMode::Closed
                    && state.revision.get() == 3
                    && state.binding.as_ref()
                        == Some(&ProductionMutationAdmissionBinding::Qualification(binding.clone()))
        ));
    }
}
