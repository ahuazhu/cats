//! ADR-0051 production product-mutation admission authority.
//!
//! Product transactions take a shared lock on the singleton only after their
//! exact API replay lookup.  Open/close commands take the same row for update.
//! PostgreSQL therefore orders an emergency close after every already-admitted
//! write, while Closed still permits deterministic replay and all read paths.

use cats_api::production_mutation_admission::{
    encode_production_mutation_admission_command,
    encode_production_mutation_admission_command_receipt,
    encode_production_mutation_admission_state, production_mutation_admission_binding_sha256,
    production_mutation_admission_command_sha256, ProductionCutoverOperatorPrincipal,
    ProductionMutationAdmissionBinding, ProductionMutationAdmissionCommand,
    ProductionMutationAdmissionCommandReceipt, ProductionMutationAdmissionMode,
    ProductionMutationAdmissionMutation, ProductionMutationAdmissionState,
    ProductionMutationAdmissionStoredOutcome, PRODUCTION_CUTOVER_CLOCK_SKEW_MS,
    PRODUCTION_MUTATION_ADMISSION_SCHEMA_VERSION,
};
use cats_api::runtime_reconciliation::{
    ContractVersion, Epoch, RandomId128, Sha256Digest, UnixMillis,
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
    reset_id, deployment_id, release_id, source_commit_sha,
    control_schema_version, source_manifest_sha256, source_bundle_sha256,
    release_manifest_sha256, proof_set_sha256, fresh_targets_sha256,
    reset_complete_receipt_sha256, fleet_closed_receipt_sha256,
    route_signing_command_receipt_sha256,
    route_ring_delivery_receipt_sha256, usage_terminal_receipt_sha256,
    old_host_coverage_sha256, kernel_nbd_qualification_bundle_sha256,
    vhost_user_qualification_bundle_sha256, last_command_id,
    updated_at_unix_ms";

const COMMAND_COLUMNS: &str = "
    command_id, command::text AS command_json, request_sha256,
    principal::text AS principal_json, principal_kind, operator_credential_id,
    operator_public_key_spki_sha256, operator_trust_bundle_sha256, operator_aws_partition,
    operator_account_id, operator_role_arn, operator_principal_arn,
    issued_at_unix_ms, expires_at_unix_ms, expected_revision,
    target_mode, binding_sha256, reset_id, deployment_id, release_id,
    source_commit_sha, control_schema_version, source_manifest_sha256,
    source_bundle_sha256, release_manifest_sha256, proof_set_sha256,
    fresh_targets_sha256, reset_complete_receipt_sha256,
    fleet_closed_receipt_sha256, route_signing_command_receipt_sha256,
    route_ring_delivery_receipt_sha256, usage_terminal_receipt_sha256,
    old_host_coverage_sha256, kernel_nbd_qualification_bundle_sha256,
    vhost_user_qualification_bundle_sha256, outcome::text AS outcome_json,
    outcome_kind, resulting_revision, resulting_mode, committed_at_unix_ms";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProductionMutationAdmissionCommandStoreOutcome {
    Stored(ProductionMutationAdmissionCommandReceipt),
    CommandIdConflict,
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
}

/// Gate a new product mutation in the same transaction as its business write.
/// Exact API replays call this only after finding no stored result.
pub(super) fn require_production_product_mutations_open(
    transaction: &mut Transaction<'_>,
) -> AuthorityTxResult<ProductionMutationAdmissionBinding> {
    let state = load_state_locked(transaction, "FOR SHARE")?;
    let Some(binding) = state.binding else {
        return Err(closed());
    };
    if state.mode != ProductionMutationAdmissionMode::Open {
        return Err(closed());
    }
    let Some(release_commit) = qualified_release_commit() else {
        return Err(AuthorityTransactionError::Application(ApiError::unavailable(
            "this Control build has no qualified release commit; product mutations remain Closed",
        )));
    };
    if binding.source_commit_sha != release_commit
        || binding.control_schema_version.get() != PRODUCTION_MUTATION_ADMISSION_SCHEMA_VERSION
    {
        return Err(corrupt(
            "production mutation admission binding does not match this exact release/schema",
        ));
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
    let binding = command.mutation.binding();
    let qualified_release = qualified_release_commit();
    let now = database_now(transaction)?;
    let transition_matches = current.revision == command.expected_revision
        && qualified_release == Some(binding.source_commit_sha.as_str())
        && command.issued_at_unix_ms.get()
            <= now.get().saturating_add(PRODUCTION_CUTOVER_CLOCK_SKEW_MS)
        && command.expires_at_unix_ms > now
        && match &command.mutation {
            ProductionMutationAdmissionMutation::Open { .. } => {
                current.mode == ProductionMutationAdmissionMode::Closed
                    && current
                        .binding
                        .as_ref()
                        .is_none_or(|installed| installed == binding)
            }
            ProductionMutationAdmissionMutation::EmergencyClose { .. } => {
                current.mode == ProductionMutationAdmissionMode::Open
                    && current.binding.as_ref() == Some(binding)
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
            ProductionMutationAdmissionMutation::Open { .. } => {
                ProductionMutationAdmissionMode::Open
            }
            ProductionMutationAdmissionMutation::EmergencyClose { .. } => {
                ProductionMutationAdmissionMode::Closed
            }
        };
        let state = ProductionMutationAdmissionState {
            version: ContractVersion::V1,
            revision,
            mode,
            binding: Some(binding.clone()),
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
    let binding = receipt.command.mutation.binding();
    validate_binding_projection(row, Some(binding))?;
    let (target_mode, outcome_kind, resulting_revision, resulting_mode) =
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
            != production_mutation_admission_binding_sha256(binding).map_err(corrupt)?
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
    Option<Epoch>,
    Option<&'static str>,
) {
    let target = match &receipt.command.mutation {
        ProductionMutationAdmissionMutation::Open { .. } => "open",
        ProductionMutationAdmissionMutation::EmergencyClose { .. } => "closed",
    };
    match &receipt.outcome {
        ProductionMutationAdmissionStoredOutcome::Applied { state } => (
            target,
            "applied",
            Some(state.revision),
            Some(mode_text(state.mode)),
        ),
        ProductionMutationAdmissionStoredOutcome::AuthorityPreconditionFailed => {
            (target, "authority_precondition_failed", None, None)
        }
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
    let binding = receipt.command.mutation.binding();
    let binding_sha256 = production_mutation_admission_binding_sha256(binding).map_err(corrupt)?;
    let expected_revision = receipt.command.expected_revision.to_pg().map_err(corrupt)?;
    let issued_at = receipt.command.issued_at_unix_ms.to_pg().map_err(corrupt)?;
    let expires_at = receipt
        .command
        .expires_at_unix_ms
        .to_pg()
        .map_err(corrupt)?;
    let schema_version = i64::try_from(binding.control_schema_version.get()).map_err(corrupt)?;
    let committed_at = receipt.committed_at_unix_ms.to_pg().map_err(corrupt)?;
    let (target_mode, outcome_kind, resulting_revision, resulting_mode) =
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
            expected_revision, target_mode, binding_sha256, reset_id,
            deployment_id, release_id, source_commit_sha, control_schema_version,
            source_manifest_sha256, source_bundle_sha256,
            release_manifest_sha256, proof_set_sha256, fresh_targets_sha256,
            reset_complete_receipt_sha256, fleet_closed_receipt_sha256,
            route_signing_command_receipt_sha256,
            route_ring_delivery_receipt_sha256, usage_terminal_receipt_sha256,
            old_host_coverage_sha256, kernel_nbd_qualification_bundle_sha256,
            vhost_user_qualification_bundle_sha256, outcome, outcome_kind,
            resulting_revision, resulting_mode, committed_at_unix_ms
         ) VALUES (
            $1,$2::TEXT::jsonb,$3,$4::TEXT::jsonb,'production_cutover_operator',
            $5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
            $21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,
            $35::TEXT::jsonb,$36,$37,$38,$39)",
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
            &target_mode,
            &binding_sha256.as_str(),
            &binding.reset_id.as_str(),
            &binding.deployment_id.as_str(),
            &binding.release_id.as_str(),
            &binding.source_commit_sha,
            &schema_version,
            &binding.source_manifest_sha256.as_str(),
            &binding.source_bundle_sha256.as_str(),
            &binding.release_manifest_sha256.as_str(),
            &binding.proof_set_sha256.as_str(),
            &binding.fresh_targets_sha256.as_str(),
            &binding.reset_complete_receipt_sha256.as_str(),
            &binding.fleet_closed_receipt_sha256.as_str(),
            &binding.route_signing_command_receipt_sha256.as_str(),
            &binding.route_ring_delivery_receipt_sha256.as_str(),
            &binding.usage_terminal_receipt_sha256.as_str(),
            &binding.old_host_coverage_sha256.as_str(),
            &binding.kernel_nbd_qualification_bundle_sha256.as_str(),
            &binding.vhost_user_qualification_bundle_sha256.as_str(),
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
    let schema_version = i64::try_from(binding.control_schema_version.get()).map_err(corrupt)?;
    let updated_at = successor.updated_at_unix_ms.to_pg().map_err(corrupt)?;
    let command_id = successor
        .last_command_id
        .as_ref()
        .ok_or_else(|| corrupt("applied production admission state has no command"))?;
    exactly_one(transaction.execute(
        "UPDATE production_mutation_admission SET
            revision=$2, mode=$3, binding=$4::TEXT::jsonb,
            binding_sha256=$5, reset_id=$6, deployment_id=$7, release_id=$8,
            source_commit_sha=$9, control_schema_version=$10,
            source_manifest_sha256=$11, source_bundle_sha256=$12,
            release_manifest_sha256=$13, proof_set_sha256=$14,
            fresh_targets_sha256=$15, reset_complete_receipt_sha256=$16,
            fleet_closed_receipt_sha256=$17,
            route_signing_command_receipt_sha256=$18,
            route_ring_delivery_receipt_sha256=$19,
            usage_terminal_receipt_sha256=$20, old_host_coverage_sha256=$21,
            kernel_nbd_qualification_bundle_sha256=$22,
            vhost_user_qualification_bundle_sha256=$23,
            last_command_id=$24, updated_at_unix_ms=$25
          WHERE singleton AND revision=$1",
        &[
            &current_revision,
            &revision,
            &mode_text(successor.mode),
            &binding_json,
            &binding_sha256.as_str(),
            &binding.reset_id.as_str(),
            &binding.deployment_id.as_str(),
            &binding.release_id.as_str(),
            &binding.source_commit_sha,
            &schema_version,
            &binding.source_manifest_sha256.as_str(),
            &binding.source_bundle_sha256.as_str(),
            &binding.release_manifest_sha256.as_str(),
            &binding.proof_set_sha256.as_str(),
            &binding.fresh_targets_sha256.as_str(),
            &binding.reset_complete_receipt_sha256.as_str(),
            &binding.fleet_closed_receipt_sha256.as_str(),
            &binding.route_signing_command_receipt_sha256.as_str(),
            &binding.route_ring_delivery_receipt_sha256.as_str(),
            &binding.usage_terminal_receipt_sha256.as_str(),
            &binding.old_host_coverage_sha256.as_str(),
            &binding.kernel_nbd_qualification_bundle_sha256.as_str(),
            &binding.vhost_user_qualification_bundle_sha256.as_str(),
            &command_id.as_str(),
            &updated_at,
        ],
    )?)
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
    let expected_schema = i64::try_from(binding.control_schema_version.get()).map_err(corrupt)?;
    let digest = production_mutation_admission_binding_sha256(binding).map_err(corrupt)?;
    let projections_match = stored_digest.as_deref() == Some(digest.as_str())
        && text(row, "reset_id")? == binding.reset_id.as_str()
        && text(row, "deployment_id")? == binding.deployment_id.as_str()
        && text(row, "release_id")? == binding.release_id.as_str()
        && text(row, "source_commit_sha")? == binding.source_commit_sha
        && schema == Some(expected_schema)
        && text(row, "source_manifest_sha256")? == binding.source_manifest_sha256.as_str()
        && text(row, "source_bundle_sha256")? == binding.source_bundle_sha256.as_str()
        && text(row, "release_manifest_sha256")? == binding.release_manifest_sha256.as_str()
        && text(row, "proof_set_sha256")? == binding.proof_set_sha256.as_str()
        && text(row, "fresh_targets_sha256")? == binding.fresh_targets_sha256.as_str()
        && text(row, "reset_complete_receipt_sha256")?
            == binding.reset_complete_receipt_sha256.as_str()
        && text(row, "fleet_closed_receipt_sha256")?
            == binding.fleet_closed_receipt_sha256.as_str()
        && text(row, "route_signing_command_receipt_sha256")?
            == binding.route_signing_command_receipt_sha256.as_str()
        && text(row, "route_ring_delivery_receipt_sha256")?
            == binding.route_ring_delivery_receipt_sha256.as_str()
        && text(row, "usage_terminal_receipt_sha256")?
            == binding.usage_terminal_receipt_sha256.as_str()
        && text(row, "old_host_coverage_sha256")? == binding.old_host_coverage_sha256.as_str()
        && text(row, "kernel_nbd_qualification_bundle_sha256")?
            == binding.kernel_nbd_qualification_bundle_sha256.as_str()
        && text(row, "vhost_user_qualification_bundle_sha256")?
            == binding.vhost_user_qualification_bundle_sha256.as_str();
    if !projections_match {
        return Err(corrupt(
            "production mutation admission binding projection diverged",
        ));
    }
    Ok(())
}

fn text(row: &Row, column: &str) -> AuthorityTxResult<String> {
    row.try_get::<_, Option<String>>(column)?
        .ok_or_else(|| corrupt("production mutation admission binding projection is partial"))
}

fn parse_mode(value: String) -> AuthorityTxResult<ProductionMutationAdmissionMode> {
    match value.as_str() {
        "closed" => Ok(ProductionMutationAdmissionMode::Closed),
        "open" => Ok(ProductionMutationAdmissionMode::Open),
        _ => Err(corrupt(
            "stored production mutation admission mode is unknown",
        )),
    }
}

const fn mode_text(mode: ProductionMutationAdmissionMode) -> &'static str {
    match mode {
        ProductionMutationAdmissionMode::Closed => "closed",
        ProductionMutationAdmissionMode::Open => "open",
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
    #[cfg(test)]
    {
        return Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    }
    #[cfg(not(test))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::production_mutation_admission::{
        ProductionCutoverAwsPartition, ProductionCutoverStsPrincipal,
    };
    use cats_api::runtime_reconciliation::{Id, WireU64};
    use postgres::NoTls;
    use std::sync::mpsc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn binding() -> ProductionMutationAdmissionBinding {
        ProductionMutationAdmissionBinding {
            reset_id: Id::new("reset_a").unwrap(),
            deployment_id: Id::new("deployment_a").unwrap(),
            release_id: Id::new("release_a").unwrap(),
            source_commit_sha: "a".repeat(40),
            control_schema_version: WireU64::new(16).unwrap(),
            source_manifest_sha256: digest('0'),
            source_bundle_sha256: digest('1'),
            release_manifest_sha256: digest('2'),
            proof_set_sha256: digest('3'),
            fresh_targets_sha256: digest('4'),
            reset_complete_receipt_sha256: digest('5'),
            fleet_closed_receipt_sha256: digest('6'),
            route_signing_command_receipt_sha256: digest('7'),
            route_ring_delivery_receipt_sha256: digest('8'),
            usage_terminal_receipt_sha256: digest('9'),
            old_host_coverage_sha256: digest('a'),
            kernel_nbd_qualification_bundle_sha256: digest('b'),
            vhost_user_qualification_bundle_sha256: digest('c'),
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
    fn emergency_close_waits_for_admitted_product_transaction_and_cancelled_reopen_is_empty() {
        let dsn = crate::testsupport::isolated_control_store_url();
        let store = Store::connect(&dsn, None).unwrap();
        let binding = binding();
        let open = command(
            '1',
            1,
            ProductionMutationAdmissionMutation::Open {
                binding: binding.clone(),
            },
        );
        let opened = apply(&store, &open);
        assert!(matches!(
            opened.outcome,
            ProductionMutationAdmissionStoredOutcome::Applied { ref state }
                if state.mode == ProductionMutationAdmissionMode::Open
                    && state.revision.get() == 2
        ));

        let mut product_client = postgres::Client::connect(&dsn, NoTls).unwrap();
        let mut product_transaction = product_client.transaction().unwrap();
        assert_eq!(
            require_production_product_mutations_open(&mut product_transaction).unwrap(),
            binding
        );

        let close = command(
            '2',
            2,
            ProductionMutationAdmissionMutation::EmergencyClose {
                binding: binding.clone(),
            },
        );
        let (close_started_tx, close_started_rx) = mpsc::channel();
        let (close_done_tx, close_done_rx) = mpsc::channel();
        let close_dsn = dsn.clone();
        let close_thread = std::thread::spawn(move || {
            let close_store = Store::connect(&close_dsn, None).unwrap();
            close_started_tx.send(()).unwrap();
            close_done_tx.send(apply(&close_store, &close)).unwrap();
        });
        close_started_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert!(close_done_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err());
        product_transaction.commit().unwrap();
        let closed = close_done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        close_thread.join().unwrap();
        assert!(matches!(
            closed.outcome,
            ProductionMutationAdmissionStoredOutcome::Applied { ref state }
                if state.mode == ProductionMutationAdmissionMode::Closed
                    && state.revision.get() == 3
                    && state.binding.as_ref() == Some(&binding)
        ));

        let reopen = command(
            '3',
            3,
            ProductionMutationAdmissionMutation::Open { binding },
        );
        let cancelled = AuthorityRequestContext::new(Instant::now() + Duration::from_secs(5));
        cancelled.cancel();
        assert!(store
            .apply_production_mutation_admission_command_request(&principal(), &reopen, &cancelled,)
            .is_err());
        assert_eq!(
            store
                .production_mutation_admission_state()
                .unwrap()
                .revision
                .get(),
            3
        );
        assert!(store
            .resolve_production_mutation_admission_command(&reopen)
            .unwrap()
            .is_none());
    }
}
