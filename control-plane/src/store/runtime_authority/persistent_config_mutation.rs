//! Cold-only PersistentDisk membership mutation for the atomic lifecycle.
//!
//! This path changes only the append-only product runtime config. It does not
//! create a lifecycle Operation, call a Node, or infer authority from runtime
//! inventory. The Cat row and target Volume serialize all competing binding
//! mutations; the exact terminal Cold head and current config pointer are
//! revalidated in the same transaction that stores the byte-exact API result.

use cats_api::error::ApiError;
use cats_api::persistent_disk::{
    encode_persistent_disk_binding_v2_committed_response, PersistentDiskBindingV2CommittedResponse,
    PersistentDiskBindingV2Request, PERSISTENT_DISK_BINDING_CONFLICT_BODY,
    PERSISTENT_DISK_BINDING_NOT_FOUND_BODY, PERSISTENT_DISK_BINDING_PRECONDITION_BODY,
};
use cats_api::production_mutation_admission::ProductionQualificationMutationClass;
use cats_api::runtime_lifecycle::{
    decode_immutable_runtime_config, encode_immutable_runtime_config, DiskRole as RuntimeDiskRole,
    ImmutableRuntimeConfig, LifecycleOperationState, LifecycleTerminalResult, NodeResult,
    RuntimeVolumeConfig, RuntimeVolumeGuestBinding,
};
use cats_api::runtime_reconciliation::{AsciiText, Id, Sha256Digest, UnixMillis};
use cats_storage::authority::VolumeAdminState;
use postgres::Transaction;

use super::cat_create_service::lock_cat_create_text;
use super::covered_commit::CoveredCommitState;
use super::lifecycle_commands::{
    load_lifecycle_admission_context_in, LifecycleAdmissionContext, LifecycleStableState,
};
use super::product::{
    ApiIdempotencyRequest, ApiIdempotencyResult, DiskAdminState, DiskRecord, DiskRole,
    PersistentDiskInitialization,
};
use super::product_mutation_service::{
    atomic_api_result, exact_api_replay, reserve_atomic_api_key, store_atomic_fixed_result,
    PersistentDiskBindingAction,
};
use super::product_rows::{
    insert_api_result, load_api_result_for_update, load_disk_by_id_for_update,
    load_disk_by_id_unlocked,
};
use super::production_mutation_admission::require_production_product_mutation_admitted;
use super::rows::{database_now, load_stored_volume_for_update};
use crate::store::transaction::{
    AuthorityExecutionError, AuthorityTransactionError, AuthorityTxResult,
};
use crate::store::Store;

#[derive(Debug)]
pub(super) enum PersistentDiskBindingCommitError {
    CandidateIdentityCollision,
    CurrentHeadStale,
    Store(ApiError),
}

#[derive(Debug, Clone)]
struct CurrentDiskBinding {
    workspace_id: Id,
    cat_id: Id,
    runtime_config_id: Id,
    runtime_config_digest: Sha256Digest,
    volume: RuntimeVolumeConfig,
}

pub(super) fn commit_persistent_disk_binding_covered(
    store: &Store,
    idempotency: &ApiIdempotencyRequest,
    disk_id: &Id,
    action: PersistentDiskBindingAction,
    request: &PersistentDiskBindingV2Request,
    candidate_config_id: &Id,
    commit_state: &CoveredCommitState,
) -> Result<ApiIdempotencyResult, PersistentDiskBindingCommitError> {
    let mut candidate_identity_collision = false;
    let outcome = store.authority_transaction_outcome_with_definite_retry(
        |transaction| {
            commit_state.checkpoint(transaction)?;
            reserve_atomic_api_key(transaction, idempotency)?;
            commit_state.checkpoint(transaction)?;
            if let Some(result) = load_api_result_for_update(transaction, idempotency)? {
                let result = exact_api_replay(result, idempotency)?;
                commit_state.begin_commit(transaction)?;
                return Ok(result);
            }
            require_production_product_mutation_admitted(
                transaction,
                &idempotency.authenticated_workspace_id,
                ProductionQualificationMutationClass::RuntimeMutation,
            )?;
            commit_state.checkpoint(transaction)?;

            let Some(context) = load_lifecycle_admission_context_in(
                transaction,
                &idempotency.authenticated_workspace_id,
                &request.cat_id,
            )?
            else {
                let result = store_atomic_fixed_result(
                    transaction,
                    idempotency,
                    404,
                    PERSISTENT_DISK_BINDING_NOT_FOUND_BODY,
                )?;
                commit_state.begin_commit(transaction)?;
                return Ok(result);
            };
            if !is_exact_terminal_cold(&context) {
                let result = store_atomic_fixed_result(
                    transaction,
                    idempotency,
                    412,
                    PERSISTENT_DISK_BINDING_PRECONDITION_BODY,
                )?;
                commit_state.begin_commit(transaction)?;
                return Ok(result);
            }

            // Disk identity is immutable, but the global lock order puts the
            // Volume before the Disk. This unlocked lookup only discovers the
            // Volume key; both rows are reread and compared after locking.
            let Some(preflight_disk) = load_disk_by_id_unlocked(transaction, disk_id)? else {
                let result = store_atomic_fixed_result(
                    transaction,
                    idempotency,
                    404,
                    PERSISTENT_DISK_BINDING_NOT_FOUND_BODY,
                )?;
                commit_state.begin_commit(transaction)?;
                return Ok(result);
            };
            if preflight_disk.workspace_id != idempotency.authenticated_workspace_id {
                let result = store_atomic_fixed_result(
                    transaction,
                    idempotency,
                    404,
                    PERSISTENT_DISK_BINDING_NOT_FOUND_BODY,
                )?;
                commit_state.begin_commit(transaction)?;
                return Ok(result);
            }
            let Some(volume) =
                load_stored_volume_for_update(transaction, &preflight_disk.volume_id)?
            else {
                return Err(corrupt("PersistentDisk references a missing Volume"));
            };
            let Some(disk) = load_disk_by_id_for_update(transaction, disk_id)? else {
                return Err(AuthorityTransactionError::PlacementStale);
            };
            if disk != preflight_disk {
                return Err(AuthorityTransactionError::PlacementStale);
            }
            let Some(filesystem_uuid) = binding_filesystem_uuid(&disk) else {
                let result = store_atomic_fixed_result(
                    transaction,
                    idempotency,
                    412,
                    PERSISTENT_DISK_BINDING_PRECONDITION_BODY,
                )?;
                commit_state.begin_commit(transaction)?;
                return Ok(result);
            };
            if volume.record.volume_id != disk.volume_id
                || volume.record.size_bytes != disk.size_bytes
                || volume.record.durability != disk.durability
            {
                return Err(corrupt(
                    "PersistentDisk and Volume immutable projections disagree",
                ));
            }
            if !matches!(volume.record.admin_state, VolumeAdminState::Active)
                || volume.record.lease_owner.is_some()
                || volume.record.lease_expires_at.is_some()
                || volume.owner_binding.is_some()
            {
                let result = store_atomic_fixed_result(
                    transaction,
                    idempotency,
                    412,
                    PERSISTENT_DISK_BINDING_PRECONDITION_BODY,
                )?;
                commit_state.begin_commit(transaction)?;
                return Ok(result);
            }

            let bindings = load_current_disk_bindings(transaction, disk_id, &disk.volume_id)?;
            let target = match build_target_runtime_config(
                &context,
                &disk,
                filesystem_uuid,
                request,
                action,
                &bindings,
                candidate_config_id,
            )? {
                BindingPlan::Conflict => {
                    let result = store_atomic_fixed_result(
                        transaction,
                        idempotency,
                        409,
                        PERSISTENT_DISK_BINDING_CONFLICT_BODY,
                    )?;
                    commit_state.begin_commit(transaction)?;
                    return Ok(result);
                }
                BindingPlan::Target(target) => target,
            };
            let head_operation_id = context
                .lifecycle_head
                .as_ref()
                .ok_or_else(|| corrupt("terminal Cold Cat has no lifecycle head"))?
                .operation_id
                .clone();
            let config_created_at = database_now(transaction)?;
            match append_and_advance_runtime_config(
                transaction,
                &idempotency.authenticated_workspace_id,
                &request.cat_id,
                &head_operation_id,
                &context.immutable_runtime_config,
                &target,
                config_created_at,
            )? {
                ConfigAdvance::Advanced => {}
                ConfigAdvance::CandidateIdentityCollision => {
                    candidate_identity_collision = true;
                    return Err(AuthorityTransactionError::CandidateCollision);
                }
            }
            let response = PersistentDiskBindingV2CommittedResponse {
                cat_id: request.cat_id.clone(),
                disk_id: disk_id.clone(),
                runtime_config_id: target.config_id.clone(),
                runtime_config_digest: target.config_digest.clone(),
            };
            let response_body = encode_persistent_disk_binding_v2_committed_response(&response)
                .map_err(|_| corrupt("PersistentDisk binding response cannot be encoded"))?;
            let result =
                atomic_api_result(idempotency, 200, response_body, database_now(transaction)?);
            insert_api_result(transaction, &result)?;
            commit_state.begin_commit(transaction)?;
            Ok(result)
        },
        || commit_state.reset_after_definite_retry(),
    );
    match outcome {
        Ok(result) => Ok(result),
        Err(AuthorityExecutionError::CandidateCollision) if candidate_identity_collision => {
            Err(PersistentDiskBindingCommitError::CandidateIdentityCollision)
        }
        Err(AuthorityExecutionError::PlacementStale) => {
            Err(PersistentDiskBindingCommitError::CurrentHeadStale)
        }
        Err(AuthorityExecutionError::Store(error)) => {
            Err(PersistentDiskBindingCommitError::Store(error))
        }
        Err(AuthorityExecutionError::CandidateCollision) => {
            Err(PersistentDiskBindingCommitError::Store(ApiError::internal(
                "PersistentDisk binding transaction lost its config collision",
            )))
        }
    }
}

fn is_exact_terminal_cold(context: &LifecycleAdmissionContext) -> bool {
    context.deleted_at.is_none()
        && context.unresolved_operation.is_none()
        && context.stable_state == Some(LifecycleStableState::Cold)
        && context.lifecycle_head.as_ref().is_some_and(|head| {
            // Config membership can advance more than once in one settled
            // Cold window without manufacturing a lifecycle Operation. Close
            // the head against its own frozen config/result; the independently
            // locked current pointer is the source and CAS guard below.
            head.runtime_config_id == head.canonical_request.runtime_config.config_id
                && head.runtime_config_digest == head.canonical_request.runtime_config.config_digest
                && matches!(
                    &head.state,
                    LifecycleOperationState::Terminal { terminal, .. }
                        if matches!(
                            terminal.as_ref(),
                            LifecycleTerminalResult::NodeResult { response }
                                if matches!(
                                    &response.result,
                                    NodeResult::Cold(cold)
                                        if cold.runtime_config_digest
                                            == head.runtime_config_digest
                                )
                        )
                )
        })
}

fn binding_filesystem_uuid(
    disk: &DiskRecord,
) -> Option<cats_api::runtime_reconciliation::RandomId128> {
    if !matches!(disk.admin_state, DiskAdminState::Active) {
        return None;
    }
    let DiskRole::Persistent { initialization } = &disk.role else {
        return None;
    };
    Some(match initialization.as_ref() {
        PersistentDiskInitialization::Uninitialized {
            filesystem_uuid, ..
        }
        | PersistentDiskInitialization::Initialized {
            filesystem_uuid, ..
        } => filesystem_uuid.clone(),
    })
}

fn load_current_disk_bindings(
    transaction: &mut Transaction<'_>,
    disk_id: &Id,
    volume_id: &Id,
) -> AuthorityTxResult<Vec<CurrentDiskBinding>> {
    let rows = transaction.query(
        "SELECT cat.workspace_id, cat.cat_id,
                cat.current_runtime_config_id,
                cat.current_runtime_config_sha256,
                config.config_id, config.canonical_config_bytes,
                config.canonical_config_sha256
           FROM cat_records cat
           JOIN cat_runtime_configs config
             ON config.workspace_id=cat.workspace_id
            AND config.cat_id=cat.cat_id
            AND config.config_id=cat.current_runtime_config_id
            AND config.canonical_config_sha256=cat.current_runtime_config_sha256
          WHERE cat.deleted_at IS NULL
            AND EXISTS (
                SELECT 1
                 FROM jsonb_array_elements(
                    (convert_from(config.canonical_config_bytes, 'UTF8')::jsonb)->'volumes'
                  ) AS candidate
                 WHERE candidate->>'disk_id'=$1
                    OR candidate->>'volume_id'=$2
            )
          ORDER BY cat.cat_id COLLATE \"C\"
          LIMIT 2",
        &[&disk_id.as_str(), &volume_id.as_str()],
    )?;
    let mut bindings = Vec::with_capacity(rows.len());
    for row in rows {
        let workspace_id = parse_id(row.try_get("workspace_id")?)?;
        let cat_id = parse_id(row.try_get("cat_id")?)?;
        let current_config_id = parse_id(row.try_get("current_runtime_config_id")?)?;
        let current_digest = parse_digest(row.try_get("current_runtime_config_sha256")?)?;
        let row_config_id = parse_id(row.try_get("config_id")?)?;
        let row_digest = parse_digest(row.try_get("canonical_config_sha256")?)?;
        let bytes: Vec<u8> = row.try_get("canonical_config_bytes")?;
        let config = decode_immutable_runtime_config(&bytes)
            .map_err(|_| corrupt("current runtime config bytes are invalid"))?;
        if current_config_id != row_config_id
            || current_digest != row_digest
            || config.config_id != row_config_id
            || config.config_digest != row_digest
        {
            return Err(corrupt(
                "current runtime config pointer disagrees with immutable history",
            ));
        }
        let mut matching = config
            .volumes
            .into_iter()
            .filter(|volume| volume.disk_id == *disk_id || volume.volume_id == *volume_id);
        let Some(volume) = matching.next() else {
            return Err(corrupt(
                "runtime config disk membership index returned no exact member",
            ));
        };
        if matching.next().is_some() {
            return Err(corrupt(
                "one runtime config contains duplicate PersistentDisk membership",
            ));
        }
        bindings.push(CurrentDiskBinding {
            workspace_id,
            cat_id,
            runtime_config_id: row_config_id,
            runtime_config_digest: row_digest,
            volume,
        });
    }
    Ok(bindings)
}

enum BindingPlan {
    Conflict,
    Target(Box<ImmutableRuntimeConfig>),
}

#[allow(clippy::too_many_arguments)]
fn build_target_runtime_config(
    context: &LifecycleAdmissionContext,
    disk: &DiskRecord,
    filesystem_uuid: cats_api::runtime_reconciliation::RandomId128,
    request: &PersistentDiskBindingV2Request,
    action: PersistentDiskBindingAction,
    bindings: &[CurrentDiskBinding],
    candidate_config_id: &Id,
) -> AuthorityTxResult<BindingPlan> {
    if bindings.len() > 1 {
        return Err(corrupt(
            "PersistentDisk is referenced by more than one current runtime config",
        ));
    }
    let source = &context.immutable_runtime_config;
    let mut volumes = source.volumes.clone();
    match action {
        PersistentDiskBindingAction::Attach => {
            if !bindings.is_empty() {
                return Ok(BindingPlan::Conflict);
            }
            let (guest_device_slot, guest_device_serial) = next_guest_device_identity(&volumes)?;
            let mount_path = AsciiText::new(request.mount_path.as_str().to_owned())
                .ok_or_else(|| corrupt("validated mount path no longer fits runtime config"))?;
            volumes.push(RuntimeVolumeConfig {
                volume_id: disk.volume_id.clone(),
                disk_id: disk.disk_id.clone(),
                disk_role: RuntimeDiskRole::Persistent,
                size_bytes: disk.size_bytes,
                durability: disk.durability,
                guest_device_serial,
                guest_device_slot,
                guest_binding: RuntimeVolumeGuestBinding::PersistentExt4 {
                    filesystem_uuid,
                    mount_path,
                },
            });
            volumes.sort_by(|left, right| left.volume_id.as_str().cmp(right.volume_id.as_str()));
        }
        PersistentDiskBindingAction::Detach => {
            let Some(binding) = bindings.first() else {
                return Ok(BindingPlan::Conflict);
            };
            let mount_matches = matches!(
                &binding.volume.guest_binding,
                RuntimeVolumeGuestBinding::PersistentExt4 {
                    filesystem_uuid: bound_uuid,
                    mount_path,
                } if bound_uuid == &filesystem_uuid
                    && mount_path.as_str() == request.mount_path.as_str()
            );
            if binding.workspace_id != disk.workspace_id
                || binding.cat_id != request.cat_id
                || binding.runtime_config_id != source.config_id
                || binding.runtime_config_digest != source.config_digest
                || binding.volume.volume_id != disk.volume_id
                || binding.volume.disk_id != disk.disk_id
                || binding.volume.disk_role != RuntimeDiskRole::Persistent
                || binding.volume.size_bytes != disk.size_bytes
                || binding.volume.durability != disk.durability
                || !mount_matches
            {
                return Ok(BindingPlan::Conflict);
            }
            let before = volumes.len();
            volumes.retain(|volume| volume.disk_id != disk.disk_id);
            if volumes.len().checked_add(1) != Some(before) {
                return Err(corrupt(
                    "exact PersistentDisk binding is absent from its source config",
                ));
            }
        }
    }
    let target = ImmutableRuntimeConfig::new(
        candidate_config_id.clone(),
        source.boot_image_digest.clone(),
        source.vcpus,
        source.memory_bytes,
        source.guest_runtime_profile_digest.clone(),
        source.network_config.clone(),
        volumes,
    )
    .map_err(|_| corrupt("PersistentDisk mutation produced an invalid runtime config"))?;
    Ok(BindingPlan::Target(Box::new(target)))
}

fn next_guest_device_identity(volumes: &[RuntimeVolumeConfig]) -> AuthorityTxResult<(u16, Id)> {
    for slot in 0..=u16::MAX {
        if volumes
            .iter()
            .any(|volume| volume.guest_device_slot == slot)
        {
            continue;
        }
        let serial = Id::new(format!("cats-pd-{slot}"))
            .ok_or_else(|| corrupt("PersistentDisk guest serial is invalid"))?;
        if volumes
            .iter()
            .all(|volume| volume.guest_device_serial != serial)
        {
            return Ok((slot, serial));
        }
    }
    Err(corrupt("runtime config exhausted all Guest device slots"))
}

enum ConfigAdvance {
    Advanced,
    CandidateIdentityCollision,
}

#[allow(clippy::too_many_arguments)]
fn append_and_advance_runtime_config(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
    lifecycle_head_operation_id: &Id,
    source: &ImmutableRuntimeConfig,
    target: &ImmutableRuntimeConfig,
    now: UnixMillis,
) -> AuthorityTxResult<ConfigAdvance> {
    lock_cat_create_text(
        transaction,
        "config-id",
        target.config_id.as_str(),
        "candidate",
    )?;
    let exists: bool = transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM cat_runtime_configs WHERE config_id=$1)",
            &[&target.config_id.as_str()],
        )?
        .try_get(0)?;
    if exists {
        return Ok(ConfigAdvance::CandidateIdentityCollision);
    }
    let canonical = encode_immutable_runtime_config(target)
        .map_err(|_| corrupt("target runtime config cannot be encoded canonically"))?;
    let now_pg =
        i64::try_from(now.get()).map_err(|_| corrupt("database time exceeds PostgreSQL BIGINT"))?;
    transaction.execute(
        "INSERT INTO cat_runtime_configs (
            config_id, workspace_id, cat_id, canonical_config_bytes,
            canonical_config_sha256, created_at_unix_ms
         ) VALUES ($1,$2,$3,$4,$5,$6)",
        &[
            &target.config_id.as_str(),
            &workspace_id.as_str(),
            &cat_id.as_str(),
            &canonical,
            &target.config_digest.as_str(),
            &now_pg,
        ],
    )?;
    let updated = transaction.execute(
        "UPDATE cat_records
            SET current_runtime_config_id=$1,
                current_runtime_config_sha256=$2
          WHERE workspace_id=$3 AND cat_id=$4
            AND lifecycle_head_operation_id=$5
            AND current_runtime_config_id=$6
            AND current_runtime_config_sha256=$7
            AND stable_state='cold' AND deleted_at IS NULL
            AND NOT EXISTS (
                SELECT 1 FROM runtime_operations pending
                 WHERE pending.cat_id=cat_records.cat_id
                   AND pending.state='unresolved'
            )",
        &[
            &target.config_id.as_str(),
            &target.config_digest.as_str(),
            &workspace_id.as_str(),
            &cat_id.as_str(),
            &lifecycle_head_operation_id.as_str(),
            &source.config_id.as_str(),
            &source.config_digest.as_str(),
        ],
    )?;
    if updated != 1 {
        return Err(AuthorityTransactionError::PlacementStale);
    }
    Ok(ConfigAdvance::Advanced)
}

fn parse_id(value: String) -> AuthorityTxResult<Id> {
    Id::new(value).ok_or_else(|| corrupt("stored runtime identity is invalid"))
}

fn parse_digest(value: String) -> AuthorityTxResult<Sha256Digest> {
    Sha256Digest::new(value).ok_or_else(|| corrupt("stored runtime digest is invalid"))
}

fn corrupt(message: impl Into<String>) -> AuthorityTransactionError {
    ApiError::internal(message.into()).into()
}
