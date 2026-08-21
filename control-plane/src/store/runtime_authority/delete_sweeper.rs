//! Level-triggered `Deleting -> Removed` reconciliation.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{anyhow, Context};
use cats_api::runtime_lifecycle::{LifecycleCommand, LifecycleCommandEnvelope};
use cats_api::runtime_reconciliation::Id;
use cats_storage::authority::{
    complete_disposable_root_delete, complete_normal_delete, AuthorizationConsumedReceipt,
    AuthorizationRecord, AuthorizationState, DeleteCompletionReceipt,
    DisposableDeleteIsolationBasis, LastVolumeTransition, VolumeAdminState, VolumeAuthorization,
    VolumeRecord, VolumeTransitionSource,
};
use cats_storage::lifecycle_volume::{
    encode_command_delete_already_unowned_receipt,
    encode_command_delete_already_unowned_receipt_for_deleting_root,
    encode_command_disposable_authorization_consumed_receipt,
    encode_command_normal_release_receipt, encode_command_normal_release_receipt_for_deleting_root,
    persistent_delete_dispositions_digest, CommandBoundDisposableRootAuthorization,
    CommandDeleteCompletionReceipt, CommandRootDeleteAuthorityReceipt,
    CommandVolumeDispositionReceipt, DefaultRootDiscardDisposition, DeleteCommandVolumeSet,
    LifecycleVolumeIdentity,
};
use cats_storage::{delete_volume_objects_page, BlobStore, DeletePrefixPage};

use super::product::{DiskAdminState, DiskRecord};
use super::product_rows::{
    delete_disk, load_any_disk_by_id_for_update, load_any_disk_snapshot_for_update,
    load_any_disk_snapshot_unlocked, load_disk_by_volume_unlocked,
};
use super::rows::{
    database_now, delete_volume, insert_command_delete_completion_receipt,
    insert_delete_completion, load_authorization_for_update, load_authorization_unlocked,
    load_command_already_unowned_receipt_for_update, load_command_already_unowned_receipt_unlocked,
    load_command_delete_completion_receipt_for_update,
    load_command_normal_release_receipt_for_update, load_command_normal_release_receipt_unlocked,
    load_delete_completion_for_update, load_delete_lifecycle_volume_receipt_source_for_update,
    load_delete_lifecycle_volume_receipt_source_unlocked, load_volume_for_update,
    load_volume_unlocked, lock_lifecycle_receipt_operation, LifecycleReceiptOperationState,
    LifecycleVolumeReceiptKind, StoredCommandAlreadyUnownedReceipt,
    StoredCommandDisposableAuthorizationConsumedReceipt, StoredCommandNormalReleaseReceipt,
    StoredLifecycleVolumeReceipt,
};
use crate::store::transaction::AuthorityTxResult;
use crate::store::{Result as StoreResult, Store};

const DELETE_CANDIDATE_PAGE_MAX: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeleteSweepBudget {
    max_candidates: usize,
    max_objects_per_candidate: usize,
}

impl DeleteSweepBudget {
    pub(crate) fn new(max_candidates: usize, max_objects_per_candidate: usize) -> Option<Self> {
        (max_candidates > 0
            && max_candidates <= DELETE_CANDIDATE_PAGE_MAX
            && max_objects_per_candidate > 0
            && max_objects_per_candidate <= cats_storage::BLOB_LIST_PAGE_MAX_KEYS)
            .then_some(Self {
                max_candidates,
                max_objects_per_candidate,
            })
    }
}

impl Default for DeleteSweepBudget {
    fn default() -> Self {
        Self {
            max_candidates: 32,
            max_objects_per_candidate: cats_storage::BLOB_LIST_PAGE_MAX_KEYS,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DeleteSweepPass {
    pub(crate) candidates_examined: usize,
    pub(crate) objects_deleted: usize,
    pub(crate) completions_committed: usize,
    pub(crate) blocked_missing_provider_evidence: usize,
    pub(crate) more_work: bool,
}

pub(crate) struct DeleteSweeper {
    store: Arc<Store>,
    blob: Arc<dyn BlobStore>,
    cursor: Mutex<Option<Id>>,
}

impl DeleteSweeper {
    pub(crate) fn new(store: Arc<Store>, blob: Arc<dyn BlobStore>) -> Self {
        Self {
            store,
            blob,
            cursor: Mutex::new(None),
        }
    }

    /// Run one bounded keyset page. Dropping this future starts no later page;
    /// a blocking object effect already dispatched continues through its
    /// mandatory discovery re-list before its worker exits.
    pub(crate) async fn run_once(
        &self,
        budget: DeleteSweepBudget,
        deadline: Instant,
    ) -> anyhow::Result<DeleteSweepPass> {
        if Instant::now() >= deadline {
            return Err(anyhow!("volume delete sweep deadline elapsed"));
        }
        let after = self
            .cursor
            .lock()
            .map_err(|_| anyhow!("volume delete sweep cursor mutex was poisoned"))?
            .clone();
        let requested_after = after.clone();
        let candidates = self
            .store
            .execute(move |store| {
                store.load_delete_candidates(after.as_ref(), budget.max_candidates)
            })
            .await
            .context("load volume delete candidates")?;
        if candidates.is_empty() {
            if requested_after.is_some() {
                *self
                    .cursor
                    .lock()
                    .map_err(|_| anyhow!("volume delete sweep cursor mutex was poisoned"))? = None;
            }
            return Ok(DeleteSweepPass {
                more_work: requested_after.is_some(),
                ..DeleteSweepPass::default()
            });
        }

        let mut pass = DeleteSweepPass::default();
        for candidate in candidates {
            if Instant::now() >= deadline {
                pass.more_work = true;
                break;
            }
            pass.candidates_examined += 1;
            *self
                .cursor
                .lock()
                .map_err(|_| anyhow!("volume delete sweep cursor mutex was poisoned"))? =
                Some(candidate.volume.volume_id.clone());

            if candidate.eligibility == DeleteCandidateEligibility::MissingProviderEvidence {
                pass.blocked_missing_provider_evidence += 1;
                pass.more_work = true;
                continue;
            }

            let blob = Arc::clone(&self.blob);
            let volume_id = candidate.volume.volume_id.clone();
            let maximum = budget.max_objects_per_candidate;
            let effect = tokio::task::spawn_blocking(move || {
                delete_volume_objects_page(blob.as_ref(), &volume_id, maximum, deadline)
            })
            .await
            .context("volume object delete worker panicked")?
            .context("delete and discover volume object prefix")?;
            let prefix_empty = match effect {
                DeletePrefixPage::Empty => true,
                DeletePrefixPage::Progress { deleted, now_empty } => {
                    pass.objects_deleted += deleted;
                    now_empty
                }
            };
            if !prefix_empty {
                pass.more_work = true;
                continue;
            }

            let proof = EmptyVolumePrefix { candidate };
            let completed = self
                .store
                .execute(move |store| store.complete_delete(proof))
                .await
                .context("commit volume delete completion")?;
            if completed {
                pass.completions_committed += 1;
            }
        }
        if pass.candidates_examined == budget.max_candidates {
            pass.more_work = true;
        }
        Ok(pass)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeleteCandidateEligibility {
    Eligible,
    MissingProviderEvidence,
}

#[derive(Debug, Clone)]
struct DeleteSweepCandidate {
    disk: DiskRecord,
    volume: VolumeRecord,
    authorization: Option<AuthorizationRecord>,
    lifecycle_delete: Option<LifecycleDeleteEvidence>,
    eligibility: DeleteCandidateEligibility,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LifecycleRootAuthoritySource {
    Normal(Box<StoredCommandNormalReleaseReceipt>),
    AlreadyUnowned(Box<StoredCommandAlreadyUnownedReceipt>),
    Disposable(Box<StoredCommandDisposableAuthorizationConsumedReceipt>),
}

impl LifecycleRootAuthoritySource {
    fn operation(&self) -> &LifecycleCommandEnvelope {
        match self {
            Self::Normal(source) => &source.operation,
            Self::AlreadyUnowned(source) => &source.operation,
            Self::Disposable(source) => &source.operation,
        }
    }

    const fn kind(&self) -> LifecycleVolumeReceiptKind {
        match self {
            Self::Normal(_) => LifecycleVolumeReceiptKind::NormalRelease,
            Self::AlreadyUnowned(_) => LifecycleVolumeReceiptKind::AlreadyUnowned,
            Self::Disposable(_) => LifecycleVolumeReceiptKind::DisposableAuthorizationConsumed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LifecycleDeleteEvidence {
    command: DeleteCommandVolumeSet,
    root_authority: LifecycleRootAuthoritySource,
    persistent_dispositions: Vec<LifecyclePersistentAuthoritySource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LifecyclePersistentAuthoritySource {
    Normal(Box<StoredCommandNormalReleaseReceipt>),
    AlreadyUnowned(Box<StoredCommandAlreadyUnownedReceipt>),
}

/// An in-process capability constructed only by the authoritative empty
/// re-list path above. It is neither serializable nor accepted from a caller.
struct EmptyVolumePrefix {
    candidate: DeleteSweepCandidate,
}

impl Store {
    fn load_delete_candidates(
        &self,
        after: Option<&Id>,
        maximum: usize,
    ) -> StoreResult<Vec<DeleteSweepCandidate>> {
        if maximum == 0 || maximum > DELETE_CANDIDATE_PAGE_MAX {
            return Err(cats_api::error::ApiError::internal(
                "invalid delete candidate page bound",
            ));
        }
        self.authority_read_snapshot(|transaction| {
            let split = transaction.query_opt(
                "SELECT d.disk_id
                   FROM disk_records d
                   LEFT JOIN volume_records v ON v.volume_id=d.volume_id
                  WHERE d.admin_state='deleting'
                    AND (v.volume_id IS NULL OR v.admin_state <> 'deleting'
                         OR v.delete_id IS DISTINCT FROM d.delete_id)
                  ORDER BY d.disk_id COLLATE \"C\" LIMIT 1",
                &[],
            )?;
            if split.is_some() {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            }
            let maximum = i64::try_from(maximum)
                .map_err(|_| cats_storage::authority::AuthorityError::BackendUnknown)?;
            let after = after.map(Id::as_str);
            let rows = transaction.query(
                "SELECT volume_id FROM volume_records
                  WHERE admin_state='deleting'
                    AND ($1::TEXT IS NULL OR volume_id COLLATE \"C\" > $1 COLLATE \"C\")
                  ORDER BY volume_id COLLATE \"C\" LIMIT $2",
                &[&after, &maximum],
            )?;
            let mut candidates = Vec::with_capacity(rows.len());
            for row in rows {
                let volume_id = Id::new(row.try_get::<_, String>("volume_id")?)
                    .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
                let volume = load_volume_unlocked(transaction, &volume_id)?
                    .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
                let disk = load_disk_by_volume_unlocked(transaction, &volume_id)?
                    .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
                // A live snapshot is an independent GC root. This check must
                // happen before returning a candidate because object deletion
                // begins outside PostgreSQL; the completion-time lock below
                // remains the second half of the race closure.
                if load_any_disk_snapshot_unlocked(
                    transaction,
                    &disk.disk_id,
                    &volume.volume_id,
                    disk.size_bytes,
                )?
                .is_some()
                {
                    continue;
                }
                let (authorization, lifecycle_delete, eligibility) =
                    candidate_origin(transaction, &disk, &volume, false)?;
                candidates.push(DeleteSweepCandidate {
                    disk,
                    volume,
                    authorization,
                    lifecycle_delete,
                    eligibility,
                });
            }
            Ok(candidates)
        })
    }

    /// `true` means this transaction committed the receipt; `false` means an
    /// exact concurrent completion was discovered and replayed.
    fn complete_delete(&self, proof: EmptyVolumePrefix) -> StoreResult<bool> {
        self.authority_transaction(|transaction| {
            let candidate = &proof.candidate;
            if candidate.lifecycle_delete.is_some() {
                return complete_lifecycle_delete(transaction, candidate);
            }
            let Some(volume) = load_volume_for_update(transaction, &candidate.volume.volume_id)?
            else {
                let disk = load_any_disk_by_id_for_update(transaction, &candidate.disk.disk_id)?;
                let receipt =
                    load_delete_completion_for_update(transaction, candidate_delete_id(candidate))?
                        .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
                if disk.is_some() || !receipt_matches_candidate(&receipt, candidate)? {
                    return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
                }
                return Ok(false);
            };
            let disk = load_any_disk_by_id_for_update(transaction, &candidate.disk.disk_id)?
                .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
            if volume != candidate.volume || disk != candidate.disk {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            }
            if load_any_disk_snapshot_for_update(
                transaction,
                &disk.disk_id,
                &volume.volume_id,
                disk.size_bytes,
            )?
            .is_some()
            {
                return Err(cats_storage::authority::AuthorityError::SnapshotInUse.into());
            }
            let authorization = match &candidate.authorization {
                Some(expected) => {
                    let authorization_id = authorization_id(expected)?;
                    let current = load_authorization_for_update(transaction, authorization_id)?
                        .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
                    if current != *expected {
                        return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
                    }
                    Some(current)
                }
                None => None,
            };
            let completed_at = database_now(transaction)?;
            let receipt = match authorization.as_ref() {
                Some(authorization) => {
                    complete_disposable_root_delete(&volume, authorization, completed_at)?
                }
                None => complete_normal_delete(&volume, completed_at)?,
            };
            insert_delete_completion(transaction, &receipt)?;
            // Disk first satisfies its FK to Volume; both removals and the
            // exact receipt are still one PostgreSQL commit.
            delete_disk(transaction, &disk)?;
            delete_volume(transaction, &volume)?;
            Ok(true)
        })
    }
}

fn complete_lifecycle_delete(
    transaction: &mut postgres::Transaction<'_>,
    candidate: &DeleteSweepCandidate,
) -> AuthorityTxResult<bool> {
    let expected = candidate
        .lifecycle_delete
        .as_ref()
        .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
    let operation_id = &expected.root_authority.operation().operation_id;

    // The immutable source's Operation identity locates the Cat but grants no
    // authority. Global order is Cat -> exact Operation -> sorted Volume ->
    // sorted Disk -> immutable receipt ledger.
    let located_operation = expected.root_authority.operation();
    let cat = transaction
        .query_opt(
            "SELECT cat_id, lifecycle_head_operation_id,
                    current_runtime_config_id, current_runtime_config_sha256,
                    deleted_at
               FROM cat_records
              WHERE cat_id=$1 AND workspace_id=$2 FOR UPDATE",
            &[
                &located_operation.cat_id.as_str(),
                &located_operation.workspace_id.as_str(),
            ],
        )?
        .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
    let (locked_operation, operation_state) =
        lock_lifecycle_receipt_operation(transaction, operation_id)?
            .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
    if locked_operation != *located_operation {
        return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
    }
    if cat
        .try_get::<_, Option<String>>("lifecycle_head_operation_id")?
        .as_deref()
        != locked_operation
            .expected_predecessor_operation_id
            .as_ref()
            .map(Id::as_str)
        || cat.try_get::<_, String>("current_runtime_config_id")?
            != locked_operation.runtime_config.config_id.as_str()
        || cat.try_get::<_, String>("current_runtime_config_sha256")?
            != locked_operation.runtime_config.config_digest.as_str()
        || (operation_state == LifecycleReceiptOperationState::Unresolved
            && cat.try_get::<_, Option<i64>>("deleted_at")?.is_some())
    {
        return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
    }

    let mut volume_configs: Vec<_> = locked_operation.runtime_config.volumes.iter().collect();
    volume_configs.sort_by(|left, right| left.volume_id.as_str().cmp(right.volume_id.as_str()));
    let mut locked_root = None;
    for config in volume_configs {
        let current = load_volume_for_update(transaction, &config.volume_id)?;
        if config.volume_id == candidate.volume.volume_id {
            locked_root = current;
        } else if current.is_none() {
            return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
        }
    }

    let mut disk_configs: Vec<_> = locked_operation.runtime_config.volumes.iter().collect();
    disk_configs.sort_by(|left, right| left.disk_id.as_str().cmp(right.disk_id.as_str()));
    let mut locked_root_disk = None;
    for config in disk_configs {
        let current = load_any_disk_by_id_for_update(transaction, &config.disk_id)?;
        if config.disk_id == candidate.disk.disk_id {
            locked_root_disk = current;
        } else {
            let current = current.ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
            if current.volume_id != config.volume_id {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            }
        }
    }

    let Some(volume) = locked_root else {
        let generic =
            load_delete_completion_for_update(transaction, candidate_delete_id(candidate))?
                .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
        let command = load_command_delete_completion_receipt_for_update(
            transaction,
            operation_id,
            &candidate.volume.volume_id,
        )?
        .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
        if locked_root_disk.is_some()
            || !receipt_matches_candidate(&generic, candidate)?
            || command.operation != locked_operation
            || command.delete_id != *candidate_delete_id(candidate)
            || command.receipt.command != expected.command
            || command.receipt.completion != generic
        {
            return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
        }
        let bound = candidate.authorization.as_ref().map(|authorization| {
            CommandBoundDisposableRootAuthorization {
                scope: expected.command.scope.clone(),
                authorization: authorization.clone(),
            }
        });
        let encoded = cats_storage::lifecycle_volume::encode_command_delete_completion_receipt(
            &expected.command,
            None,
            bound.as_ref(),
            &command.receipt,
        )
        .map_err(|_| cats_storage::authority::AuthorityError::BackendUnknown)?;
        if encoded.receipt_digest != command.receipt_digest {
            return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
        }
        return Ok(false);
    };
    if operation_state != LifecycleReceiptOperationState::Unresolved {
        return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
    }
    let disk = locked_root_disk.ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
    if volume != candidate.volume || disk != candidate.disk {
        return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
    }
    if load_any_disk_snapshot_for_update(
        transaction,
        &disk.disk_id,
        &volume.volume_id,
        disk.size_bytes,
    )?
    .is_some()
    {
        return Err(cats_storage::authority::AuthorityError::SnapshotInUse.into());
    }
    let authorization = match &candidate.authorization {
        Some(expected_authorization) => {
            let authorization_id = authorization_id(expected_authorization)?;
            let current = load_authorization_for_update(transaction, authorization_id)?
                .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
            if current != *expected_authorization {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            }
            Some(current)
        }
        None => None,
    };
    let reloaded = load_lifecycle_delete_evidence(
        transaction,
        &disk,
        &volume,
        authorization.as_ref(),
        expected.root_authority.kind(),
        true,
    )?
    .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
    if reloaded != *expected {
        return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
    }

    let completed_at = database_now(transaction)?;
    let generic = match authorization.as_ref() {
        Some(authorization) => {
            complete_disposable_root_delete(&volume, authorization, completed_at)?
        }
        None => complete_normal_delete(&volume, completed_at)?,
    };
    insert_delete_completion(transaction, &generic)?;
    delete_disk(transaction, &disk)?;
    delete_volume(transaction, &volume)?;

    let root_authority = match &reloaded.root_authority {
        LifecycleRootAuthoritySource::Normal(source) => {
            CommandRootDeleteAuthorityReceipt::NormalRelease(source.receipt.clone())
        }
        LifecycleRootAuthoritySource::AlreadyUnowned(source) => {
            CommandRootDeleteAuthorityReceipt::AlreadyUnowned(source.receipt.clone())
        }
        LifecycleRootAuthoritySource::Disposable(source) => {
            CommandRootDeleteAuthorityReceipt::DisposableAuthorizationConsumed(
                source.receipt.clone(),
            )
        }
    };
    let command_receipt = CommandDeleteCompletionReceipt {
        command: reloaded.command.clone(),
        root_authority,
        completion: generic,
    };
    let bound =
        authorization
            .as_ref()
            .map(|authorization| CommandBoundDisposableRootAuthorization {
                scope: reloaded.command.scope.clone(),
                authorization: authorization.clone(),
            });
    insert_command_delete_completion_receipt(
        transaction,
        &locked_operation,
        bound.as_ref(),
        &command_receipt,
    )?;
    Ok(true)
}

fn candidate_origin(
    transaction: &mut postgres::Transaction<'_>,
    disk: &DiskRecord,
    volume: &VolumeRecord,
    lock_lifecycle_receipts: bool,
) -> AuthorityTxResult<(
    Option<AuthorizationRecord>,
    Option<LifecycleDeleteEvidence>,
    DeleteCandidateEligibility,
)> {
    let (
        DiskAdminState::Deleting {
            delete_id: disk_delete,
        },
        VolumeAdminState::Deleting {
            delete_id: volume_delete,
        },
    ) = (&disk.admin_state, &volume.admin_state)
    else {
        return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
    };
    if disk.volume_id != volume.volume_id
        || disk.size_bytes != volume.size_bytes
        || disk.durability != volume.durability
        || disk_delete != volume_delete
    {
        return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
    }
    match volume.last_transition.as_ref() {
        Some(LastVolumeTransition::BeginDelete {
            source,
            request,
            result,
        }) if request.delete_id == *volume_delete
            && request.disk_id == disk.disk_id
            && request.volume_id == volume.volume_id
            && result.delete_id == *volume_delete
            && result.disk_id == disk.disk_id
            && result.volume_id == volume.volume_id
            && result.resulting_epoch == volume.lease_epoch
            && result.resulting_head == volume.head =>
        {
            let lifecycle_delete = match (&disk.role, source) {
                (
                    super::product::DiskRole::Persistent { .. },
                    VolumeTransitionSource::Independent,
                ) => None,
                (
                    super::product::DiskRole::Root { .. },
                    VolumeTransitionSource::Lifecycle { .. },
                ) => {
                    let source_kind = load_normal_begin_delete_source_kind(
                        transaction,
                        &volume.volume_id,
                        volume_delete,
                        lock_lifecycle_receipts,
                    )?;
                    load_lifecycle_delete_evidence(
                        transaction,
                        disk,
                        volume,
                        None,
                        source_kind,
                        lock_lifecycle_receipts,
                    )?
                }
                // A Root delete is lifecycle-owned in the atomic release;
                // PersistentDisk administration is deliberately independent.
                // Any crossed source/role pair is an unknown authority graph.
                _ => {
                    return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
                }
            };
            validate_candidate_transition_source(source, lifecycle_delete.as_ref())?;
            Ok((None, lifecycle_delete, DeleteCandidateEligibility::Eligible))
        }
        Some(LastVolumeTransition::BeginDisposableDelete {
            source,
            authorization_id,
        }) => {
            let authorization = load_authorization_unlocked(transaction, authorization_id)?
                .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
            let VolumeAuthorization::DisposableRootDelete(payload) = &authorization.authorization
            else {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            };
            if payload.disk_id != disk.disk_id
                || payload.volume_id != volume.volume_id
                || payload.delete_id != *volume_delete
                || !matches!(
                    &disk.role,
                    super::product::DiskRole::Root { cat_id } if cat_id == &payload.cat_id
                )
            {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            }
            if source
                != &(VolumeTransitionSource::Lifecycle {
                    operation_id: payload.operation_id.clone(),
                    request_fingerprint: payload.request_fingerprint.clone(),
                })
            {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            }
            let AuthorizationState::Consumed(consumed) = &authorization.state else {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            };
            let AuthorizationConsumedReceipt::BeginDisposableDelete(consumed) = consumed.as_ref()
            else {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            };
            // Validate the entire authorization/consumed/direct-state closure
            // before deleting even one object, not only in the final receipt
            // transaction.
            complete_disposable_root_delete(volume, &authorization, consumed.consumed_at)?;
            let eligibility = match payload.isolation_basis {
                DisposableDeleteIsolationBasis::LifecycleStrongStop { .. } => {
                    DeleteCandidateEligibility::Eligible
                }
                // V8 has not frozen/persisted provider_evidence. Do not infer
                // the object-write cutoff/barrier from a plain fence event.
                DisposableDeleteIsolationBasis::HostFenceEvent { .. } => {
                    DeleteCandidateEligibility::MissingProviderEvidence
                }
            };
            let lifecycle_delete = load_lifecycle_delete_evidence(
                transaction,
                disk,
                volume,
                Some(&authorization),
                LifecycleVolumeReceiptKind::DisposableAuthorizationConsumed,
                lock_lifecycle_receipts,
            )?;
            validate_candidate_transition_source(source, lifecycle_delete.as_ref())?;
            Ok((Some(authorization), lifecycle_delete, eligibility))
        }
        _ => Err(cats_storage::authority::AuthorityError::BackendUnknown.into()),
    }
}

fn load_normal_begin_delete_source_kind(
    transaction: &mut postgres::Transaction<'_>,
    volume_id: &Id,
    delete_id: &Id,
    lock: bool,
) -> AuthorityTxResult<LifecycleVolumeReceiptKind> {
    let load = |transaction: &mut postgres::Transaction<'_>, kind| {
        if lock {
            load_delete_lifecycle_volume_receipt_source_for_update(
                transaction,
                volume_id,
                delete_id,
                kind,
            )
        } else {
            load_delete_lifecycle_volume_receipt_source_unlocked(
                transaction,
                volume_id,
                delete_id,
                kind,
            )
        }
    };
    let normal = load(transaction, LifecycleVolumeReceiptKind::NormalRelease)?.is_some();
    let already = load(transaction, LifecycleVolumeReceiptKind::AlreadyUnowned)?.is_some();
    match (normal, already) {
        (true, false) => Ok(LifecycleVolumeReceiptKind::NormalRelease),
        (false, true) => Ok(LifecycleVolumeReceiptKind::AlreadyUnowned),
        _ => Err(cats_storage::authority::AuthorityError::BackendUnknown.into()),
    }
}

fn validate_candidate_transition_source(
    source: &VolumeTransitionSource,
    evidence: Option<&LifecycleDeleteEvidence>,
) -> AuthorityTxResult<()> {
    let expected = match evidence {
        Some(evidence) => VolumeTransitionSource::Lifecycle {
            operation_id: evidence.root_authority.operation().operation_id.clone(),
            request_fingerprint: evidence
                .root_authority
                .operation()
                .request_fingerprint
                .clone(),
        },
        None => VolumeTransitionSource::Independent,
    };
    if source != &expected {
        return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
    }
    Ok(())
}

fn load_lifecycle_delete_evidence(
    transaction: &mut postgres::Transaction<'_>,
    disk: &DiskRecord,
    deleting_root: &VolumeRecord,
    authorization: Option<&AuthorizationRecord>,
    kind: LifecycleVolumeReceiptKind,
    lock: bool,
) -> AuthorityTxResult<Option<LifecycleDeleteEvidence>> {
    let super::product::DiskRole::Root { cat_id } = &disk.role else {
        // Independent PersistentDisk deletion remains the generic Volume
        // Authority path and never manufactures lifecycle Delete evidence.
        return Ok(None);
    };
    let delete_id = candidate_volume_delete_id(deleting_root)?;
    let source = if lock {
        load_delete_lifecycle_volume_receipt_source_for_update(
            transaction,
            &deleting_root.volume_id,
            delete_id,
            kind,
        )?
    } else {
        load_delete_lifecycle_volume_receipt_source_unlocked(
            transaction,
            &deleting_root.volume_id,
            delete_id,
            kind,
        )?
    }
    .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
    let root_authority = match (kind, source) {
        (
            LifecycleVolumeReceiptKind::NormalRelease,
            StoredLifecycleVolumeReceipt::NormalRelease(source),
        ) => LifecycleRootAuthoritySource::Normal(source),
        (
            LifecycleVolumeReceiptKind::AlreadyUnowned,
            StoredLifecycleVolumeReceipt::AlreadyUnowned(source),
        ) => LifecycleRootAuthoritySource::AlreadyUnowned(source),
        (
            LifecycleVolumeReceiptKind::DisposableAuthorizationConsumed,
            StoredLifecycleVolumeReceipt::DisposableAuthorizationConsumed(source),
        ) => LifecycleRootAuthoritySource::Disposable(source),
        _ => return Err(cats_storage::authority::AuthorityError::BackendUnknown.into()),
    };
    let operation = root_authority.operation();
    if operation.cat_id != *cat_id {
        return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
    }
    let LifecycleCommand::Delete(spec) = &operation.command else {
        return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
    };
    if spec.delete_id != *delete_id {
        return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
    }
    if !lock {
        let operation_state = transaction
            .query_one(
                "SELECT state FROM runtime_operations WHERE operation_id=$1",
                &[&operation.operation_id.as_str()],
            )?
            .try_get::<_, String>("state")?;
        if operation_state != "unresolved" {
            return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
        }
    }

    let command = match &root_authority {
        LifecycleRootAuthoritySource::Normal(source) => DeleteCommandVolumeSet {
            scope: source.receipt.durability.scope.clone(),
            root_disposition: DefaultRootDiscardDisposition {
                root: source.receipt.durability.volume.identity(),
                delete_id: delete_id.clone(),
            },
            persistent_volumes: operation
                .runtime_config
                .volumes
                .iter()
                .filter(|volume| {
                    volume.disk_role == cats_api::runtime_lifecycle::DiskRole::Persistent
                })
                .map(|volume| LifecycleVolumeIdentity {
                    disk_id: volume.disk_id.clone(),
                    disk_role: volume.disk_role,
                    volume_id: volume.volume_id.clone(),
                })
                .collect(),
        },
        LifecycleRootAuthoritySource::AlreadyUnowned(source) => DeleteCommandVolumeSet {
            scope: source.receipt.scope.clone(),
            root_disposition: DefaultRootDiscardDisposition {
                root: source.receipt.volume.clone(),
                delete_id: delete_id.clone(),
            },
            persistent_volumes: operation
                .runtime_config
                .volumes
                .iter()
                .filter(|volume| {
                    volume.disk_role == cats_api::runtime_lifecycle::DiskRole::Persistent
                })
                .map(|volume| LifecycleVolumeIdentity {
                    disk_id: volume.disk_id.clone(),
                    disk_role: volume.disk_role,
                    volume_id: volume.volume_id.clone(),
                })
                .collect(),
        },
        LifecycleRootAuthoritySource::Disposable(source) => source.receipt.command.clone(),
    };

    let mut persistent_dispositions = Vec::with_capacity(command.persistent_volumes.len());
    let mut current_persistent_volumes = Vec::with_capacity(command.persistent_volumes.len());
    let mut persistent_receipts = Vec::with_capacity(command.persistent_volumes.len());
    for target in &command.persistent_volumes {
        let normal =
            load_normal_release_source_optional(transaction, operation, &target.volume_id, lock)?;
        let already = if lock {
            load_command_already_unowned_receipt_for_update(
                transaction,
                &operation.operation_id,
                &target.volume_id,
            )?
        } else {
            load_command_already_unowned_receipt_unlocked(
                transaction,
                &operation.operation_id,
                &target.volume_id,
            )?
        };
        if normal.is_some() == already.is_some() {
            return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
        }
        let current = if lock {
            load_volume_for_update(transaction, &target.volume_id)?
        } else {
            load_volume_unlocked(transaction, &target.volume_id)?
        }
        .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
        if let Some(source) = normal {
            if source.delete_id.as_ref() != Some(delete_id)
                || source.receipt.durability.volume.identity() != *target
            {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            }
            let encoded = encode_command_normal_release_receipt(
                &command.scope,
                &source.receipt.durability.volume,
                &current,
                &source.receipt,
            )
            .map_err(|_| cats_storage::authority::AuthorityError::BackendUnknown)?;
            if encoded.receipt_digest != source.receipt_digest {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            }
            persistent_receipts.push(CommandVolumeDispositionReceipt::NormallyReleased {
                receipt: Box::new(source.receipt.clone()),
            });
            persistent_dispositions
                .push(LifecyclePersistentAuthoritySource::Normal(Box::new(source)));
        } else if let Some(source) = already {
            if source.operation != *operation
                || source.delete_id.as_ref() != Some(delete_id)
                || source.receipt.volume != *target
            {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            }
            let encoded = encode_command_delete_already_unowned_receipt(
                &command.scope,
                target,
                &current,
                &source.receipt,
            )
            .map_err(|_| cats_storage::authority::AuthorityError::BackendUnknown)?;
            if encoded.receipt_digest != source.receipt_digest {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            }
            persistent_receipts.push(CommandVolumeDispositionReceipt::AlreadyUnowned {
                receipt: Box::new(source.receipt.clone()),
            });
            persistent_dispositions.push(LifecyclePersistentAuthoritySource::AlreadyUnowned(
                Box::new(source),
            ));
        }
        current_persistent_volumes.push(current);
    }

    let persistent_dispositions_digest = persistent_delete_dispositions_digest(
        &command,
        &current_persistent_volumes,
        &persistent_receipts,
    )
    .map_err(|_| cats_storage::authority::AuthorityError::BackendUnknown)?;

    match (&root_authority, authorization) {
        (LifecycleRootAuthoritySource::Normal(source), None) => {
            let encoded = encode_command_normal_release_receipt_for_deleting_root(
                &command,
                deleting_root,
                &source.receipt,
            )
            .map_err(|_| cats_storage::authority::AuthorityError::BackendUnknown)?;
            if encoded.receipt_digest != source.receipt_digest {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            }
        }
        (LifecycleRootAuthoritySource::AlreadyUnowned(source), None) => {
            let encoded = encode_command_delete_already_unowned_receipt_for_deleting_root(
                &command,
                deleting_root,
                &source.receipt,
            )
            .map_err(|_| cats_storage::authority::AuthorityError::BackendUnknown)?;
            if encoded.receipt_digest != source.receipt_digest {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            }
        }
        (LifecycleRootAuthoritySource::Disposable(source), Some(authorization)) => {
            let VolumeAuthorization::DisposableRootDelete(payload) = &authorization.authorization
            else {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            };
            if payload.persistent_dispositions_digest != persistent_dispositions_digest {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            }
            let bound = CommandBoundDisposableRootAuthorization {
                scope: command.scope.clone(),
                authorization: authorization.clone(),
            };
            let encoded = encode_command_disposable_authorization_consumed_receipt(
                &command,
                deleting_root,
                &bound,
                &source.receipt,
            )
            .map_err(|_| cats_storage::authority::AuthorityError::BackendUnknown)?;
            if encoded.receipt_digest != source.receipt_digest {
                return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
            }
        }
        _ => return Err(cats_storage::authority::AuthorityError::BackendUnknown.into()),
    }
    Ok(Some(LifecycleDeleteEvidence {
        command,
        root_authority,
        persistent_dispositions,
    }))
}

fn load_normal_release_source_optional(
    transaction: &mut postgres::Transaction<'_>,
    operation: &LifecycleCommandEnvelope,
    volume_id: &Id,
    lock: bool,
) -> AuthorityTxResult<Option<StoredCommandNormalReleaseReceipt>> {
    let source = if lock {
        load_command_normal_release_receipt_for_update(
            transaction,
            &operation.operation_id,
            volume_id,
        )?
    } else {
        load_command_normal_release_receipt_unlocked(
            transaction,
            &operation.operation_id,
            volume_id,
        )?
    };
    if source
        .as_ref()
        .is_some_and(|source| source.operation != *operation)
    {
        return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
    }
    Ok(source)
}

fn candidate_volume_delete_id(volume: &VolumeRecord) -> AuthorityTxResult<&Id> {
    match &volume.admin_state {
        VolumeAdminState::Deleting { delete_id } => Ok(delete_id),
        VolumeAdminState::Active => {
            Err(cats_storage::authority::AuthorityError::BackendUnknown.into())
        }
    }
}

fn candidate_delete_id(candidate: &DeleteSweepCandidate) -> &Id {
    match &candidate.volume.admin_state {
        VolumeAdminState::Deleting { delete_id } => delete_id,
        VolumeAdminState::Active => unreachable!("candidate loader accepts only Deleting"),
    }
}

fn authorization_id(record: &AuthorizationRecord) -> AuthorityTxResult<&Id> {
    match &record.authorization {
        VolumeAuthorization::DisposableRootDelete(authorization) => {
            Ok(&authorization.authorization_id)
        }
        VolumeAuthorization::Takeover(_) => {
            Err(cats_storage::authority::AuthorityError::BackendUnknown.into())
        }
    }
}

fn receipt_matches_candidate(
    receipt: &DeleteCompletionReceipt,
    candidate: &DeleteSweepCandidate,
) -> AuthorityTxResult<bool> {
    let expected = match (&candidate.authorization, receipt) {
        (None, DeleteCompletionReceipt::Normal { completed_at, .. }) => {
            complete_normal_delete(&candidate.volume, *completed_at)?
        }
        (Some(authorization), DeleteCompletionReceipt::DisposableRoot { completed_at, .. }) => {
            complete_disposable_root_delete(&candidate.volume, authorization, *completed_at)?
        }
        _ => return Ok(false),
    };
    Ok(expected == *receipt)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    use cats_api::runtime_inventory::{
        full_inventory_digest, ObservedCatRuntimeTelemetry, ObservedCommandJournal,
        ObservedRuntimePhysicalState, ObservedVolumeAttachment, ObservedVolumeWatermark,
        ObservedVolumeWatermarkSummary, RuntimeInventoryAcceptanceKind, RuntimeInventoryBody,
        RuntimeInventoryReport,
    };
    use cats_api::runtime_lifecycle::{
        DeleteSpec, ExecutionAbsenceProof, LifecycleOperation, LifecycleOperationState,
        LifecyclePredecessor, RequestedVolumeDisposition,
    };
    use cats_api::runtime_lifecycle_volume::LifecycleVolumeStrongStopEvidence;
    use cats_api::runtime_reconciliation::{
        AsciiText, ContractVersion, DisposableRootDisposition, Epoch, FenceEpoch, Generation,
        RandomId128, Sequence, Sha256Digest, UnixMillis, WireU64,
    };
    use cats_storage::authority::{
        begin_delete, AuthorizationRecord, AuthorizationState, BeginDeleteRequest,
        DisposableRootDeleteAuthorization, HostFenceEvent, HostFenceEventState, HostIsolationState,
        RemoteHead, VolumeAuthorization, VolumeDurability,
    };
    use cats_storage::lifecycle_volume::{
        begin_delete_disposable_root, CommandNormalReleaseInput, CommandVolumeDurabilityProof,
        DeleteDisposableRootInput, LifecycleVolumeCommandScope, LifecycleVolumeTarget,
    };
    use cats_storage::{BlobError, BlobListPage, QualifiedDeleteListPage};

    use super::super::lifecycle_commands::LifecycleCommandAdmission;
    use super::super::lifecycle_commands_tests::{
        genesis_start, seed_cat, session_binding, settle_genesis_runtime_ready, workspace_id,
    };
    use super::super::lifecycle_volume_transitions::{
        LifecycleVolumeTransition, LifecycleVolumeTransitionApplied,
        LifecycleVolumeTransitionOutcome, LifecycleVolumeTransitionRequest,
        RequestedVolumeDispositionInput,
    };
    use super::super::runtime_spine::RuntimeInventoryOutcome;
    use super::*;
    use crate::store::runtime_authority::product::{
        DiskRole, DiskSnapshotRecord, PersistentDiskInitialization,
    };
    use crate::store::runtime_authority::product_rows::{
        insert_disk, insert_disk_snapshot, load_cat_by_id_for_update, update_disk,
    };
    use crate::store::runtime_authority::rows::{
        insert_authorization, insert_command_disposable_authorization_consumed_receipt,
        insert_event, insert_volume, load_delete_completion_for_update,
        lock_lifecycle_receipt_operation_unresolved, update_authorization, update_volume_owner,
    };

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn head(generation: u64) -> RemoteHead {
        RemoteHead {
            generation: Generation::new(generation).unwrap(),
            root_hash: (generation > 0)
                .then(|| Sha256Digest::new(format!("sha256:{generation:064x}")).unwrap()),
            root_object_id: (generation > 0)
                .then(|| AsciiText::new(format!("roots/{generation}")).unwrap()),
        }
    }

    fn random_id(value: u128) -> RandomId128 {
        RandomId128::new(format!("{value:032x}")).unwrap()
    }

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    fn same_node_delete(
        head: &LifecycleOperation,
        operation_id: &str,
        delete_id: &Id,
    ) -> LifecycleCommandEnvelope {
        let LifecycleOperationState::Terminal {
            terminal,
            terminal_result_digest,
        } = &head.state
        else {
            panic!("Delete fixture requires a terminal RuntimeReady predecessor")
        };
        let root = &head.canonical_request.runtime_config.volumes[0];
        LifecycleCommandEnvelope::new(
            id(operation_id),
            head.workspace_id.clone(),
            head.cat_id.clone(),
            head.node_id.clone(),
            head.placement_identity.clone(),
            head.canonical_request.runtime_config.as_ref().clone(),
            Some(head.operation_id.clone()),
            LifecyclePredecessor::SameNode {
                operation_id: head.operation_id.clone(),
                terminal_result_kind: terminal.kind(),
                terminal_result_digest: terminal_result_digest.clone(),
                node_id: head.node_id.clone(),
                placement_identity: head.placement_identity.clone(),
            },
            LifecycleCommand::Delete(DeleteSpec {
                delete_id: delete_id.clone(),
                grace_deadline_unix_ms: UnixMillis::new(8_000_000_000_000).unwrap(),
                convergence_deadline_unix_ms: UnixMillis::new(8_000_000_060_000).unwrap(),
                volume_dispositions: vec![RequestedVolumeDisposition::DiscardWithCat {
                    volume_id: root.volume_id.clone(),
                    disk_id: root.disk_id.clone(),
                    disk_role: root.disk_role,
                }],
            }),
        )
        .unwrap()
    }

    struct PreparedLifecycleDelete {
        authenticated: cats_api::agent_registration::AuthenticatedNodeCredential,
        session: cats_api::runtime_reconciliation::AgentSession,
        operation: LifecycleCommandEnvelope,
        command: DeleteCommandVolumeSet,
        root_durability: CommandVolumeDurabilityProof,
        strong_stop: LifecycleVolumeStrongStopEvidence,
    }

    fn prepare_lifecycle_delete(
        store: &Store,
        suffix: &str,
        disposable_root_tail: bool,
    ) -> PreparedLifecycleDelete {
        let workspace = workspace_id(store, &format!("delete-sweeper-{suffix}"));
        let node = id(&format!("node-delete-sweeper-{suffix}"));
        let cat = id(&format!("cat-delete-sweeper-{suffix}"));
        let creation = id(&format!("creation-delete-sweeper-{suffix}"));
        let config = seed_cat(store, &workspace, &cat, &creation);
        let start = genesis_start(
            &workspace,
            &node,
            &cat,
            &creation,
            &format!("operation-start-delete-sweeper-{suffix}"),
            &config,
        );
        assert!(matches!(
            store.admit_lifecycle_command(&workspace, &start).unwrap(),
            LifecycleCommandAdmission::Admitted(_)
        ));
        let running = settle_genesis_runtime_ready(store, &node, &start, &config);
        let delete_id = id(&format!("delete-sweeper-{suffix}"));
        let operation = same_node_delete(
            &running.running_head,
            &format!("operation-delete-sweeper-{suffix}"),
            &delete_id,
        );
        assert!(matches!(
            store
                .admit_lifecycle_command(&workspace, &operation)
                .unwrap(),
            LifecycleCommandAdmission::Admitted(_)
        ));

        let scope = LifecycleVolumeCommandScope {
            operation_id: operation.operation_id.clone(),
            request_fingerprint: operation.request_fingerprint.clone(),
            cat_id: operation.cat_id.clone(),
            node_id: operation.node_id.clone(),
            placement_identity: operation.placement_identity.clone(),
        };
        let receipt = &running.volume_receipt;
        let root = LifecycleVolumeTarget {
            disk_id: receipt.disk_id.clone(),
            disk_role: receipt.disk_role,
            volume_id: receipt.volume_id.clone(),
            attachment_id: receipt.attachment_id.clone(),
            attachment_epoch: receipt.attachment_epoch,
        };
        let current = store
            .authority_transaction(|transaction| {
                load_volume_for_update(transaction, &root.volume_id)?
                    .ok_or(cats_storage::authority::AuthorityError::BackendUnknown.into())
            })
            .unwrap();
        let root_durability = CommandVolumeDurabilityProof {
            scope: scope.clone(),
            volume: root.clone(),
            remote_head: current.head.clone(),
            local_durable_generation: if disposable_root_tail {
                Generation::new(current.head.generation.get() + 1).unwrap()
            } else {
                current.head.generation
            },
            remote_durable_generation: current.head.generation,
            pending_pack_count: WireU64::new(u64::from(disposable_root_tail)).unwrap(),
        };
        let command = DeleteCommandVolumeSet {
            scope,
            root_disposition: DefaultRootDiscardDisposition {
                root: root.identity(),
                delete_id,
            },
            persistent_volumes: Vec::new(),
        };

        let mut report = RuntimeInventoryReport {
            version: ContractVersion::V1,
            session: session_binding(&running.session),
            report_id: random_id(210),
            sequence: Sequence::new(1).unwrap(),
            collected_at_unix_ms: store.authority_transaction(database_now).unwrap(),
            inventory: RuntimeInventoryBody::Full {
                inventory_epoch: Epoch::new(1).unwrap(),
                scan_id: random_id(211),
                inventory_digest: digest(0),
                cats: vec![ObservedCatRuntimeTelemetry {
                    cat_id: operation.cat_id.clone(),
                    observed_placement: operation.placement_identity.clone(),
                    observed_command_journal: Some(ObservedCommandJournal::Executing {
                        operation_id: operation.operation_id.clone(),
                        command_kind: operation.command.kind(),
                        request_fingerprint: operation.request_fingerprint.clone(),
                        journal_digest: digest(212),
                    }),
                    observed_physical_state: ObservedRuntimePhysicalState::Absent,
                    observed_runtime_incarnation: None,
                    observed_artifact_manifest_digest: digest(213),
                    observed_artifact_classifications: Vec::new(),
                    observed_volumes: vec![ObservedVolumeWatermarkSummary {
                        volume_id: root.volume_id.clone(),
                        disk_id: root.disk_id.clone(),
                        disk_role: root.disk_role,
                        observed_attachment: ObservedVolumeAttachment::Owned {
                            owner_node_id: operation.node_id.clone(),
                            attachment_id: root.attachment_id.clone(),
                            attachment_epoch: root.attachment_epoch,
                        },
                        observed_watermark: ObservedVolumeWatermark::Known {
                            local_durable_generation: root_durability.local_durable_generation,
                            remote_durable_generation: root_durability.remote_durable_generation,
                        },
                    }],
                    observed_conditions: Vec::new(),
                }],
                unattributed_artifacts: Vec::new(),
            },
        };
        let computed = full_inventory_digest(&report).unwrap();
        let RuntimeInventoryBody::Full {
            inventory_digest, ..
        } = &mut report.inventory
        else {
            unreachable!()
        };
        *inventory_digest = computed;
        let RuntimeInventoryOutcome::Accepted(acceptance) = store
            .runtime_accept_inventory(&running.authenticated, &report)
            .unwrap()
        else {
            panic!("full post-stop inventory was rejected")
        };
        let RuntimeInventoryAcceptanceKind::Full { attestation } = acceptance.inventory else {
            panic!("full post-stop inventory returned a partial acceptance")
        };
        let strong_stop = LifecycleVolumeStrongStopEvidence {
            execution_absence: ExecutionAbsenceProof {
                stop_fence_receipt_digest: digest(214),
                admission_closed_receipt_digest: digest(215),
                dedicated_scope_absence_receipt_digest: digest(216),
                frontend_absence_receipt_digest: digest(217),
                restart_source_absence_receipt_digest: digest(218),
            },
            post_stop_inventory_attestation: *attestation,
        };
        PreparedLifecycleDelete {
            authenticated: running.authenticated,
            session: running.session,
            operation,
            command,
            root_durability,
            strong_stop,
        }
    }

    fn seed_lifecycle_normal_delete(store: &Store, suffix: &str) -> PreparedLifecycleDelete {
        let prepared = prepare_lifecycle_delete(store, suffix, false);
        let request = LifecycleVolumeTransitionRequest {
            session: session_binding(&prepared.session),
            transition: LifecycleVolumeTransition::DeleteNormal {
                command: prepared.command.clone(),
                volumes: vec![RequestedVolumeDispositionInput::OwnedRelease(Box::new(
                    CommandNormalReleaseInput {
                        durability: prepared.root_durability.clone(),
                        transition_id: random_id(219),
                    },
                ))],
                strong_stop: Box::new(prepared.strong_stop.clone()),
            },
        };
        assert!(matches!(
            store
                .apply_lifecycle_volume_transition(&prepared.authenticated, &request)
                .unwrap(),
            LifecycleVolumeTransitionOutcome::Applied(applied)
                if matches!(*applied, LifecycleVolumeTransitionApplied::DeleteNormallyDeleting { .. })
        ));
        prepared
    }

    fn seed_lifecycle_disposable_delete(
        store: &Store,
        suffix: &str,
    ) -> (PreparedLifecycleDelete, Id) {
        let prepared = prepare_lifecycle_delete(store, suffix, true);
        let request = LifecycleVolumeTransitionRequest {
            session: session_binding(&prepared.session),
            transition: LifecycleVolumeTransition::DeleteDisposableRoot {
                command: prepared.command.clone(),
                persistent_volumes: Vec::new(),
                root_durability: Box::new(prepared.root_durability.clone()),
                strong_stop: Box::new(prepared.strong_stop.clone()),
            },
        };
        let outcome = store
            .apply_lifecycle_volume_transition(&prepared.authenticated, &request)
            .unwrap();
        let LifecycleVolumeTransitionOutcome::Applied(applied) = outcome else {
            panic!("lifecycle disposable Root delete was rejected: {outcome:?}")
        };
        let LifecycleVolumeTransitionApplied::DeleteDisposableRootDeleting {
            authorization_id, ..
        } = *applied
        else {
            panic!("lifecycle disposable Root delete returned the wrong outcome")
        };
        (prepared, authorization_id)
    }

    fn seed_lifecycle_host_fence_delete(store: &Store, suffix: &str) -> PreparedLifecycleDelete {
        let prepared = prepare_lifecycle_delete(store, suffix, true);
        store
            .authority_transaction(|transaction| {
                load_cat_by_id_for_update(transaction, &prepared.operation.cat_id)?
                    .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
                let operation = lock_lifecycle_receipt_operation_unresolved(
                    transaction,
                    &prepared.operation.operation_id,
                )?;
                if operation != prepared.operation {
                    return Err(cats_storage::authority::AuthorityError::BackendUnknown.into());
                }
                let current = load_volume_for_update(
                    transaction,
                    &prepared.command.root_disposition.root.volume_id,
                )?
                .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
                let mut disk = load_any_disk_by_id_for_update(
                    transaction,
                    &prepared.command.root_disposition.root.disk_id,
                )?
                .ok_or(cats_storage::authority::AuthorityError::BackendUnknown)?;
                let now = database_now(transaction)?;
                let event = HostFenceEvent {
                    event_id: id(&format!("fence-event-delete-sweeper-{suffix}")),
                    provider: id("test-provider"),
                    immutable_host_id: prepared.session.immutable_host_id.clone(),
                    node_id: prepared.operation.node_id.clone(),
                    expected_node_boot_id: prepared.session.node_boot_id.clone(),
                    expected_agent_session_epoch: prepared.session.agent_session_epoch,
                    fence_attempt_id: id(&format!("fence-attempt-delete-sweeper-{suffix}")),
                    isolation_state: HostIsolationState::Isolated,
                    observed_at: now,
                    state: HostFenceEventState::Active,
                };
                let persistent_dispositions_digest =
                    persistent_delete_dispositions_digest(&prepared.command, &[], &[])
                        .map_err(|_| cats_storage::authority::AuthorityError::BackendUnknown)?;
                let authorization = AuthorizationRecord {
                    authorization: VolumeAuthorization::DisposableRootDelete(
                        DisposableRootDeleteAuthorization {
                            authorization_id: id(&format!("authorization-delete-sweeper-{suffix}")),
                            operation_id: prepared.operation.operation_id.clone(),
                            request_fingerprint: prepared.operation.request_fingerprint.clone(),
                            authorized_node_id: prepared.operation.node_id.clone(),
                            delete_id: prepared.command.root_disposition.delete_id.clone(),
                            disk_id: prepared.command.root_disposition.root.disk_id.clone(),
                            volume_id: prepared.command.root_disposition.root.volume_id.clone(),
                            cat_id: prepared.operation.cat_id.clone(),
                            placement_epoch: prepared.operation.placement_identity.placement_epoch,
                            expected_attachment_id: prepared
                                .root_durability
                                .volume
                                .attachment_id
                                .clone(),
                            expected_epoch: prepared.root_durability.volume.attachment_epoch,
                            expected_head: prepared.root_durability.remote_head.clone(),
                            disposition: DisposableRootDisposition::DiscardWithCat,
                            persistent_dispositions_digest,
                            isolation_basis: DisposableDeleteIsolationBasis::HostFenceEvent {
                                event_id: event.event_id.clone(),
                                interrupted_operation_id: prepared
                                    .operation
                                    .expected_predecessor_operation_id
                                    .clone()
                                    .ok_or(
                                        cats_storage::authority::AuthorityError::BackendUnknown,
                                    )?,
                                host_lost_result_digest: digest(220),
                            },
                            not_after: UnixMillis::new(8_000_000_060_000).unwrap(),
                        },
                    ),
                    state: AuthorizationState::Unconsumed,
                };
                let bound = CommandBoundDisposableRootAuthorization {
                    scope: prepared.command.scope.clone(),
                    authorization: authorization.clone(),
                };
                let outcome = begin_delete_disposable_root(
                    &[],
                    &current,
                    Some(&event),
                    &DeleteDisposableRootInput {
                        command: prepared.command.clone(),
                        persistent_volumes: Vec::new(),
                        root_durability: prepared.root_durability.clone(),
                        root_authorization: bound,
                    },
                    now,
                )
                .map_err(|_| cats_storage::authority::AuthorityError::BackendUnknown)?;

                insert_event(transaction, &event)?;
                insert_authorization(transaction, &authorization)?;
                update_volume_owner(transaction, &outcome.root_volume, None)?;
                update_authorization(
                    transaction,
                    &authorization,
                    &outcome.root_authorization.authorization,
                )?;
                disk.admin_state = DiskAdminState::Deleting {
                    delete_id: prepared.command.root_disposition.delete_id.clone(),
                };
                update_disk(transaction, &disk)?;
                insert_command_disposable_authorization_consumed_receipt(
                    transaction,
                    &operation,
                    &outcome.root_volume,
                    &outcome.root_authorization,
                    &outcome.receipt.root_begin,
                )?;
                Ok(())
            })
            .unwrap();
        prepared
    }

    fn seed_normal_delete(store: &Store) -> DeleteCompletionReceipt {
        store
            .with(|client| {
                client.batch_execute(
                    "INSERT INTO accounts (
                        id, slug, display_name, kind, workos_organization_id,
                        billing_account_id, personal_owner_user_id, status, created_at
                     ) VALUES (
                        'account-delete-test', 'delete-test', 'Delete Test', 'organization',
                        'org-delete-test', 'billing-delete-test', NULL, 'active', 1
                     );
                     INSERT INTO workspaces (
                        id, account_id, slug, display_name, is_default, created_at
                     ) VALUES (
                        'workspace-delete-test', 'account-delete-test', 'default',
                        'Default', TRUE, 1
                     );",
                )
            })
            .unwrap();
        let volume = VolumeRecord {
            volume_id: id("vol_delete_test"),
            size_bytes: 4 * 1024 * 1024,
            durability: VolumeDurability::Strict,
            admin_state: VolumeAdminState::Active,
            head: head(3),
            lease_owner: None,
            lease_epoch: FenceEpoch::new(7).unwrap(),
            lease_expires_at: None,
            last_transition: None,
        };
        let request = BeginDeleteRequest {
            delete_id: id("delete_test"),
            disk_id: id("disk_delete_test"),
            volume_id: volume.volume_id.clone(),
            expected_unowned_epoch: volume.lease_epoch,
            expected_head: volume.head.clone(),
        };
        let (deleting, result) = begin_delete(&volume, &request).unwrap();
        let disk = DiskRecord {
            disk_id: request.disk_id.clone(),
            workspace_id: id("workspace-delete-test"),
            name: id("persistent-delete-test"),
            volume_id: request.volume_id.clone(),
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            created_at: UnixMillis::new(1).unwrap(),
            admin_state: DiskAdminState::Deleting {
                delete_id: request.delete_id.clone(),
            },
            role: DiskRole::Persistent {
                initialization: Box::new(PersistentDiskInitialization::Uninitialized {
                    initialization_token: RandomId128::new("11111111111111111111111111111111")
                        .unwrap(),
                    filesystem_uuid: RandomId128::new("22222222222222222222222222222222").unwrap(),
                    expected_blank_head: head(0),
                }),
            },
        };
        store
            .authority_transaction(|transaction| {
                insert_volume(transaction, &deleting)?;
                insert_disk(transaction, &disk)
            })
            .unwrap();
        DeleteCompletionReceipt::Normal {
            request,
            deleting_epoch: result.resulting_epoch,
            deleting_head: result.resulting_head,
            completed_at: UnixMillis::new(1).unwrap(),
        }
    }

    #[derive(Default)]
    struct MemoryBlob {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl MemoryBlob {
        fn with_keys(keys: &[&str]) -> Self {
            Self {
                objects: Mutex::new(
                    keys.iter()
                        .map(|key| ((*key).to_string(), Vec::new()))
                        .collect(),
                ),
            }
        }
    }

    impl BlobStore for MemoryBlob {
        fn put_immutable(&self, key: &str, data: &[u8]) -> cats_storage::blob::Result<()> {
            self.objects
                .lock()
                .unwrap()
                .insert(key.to_string(), data.to_vec());
            Ok(())
        }

        fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
            self.objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| BlobError::NotFound(key.to_string()))
        }

        fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
            Ok(self.objects.lock().unwrap().contains_key(key))
        }

        fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
            self.objects.lock().unwrap().remove(key);
            Ok(())
        }

        fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect())
        }

        fn list_bounded(
            &self,
            prefix: &str,
            maximum: usize,
        ) -> cats_storage::blob::Result<BlobListPage> {
            let mut keys = self.list(prefix)?;
            let is_truncated = keys.len() > maximum;
            keys.truncate(maximum);
            Ok(BlobListPage { keys, is_truncated })
        }

        fn list_for_delete_bounded_until(
            &self,
            prefix: &str,
            maximum: usize,
            deadline: Instant,
        ) -> cats_storage::blob::Result<QualifiedDeleteListPage> {
            if Instant::now() >= deadline {
                return Err(BlobError::Backend {
                    key: prefix.to_string(),
                    message: "test destructive LIST deadline elapsed".into(),
                });
            }
            self.list_bounded(prefix, maximum)
                .map(QualifiedDeleteListPage::from_strongly_consistent_adapter)
        }
    }

    fn stored_receipt_for(store: &Store, delete_id: &Id) -> DeleteCompletionReceipt {
        store
            .authority_transaction(|transaction| {
                Ok(load_delete_completion_for_update(transaction, delete_id)?.unwrap())
            })
            .unwrap()
    }

    fn stored_receipt(store: &Store) -> DeleteCompletionReceipt {
        stored_receipt_for(store, &id("delete_test"))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bounded_restart_pass_deletes_only_exact_prefix_then_commits_exact_receipt() {
        let store = Arc::new(
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap(),
        );
        let expected = seed_normal_delete(&store);
        let blob = Arc::new(MemoryBlob::with_keys(&[
            "volumes/vol_delete_test/data/a",
            "volumes/vol_delete_test/maps/b",
            "volumes/vol_delete_test/commits/c",
            "volumes/vol_delete_test_peer/data/keep",
            "images/shared/data/keep",
        ]));
        let sweeper = DeleteSweeper::new(store.clone(), blob.clone());
        let budget = DeleteSweepBudget::new(1, 2).unwrap();

        let first = sweeper
            .run_once(budget, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(first.objects_deleted, 2);
        assert_eq!(first.completions_committed, 0);

        // A fresh process has no cursor/job state and resumes from the PG
        // Deleting row plus the exact prefix.
        let restarted = DeleteSweeper::new(store.clone(), blob.clone());
        let second = restarted
            .run_once(budget, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(second.objects_deleted, 1);
        assert_eq!(second.completions_committed, 1);
        assert!(blob
            .exists("volumes/vol_delete_test_peer/data/keep")
            .unwrap());
        assert!(blob.exists("images/shared/data/keep").unwrap());

        let actual = stored_receipt(&store);
        match (actual, expected) {
            (
                DeleteCompletionReceipt::Normal {
                    request: actual_request,
                    deleting_epoch: actual_epoch,
                    deleting_head: actual_head,
                    completed_at,
                },
                DeleteCompletionReceipt::Normal {
                    request: expected_request,
                    deleting_epoch: expected_epoch,
                    deleting_head: expected_head,
                    ..
                },
            ) => {
                assert_eq!(actual_request, expected_request);
                assert_eq!(actual_epoch, expected_epoch);
                assert_eq!(actual_head, expected_head);
                assert!(completed_at.get() > 0);
            }
            _ => panic!("normal delete produced a disposable receipt"),
        }
        store
            .authority_transaction(|transaction| {
                assert!(load_volume_for_update(transaction, &id("vol_delete_test"))?.is_none());
                assert!(
                    load_any_disk_by_id_for_update(transaction, &id("disk_delete_test"))?.is_none()
                );
                Ok(())
            })
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_stopped_disposable_root_commits_exact_receipt() {
        let store = Arc::new(
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap(),
        );
        let (prepared, expected_authorization) =
            seed_lifecycle_disposable_delete(&store, "disposable");
        let sweeper = DeleteSweeper::new(store.clone(), Arc::new(MemoryBlob::default()));

        let pass = sweeper
            .run_once(
                DeleteSweepBudget::new(1, 1).unwrap(),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();

        assert_eq!(pass.completions_committed, 1);
        let actual = stored_receipt_for(&store, &prepared.command.root_disposition.delete_id);
        match actual {
            DeleteCompletionReceipt::DisposableRoot {
                authorization_id,
                delete_id,
                volume_id,
                disk_id,
                deleting_head,
                ..
            } => {
                assert_eq!(authorization_id, expected_authorization);
                assert_eq!(delete_id, prepared.command.root_disposition.delete_id);
                assert_eq!(volume_id, prepared.command.root_disposition.root.volume_id);
                assert_eq!(disk_id, prepared.command.root_disposition.root.disk_id);
                assert_eq!(deleting_head, prepared.root_durability.remote_head);
            }
            _ => panic!("disposable delete produced a normal receipt"),
        }
        store
            .authority_transaction(|transaction| {
                assert!(load_volume_for_update(
                    transaction,
                    &prepared.command.root_disposition.root.volume_id
                )?
                .is_none());
                assert!(load_any_disk_by_id_for_update(
                    transaction,
                    &prepared.command.root_disposition.root.disk_id
                )?
                .is_none());
                Ok(())
            })
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn live_snapshot_prevents_any_object_delete_and_keeps_metadata() {
        let store = Arc::new(
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap(),
        );
        seed_normal_delete(&store);
        store
            .authority_transaction(|transaction| {
                insert_disk_snapshot(
                    transaction,
                    &DiskSnapshotRecord {
                        snapshot_id: id("snapshot_pre_delete_test"),
                        disk_id: id("disk_delete_test"),
                        volume_id: id("vol_delete_test"),
                        size_bytes: 4 * 1024 * 1024,
                        head: head(3),
                        created_at: UnixMillis::new(2).unwrap(),
                    },
                )
            })
            .unwrap();
        let blob = Arc::new(MemoryBlob::with_keys(&[
            "volumes/vol_delete_test/data/snapshot-live",
        ]));
        let sweeper = DeleteSweeper::new(store.clone(), blob.clone());

        let pass = sweeper
            .run_once(
                DeleteSweepBudget::new(1, 1).unwrap(),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();

        assert_eq!(pass.candidates_examined, 0);
        assert!(blob
            .exists("volumes/vol_delete_test/data/snapshot-live")
            .unwrap());
        store
            .authority_transaction(|transaction| {
                assert!(load_volume_for_update(transaction, &id("vol_delete_test"))?.is_some());
                assert!(
                    load_any_disk_by_id_for_update(transaction, &id("disk_delete_test"))?.is_some()
                );
                Ok(())
            })
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn normal_root_delete_is_a_closed_eligible_candidate() {
        let store = Arc::new(
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap(),
        );
        let prepared = seed_lifecycle_normal_delete(&store, "normal-root");
        let sweeper = DeleteSweeper::new(store.clone(), Arc::new(MemoryBlob::default()));

        let pass = sweeper
            .run_once(
                DeleteSweepBudget::new(1, 1).unwrap(),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();

        assert_eq!(pass.completions_committed, 1);
        assert!(matches!(
            stored_receipt_for(&store, &prepared.command.root_disposition.delete_id),
            DeleteCompletionReceipt::Normal { .. }
        ));
        let discovered = store
            .apply_lifecycle_volume_transition(
                &prepared.authenticated,
                &LifecycleVolumeTransitionRequest {
                    session: session_binding(&prepared.session),
                    transition: LifecycleVolumeTransition::DiscoverDeleteCompletion {
                        command: prepared.command.clone(),
                    },
                },
            )
            .unwrap();
        assert!(matches!(
            discovered,
            LifecycleVolumeTransitionOutcome::Applied(applied)
                if matches!(
                    *applied,
                    LifecycleVolumeTransitionApplied::DeleteCompleted { ref receipt, .. }
                        if receipt.command == prepared.command
                )
        ));
        store
            .authority_transaction(|transaction| {
                assert!(load_volume_for_update(
                    transaction,
                    &prepared.command.root_disposition.root.volume_id
                )?
                .is_none());
                assert!(load_any_disk_by_id_for_update(
                    transaction,
                    &prepared.command.root_disposition.root.disk_id
                )?
                .is_none());
                Ok(())
            })
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn host_fence_disposable_root_without_v8_provider_evidence_is_blocked() {
        let store = Arc::new(
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap(),
        );
        let prepared = seed_lifecycle_host_fence_delete(&store, "host-fence");
        let tail_key = format!(
            "volumes/{}/data/unique-local-tail",
            prepared.command.root_disposition.root.volume_id
        );
        let blob = Arc::new(MemoryBlob::with_keys(&[&tail_key]));
        let sweeper = DeleteSweeper::new(store.clone(), blob.clone());

        let pass = sweeper
            .run_once(
                DeleteSweepBudget::new(1, 1).unwrap(),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();

        assert_eq!(pass.blocked_missing_provider_evidence, 1);
        assert_eq!(pass.objects_deleted, 0);
        assert_eq!(pass.completions_committed, 0);
        assert!(blob.exists(&tail_key).unwrap());
        store
            .authority_transaction(|transaction| {
                assert!(load_volume_for_update(
                    transaction,
                    &prepared.command.root_disposition.root.volume_id
                )?
                .is_some());
                assert!(load_any_disk_by_id_for_update(
                    transaction,
                    &prepared.command.root_disposition.root.disk_id
                )?
                .is_some());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn completion_commit_response_loss_is_discovered_from_exact_receipt() {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        let prepared = seed_lifecycle_normal_delete(&store, "response-loss");
        let candidate = store.load_delete_candidates(None, 1).unwrap().remove(0);
        store.inject_committed_response_loss_once();
        let error = store
            .complete_delete(EmptyVolumePrefix {
                candidate: candidate.clone(),
            })
            .unwrap_err();
        assert_eq!(error.code, cats_api::error::ErrorCode::Unavailable);
        assert!(matches!(
            stored_receipt_for(&store, &prepared.command.root_disposition.delete_id),
            DeleteCompletionReceipt::Normal { .. }
        ));
        assert!(!store
            .complete_delete(EmptyVolumePrefix { candidate })
            .unwrap());
    }

    #[test]
    fn completion_relocks_snapshots_and_keeps_both_deleting_rows() {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        seed_lifecycle_normal_delete(&store, "snapshot-race");
        let candidate = store.load_delete_candidates(None, 1).unwrap().remove(0);
        store
            .authority_transaction(|transaction| {
                insert_disk_snapshot(
                    transaction,
                    &DiskSnapshotRecord {
                        snapshot_id: id("snapshot_delete_test"),
                        disk_id: candidate.disk.disk_id.clone(),
                        volume_id: candidate.volume.volume_id.clone(),
                        size_bytes: candidate.disk.size_bytes,
                        head: candidate.volume.head.clone(),
                        created_at: UnixMillis::new(2).unwrap(),
                    },
                )
            })
            .unwrap();
        let error = store
            .complete_delete(EmptyVolumePrefix {
                candidate: candidate.clone(),
            })
            .unwrap_err();
        assert_eq!(error.code, cats_api::error::ErrorCode::Conflict);
        store
            .authority_transaction(|transaction| {
                assert_eq!(
                    load_volume_for_update(transaction, &candidate.volume.volume_id)?.unwrap(),
                    candidate.volume
                );
                assert_eq!(
                    load_any_disk_by_id_for_update(transaction, &candidate.disk.disk_id)?.unwrap(),
                    candidate.disk
                );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn concurrent_completion_has_one_commit_and_one_exact_replay() {
        let url = crate::testsupport::isolated_control_store_url();
        let seed = Store::connect(&url, None).unwrap();
        let prepared = seed_lifecycle_normal_delete(&seed, "concurrent");
        let first_candidate = seed.load_delete_candidates(None, 1).unwrap().remove(0);
        let second_candidate = first_candidate.clone();
        let first = Store::connect(&url, None).unwrap();
        let second = Store::connect(&url, None).unwrap();
        let (start_tx, start_rx) = mpsc::channel();
        let start = Arc::new(std::sync::Barrier::new(3));
        for (store, candidate) in [(first, first_candidate), (second, second_candidate)] {
            let start = Arc::clone(&start);
            let done = start_tx.clone();
            std::thread::spawn(move || {
                start.wait();
                done.send(store.complete_delete(EmptyVolumePrefix { candidate }))
                    .unwrap();
            });
        }
        start.wait();
        let outcomes = [
            start_rx.recv().unwrap().unwrap(),
            start_rx.recv().unwrap().unwrap(),
        ];
        assert_eq!(
            outcomes.into_iter().filter(|committed| *committed).count(),
            1
        );
        assert!(matches!(
            stored_receipt_for(&seed, &prepared.command.root_disposition.delete_id),
            DeleteCompletionReceipt::Normal { .. }
        ));
    }

    struct BlockingDeleteBlob {
        inner: MemoryBlob,
        entered: Mutex<Option<mpsc::Sender<()>>>,
        release: Mutex<mpsc::Receiver<()>>,
        delete_finished: AtomicBool,
    }

    impl BlobStore for BlockingDeleteBlob {
        fn put_immutable(&self, key: &str, data: &[u8]) -> cats_storage::blob::Result<()> {
            self.inner.put_immutable(key, data)
        }

        fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
            self.inner.get(key)
        }

        fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
            self.inner.exists(key)
        }

        fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
            if let Some(entered) = self.entered.lock().unwrap().take() {
                entered.send(()).unwrap();
            }
            self.release.lock().unwrap().recv().unwrap();
            self.inner.delete(key)?;
            self.delete_finished.store(true, Ordering::Release);
            Ok(())
        }

        fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
            self.inner.list(prefix)
        }

        fn list_bounded(
            &self,
            prefix: &str,
            maximum: usize,
        ) -> cats_storage::blob::Result<BlobListPage> {
            self.inner.list_bounded(prefix, maximum)
        }

        fn list_for_delete_bounded_until(
            &self,
            prefix: &str,
            maximum: usize,
            deadline: Instant,
        ) -> cats_storage::blob::Result<QualifiedDeleteListPage> {
            self.inner
                .list_for_delete_bounded_until(prefix, maximum, deadline)
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_role_finishes_dispatched_delete_discovery_and_restart_completes() {
        let store = Arc::new(
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap(),
        );
        seed_normal_delete(&store);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let blob = Arc::new(BlockingDeleteBlob {
            inner: MemoryBlob::with_keys(&["volumes/vol_delete_test/data/a"]),
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(release_rx),
            delete_finished: AtomicBool::new(false),
        });
        let sweeper = Arc::new(DeleteSweeper::new(store.clone(), blob.clone()));
        let running = {
            let sweeper = sweeper.clone();
            tokio::spawn(async move {
                sweeper
                    .run_once(
                        DeleteSweepBudget::new(1, 1).unwrap(),
                        Instant::now() + Duration::from_secs(5),
                    )
                    .await
            })
        };
        entered_rx
            .recv_timeout(cats_test_support::poll_bound())
            .unwrap();
        running.abort();
        release_tx.send(()).unwrap();
        let finish_deadline = Instant::now() + cats_test_support::poll_bound();
        while !blob.delete_finished.load(Ordering::Acquire) && Instant::now() < finish_deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(blob.delete_finished.load(Ordering::Acquire));
        assert!(blob.list("volumes/vol_delete_test/").unwrap().is_empty());

        let restarted = DeleteSweeper::new(store.clone(), blob);
        let pass = restarted
            .run_once(
                DeleteSweepBudget::new(1, 1).unwrap(),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(pass.completions_committed, 1);
        let _ = stored_receipt(&store);
    }
}
