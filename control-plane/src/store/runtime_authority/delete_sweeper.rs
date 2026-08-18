//! Level-triggered `Deleting -> Removed` reconciliation.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{anyhow, Context};
use cats_api::runtime_reconciliation::Id;
use cats_storage::authority::{
    complete_disposable_root_delete, complete_normal_delete, AuthorizationConsumedReceipt,
    AuthorizationRecord, AuthorizationState, DeleteCompletionReceipt,
    DisposableDeleteIsolationBasis, LastVolumeTransition, VolumeAdminState, VolumeAuthorization,
    VolumeRecord,
};
use cats_storage::{delete_volume_objects_page, BlobStore, DeletePrefixPage};

use super::product::{DiskAdminState, DiskRecord};
use super::product_rows::{
    delete_disk, load_any_disk_by_id_for_update, load_any_disk_snapshot_for_update,
    load_any_disk_snapshot_unlocked, load_disk_by_volume_unlocked,
};
use super::rows::{
    database_now, delete_volume, insert_delete_completion, load_authorization_for_update,
    load_authorization_unlocked, load_delete_completion_for_update, load_volume_for_update,
    load_volume_unlocked,
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
    eligibility: DeleteCandidateEligibility,
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
                let (authorization, eligibility) = candidate_origin(transaction, &disk, &volume)?;
                candidates.push(DeleteSweepCandidate {
                    disk,
                    volume,
                    authorization,
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

fn candidate_origin(
    transaction: &mut postgres::Transaction<'_>,
    disk: &DiskRecord,
    volume: &VolumeRecord,
) -> AuthorityTxResult<(Option<AuthorizationRecord>, DeleteCandidateEligibility)> {
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
        Some(LastVolumeTransition::BeginDelete { request, result })
            if request.delete_id == *volume_delete
                && request.disk_id == disk.disk_id
                && request.volume_id == volume.volume_id
                && result.delete_id == *volume_delete
                && result.disk_id == disk.disk_id
                && result.volume_id == volume.volume_id
                && result.resulting_epoch == volume.lease_epoch
                && result.resulting_head == volume.head =>
        {
            Ok((None, DeleteCandidateEligibility::Eligible))
        }
        Some(LastVolumeTransition::BeginDisposableDelete { authorization_id }) => {
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
                DisposableDeleteIsolationBasis::RuntimeStopped { .. } => {
                    DeleteCandidateEligibility::Eligible
                }
                // V8 has not frozen/persisted provider_evidence. Do not infer
                // the object-write cutoff/barrier from a plain fence event.
                DisposableDeleteIsolationBasis::HostFenceEvent { .. } => {
                    DeleteCandidateEligibility::MissingProviderEvidence
                }
            };
            Ok((Some(authorization), eligibility))
        }
        _ => Err(cats_storage::authority::AuthorityError::BackendUnknown.into()),
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

    use cats_api::runtime_reconciliation::{
        AsciiText, Epoch, FenceEpoch, Generation, NodeBootId, RandomId128, Revision, Sha256Digest,
        UnixMillis,
    };
    use cats_storage::authority::{
        begin_delete, consume_disposable_root_delete, normal_acquire, AuthorizationRecord,
        AuthorizationState, BeginDeleteRequest, DisposableRootDeleteAuthorization, HostFenceEvent,
        HostFenceEventState, HostIsolationState, NormalAcquireRequest, RemoteHead,
        VolumeAuthorization, VolumeDurability, VolumeOwnerBinding,
    };
    use cats_storage::{BlobError, BlobListPage, QualifiedDeleteListPage};

    use super::*;
    use crate::store::runtime_authority::product::{
        CatRecord, DiskRole, DiskSnapshotRecord, PersistentDiskInitialization,
    };
    use crate::store::runtime_authority::product_rows::{
        insert_cat, insert_disk, insert_disk_snapshot, update_disk,
    };
    use crate::store::runtime_authority::rows::{
        insert_authorization, insert_event, insert_volume, load_delete_completion_for_update,
        update_authorization, update_volume_owner,
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

    fn seed_disposable_delete(
        store: &Store,
        isolation_basis: DisposableDeleteIsolationBasis,
        event: Option<HostFenceEvent>,
    ) -> DeleteCompletionReceipt {
        store
            .with(|client| {
                client.batch_execute(
                    "INSERT INTO accounts (
                        id, slug, display_name, kind, workos_organization_id,
                        billing_account_id, personal_owner_user_id, status, created_at
                     ) VALUES (
                        'account-disposable-test', 'disposable-test', 'Disposable Test',
                        'organization', 'org-disposable-test', 'billing-disposable-test',
                        NULL, 'active', 1
                     );
                     INSERT INTO workspaces (
                        id, account_id, slug, display_name, is_default, created_at
                     ) VALUES (
                        'workspace-disposable-test', 'account-disposable-test', 'default',
                        'Default', TRUE, 1
                     );",
                )
            })
            .unwrap();
        let base = VolumeRecord {
            volume_id: id("vol_disposable_test"),
            size_bytes: 4 * 1024 * 1024,
            durability: VolumeDurability::Strict,
            admin_state: VolumeAdminState::Active,
            head: head(3),
            lease_owner: None,
            lease_epoch: FenceEpoch::new(7).unwrap(),
            lease_expires_at: None,
            last_transition: None,
        };
        let authorized_node_id = match &isolation_basis {
            DisposableDeleteIsolationBasis::RuntimeStopped { node_id, .. } => node_id.clone(),
            DisposableDeleteIsolationBasis::HostFenceEvent { .. } => {
                event.as_ref().unwrap().node_id.clone()
            }
        };
        let attachment_id = id("attachment-disposable-test");
        let (owned, _) = normal_acquire(
            &base,
            &NormalAcquireRequest {
                volume_id: base.volume_id.clone(),
                transition_id: random_id(1),
                attachment_id: attachment_id.clone(),
                expected_unowned_epoch: base.lease_epoch,
                desired_revision: Revision::new(12).unwrap(),
                placement_epoch: Epoch::new(4).unwrap(),
                lease_duration_ms: 30_000,
            },
            UnixMillis::new(10_000).unwrap(),
        )
        .unwrap();
        let authorization = AuthorizationRecord {
            authorization: VolumeAuthorization::DisposableRootDelete(
                DisposableRootDeleteAuthorization {
                    authorization_id: id("delete_auth_disposable_test"),
                    authorized_node_id: authorized_node_id.clone(),
                    delete_id: id("delete_disposable_test"),
                    disk_id: id("disk_disposable_test"),
                    volume_id: owned.volume_id.clone(),
                    cat_id: id("cat_disposable_test"),
                    desired_revision: Revision::new(12).unwrap(),
                    placement_epoch: Epoch::new(4).unwrap(),
                    expected_attachment_id: attachment_id.clone(),
                    expected_epoch: owned.lease_epoch,
                    expected_head: owned.head.clone(),
                    isolation_basis,
                    not_after: UnixMillis::new(50_000).unwrap(),
                },
            ),
            state: AuthorizationState::Unconsumed,
        };
        let (deleting, consumed, _) = consume_disposable_root_delete(
            &owned,
            event.as_ref(),
            &authorization,
            &id("delete_auth_disposable_test"),
            UnixMillis::new(20_000).unwrap(),
        )
        .unwrap();
        let active_disk = DiskRecord {
            disk_id: id("disk_disposable_test"),
            workspace_id: id("workspace-disposable-test"),
            name: id("disk_disposable_test"),
            volume_id: base.volume_id.clone(),
            size_bytes: base.size_bytes,
            durability: base.durability,
            created_at: UnixMillis::new(1).unwrap(),
            admin_state: DiskAdminState::Active,
            role: DiskRole::Root {
                cat_id: id("cat_disposable_test"),
            },
        };
        let mut deleting_disk = active_disk.clone();
        deleting_disk.admin_state = DiskAdminState::Deleting {
            delete_id: id("delete_disposable_test"),
        };
        store
            .authority_transaction(|transaction| {
                insert_volume(transaction, &base)?;
                update_volume_owner(
                    transaction,
                    &owned,
                    Some(&VolumeOwnerBinding {
                        volume_id: base.volume_id.clone(),
                        owner_node_id: authorized_node_id.clone(),
                        attachment_id: attachment_id.clone(),
                        attachment_epoch: owned.lease_epoch,
                    }),
                )?;
                insert_cat(
                    transaction,
                    &CatRecord {
                        cat_id: id("cat_disposable_test"),
                        workspace_id: id("workspace-disposable-test"),
                        name: id("cat_disposable_test"),
                        created_at: UnixMillis::new(1).unwrap(),
                    },
                )?;
                insert_disk(transaction, &active_disk)?;
                if let Some(event) = event.as_ref() {
                    insert_event(transaction, event)?;
                }
                insert_authorization(transaction, &authorization)?;
                update_volume_owner(transaction, &deleting, None)?;
                update_authorization(transaction, &authorization, &consumed)?;
                update_disk(transaction, &deleting_disk)
            })
            .unwrap();
        complete_disposable_root_delete(&deleting, &consumed, UnixMillis::new(21_000).unwrap())
            .unwrap()
    }

    fn host_fence_event() -> HostFenceEvent {
        HostFenceEvent {
            event_id: id("fence_event_disposable_test"),
            provider: id("provider_test"),
            immutable_host_id: id("host_test"),
            node_id: id("node_disposable_test"),
            expected_node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
            expected_agent_session_epoch: Epoch::new(8).unwrap(),
            fence_attempt_id: id("fence_attempt_disposable_test"),
            isolation_state: HostIsolationState::Isolated,
            observed_at: UnixMillis::new(12_000).unwrap(),
            state: HostFenceEventState::Active,
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
        let expected = seed_disposable_delete(
            &store,
            DisposableDeleteIsolationBasis::RuntimeStopped {
                node_id: id("node_disposable_test"),
                agent_session_epoch: Epoch::new(8).unwrap(),
                runtime_incarnation: random_id(2),
                observation_id: random_id(3),
            },
            None,
        );
        let sweeper = DeleteSweeper::new(store.clone(), Arc::new(MemoryBlob::default()));

        let pass = sweeper
            .run_once(
                DeleteSweepBudget::new(1, 1).unwrap(),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();

        assert_eq!(pass.completions_committed, 1);
        let actual = stored_receipt_for(&store, &id("delete_disposable_test"));
        match (actual, expected) {
            (
                DeleteCompletionReceipt::DisposableRoot {
                    authorization_id: actual_authorization,
                    delete_id: actual_delete,
                    volume_id: actual_volume,
                    disk_id: actual_disk,
                    deleting_epoch: actual_epoch,
                    deleting_head: actual_head,
                    ..
                },
                DeleteCompletionReceipt::DisposableRoot {
                    authorization_id: expected_authorization,
                    delete_id: expected_delete,
                    volume_id: expected_volume,
                    disk_id: expected_disk,
                    deleting_epoch: expected_epoch,
                    deleting_head: expected_head,
                    ..
                },
            ) => {
                assert_eq!(actual_authorization, expected_authorization);
                assert_eq!(actual_delete, expected_delete);
                assert_eq!(actual_volume, expected_volume);
                assert_eq!(actual_disk, expected_disk);
                assert_eq!(actual_epoch, expected_epoch);
                assert_eq!(actual_head, expected_head);
            }
            _ => panic!("disposable delete produced a normal receipt"),
        }
        store
            .authority_transaction(|transaction| {
                assert!(load_volume_for_update(transaction, &id("vol_disposable_test"))?.is_none());
                assert!(
                    load_any_disk_by_id_for_update(transaction, &id("disk_disposable_test"))?
                        .is_none()
                );
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
        seed_normal_delete(&store);
        store
            .authority_transaction(|transaction| {
                insert_cat(
                    transaction,
                    &CatRecord {
                        cat_id: id("cat_normal_root_test"),
                        workspace_id: id("workspace-delete-test"),
                        name: id("cat_normal_root_test"),
                        created_at: UnixMillis::new(1).unwrap(),
                    },
                )?;
                let mut disk =
                    load_any_disk_by_id_for_update(transaction, &id("disk_delete_test"))?.unwrap();
                disk.name = disk.disk_id.clone();
                disk.role = DiskRole::Root {
                    cat_id: id("cat_normal_root_test"),
                };
                update_disk(transaction, &disk)
            })
            .unwrap();
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
            stored_receipt(&store),
            DeleteCompletionReceipt::Normal { .. }
        ));
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
    async fn host_fence_disposable_root_without_v8_provider_evidence_is_blocked() {
        let store = Arc::new(
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap(),
        );
        let event = host_fence_event();
        seed_disposable_delete(
            &store,
            DisposableDeleteIsolationBasis::HostFenceEvent {
                event_id: event.event_id.clone(),
            },
            Some(event),
        );
        let blob = Arc::new(MemoryBlob::with_keys(&[
            "volumes/vol_disposable_test/data/unique-local-tail",
        ]));
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
        assert!(blob
            .exists("volumes/vol_disposable_test/data/unique-local-tail")
            .unwrap());
        store
            .authority_transaction(|transaction| {
                assert!(load_volume_for_update(transaction, &id("vol_disposable_test"))?.is_some());
                assert!(
                    load_any_disk_by_id_for_update(transaction, &id("disk_disposable_test"))?
                        .is_some()
                );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn completion_commit_response_loss_is_discovered_from_exact_receipt() {
        let store =
            Store::connect(&crate::testsupport::isolated_control_store_url(), None).unwrap();
        seed_normal_delete(&store);
        let candidate = store.load_delete_candidates(None, 1).unwrap().remove(0);
        store.inject_committed_response_loss_once();
        let error = store
            .complete_delete(EmptyVolumePrefix {
                candidate: candidate.clone(),
            })
            .unwrap_err();
        assert_eq!(error.code, cats_api::error::ErrorCode::Unavailable);
        assert!(matches!(
            stored_receipt(&store),
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
        seed_normal_delete(&store);
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
        seed_normal_delete(&seed);
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
            stored_receipt(&seed),
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
