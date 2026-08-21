//! Command-scoped PostgreSQL composition for lifecycle Volume transitions.
//!
//! This is the only atomic-lifecycle writer for normal-release and disposable
//! authorization-consumption receipts. It deliberately does not reuse the
//! Desired/revision transition path: every request is bound to one exact
//! unresolved lifecycle Operation and current authenticated AgentSession.

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::runtime_inventory::{
    ObservedCommandJournal, ObservedRuntimePhysicalState, RuntimeInventoryBody,
};
use cats_api::runtime_lifecycle::{
    decode_immutable_runtime_config, encode_immutable_runtime_config,
    DiskRole as LifecycleDiskRole, LifecycleCommand, LifecycleCommandEnvelope,
    LifecycleCommandKind, RequestedVolumeDisposition, RuntimeVolumeAuthorityInput,
    RuntimeVolumeGuestBinding,
};
use cats_api::runtime_lifecycle_volume::{
    execution_absence_proof_digest, validate_lifecycle_volume_transition_request,
    LifecycleAlreadyUnownedProvenance as WireAlreadyUnownedProvenance,
    LifecycleColdVolumeSet as WireColdVolumeSet,
    LifecycleCommandAlreadyUnownedReceipt as WireAlreadyUnownedReceipt,
    LifecycleCommandDeleteCompletionReceipt as WireCommandDeleteCompletionReceipt,
    LifecycleCommandDisposableAuthorizationConsumedReceipt as WireDisposableConsumedReceipt,
    LifecycleCommandNormalReleaseReceipt as WireNormalReleaseReceipt,
    LifecycleCommandRootDeleteAuthorityReceipt as WireRootDeleteAuthorityReceipt,
    LifecycleCommandStartVolumeGrantReceipt as WireStartGrantReceipt,
    LifecycleDeleteCompletionEvidence as WireDeleteCompletionEvidence,
    LifecycleDeleteVolumeSet as WireDeleteVolumeSet,
    LifecycleNormalReleaseInput as WireNormalReleaseInput,
    LifecyclePersistentInitializationBinding as WirePersistentInitializationBinding,
    LifecyclePersistentInitializationCommitRequest as WirePersistentInitializationCommitRequest,
    LifecyclePersistentInitializationInspectRequest as WirePersistentInitializationInspectRequest,
    LifecyclePersistentInitializationInspection as WirePersistentInitializationInspection,
    LifecyclePersistentInitializationState as WirePersistentInitializationState,
    LifecycleRenewLeaseRequest as WireRenewLeaseRequest,
    LifecycleRenewLeaseResult as WireRenewLeaseResult,
    LifecycleServingAcquire as WireServingAcquire, LifecycleStartVolumeAction as WireStartAction,
    LifecycleStartVolumeBatch as WireStartVolumeBatch,
    LifecycleStartVolumeGrantAuthority as WireStartGrantAuthority,
    LifecycleStoredAlreadyUnownedReceipt as WireStoredAlreadyUnownedReceipt,
    LifecycleStoredNormalReleaseReceipt as WireStoredNormalReleaseReceipt,
    LifecycleStoredPersistentInitializationCommit as WireStoredPersistentInitializationCommit,
    LifecycleStoredStartVolumeGrant as WireStoredStartGrant,
    LifecycleStoredVolumeDisposition as WireStoredVolumeDisposition,
    LifecycleVolumeCommandScope as WireCommandScope,
    LifecycleVolumeDispositionInput as WireDispositionInput,
    LifecycleVolumeDurabilityProof as WireDurabilityProof,
    LifecycleVolumeIdentity as WireVolumeIdentity, LifecycleVolumeStrongStopEvidence,
    LifecycleVolumeTarget as WireVolumeTarget,
    LifecycleVolumeTransitionApplied as WireTransitionApplied,
    LifecycleVolumeTransitionRejection as WireTransitionRejection,
    LifecycleVolumeTransitionRequest as WireTransitionRequest,
    LifecycleVolumeTransitionRequestKind as WireTransitionRequestKind,
    LifecycleVolumeTransitionResponse as WireTransitionResponse,
    LifecycleVolumeTransitionResult as WireTransitionResult,
};
use cats_api::runtime_reconciliation::{
    AuthorizationState, BeginDeleteRequest, DisposableDeleteIsolationBasis,
    DisposableRootDeleteAuthorization, DisposableRootDisposition, Id, SessionBinding, Sha256Digest,
    VolumeAuthorization,
};
use cats_storage::authority::{
    begin_delete_with_source, normal_acquire_with_source, renew_lease, AuthorizationRecord,
    LastVolumeTransition, NormalAcquireRequest, RenewLeaseRequest, VolumeAdminState,
    VolumeOwnerBinding, VolumeRecord, VolumeTransitionSource,
};
use cats_storage::lifecycle_volume::{
    begin_delete_disposable_root, commit_persistent_initialization,
    encode_command_normal_release_receipt, encode_command_normal_release_receipt_for_deleting_root,
    inspect_persistent_initialization, persistent_delete_dispositions_digest,
    release_cold_volume_set, release_delete_normal_volume_set,
    release_delete_persistent_volume_set, AlreadyUnownedProvenance, ColdCommandVolumeSet,
    CommandAlreadyUnownedReceipt, CommandBoundDisposableRootAuthorization,
    CommandDeleteCompletionReceipt, CommandDisposableAuthorizationConsumedReceipt,
    CommandNormalReleaseInput, CommandNormalReleaseReceipt, CommandRootDeleteAuthorityReceipt,
    CommandVolumeDispositionReceipt, CommandVolumeDurabilityProof, DefaultRootDiscardDisposition,
    DeleteCommandVolumeSet, DeleteDisposableRootInput, LifecycleVolumeCommandScope,
    LifecycleVolumeDispositionInput, LifecycleVolumeIdentity, LifecycleVolumeTarget,
};
use postgres::Transaction;
use sha2::{Digest as _, Sha256};

use super::lifecycle_commands::{authenticate_session, LifecycleSessionRejection};
use super::product::{
    DiskAdminState, DiskRecord, DiskRole as ProductDiskRole, PersistentDiskInitialization,
};
use super::product_rows::{
    load_any_disk_snapshot_for_update, load_cat_by_id_for_update, load_disk_by_id_for_update,
    update_disk,
};
use super::rows::{
    database_now, insert_authorization, insert_command_already_unowned_receipt,
    insert_command_disposable_authorization_consumed_receipt,
    insert_command_normal_release_receipt, insert_command_start_volume_grant_receipt,
    load_authorization_for_update, load_command_already_unowned_receipt_for_update,
    load_command_delete_completion_receipt_for_update,
    load_command_normal_release_receipt_for_update,
    load_command_start_volume_grant_receipt_for_update,
    load_latest_command_start_volume_grant_receipt_for_update,
    load_lifecycle_receipt_operation_unlocked, load_stored_volume_for_update,
    lock_lifecycle_receipt_operation_unresolved, update_authorization, update_volume_owner,
    StoredVolume,
};
use super::runtime_spine::{load_runtime_full_inventory_for_update, RuntimeFullInventoryState};
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{Result as StoreResult, Store};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LifecycleVolumeTransitionRequest {
    pub(crate) session: SessionBinding,
    pub(crate) transition: LifecycleVolumeTransition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleVolumeTransition {
    StartVolumes {
        scope: LifecycleVolumeCommandScope,
        batch: WireStartVolumeBatch,
    },
    InspectPersistentInitialization {
        scope: LifecycleVolumeCommandScope,
        inspect: Box<WirePersistentInitializationInspectRequest>,
    },
    CommitPersistentInitialization {
        scope: LifecycleVolumeCommandScope,
        commit: Box<WirePersistentInitializationCommitRequest>,
    },
    ColdRelease {
        command: ColdCommandVolumeSet,
        volumes: Vec<RequestedVolumeDispositionInput>,
        strong_stop: Box<LifecycleVolumeStrongStopEvidence>,
    },
    DeleteNormal {
        command: DeleteCommandVolumeSet,
        volumes: Vec<RequestedVolumeDispositionInput>,
        strong_stop: Box<LifecycleVolumeStrongStopEvidence>,
    },
    DeleteDisposableRoot {
        command: DeleteCommandVolumeSet,
        persistent_volumes: Vec<RequestedVolumeDispositionInput>,
        root_durability: Box<CommandVolumeDurabilityProof>,
        strong_stop: Box<LifecycleVolumeStrongStopEvidence>,
    },
    DiscoverDeleteCompletion {
        command: DeleteCommandVolumeSet,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RequestedVolumeDispositionInput {
    OwnedRelease(Box<CommandNormalReleaseInput>),
    AlreadyUnowned {
        volume: LifecycleVolumeIdentity,
        expected_epoch: cats_api::runtime_reconciliation::FenceEpoch,
        expected_head: cats_api::runtime_reconciliation::RemoteHead,
    },
}

impl LifecycleVolumeTransition {
    fn scope(&self) -> &LifecycleVolumeCommandScope {
        match self {
            Self::StartVolumes { scope, .. } => scope,
            Self::InspectPersistentInitialization { scope, .. }
            | Self::CommitPersistentInitialization { scope, .. } => scope,
            Self::ColdRelease { command, .. } => &command.scope,
            Self::DeleteNormal { command, .. }
            | Self::DeleteDisposableRoot { command, .. }
            | Self::DiscoverDeleteCompletion { command } => &command.scope,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredNormalReleaseReceipt {
    pub(crate) receipt: CommandNormalReleaseReceipt,
    pub(crate) receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredAlreadyUnownedReceipt {
    pub(crate) receipt: CommandAlreadyUnownedReceipt,
    pub(crate) receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoredVolumeDisposition {
    NormallyReleased(Box<StoredNormalReleaseReceipt>),
    AlreadyUnowned(Box<StoredAlreadyUnownedReceipt>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleVolumeTransitionApplied {
    StartVolumesReady {
        grant_sequence: cats_api::runtime_reconciliation::WireU64,
        grants: Vec<WireStoredStartGrant>,
    },
    PersistentInitializationInspected {
        inspection: Box<WirePersistentInitializationInspection>,
    },
    PersistentInitializationCommitted {
        committed: Box<WireStoredPersistentInitializationCommit>,
    },
    ColdReleased {
        dispositions: Vec<StoredVolumeDisposition>,
    },
    DeleteNormallyDeleting {
        dispositions: Vec<StoredVolumeDisposition>,
    },
    DeleteDisposableRootDeleting {
        persistent_dispositions: Vec<StoredVolumeDisposition>,
        authorization_id: Id,
        authorization_consumed_receipt_digest: Sha256Digest,
    },
    DeleteCompleted {
        receipt: Box<CommandDeleteCompletionReceipt>,
        receipt_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleVolumeTransitionRejection {
    Session(LifecycleSessionRejection),
    StaleInventoryAttestation,
    CompletionPending,
    InvalidCommandBinding,
    AuthorityRejected,
    TakeoverUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleVolumeTransitionOutcome {
    Applied(Box<LifecycleVolumeTransitionApplied>),
    Rejected(LifecycleVolumeTransitionRejection),
}

fn applied(value: LifecycleVolumeTransitionApplied) -> LifecycleVolumeTransitionOutcome {
    LifecycleVolumeTransitionOutcome::Applied(Box::new(value))
}

impl Store {
    pub(crate) fn apply_lifecycle_volume_transition_wire(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        request: &WireTransitionRequest,
    ) -> StoreResult<WireTransitionResponse> {
        validate_lifecycle_volume_transition_request(request).map_err(crate::store::internal)?;
        let internal = decode_wire_request(request)
            .map_err(|_| crate::store::internal("invalid lifecycle Volume transition"))?;
        let outcome = self.apply_lifecycle_volume_transition(authenticated, &internal)?;
        encode_wire_response(request, outcome)
            .map_err(|_| crate::store::internal("invalid lifecycle Volume response"))
    }

    pub(crate) fn apply_lifecycle_volume_transition(
        &self,
        authenticated: &AuthenticatedNodeCredential,
        request: &LifecycleVolumeTransitionRequest,
    ) -> StoreResult<LifecycleVolumeTransitionOutcome> {
        self.authority_transaction(|transaction| {
            apply_lifecycle_volume_transition_in(transaction, authenticated, request)
        })
    }
}

fn decode_wire_request(
    request: &WireTransitionRequest,
) -> Result<LifecycleVolumeTransitionRequest, ()> {
    let transition = match &request.transition {
        WireTransitionRequestKind::StartVolumes { batch } => {
            LifecycleVolumeTransition::StartVolumes {
                scope: scope_from_wire(&batch.scope),
                batch: batch.as_ref().clone(),
            }
        }
        WireTransitionRequestKind::InspectPersistentInitialization { inspect } => {
            LifecycleVolumeTransition::InspectPersistentInitialization {
                scope: scope_from_wire(&inspect.binding.scope),
                inspect: inspect.clone(),
            }
        }
        WireTransitionRequestKind::CommitPersistentInitialization { commit } => {
            LifecycleVolumeTransition::CommitPersistentInitialization {
                scope: scope_from_wire(&commit.binding.scope),
                commit: commit.clone(),
            }
        }
        WireTransitionRequestKind::ColdRelease {
            command,
            volumes,
            strong_stop,
        } => LifecycleVolumeTransition::ColdRelease {
            command: cold_command_from_wire(command),
            volumes: volumes.iter().map(disposition_input_from_wire).collect(),
            strong_stop: strong_stop.clone(),
        },
        WireTransitionRequestKind::DeleteNormal {
            command,
            volumes,
            strong_stop,
        } => LifecycleVolumeTransition::DeleteNormal {
            command: delete_command_from_wire(command),
            volumes: volumes.iter().map(disposition_input_from_wire).collect(),
            strong_stop: strong_stop.clone(),
        },
        WireTransitionRequestKind::DeleteDisposableRoot {
            command,
            persistent_volumes,
            root_durability,
            strong_stop,
        } => LifecycleVolumeTransition::DeleteDisposableRoot {
            command: delete_command_from_wire(command),
            persistent_volumes: persistent_volumes
                .iter()
                .map(disposition_input_from_wire)
                .collect(),
            root_durability: Box::new(durability_from_wire(root_durability)),
            strong_stop: strong_stop.clone(),
        },
        WireTransitionRequestKind::DiscoverDeleteCompletion { command } => {
            LifecycleVolumeTransition::DiscoverDeleteCompletion {
                command: delete_command_from_wire(command),
            }
        }
    };
    Ok(LifecycleVolumeTransitionRequest {
        session: request.session.clone(),
        transition,
    })
}

fn encode_wire_response(
    request: &WireTransitionRequest,
    outcome: LifecycleVolumeTransitionOutcome,
) -> Result<WireTransitionResponse, ()> {
    let result = match outcome {
        LifecycleVolumeTransitionOutcome::Applied(applied) => WireTransitionResult::Applied {
            applied: match *applied {
                LifecycleVolumeTransitionApplied::StartVolumesReady {
                    grant_sequence,
                    grants,
                } => WireTransitionApplied::StartVolumesReady {
                    grant_sequence,
                    grants,
                },
                LifecycleVolumeTransitionApplied::PersistentInitializationInspected {
                    inspection,
                } => WireTransitionApplied::PersistentInitializationInspected { inspection },
                LifecycleVolumeTransitionApplied::PersistentInitializationCommitted {
                    committed,
                } => WireTransitionApplied::PersistentInitializationCommitted { committed },
                LifecycleVolumeTransitionApplied::ColdReleased { dispositions } => {
                    WireTransitionApplied::ColdReleased {
                        dispositions: dispositions
                            .iter()
                            .map(stored_disposition_to_wire)
                            .collect(),
                    }
                }
                LifecycleVolumeTransitionApplied::DeleteNormallyDeleting { dispositions } => {
                    WireTransitionApplied::DeleteNormallyDeleting {
                        dispositions: dispositions
                            .iter()
                            .map(stored_disposition_to_wire)
                            .collect(),
                    }
                }
                LifecycleVolumeTransitionApplied::DeleteDisposableRootDeleting {
                    persistent_dispositions,
                    authorization_id,
                    authorization_consumed_receipt_digest,
                } => WireTransitionApplied::DeleteDisposableRootDeleting {
                    persistent_dispositions: persistent_dispositions
                        .iter()
                        .map(stored_disposition_to_wire)
                        .collect(),
                    authorization_id,
                    authorization_consumed_receipt_digest,
                },
                LifecycleVolumeTransitionApplied::DeleteCompleted {
                    receipt,
                    receipt_digest,
                } => WireTransitionApplied::DeleteCompleted {
                    completion: Box::new(WireDeleteCompletionEvidence {
                        receipt: delete_completion_to_wire(&receipt),
                        receipt_digest,
                    }),
                },
            },
        },
        LifecycleVolumeTransitionOutcome::Rejected(rejection) => WireTransitionResult::Rejected {
            reason: match rejection {
                LifecycleVolumeTransitionRejection::Session(_) => {
                    WireTransitionRejection::StaleSession
                }
                LifecycleVolumeTransitionRejection::StaleInventoryAttestation => {
                    WireTransitionRejection::StaleInventoryAttestation
                }
                LifecycleVolumeTransitionRejection::CompletionPending => {
                    WireTransitionRejection::CompletionPending
                }
                LifecycleVolumeTransitionRejection::InvalidCommandBinding => {
                    WireTransitionRejection::InvalidCommandBinding
                }
                LifecycleVolumeTransitionRejection::AuthorityRejected => {
                    WireTransitionRejection::AuthorityRejected
                }
                LifecycleVolumeTransitionRejection::TakeoverUnavailable => {
                    WireTransitionRejection::TakeoverUnavailable
                }
            },
        },
    };
    let scope = request.transition.scope();
    Ok(WireTransitionResponse {
        version: cats_api::runtime_reconciliation::ContractVersion::V1,
        session: request.session.clone(),
        operation_id: scope.operation_id.clone(),
        request_fingerprint: scope.request_fingerprint.clone(),
        result,
    })
}

fn scope_from_wire(scope: &WireCommandScope) -> LifecycleVolumeCommandScope {
    LifecycleVolumeCommandScope {
        operation_id: scope.operation_id.clone(),
        request_fingerprint: scope.request_fingerprint.clone(),
        cat_id: scope.cat_id.clone(),
        node_id: scope.node_id.clone(),
        placement_identity: scope.placement_identity.clone(),
    }
}

pub(super) fn scope_to_wire(scope: &LifecycleVolumeCommandScope) -> WireCommandScope {
    WireCommandScope {
        operation_id: scope.operation_id.clone(),
        request_fingerprint: scope.request_fingerprint.clone(),
        cat_id: scope.cat_id.clone(),
        node_id: scope.node_id.clone(),
        placement_identity: scope.placement_identity.clone(),
    }
}

fn target_from_wire(target: &WireVolumeTarget) -> LifecycleVolumeTarget {
    LifecycleVolumeTarget {
        disk_id: target.disk_id.clone(),
        disk_role: target.disk_role,
        volume_id: target.volume_id.clone(),
        attachment_id: target.attachment_id.clone(),
        attachment_epoch: target.attachment_epoch,
    }
}

fn target_to_wire(target: &LifecycleVolumeTarget) -> WireVolumeTarget {
    WireVolumeTarget {
        disk_id: target.disk_id.clone(),
        disk_role: target.disk_role,
        volume_id: target.volume_id.clone(),
        attachment_id: target.attachment_id.clone(),
        attachment_epoch: target.attachment_epoch,
    }
}

fn identity_from_wire(identity: &WireVolumeIdentity) -> LifecycleVolumeIdentity {
    LifecycleVolumeIdentity {
        disk_id: identity.disk_id.clone(),
        disk_role: identity.disk_role,
        volume_id: identity.volume_id.clone(),
    }
}

fn identity_to_wire(identity: &LifecycleVolumeIdentity) -> WireVolumeIdentity {
    WireVolumeIdentity {
        disk_id: identity.disk_id.clone(),
        disk_role: identity.disk_role,
        volume_id: identity.volume_id.clone(),
    }
}

fn durability_from_wire(proof: &WireDurabilityProof) -> CommandVolumeDurabilityProof {
    CommandVolumeDurabilityProof {
        scope: scope_from_wire(&proof.scope),
        volume: target_from_wire(&proof.volume),
        remote_head: proof.remote_head.clone(),
        local_durable_generation: proof.local_durable_generation,
        remote_durable_generation: proof.remote_durable_generation,
        pending_pack_count: proof.pending_pack_count,
    }
}

fn durability_to_wire(proof: &CommandVolumeDurabilityProof) -> WireDurabilityProof {
    WireDurabilityProof {
        scope: scope_to_wire(&proof.scope),
        volume: target_to_wire(&proof.volume),
        remote_head: proof.remote_head.clone(),
        local_durable_generation: proof.local_durable_generation,
        remote_durable_generation: proof.remote_durable_generation,
        pending_pack_count: proof.pending_pack_count,
    }
}

fn release_input_from_wire(input: &WireNormalReleaseInput) -> CommandNormalReleaseInput {
    CommandNormalReleaseInput {
        durability: durability_from_wire(&input.durability),
        transition_id: input.transition_id.clone(),
    }
}

fn disposition_input_from_wire(input: &WireDispositionInput) -> RequestedVolumeDispositionInput {
    match input {
        WireDispositionInput::OwnedRelease { release } => {
            RequestedVolumeDispositionInput::OwnedRelease(Box::new(release_input_from_wire(
                release,
            )))
        }
        WireDispositionInput::AlreadyUnowned {
            volume,
            expected_epoch,
            expected_head,
        } => RequestedVolumeDispositionInput::AlreadyUnowned {
            volume: identity_from_wire(volume),
            expected_epoch: *expected_epoch,
            expected_head: expected_head.clone(),
        },
    }
}

fn cold_command_from_wire(command: &WireColdVolumeSet) -> ColdCommandVolumeSet {
    ColdCommandVolumeSet {
        scope: scope_from_wire(&command.scope),
        volumes: command.volumes.iter().map(identity_from_wire).collect(),
    }
}

fn delete_command_from_wire(command: &WireDeleteVolumeSet) -> DeleteCommandVolumeSet {
    DeleteCommandVolumeSet {
        scope: scope_from_wire(&command.scope),
        root_disposition: DefaultRootDiscardDisposition {
            root: identity_from_wire(&command.root_disposition.root),
            delete_id: command.root_disposition.delete_id.clone(),
        },
        persistent_volumes: command
            .persistent_volumes
            .iter()
            .map(identity_from_wire)
            .collect(),
    }
}

fn delete_command_to_wire(command: &DeleteCommandVolumeSet) -> WireDeleteVolumeSet {
    WireDeleteVolumeSet {
        scope: scope_to_wire(&command.scope),
        root_disposition:
            cats_api::runtime_lifecycle_volume::LifecycleDefaultRootDiscardDisposition {
                root: identity_to_wire(&command.root_disposition.root),
                delete_id: command.root_disposition.delete_id.clone(),
            },
        persistent_volumes: command
            .persistent_volumes
            .iter()
            .map(identity_to_wire)
            .collect(),
    }
}

fn normal_release_to_wire(receipt: &CommandNormalReleaseReceipt) -> WireNormalReleaseReceipt {
    WireNormalReleaseReceipt {
        durability: durability_to_wire(&receipt.durability),
        request: receipt.request.clone(),
        result: receipt.result.clone(),
    }
}

fn stored_release_to_wire(receipt: &StoredNormalReleaseReceipt) -> WireStoredNormalReleaseReceipt {
    WireStoredNormalReleaseReceipt {
        receipt: normal_release_to_wire(&receipt.receipt),
        receipt_digest: receipt.receipt_digest.clone(),
    }
}

fn already_unowned_to_wire(receipt: &CommandAlreadyUnownedReceipt) -> WireAlreadyUnownedReceipt {
    WireAlreadyUnownedReceipt {
        scope: scope_to_wire(&receipt.scope),
        volume: identity_to_wire(&receipt.volume),
        expected_epoch: receipt.expected_epoch,
        expected_head: receipt.expected_head.clone(),
        provenance: match &receipt.provenance {
            AlreadyUnownedProvenance::Pristine => WireAlreadyUnownedProvenance::Pristine,
            AlreadyUnownedProvenance::NormalRelease {
                receipt,
                receipt_digest,
            } => WireAlreadyUnownedProvenance::NormalRelease {
                receipt: Box::new(normal_release_to_wire(receipt)),
                receipt_digest: receipt_digest.clone(),
            },
        },
    }
}

fn stored_disposition_to_wire(
    disposition: &StoredVolumeDisposition,
) -> WireStoredVolumeDisposition {
    match disposition {
        StoredVolumeDisposition::NormallyReleased(release) => {
            WireStoredVolumeDisposition::NormallyReleased {
                release: Box::new(stored_release_to_wire(release)),
            }
        }
        StoredVolumeDisposition::AlreadyUnowned(receipt) => {
            WireStoredVolumeDisposition::AlreadyUnowned {
                receipt: Box::new(WireStoredAlreadyUnownedReceipt {
                    receipt: already_unowned_to_wire(&receipt.receipt),
                    receipt_digest: receipt.receipt_digest.clone(),
                }),
            }
        }
    }
}

fn disposable_consumed_to_wire(
    receipt: &CommandDisposableAuthorizationConsumedReceipt,
) -> WireDisposableConsumedReceipt {
    WireDisposableConsumedReceipt {
        command: delete_command_to_wire(&receipt.command),
        authorization_id: receipt.authorization_id.clone(),
        persistent_dispositions_digest: receipt.persistent_dispositions_digest.clone(),
        receipt: receipt.receipt.clone(),
    }
}

fn delete_completion_to_wire(
    receipt: &CommandDeleteCompletionReceipt,
) -> WireCommandDeleteCompletionReceipt {
    WireCommandDeleteCompletionReceipt {
        command: delete_command_to_wire(&receipt.command),
        root_authority: match &receipt.root_authority {
            CommandRootDeleteAuthorityReceipt::NormalRelease(receipt) => {
                WireRootDeleteAuthorityReceipt::NormalRelease(normal_release_to_wire(receipt))
            }
            CommandRootDeleteAuthorityReceipt::AlreadyUnowned(receipt) => {
                WireRootDeleteAuthorityReceipt::AlreadyUnowned(already_unowned_to_wire(receipt))
            }
            CommandRootDeleteAuthorityReceipt::DisposableAuthorizationConsumed(receipt) => {
                WireRootDeleteAuthorityReceipt::DisposableAuthorizationConsumed(
                    disposable_consumed_to_wire(receipt),
                )
            }
        },
        completion: receipt.completion.clone(),
    }
}

fn apply_lifecycle_volume_transition_in(
    transaction: &mut Transaction<'_>,
    authenticated: &AuthenticatedNodeCredential,
    request: &LifecycleVolumeTransitionRequest,
) -> AuthorityTxResult<LifecycleVolumeTransitionOutcome> {
    let session = match authenticate_session(transaction, authenticated, &request.session)? {
        Ok(session) => session,
        Err(rejection) => {
            return Ok(LifecycleVolumeTransitionOutcome::Rejected(
                LifecycleVolumeTransitionRejection::Session(rejection),
            ));
        }
    };
    let scope = request.transition.scope();
    if scope.node_id != session.node_id || scope.placement_identity.node_id != session.node_id {
        return Ok(invalid_command());
    }
    let post_stop_inventory = match &request.transition {
        LifecycleVolumeTransition::ColdRelease { strong_stop, .. }
        | LifecycleVolumeTransition::DeleteNormal { strong_stop, .. }
        | LifecycleVolumeTransition::DeleteDisposableRoot { strong_stop, .. } => {
            let Some(current) =
                load_runtime_full_inventory_for_update(transaction, &session.node_id)?
            else {
                return Ok(stale_inventory());
            };
            if current.attestation != strong_stop.post_stop_inventory_attestation
                || current.attestation.session != request.session
            {
                return Ok(stale_inventory());
            }
            Some(current)
        }
        LifecycleVolumeTransition::StartVolumes { .. }
        | LifecycleVolumeTransition::InspectPersistentInitialization { .. }
        | LifecycleVolumeTransition::CommitPersistentInitialization { .. }
        | LifecycleVolumeTransition::DiscoverDeleteCompletion { .. } => None,
    };

    // The unlocked lookup only locates the Cat. It grants no authority. The
    // fixed order is Cat -> exact current Operation -> sorted Volume -> sorted
    // Disk -> authority mutation -> immutable ledger.
    let located_operation =
        load_lifecycle_receipt_operation_unlocked(transaction, &scope.operation_id)?
            .ok_or_else(backend_unknown)?;
    if !scope_matches_operation(scope, &located_operation) {
        return Ok(invalid_command());
    }
    let cat = load_cat_by_id_for_update(transaction, &located_operation.cat_id)?
        .ok_or_else(backend_unknown)?;
    if cat.workspace_id != located_operation.workspace_id {
        return Err(backend_unknown());
    }
    let operation = lock_lifecycle_receipt_operation_unresolved(transaction, &scope.operation_id)?;
    if operation != located_operation || !scope_matches_operation(scope, &operation) {
        return Err(backend_unknown());
    }
    let current = transaction.query_one(
        "SELECT lifecycle_head_operation_id, current_runtime_config_id,
                current_runtime_config_sha256, deleted_at,
                (SELECT operation_id FROM runtime_operations
                  WHERE cat_id=$1 AND state='unresolved') AS unresolved_operation_id
           FROM cat_records WHERE cat_id=$1",
        &[&operation.cat_id.as_str()],
    )?;
    if current
        .try_get::<_, Option<String>>("lifecycle_head_operation_id")?
        .as_deref()
        != operation
            .expected_predecessor_operation_id
            .as_ref()
            .map(Id::as_str)
        || current.try_get::<_, String>("current_runtime_config_id")?
            != operation.runtime_config.config_id.as_str()
        || current.try_get::<_, String>("current_runtime_config_sha256")?
            != operation.runtime_config.config_digest.as_str()
        || current.try_get::<_, Option<i64>>("deleted_at")?.is_some()
        || current
            .try_get::<_, Option<String>>("unresolved_operation_id")?
            .as_deref()
            != Some(operation.operation_id.as_str())
    {
        return Err(backend_unknown());
    }

    if let Some(inventory) = &post_stop_inventory {
        if !post_stop_inventory_closes_transition(
            inventory,
            &operation,
            &request.session,
            &request.transition,
        ) {
            return Ok(stale_inventory());
        }
    }

    if let LifecycleVolumeTransition::DiscoverDeleteCompletion { command } = &request.transition {
        if !delete_command_matches_operation(command, &operation) {
            return Ok(invalid_command());
        }
        return discover_delete_completion(transaction, &operation, command);
    }

    if let LifecycleVolumeTransition::StartVolumes { batch, .. } = &request.transition {
        if !start_batch_matches_operation(batch, &operation) {
            return Ok(invalid_command());
        }
        return apply_start_volumes(transaction, &operation, batch);
    }

    if let LifecycleVolumeTransition::InspectPersistentInitialization { inspect, .. } =
        &request.transition
    {
        return apply_persistent_initialization_inspect(transaction, &operation, inspect);
    }

    if let LifecycleVolumeTransition::CommitPersistentInitialization { commit, .. } =
        &request.transition
    {
        return apply_persistent_initialization_commit(transaction, &operation, commit);
    }

    let expected_targets = match &request.transition {
        LifecycleVolumeTransition::ColdRelease {
            command, volumes, ..
        } => {
            if !matches!(operation.command, LifecycleCommand::Cold(_))
                || volumes.len() != command.volumes.len()
                || !targets_match_runtime_config(&command.volumes, &operation)
            {
                return Ok(invalid_command());
            }
            command.volumes.clone()
        }
        LifecycleVolumeTransition::DeleteNormal {
            command, volumes, ..
        } => {
            let targets = delete_targets(command);
            if volumes.len() != targets.len()
                || !delete_command_matches_operation(command, &operation)
            {
                return Ok(invalid_command());
            }
            targets
        }
        LifecycleVolumeTransition::DeleteDisposableRoot {
            command,
            persistent_volumes,
            root_durability,
            ..
        } => {
            if persistent_volumes.len() != command.persistent_volumes.len()
                || root_durability.scope != command.scope
                || root_durability.volume.identity() != command.root_disposition.root
                || !delete_command_matches_operation(command, &operation)
            {
                return Ok(invalid_command());
            }
            delete_targets(command)
        }
        LifecycleVolumeTransition::DiscoverDeleteCompletion { .. } => {
            unreachable!("Delete completion discovery returns before locking live Volume rows")
        }
        LifecycleVolumeTransition::StartVolumes { .. } => {
            unreachable!("Start Volume batch returns through its command-scoped graph")
        }
        LifecycleVolumeTransition::InspectPersistentInitialization { .. }
        | LifecycleVolumeTransition::CommitPersistentInitialization { .. } => {
            unreachable!("Persistent initialization returns through its Start-scoped graph")
        }
    };

    let locked = lock_runtime_volume_graph(transaction, &operation, &expected_targets)?;
    match &request.transition {
        LifecycleVolumeTransition::ColdRelease {
            command, volumes, ..
        } => apply_cold_release(transaction, &operation, command, volumes, &locked),
        LifecycleVolumeTransition::DeleteNormal {
            command, volumes, ..
        } => apply_normal_delete(transaction, &operation, command, volumes, &locked),
        LifecycleVolumeTransition::DeleteDisposableRoot {
            command,
            persistent_volumes,
            root_durability,
            strong_stop,
        } => apply_disposable_delete(
            transaction,
            &operation,
            command,
            persistent_volumes,
            root_durability,
            strong_stop,
            &locked,
        ),
        LifecycleVolumeTransition::DiscoverDeleteCompletion { .. } => {
            unreachable!("Delete completion discovery returns before locking live Volume rows")
        }
        LifecycleVolumeTransition::StartVolumes { .. } => {
            unreachable!("Start Volume batch returns through its command-scoped graph")
        }
        LifecycleVolumeTransition::InspectPersistentInitialization { .. }
        | LifecycleVolumeTransition::CommitPersistentInitialization { .. } => {
            unreachable!("Persistent initialization returns through its Start-scoped graph")
        }
    }
}

fn post_stop_inventory_closes_transition(
    inventory: &RuntimeFullInventoryState,
    operation: &LifecycleCommandEnvelope,
    session: &SessionBinding,
    transition: &LifecycleVolumeTransition,
) -> bool {
    if inventory.attestation.session != *session
        || inventory.full_report.session != *session
        || inventory.attestation.inventory_digest
            != match &inventory.full_report.inventory {
                RuntimeInventoryBody::Full {
                    inventory_digest, ..
                } => inventory_digest.clone(),
                RuntimeInventoryBody::Partial { .. } => return false,
            }
    {
        return false;
    }
    let RuntimeInventoryBody::Full { cats, .. } = &inventory.full_report.inventory else {
        return false;
    };
    let Some(cat) = cats.iter().find(|cat| cat.cat_id == operation.cat_id) else {
        return false;
    };
    let expected_command_kind = match operation.command {
        LifecycleCommand::Cold(_) => LifecycleCommandKind::Cold,
        LifecycleCommand::Delete(_) => LifecycleCommandKind::Delete,
        _ => return false,
    };
    if cat.observed_placement != operation.placement_identity
        || cat.observed_physical_state != ObservedRuntimePhysicalState::Absent
        || cat.observed_runtime_incarnation.is_some()
        || !matches!(
            &cat.observed_command_journal,
            Some(ObservedCommandJournal::Executing {
                operation_id,
                command_kind,
                request_fingerprint,
                ..
            }) if command_kind == &expected_command_kind
                && operation_id == &operation.operation_id
                && request_fingerprint == &operation.request_fingerprint
        )
    {
        return false;
    }
    let mut slots: Vec<&RequestedVolumeDispositionInput> = match transition {
        LifecycleVolumeTransition::ColdRelease { volumes, .. }
        | LifecycleVolumeTransition::DeleteNormal { volumes, .. } => volumes.iter().collect(),
        LifecycleVolumeTransition::DeleteDisposableRoot {
            persistent_volumes, ..
        } => persistent_volumes.iter().collect(),
        LifecycleVolumeTransition::StartVolumes { .. }
        | LifecycleVolumeTransition::InspectPersistentInitialization { .. }
        | LifecycleVolumeTransition::CommitPersistentInitialization { .. }
        | LifecycleVolumeTransition::DiscoverDeleteCompletion { .. } => return false,
    };
    let disposable_root = match transition {
        LifecycleVolumeTransition::DeleteDisposableRoot {
            root_durability, ..
        } => Some(root_durability),
        _ => None,
    };
    if cat.observed_volumes.len() != slots.len() + usize::from(disposable_root.is_some()) {
        return false;
    }
    let disposition_matches = slots.drain(..).all(|slot| {
        let identity = match slot {
            RequestedVolumeDispositionInput::OwnedRelease(input) => {
                input.durability.volume.identity()
            }
            RequestedVolumeDispositionInput::AlreadyUnowned { volume, .. } => volume.clone(),
        };
        let Some(observed) = cat
            .observed_volumes
            .iter()
            .find(|observed| observed.volume_id == identity.volume_id)
        else {
            return false;
        };
        if observed.disk_id != identity.disk_id || observed.disk_role != identity.disk_role {
            return false;
        }
        match slot {
            RequestedVolumeDispositionInput::OwnedRelease(input) => {
                matches!(
                    &observed.observed_attachment,
                    cats_api::runtime_inventory::ObservedVolumeAttachment::Owned {
                        owner_node_id,
                        attachment_id,
                        attachment_epoch,
                    } if owner_node_id == &operation.node_id
                        && attachment_id == &input.durability.volume.attachment_id
                        && attachment_epoch == &input.durability.volume.attachment_epoch
                ) && matches!(
                    observed.observed_watermark,
                    cats_api::runtime_inventory::ObservedVolumeWatermark::Known {
                        local_durable_generation,
                        remote_durable_generation,
                    } if local_durable_generation == input.durability.local_durable_generation
                        && remote_durable_generation == input.durability.remote_durable_generation
                )
            }
            RequestedVolumeDispositionInput::AlreadyUnowned {
                expected_epoch,
                expected_head,
                ..
            } => {
                matches!(
                    observed.observed_attachment,
                    cats_api::runtime_inventory::ObservedVolumeAttachment::Unowned {
                        attachment_epoch,
                    } if attachment_epoch == *expected_epoch
                ) && matches!(
                    observed.observed_watermark,
                    cats_api::runtime_inventory::ObservedVolumeWatermark::Known {
                        local_durable_generation,
                        remote_durable_generation,
                    } if local_durable_generation == expected_head.generation
                        && remote_durable_generation == expected_head.generation
                )
            }
        }
    });
    disposition_matches
        && disposable_root.is_none_or(|proof| {
            cat.observed_volumes.iter().any(|observed| {
                observed.volume_id == proof.volume.volume_id
                    && observed.disk_id == proof.volume.disk_id
                    && observed.disk_role == proof.volume.disk_role
                    && matches!(
                        &observed.observed_attachment,
                        cats_api::runtime_inventory::ObservedVolumeAttachment::Owned {
                            owner_node_id,
                            attachment_id,
                            attachment_epoch,
                        } if owner_node_id == &operation.node_id
                            && attachment_id == &proof.volume.attachment_id
                            && attachment_epoch == &proof.volume.attachment_epoch
                    )
                    && matches!(
                        observed.observed_watermark,
                        cats_api::runtime_inventory::ObservedVolumeWatermark::Known {
                            local_durable_generation,
                            remote_durable_generation,
                        } if local_durable_generation == proof.local_durable_generation
                            && remote_durable_generation == proof.remote_durable_generation
                    )
            })
        })
}

fn start_batch_matches_operation(
    batch: &WireStartVolumeBatch,
    operation: &LifecycleCommandEnvelope,
) -> bool {
    let LifecycleCommand::Start(spec) = &operation.command else {
        return false;
    };
    batch.actions.len() == operation.runtime_config.volumes.len()
        && spec.volume_authorities.len() == operation.runtime_config.volumes.len()
        && batch
            .actions
            .iter()
            .zip(&operation.runtime_config.volumes)
            .zip(&spec.volume_authorities)
            .all(|((action, config), authority)| {
                if action.volume() != config
                    || authority.volume_id != config.volume_id
                    || authority.disk_id != config.disk_id
                {
                    return false;
                }
                if batch.grant_sequence.get() > 0 {
                    return matches!(action, WireStartAction::RenewSameNode { .. })
                        && action.lease_duration_ms() == Some(batch.renewal_lease_duration_ms);
                }
                match (action, &authority.authority) {
                    (
                        WireStartAction::NormalAcquire {
                            expected_unowned_epoch,
                            transition_id,
                            lease_duration_ms,
                            ..
                        },
                        RuntimeVolumeAuthorityInput::NormalUnowned {
                            expected_unowned_epoch: command_epoch,
                            transition_id: command_transition,
                        },
                    ) => {
                        expected_unowned_epoch == command_epoch
                            && transition_id == command_transition
                            && *lease_duration_ms == batch.renewal_lease_duration_ms
                    }
                    (
                        WireStartAction::RenewSameNode {
                            attachment_id,
                            attachment_epoch,
                            lease_duration_ms,
                            ..
                        },
                        RuntimeVolumeAuthorityInput::SameNodeOwned {
                            attachment_id: command_attachment,
                            attachment_epoch: command_epoch,
                        },
                    ) => {
                        attachment_id == command_attachment
                            && attachment_epoch == command_epoch
                            && *lease_duration_ms == batch.renewal_lease_duration_ms
                    }
                    (
                        WireStartAction::Takeover {
                            authorization_id, ..
                        },
                        RuntimeVolumeAuthorityInput::Takeover {
                            authorization_id: command_authorization,
                        },
                    ) => authorization_id == command_authorization,
                    _ => false,
                }
            })
}

#[derive(Debug, Clone)]
struct LockedPersistentInitialization {
    stored: StoredVolume,
    disk: DiskRecord,
    initialization: WirePersistentInitializationState,
    prior_commit: Option<WireStoredPersistentInitializationCommit>,
}

fn apply_persistent_initialization_inspect(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleCommandEnvelope,
    inspect: &WirePersistentInitializationInspectRequest,
) -> AuthorityTxResult<LifecycleVolumeTransitionOutcome> {
    let Some(locked) =
        lock_persistent_initialization_graph(transaction, operation, &inspect.binding)?
    else {
        return Ok(authority_rejected());
    };
    let Some(owner) = locked.stored.owner_binding.as_ref() else {
        return Ok(authority_rejected());
    };
    let Ok(inspection) = inspect_persistent_initialization(
        &inspect.binding,
        &locked.stored.record,
        owner,
        &locked.initialization,
    ) else {
        return Ok(authority_rejected());
    };
    Ok(applied(
        LifecycleVolumeTransitionApplied::PersistentInitializationInspected {
            inspection: Box::new(inspection),
        },
    ))
}

fn apply_persistent_initialization_commit(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleCommandEnvelope,
    commit: &WirePersistentInitializationCommitRequest,
) -> AuthorityTxResult<LifecycleVolumeTransitionOutcome> {
    let Some(locked) =
        lock_persistent_initialization_graph(transaction, operation, &commit.binding)?
    else {
        return Ok(authority_rejected());
    };
    let Some(owner) = locked.stored.owner_binding.as_ref() else {
        return Ok(authority_rejected());
    };
    let transaction_now = database_now(transaction)?;
    let Ok((replacement, committed)) = commit_persistent_initialization(
        commit,
        &locked.stored.record,
        owner,
        &locked.initialization,
        locked.prior_commit.as_ref(),
        transaction_now,
    ) else {
        return Ok(authority_rejected());
    };
    if replacement != locked.initialization {
        let mut disk = locked.disk;
        disk.role = ProductDiskRole::Persistent {
            initialization: Box::new(persistent_initialization_to_product(
                &replacement,
                &committed,
            )?),
        };
        update_disk(transaction, &disk)?;
    }
    Ok(applied(
        LifecycleVolumeTransitionApplied::PersistentInitializationCommitted {
            committed: Box::new(committed),
        },
    ))
}

fn lock_persistent_initialization_graph(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleCommandEnvelope,
    binding: &WirePersistentInitializationBinding,
) -> AuthorityTxResult<Option<LockedPersistentInitialization>> {
    if !matches!(operation.command, LifecycleCommand::Start(_))
        || binding.scope.operation_id != operation.operation_id
        || binding.scope.request_fingerprint != operation.request_fingerprint
        || binding.scope.cat_id != operation.cat_id
        || binding.scope.node_id != operation.node_id
        || binding.scope.placement_identity != operation.placement_identity
        || binding.runtime_config_id != operation.runtime_config.config_id
        || binding.runtime_config_digest != operation.runtime_config.config_digest
        || binding.volume.disk_role != LifecycleDiskRole::Persistent
    {
        return Ok(None);
    }
    let Some(expected) = operation
        .runtime_config
        .volumes
        .iter()
        .find(|volume| volume.volume_id == binding.volume.volume_id)
    else {
        return Ok(None);
    };
    if expected != &binding.volume {
        return Ok(None);
    }

    // The caller already holds credential/session, Cat and exact unresolved
    // Start Operation locks. Close the remaining global order exactly once:
    // Volume -> Disk -> immutable config -> immutable Start-grant evidence.
    let Some(stored) = load_stored_volume_for_update(transaction, &binding.volume.volume_id)?
    else {
        return Ok(None);
    };
    if stored.record.volume_id != binding.volume.volume_id
        || stored.record.size_bytes != binding.volume.size_bytes
        || stored.record.durability != binding.volume.durability
        || !matches!(stored.record.admin_state, VolumeAdminState::Active)
    {
        return Ok(None);
    }
    let Some(disk) = load_disk_by_id_for_update(transaction, &binding.volume.disk_id)? else {
        return Ok(None);
    };
    if disk.disk_id != binding.volume.disk_id
        || disk.workspace_id != operation.workspace_id
        || disk.volume_id != binding.volume.volume_id
        || disk.size_bytes != binding.volume.size_bytes
        || disk.durability != binding.volume.durability
        || !matches!(disk.admin_state, DiskAdminState::Active)
    {
        return Ok(None);
    }
    let Some((initialization, prior_commit)) =
        persistent_initialization_from_disk(&disk, &binding.volume)?
    else {
        return Ok(None);
    };

    let Some(config_row) = transaction.query_opt(
        "SELECT workspace_id, cat_id, canonical_config_bytes, canonical_config_sha256
           FROM cat_runtime_configs
          WHERE config_id=$1 AND workspace_id=$2 AND cat_id=$3
            AND canonical_config_sha256=$4
          FOR UPDATE",
        &[
            &binding.runtime_config_id.as_str(),
            &operation.workspace_id.as_str(),
            &operation.cat_id.as_str(),
            &binding.runtime_config_digest.as_str(),
        ],
    )?
    else {
        return Ok(None);
    };
    let config_bytes: Vec<u8> = config_row.try_get("canonical_config_bytes")?;
    let decoded_config =
        decode_immutable_runtime_config(&config_bytes).map_err(|_| backend_unknown())?;
    let canonical_config =
        encode_immutable_runtime_config(&decoded_config).map_err(|_| backend_unknown())?;
    if decoded_config != *operation.runtime_config
        || canonical_config != config_bytes
        || config_row.try_get::<_, String>("workspace_id")? != operation.workspace_id.as_str()
        || config_row.try_get::<_, String>("cat_id")? != operation.cat_id.as_str()
        || config_row.try_get::<_, String>("canonical_config_sha256")?
            != binding.runtime_config_digest.as_str()
    {
        return Err(backend_unknown());
    }

    // Lease expiry alone does not invalidate this pure Control CAS: Guest
    // format and R=L drain have already completed. Identity still closes over
    // the latest immutable Start grant. A newer grant therefore conflicts,
    // while RuntimeReady must renew before its next physical mutation.
    let Some(stored_grant) = load_latest_command_start_volume_grant_receipt_for_update(
        transaction,
        &operation.operation_id,
        &binding.volume.volume_id,
    )?
    else {
        return Ok(None);
    };
    if stored_grant.operation != *operation
        || stored_grant.receipt != binding.start_grant.receipt
        || stored_grant.receipt_digest != binding.start_grant.receipt_digest
    {
        return Ok(None);
    }
    Ok(Some(LockedPersistentInitialization {
        stored,
        disk,
        initialization,
        prior_commit,
    }))
}

fn persistent_initialization_from_disk(
    disk: &DiskRecord,
    volume: &cats_api::runtime_lifecycle::RuntimeVolumeConfig,
) -> AuthorityTxResult<
    Option<(
        WirePersistentInitializationState,
        Option<WireStoredPersistentInitializationCommit>,
    )>,
> {
    let RuntimeVolumeGuestBinding::PersistentExt4 {
        filesystem_uuid: configured_uuid,
        ..
    } = &volume.guest_binding
    else {
        return Ok(None);
    };
    let ProductDiskRole::Persistent { initialization } = &disk.role else {
        return Ok(None);
    };
    let (state, prior_commit) = match initialization.as_ref() {
        PersistentDiskInitialization::Uninitialized {
            initialization_token,
            filesystem_uuid,
            expected_blank_head,
        } => (
            WirePersistentInitializationState::Uninitialized {
                initialization_token: initialization_token.clone(),
                filesystem_uuid: filesystem_uuid.clone(),
                expected_blank_head: expected_blank_head.clone(),
            },
            None,
        ),
        PersistentDiskInitialization::Initialized {
            initialization_token,
            filesystem_uuid,
            expected_blank_head,
            initialized_head,
            initialized_at,
            commit,
        } => (
            WirePersistentInitializationState::Initialized {
                initialization_token: initialization_token.clone(),
                filesystem_uuid: filesystem_uuid.clone(),
                expected_blank_head: expected_blank_head.clone(),
                initialized_head: initialized_head.clone(),
                initialized_at: *initialized_at,
            },
            Some(commit.as_ref().clone()),
        ),
    };
    let stored_uuid = match &state {
        WirePersistentInitializationState::Uninitialized {
            filesystem_uuid, ..
        }
        | WirePersistentInitializationState::Initialized {
            filesystem_uuid, ..
        } => filesystem_uuid,
    };
    Ok((stored_uuid == configured_uuid).then_some((state, prior_commit)))
}

fn persistent_initialization_to_product(
    initialization: &WirePersistentInitializationState,
    committed: &WireStoredPersistentInitializationCommit,
) -> AuthorityTxResult<PersistentDiskInitialization> {
    match initialization {
        WirePersistentInitializationState::Uninitialized { .. } => Err(backend_unknown()),
        WirePersistentInitializationState::Initialized {
            initialization_token,
            filesystem_uuid,
            expected_blank_head,
            initialized_head,
            initialized_at,
        } => Ok(PersistentDiskInitialization::Initialized {
            initialization_token: initialization_token.clone(),
            filesystem_uuid: filesystem_uuid.clone(),
            expected_blank_head: expected_blank_head.clone(),
            initialized_head: initialized_head.clone(),
            initialized_at: *initialized_at,
            commit: Box::new(committed.clone()),
        }),
    }
}

fn apply_start_volumes(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleCommandEnvelope,
    batch: &WireStartVolumeBatch,
) -> AuthorityTxResult<LifecycleVolumeTransitionOutcome> {
    if batch
        .actions
        .iter()
        .any(|action| matches!(action, WireStartAction::Takeover { .. }))
    {
        return Ok(LifecycleVolumeTransitionOutcome::Rejected(
            LifecycleVolumeTransitionRejection::TakeoverUnavailable,
        ));
    }
    let locked = lock_start_volume_graph(transaction, operation, batch)?;
    let requested_sequence =
        i64::try_from(batch.grant_sequence.get()).map_err(|_| backend_unknown())?;
    let maximum_sequence = transaction
        .query_one(
            "SELECT max(receipt_sequence)::BIGINT AS maximum_sequence
               FROM lifecycle_volume_receipts
              WHERE operation_id=$1 AND receipt_kind='start_grant'",
            &[&operation.operation_id.as_str()],
        )?
        .try_get::<_, Option<i64>>("maximum_sequence")?;
    let replay = match maximum_sequence {
        None if requested_sequence == 0 => false,
        Some(maximum) if maximum == requested_sequence => true,
        Some(maximum) if maximum.checked_add(1) == Some(requested_sequence) => {
            let previous_count = transaction
                .query_one(
                    "SELECT count(*)::BIGINT AS count
                       FROM lifecycle_volume_receipts
                      WHERE operation_id=$1 AND receipt_kind='start_grant'
                        AND receipt_sequence=$2",
                    &[&operation.operation_id.as_str(), &maximum],
                )?
                .try_get::<_, i64>("count")?;
            if usize::try_from(previous_count).ok() != Some(batch.actions.len()) {
                return Err(backend_unknown());
            }
            false
        }
        _ => return Ok(invalid_command()),
    };
    let current_count = transaction
        .query_one(
            "SELECT count(*)::BIGINT AS count
               FROM lifecycle_volume_receipts
              WHERE operation_id=$1 AND receipt_kind='start_grant'
                AND receipt_sequence=$2",
            &[&operation.operation_id.as_str(), &requested_sequence],
        )?
        .try_get::<_, i64>("count")?;
    if replay {
        if usize::try_from(current_count).ok() != Some(batch.actions.len()) {
            return Err(backend_unknown());
        }
        let mut grants = Vec::with_capacity(batch.actions.len());
        for action in &batch.actions {
            let current = start_slot(&locked, &action.volume().volume_id)?;
            let stored = load_command_start_volume_grant_receipt_for_update(
                transaction,
                &operation.operation_id,
                &action.volume().volume_id,
                batch.grant_sequence.get(),
            )?
            .ok_or_else(backend_unknown)?;
            if stored.operation != *operation
                || !start_grant_matches_action(&stored.receipt, action, operation)
            {
                return Err(backend_unknown());
            }
            let encoded =
                cats_storage::lifecycle_volume::encode_command_start_volume_grant_receipt(
                    &scope_from_wire(&batch.scope),
                    batch.grant_sequence,
                    action.volume(),
                    &current.stored.record,
                    &stored.receipt,
                )
                .map_err(|_| backend_unknown())?;
            if encoded.receipt_digest != stored.receipt_digest {
                return Err(backend_unknown());
            }
            grants.push(WireStoredStartGrant {
                receipt: stored.receipt,
                receipt_digest: stored.receipt_digest,
            });
        }
        return Ok(applied(
            LifecycleVolumeTransitionApplied::StartVolumesReady {
                grant_sequence: batch.grant_sequence,
                grants,
            },
        ));
    }
    if current_count != 0 {
        return Err(backend_unknown());
    }
    if batch.grant_sequence.get() == 0
        && batch.actions.iter().any(|action| {
            matches!(action, WireStartAction::NormalAcquire { .. })
                && start_slot(&locked, &action.volume().volume_id)
                    .is_ok_and(|slot| slot.stored.record.lease_owner.is_some())
        })
    {
        // The authority mutation and sequence-zero ledger are one
        // transaction. An applied marker without its immutable receipt is
        // corruption, not a partially committed request to heal.
        return Err(backend_unknown());
    }
    if let Some(previous_sequence) = batch.grant_sequence.get().checked_sub(1) {
        for action in &batch.actions {
            let WireStartAction::RenewSameNode {
                attachment_id,
                attachment_epoch,
                ..
            } = action
            else {
                return Ok(invalid_command());
            };
            let current = start_slot(&locked, &action.volume().volume_id)?;
            let previous = load_command_start_volume_grant_receipt_for_update(
                transaction,
                &operation.operation_id,
                &action.volume().volume_id,
                previous_sequence,
            )?
            .ok_or_else(backend_unknown)?;
            if previous.operation != *operation
                || previous.receipt.grant_sequence.get() != previous_sequence
                || start_grant_owner(&previous.receipt)
                    != Some((attachment_id.clone(), *attachment_epoch))
            {
                return Err(backend_unknown());
            }
            let digest = cats_storage::lifecycle_volume::command_start_volume_grant_receipt_digest_for_current_owner(
                &scope_from_wire(&batch.scope),
                previous.receipt.grant_sequence,
                action.volume(),
                &current.stored.record,
                &previous.receipt,
            )
            .map_err(|_| backend_unknown())?;
            if digest != previous.receipt_digest {
                return Err(backend_unknown());
            }
        }
    }

    let now = database_now(transaction)?;
    let source = VolumeTransitionSource::Lifecycle {
        operation_id: operation.operation_id.clone(),
        request_fingerprint: operation.request_fingerprint.clone(),
    };
    let mut prepared = Vec::with_capacity(batch.actions.len());
    for action in &batch.actions {
        let current = start_slot(&locked, &action.volume().volume_id)?;
        let (updated, receipt) = match action {
            WireStartAction::NormalAcquire {
                volume,
                expected_unowned_epoch,
                transition_id,
                requested_attachment_id,
                lease_duration_ms,
            } => {
                let request = NormalAcquireRequest {
                    volume_id: volume.volume_id.clone(),
                    transition_id: transition_id.clone(),
                    attachment_id: requested_attachment_id.clone(),
                    expected_unowned_epoch: *expected_unowned_epoch,
                    placement_epoch: operation.placement_identity.placement_epoch,
                    lease_duration_ms: lease_duration_ms.get(),
                };
                let Ok((updated, result)) =
                    normal_acquire_with_source(&current.stored.record, &source, &request, now)
                else {
                    return Ok(authority_rejected());
                };
                let receipt = WireStartGrantReceipt {
                    scope: batch.scope.clone(),
                    grant_sequence: batch.grant_sequence,
                    volume: volume.clone(),
                    authority: WireStartGrantAuthority::NormalAcquire { request, result },
                };
                (updated, receipt)
            }
            WireStartAction::RenewSameNode {
                volume,
                attachment_id,
                attachment_epoch,
                lease_duration_ms,
            } => {
                let (expected_source, serving_acquire) =
                    match &current.stored.record.last_transition {
                        Some(LastVolumeTransition::NormalAcquire {
                            source,
                            request,
                            result,
                        }) if matches!(source, VolumeTransitionSource::Lifecycle { .. }) => (
                            source.clone(),
                            WireServingAcquire::Normal {
                                request: request.clone(),
                                result: result.clone(),
                            },
                        ),
                        Some(LastVolumeTransition::Takeover { .. }) => {
                            return Ok(LifecycleVolumeTransitionOutcome::Rejected(
                                LifecycleVolumeTransitionRejection::TakeoverUnavailable,
                            ));
                        }
                        _ => return Ok(authority_rejected()),
                    };
                let request = RenewLeaseRequest {
                    volume_id: volume.volume_id.clone(),
                    attachment_id: attachment_id.clone(),
                    expected_epoch: *attachment_epoch,
                    lease_duration_ms: lease_duration_ms.get(),
                };
                let Ok((updated, result)) = renew_lease(&current.stored.record, &request, now)
                else {
                    return Ok(authority_rejected());
                };
                let receipt = WireStartGrantReceipt {
                    scope: batch.scope.clone(),
                    grant_sequence: batch.grant_sequence,
                    volume: volume.clone(),
                    authority: WireStartGrantAuthority::RenewSameNode {
                        expected_source,
                        serving_acquire: Box::new(serving_acquire),
                        request: WireRenewLeaseRequest {
                            volume_id: request.volume_id,
                            attachment_id: request.attachment_id,
                            expected_epoch: request.expected_epoch,
                            lease_duration_ms: *lease_duration_ms,
                        },
                        result: WireRenewLeaseResult {
                            volume_id: result.volume_id,
                            attachment_id: result.attachment_id,
                            epoch: result.epoch,
                            resulting_head: updated.head.clone(),
                            lease_expires_at: result.lease_expires_at,
                        },
                    },
                };
                (updated, receipt)
            }
            WireStartAction::Takeover { .. } => {
                unreachable!("Takeover returns unavailable before Volume locking")
            }
        };
        cats_storage::lifecycle_volume::encode_command_start_volume_grant_receipt(
            &scope_from_wire(&batch.scope),
            batch.grant_sequence,
            action.volume(),
            &updated,
            &receipt,
        )
        .map_err(|_| backend_unknown())?;
        let binding = VolumeOwnerBinding {
            volume_id: updated.volume_id.clone(),
            owner_node_id: operation.node_id.clone(),
            attachment_id: updated.lease_owner.clone().ok_or_else(backend_unknown)?,
            attachment_epoch: updated.lease_epoch,
        };
        prepared.push((updated, binding, receipt));
    }

    let mut grants = Vec::with_capacity(prepared.len());
    for (updated, binding, receipt) in prepared {
        update_volume_owner(transaction, &updated, Some(&binding))?;
        let receipt_digest = insert_command_start_volume_grant_receipt(
            transaction,
            operation,
            batch.grant_sequence,
            &updated,
            &receipt,
        )?;
        grants.push(WireStoredStartGrant {
            receipt,
            receipt_digest,
        });
    }
    Ok(applied(
        LifecycleVolumeTransitionApplied::StartVolumesReady {
            grant_sequence: batch.grant_sequence,
            grants,
        },
    ))
}

#[derive(Debug, Clone)]
struct LockedStartVolumeSlot {
    stored: StoredVolume,
}

fn lock_start_volume_graph(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleCommandEnvelope,
    batch: &WireStartVolumeBatch,
) -> AuthorityTxResult<Vec<LockedStartVolumeSlot>> {
    let mut actions: Vec<_> = batch.actions.iter().collect();
    actions.sort_by(|left, right| {
        left.volume()
            .volume_id
            .as_str()
            .cmp(right.volume().volume_id.as_str())
    });
    let mut volumes = Vec::with_capacity(actions.len());
    for action in actions {
        let config = action.volume();
        let stored = load_stored_volume_for_update(transaction, &config.volume_id)?
            .ok_or_else(backend_unknown)?;
        if stored.record.volume_id != config.volume_id
            || stored.record.size_bytes != config.size_bytes
            || stored.record.durability != config.durability
            || !matches!(stored.record.admin_state, VolumeAdminState::Active)
        {
            return Err(backend_unknown());
        }
        let authority_matches = match action {
            WireStartAction::NormalAcquire {
                expected_unowned_epoch,
                transition_id,
                requested_attachment_id,
                lease_duration_ms,
                ..
            } => {
                (stored.owner_binding.is_none()
                    && stored.record.lease_owner.is_none()
                    && stored.record.lease_expires_at.is_none()
                    && stored.record.lease_epoch == *expected_unowned_epoch)
                    || matches!(
                        (&stored.owner_binding, &stored.record.last_transition),
                        (
                            Some(binding),
                            Some(LastVolumeTransition::NormalAcquire {
                                source: VolumeTransitionSource::Lifecycle {
                                    operation_id,
                                    request_fingerprint,
                                },
                                request,
                                result,
                            }),
                        ) if operation_id == &operation.operation_id
                            && request_fingerprint == &operation.request_fingerprint
                            && request.volume_id == config.volume_id
                            && request.transition_id == *transition_id
                            && request.attachment_id == *requested_attachment_id
                            && request.expected_unowned_epoch == *expected_unowned_epoch
                            && request.placement_epoch
                                == operation.placement_identity.placement_epoch
                            && request.lease_duration_ms == lease_duration_ms.get()
                            && result.volume_id == config.volume_id
                            && result.transition_id == *transition_id
                            && result.attachment_id == *requested_attachment_id
                            && stored.record.lease_owner.as_ref()
                                == Some(requested_attachment_id)
                            && stored.record.lease_epoch == result.resulting_epoch
                            && binding.owner_node_id == operation.node_id
                            && binding.volume_id == config.volume_id
                            && binding.attachment_id == *requested_attachment_id
                            && binding.attachment_epoch == result.resulting_epoch
                    )
            }
            WireStartAction::RenewSameNode {
                attachment_id,
                attachment_epoch,
                ..
            } => matches!(
                &stored.owner_binding,
                Some(binding) if binding.owner_node_id == operation.node_id
                    && binding.volume_id == config.volume_id
                    && binding.attachment_id == *attachment_id
                    && binding.attachment_epoch == *attachment_epoch
                    && stored.record.lease_owner.as_ref() == Some(attachment_id)
                    && stored.record.lease_epoch == *attachment_epoch
            ),
            WireStartAction::Takeover { .. } => false,
        };
        if !authority_matches {
            return Err(backend_unknown());
        }
        volumes.push(LockedStartVolumeSlot { stored });
    }

    let mut disk_configs: Vec<_> = operation.runtime_config.volumes.iter().collect();
    disk_configs.sort_by(|left, right| left.disk_id.as_str().cmp(right.disk_id.as_str()));
    for config in disk_configs {
        let disk = load_disk_by_id_for_update(transaction, &config.disk_id)?
            .ok_or_else(backend_unknown)?;
        validate_disk_slot(operation, config, &disk)?;
    }
    Ok(volumes)
}

fn start_slot<'a>(
    locked: &'a [LockedStartVolumeSlot],
    volume_id: &Id,
) -> AuthorityTxResult<&'a LockedStartVolumeSlot> {
    locked
        .iter()
        .find(|slot| slot.stored.record.volume_id == *volume_id)
        .ok_or_else(backend_unknown)
}

fn start_grant_matches_action(
    receipt: &WireStartGrantReceipt,
    action: &WireStartAction,
    operation: &LifecycleCommandEnvelope,
) -> bool {
    if receipt.volume != *action.volume()
        || receipt.scope.operation_id != operation.operation_id
        || receipt.scope.request_fingerprint != operation.request_fingerprint
        || receipt.scope.cat_id != operation.cat_id
        || receipt.scope.node_id != operation.node_id
        || receipt.scope.placement_identity != operation.placement_identity
    {
        return false;
    }
    match (action, &receipt.authority) {
        (
            WireStartAction::NormalAcquire {
                expected_unowned_epoch,
                transition_id,
                requested_attachment_id,
                lease_duration_ms,
                ..
            },
            WireStartGrantAuthority::NormalAcquire { request, .. },
        ) => {
            request.expected_unowned_epoch == *expected_unowned_epoch
                && request.transition_id == *transition_id
                && request.attachment_id == *requested_attachment_id
                && request.lease_duration_ms == lease_duration_ms.get()
                && request.placement_epoch == operation.placement_identity.placement_epoch
        }
        (
            WireStartAction::RenewSameNode {
                attachment_id,
                attachment_epoch,
                lease_duration_ms,
                ..
            },
            WireStartGrantAuthority::RenewSameNode { request, .. },
        ) => {
            request.attachment_id == *attachment_id
                && request.expected_epoch == *attachment_epoch
                && request.lease_duration_ms == *lease_duration_ms
        }
        _ => false,
    }
}

fn start_grant_owner(
    receipt: &WireStartGrantReceipt,
) -> Option<(Id, cats_storage::authority::FenceEpoch)> {
    match &receipt.authority {
        WireStartGrantAuthority::NormalAcquire { result, .. } => {
            Some((result.attachment_id.clone(), result.resulting_epoch))
        }
        WireStartGrantAuthority::RenewSameNode { result, .. } => {
            Some((result.attachment_id.clone(), result.epoch))
        }
    }
}

fn discover_delete_completion(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleCommandEnvelope,
    command: &DeleteCommandVolumeSet,
) -> AuthorityTxResult<LifecycleVolumeTransitionOutcome> {
    let Some(stored) = load_command_delete_completion_receipt_for_update(
        transaction,
        &operation.operation_id,
        &command.root_disposition.root.volume_id,
    )?
    else {
        return Ok(LifecycleVolumeTransitionOutcome::Rejected(
            LifecycleVolumeTransitionRejection::CompletionPending,
        ));
    };
    if stored.operation != *operation
        || stored.delete_id != command.root_disposition.delete_id
        || stored.receipt.command != *command
    {
        return Err(backend_unknown());
    }
    Ok(applied(LifecycleVolumeTransitionApplied::DeleteCompleted {
        receipt: Box::new(stored.receipt),
        receipt_digest: stored.receipt_digest,
    }))
}

#[derive(Debug, Clone)]
struct LockedVolumeSlot {
    target: LifecycleVolumeIdentity,
    stored: StoredVolume,
    disk: DiskRecord,
}

fn lock_runtime_volume_graph(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleCommandEnvelope,
    targets: &[LifecycleVolumeIdentity],
) -> AuthorityTxResult<Vec<LockedVolumeSlot>> {
    let mut volume_configs: Vec<_> = operation.runtime_config.volumes.iter().collect();
    volume_configs.sort_by(|left, right| left.volume_id.as_str().cmp(right.volume_id.as_str()));
    let mut volumes = Vec::with_capacity(volume_configs.len());
    for config in volume_configs {
        let target = targets
            .iter()
            .find(|target| target.volume_id == config.volume_id)
            .ok_or_else(backend_unknown)?;
        let stored = load_stored_volume_for_update(transaction, &config.volume_id)?
            .ok_or_else(backend_unknown)?;
        validate_volume_slot(operation, config, target, &stored)?;
        volumes.push((target.clone(), stored));
    }

    let mut disk_configs: Vec<_> = operation.runtime_config.volumes.iter().collect();
    disk_configs.sort_by(|left, right| left.disk_id.as_str().cmp(right.disk_id.as_str()));
    let mut disks = Vec::with_capacity(disk_configs.len());
    for config in disk_configs {
        let disk = load_disk_by_id_for_update(transaction, &config.disk_id)?
            .ok_or_else(backend_unknown)?;
        validate_disk_slot(operation, config, &disk)?;
        disks.push(disk);
    }

    volumes
        .into_iter()
        .map(|(target, stored)| {
            let disk = disks
                .iter()
                .find(|disk| disk.disk_id == target.disk_id)
                .cloned()
                .ok_or_else(backend_unknown)?;
            Ok(LockedVolumeSlot {
                target,
                stored,
                disk,
            })
        })
        .collect()
}

fn apply_cold_release(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleCommandEnvelope,
    command: &ColdCommandVolumeSet,
    inputs: &[RequestedVolumeDispositionInput],
    locked: &[LockedVolumeSlot],
) -> AuthorityTxResult<LifecycleVolumeTransitionOutcome> {
    let current = records_in_target_order(&command.volumes, locked)?;
    let inputs = materialize_disposition_inputs(transaction, inputs, locked)?;
    let Ok((released, receipts)) = release_cold_volume_set(command, &current, &inputs) else {
        return Ok(authority_rejected());
    };
    let dispositions =
        collect_stored_dispositions(transaction, operation, &released, &receipts.dispositions)?;
    Ok(applied(LifecycleVolumeTransitionApplied::ColdReleased {
        dispositions,
    }))
}

fn apply_normal_delete(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleCommandEnvelope,
    command: &DeleteCommandVolumeSet,
    inputs: &[RequestedVolumeDispositionInput],
    locked: &[LockedVolumeSlot],
) -> AuthorityTxResult<LifecycleVolumeTransitionOutcome> {
    if let Some(replayed) = replay_normal_delete(transaction, operation, command, locked)? {
        return Ok(applied(
            LifecycleVolumeTransitionApplied::DeleteNormallyDeleting {
                dispositions: replayed,
            },
        ));
    }
    let root_slot = slot(locked, &command.root_disposition.root.volume_id)?;
    reject_live_root_snapshot(transaction, root_slot)?;
    let targets = delete_release_targets(command);
    let current = records_in_target_order(&targets, locked)?;
    let inputs = materialize_disposition_inputs(transaction, inputs, locked)?;
    let Ok((released, receipts)) = release_delete_normal_volume_set(command, &current, &inputs)
    else {
        return Ok(authority_rejected());
    };
    let dispositions = collect_stored_dispositions(transaction, operation, &released, &receipts)?;

    let released_root = released.first().ok_or_else(backend_unknown)?;
    let request = BeginDeleteRequest {
        delete_id: command.root_disposition.delete_id.clone(),
        disk_id: command.root_disposition.root.disk_id.clone(),
        volume_id: command.root_disposition.root.volume_id.clone(),
        expected_unowned_epoch: released_root.lease_epoch,
        expected_head: released_root.head.clone(),
    };
    let (deleting_root, _) = begin_delete_with_source(
        released_root,
        &VolumeTransitionSource::Lifecycle {
            operation_id: command.scope.operation_id.clone(),
            request_fingerprint: command.scope.request_fingerprint.clone(),
        },
        &request,
    )
    .map_err(|_| cats_storage::authority::AuthorityError::BackendUnknown)?;
    update_volume_owner(transaction, &deleting_root, None)?;
    let mut root_disk = root_slot.disk.clone();
    if !matches!(root_disk.admin_state, DiskAdminState::Active) {
        return Err(backend_unknown());
    }
    root_disk.admin_state = DiskAdminState::Deleting {
        delete_id: command.root_disposition.delete_id.clone(),
    };
    update_disk(transaction, &root_disk)?;
    Ok(applied(
        LifecycleVolumeTransitionApplied::DeleteNormallyDeleting { dispositions },
    ))
}

fn replay_normal_delete(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleCommandEnvelope,
    command: &DeleteCommandVolumeSet,
    locked: &[LockedVolumeSlot],
) -> AuthorityTxResult<Option<Vec<StoredVolumeDisposition>>> {
    let root = slot(locked, &command.root_disposition.root.volume_id)?;
    let VolumeAdminState::Deleting { delete_id } = &root.stored.record.admin_state else {
        return Ok(None);
    };
    if delete_id != &command.root_disposition.delete_id
        || !matches!(
            &root.disk.admin_state,
            DiskAdminState::Deleting { delete_id: disk_delete }
                if disk_delete == &command.root_disposition.delete_id
        )
    {
        return Err(backend_unknown());
    }
    let mut replayed = Vec::new();
    for target in delete_release_targets(command) {
        let normal = load_command_normal_release_receipt_for_update(
            transaction,
            &operation.operation_id,
            &target.volume_id,
        )?;
        let already = load_command_already_unowned_receipt_for_update(
            transaction,
            &operation.operation_id,
            &target.volume_id,
        )?;
        if normal.is_some() == already.is_some() {
            return Err(backend_unknown());
        }
        let current = &slot(locked, &target.volume_id)?.stored.record;
        if let Some(stored) = normal {
            if stored.operation != *operation
                || stored.delete_id.as_ref() != Some(&command.root_disposition.delete_id)
                || stored.receipt.durability.volume.identity() != target
            {
                return Err(backend_unknown());
            }
            let encoded = if target.disk_role == LifecycleDiskRole::Root {
                encode_command_normal_release_receipt_for_deleting_root(
                    command,
                    current,
                    &stored.receipt,
                )
            } else {
                encode_command_normal_release_receipt(
                    &command.scope,
                    &stored.receipt.durability.volume,
                    current,
                    &stored.receipt,
                )
            }
            .map_err(|_| cats_storage::authority::AuthorityError::BackendUnknown)?;
            if encoded.receipt_digest != stored.receipt_digest {
                return Err(backend_unknown());
            }
            replayed.push(StoredVolumeDisposition::NormallyReleased(Box::new(
                StoredNormalReleaseReceipt {
                    receipt: stored.receipt,
                    receipt_digest: stored.receipt_digest,
                },
            )));
        } else if let Some(stored) = already {
            if stored.operation != *operation
                || stored.delete_id.as_ref() != Some(&command.root_disposition.delete_id)
                || stored.receipt.volume != target
            {
                return Err(backend_unknown());
            }
            let encoded = if target.disk_role == LifecycleDiskRole::Root {
                cats_storage::lifecycle_volume::encode_command_delete_already_unowned_receipt_for_deleting_root(
                    command,
                    current,
                    &stored.receipt,
                )
            } else {
                cats_storage::lifecycle_volume::encode_command_delete_already_unowned_receipt(
                    &command.scope,
                    &target,
                    current,
                    &stored.receipt,
                )
            }
            .map_err(|_| cats_storage::authority::AuthorityError::BackendUnknown)?;
            if encoded.receipt_digest != stored.receipt_digest {
                return Err(backend_unknown());
            }
            replayed.push(StoredVolumeDisposition::AlreadyUnowned(Box::new(
                StoredAlreadyUnownedReceipt {
                    receipt: stored.receipt,
                    receipt_digest: stored.receipt_digest,
                },
            )));
        }
    }
    Ok(Some(replayed))
}

#[allow(clippy::too_many_arguments)]
fn apply_disposable_delete(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleCommandEnvelope,
    command: &DeleteCommandVolumeSet,
    persistent_inputs: &[RequestedVolumeDispositionInput],
    root_durability: &CommandVolumeDurabilityProof,
    strong_stop: &LifecycleVolumeStrongStopEvidence,
    locked: &[LockedVolumeSlot],
) -> AuthorityTxResult<LifecycleVolumeTransitionOutcome> {
    let root_slot = slot(locked, &command.root_disposition.root.volume_id)?;
    reject_live_root_snapshot(transaction, root_slot)?;

    // Close the complete Persistent set before constructing any Root
    // destructive authority. These helpers are pure, so every rejection up to
    // and including the Root transition remains zero-write.
    let persistent_records = command
        .persistent_volumes
        .iter()
        .map(|target| slot(locked, &target.volume_id).map(|slot| slot.stored.record.clone()))
        .collect::<AuthorityTxResult<Vec<_>>>()?;
    let persistent_inputs = materialize_disposition_inputs(transaction, persistent_inputs, locked)?;
    let Ok((preview_persistent, preview_receipts)) =
        release_delete_persistent_volume_set(command, &persistent_records, &persistent_inputs)
    else {
        return Ok(authority_rejected());
    };
    let persistent_dispositions_digest =
        persistent_delete_dispositions_digest(command, &preview_persistent, &preview_receipts)
            .map_err(|_| backend_unknown())?;
    let now = database_now(transaction)?;
    let LifecycleCommand::Delete(delete_spec) = &operation.command else {
        return Err(backend_unknown());
    };
    let authorization_id = disposable_authorization_id(command)?;
    let execution_absence_digest = execution_absence_proof_digest(
        &scope_to_wire(&command.scope),
        &strong_stop.execution_absence,
    )
    .map_err(|_| backend_unknown())?;
    let proposed = AuthorizationRecord {
        authorization: VolumeAuthorization::DisposableRootDelete(
            DisposableRootDeleteAuthorization {
                authorization_id: authorization_id.clone(),
                operation_id: command.scope.operation_id.clone(),
                request_fingerprint: command.scope.request_fingerprint.clone(),
                authorized_node_id: command.scope.node_id.clone(),
                delete_id: command.root_disposition.delete_id.clone(),
                disk_id: command.root_disposition.root.disk_id.clone(),
                volume_id: command.root_disposition.root.volume_id.clone(),
                cat_id: command.scope.cat_id.clone(),
                placement_epoch: command.scope.placement_identity.placement_epoch,
                expected_attachment_id: root_durability.volume.attachment_id.clone(),
                expected_epoch: root_durability.volume.attachment_epoch,
                expected_head: root_durability.remote_head.clone(),
                disposition: DisposableRootDisposition::DiscardWithCat,
                persistent_dispositions_digest,
                isolation_basis: DisposableDeleteIsolationBasis::LifecycleStrongStop {
                    node_id: command.scope.node_id.clone(),
                    agent_session_epoch: strong_stop
                        .post_stop_inventory_attestation
                        .session
                        .agent_session_epoch,
                    strong_stop_operation_id: command.scope.operation_id.clone(),
                    strong_stop_receipt_digest: strong_stop
                        .execution_absence
                        .stop_fence_receipt_digest
                        .clone(),
                    execution_absence_proof_digest: execution_absence_digest,
                    inventory_attestation_digest: strong_stop
                        .post_stop_inventory_attestation
                        .inventory_digest
                        .clone(),
                },
                not_after: delete_spec.convergence_deadline_unix_ms,
            },
        ),
        state: AuthorizationState::Unconsumed,
    };
    let existing = load_authorization_for_update(transaction, &authorization_id)?;
    let authorization = match &existing {
        Some(existing) if existing.authorization == proposed.authorization => existing.clone(),
        Some(_) => return Ok(authority_rejected()),
        None => proposed.clone(),
    };
    let bound = CommandBoundDisposableRootAuthorization {
        scope: command.scope.clone(),
        authorization: authorization.clone(),
    };
    let input = DeleteDisposableRootInput {
        command: command.clone(),
        persistent_volumes: persistent_inputs,
        root_durability: root_durability.clone(),
        root_authorization: bound,
    };
    let Ok(outcome) = begin_delete_disposable_root(
        &persistent_records,
        &root_slot.stored.record,
        None,
        &input,
        now,
    ) else {
        return Ok(authority_rejected());
    };
    if outcome.persistent_volumes != preview_persistent
        || outcome.receipt.persistent_dispositions != preview_receipts
        || outcome.receipt.root_begin.persistent_dispositions_digest
            != match &proposed.authorization {
                VolumeAuthorization::DisposableRootDelete(payload) => {
                    payload.persistent_dispositions_digest.clone()
                }
                VolumeAuthorization::Takeover(_) => return Err(backend_unknown()),
            }
    {
        return Err(backend_unknown());
    }

    if existing.is_none() {
        insert_authorization(transaction, &proposed)?;
    }

    let persistent_dispositions = collect_stored_dispositions(
        transaction,
        operation,
        &outcome.persistent_volumes,
        &outcome.receipt.persistent_dispositions,
    )?;
    update_volume_owner(transaction, &outcome.root_volume, None)?;
    if outcome.root_authorization.authorization != authorization {
        update_authorization(
            transaction,
            &authorization,
            &outcome.root_authorization.authorization,
        )?;
    }
    let mut root_disk = root_slot.disk.clone();
    match &root_disk.admin_state {
        DiskAdminState::Active => {
            root_disk.admin_state = DiskAdminState::Deleting {
                delete_id: command.root_disposition.delete_id.clone(),
            };
            update_disk(transaction, &root_disk)?;
        }
        DiskAdminState::Deleting { delete_id }
            if delete_id == &command.root_disposition.delete_id
                && outcome.root_volume == root_slot.stored.record
                && outcome.root_authorization.authorization == authorization => {}
        _ => return Err(backend_unknown()),
    }
    let digest = insert_command_disposable_authorization_consumed_receipt(
        transaction,
        operation,
        &outcome.root_volume,
        &outcome.root_authorization,
        &outcome.receipt.root_begin,
    )?;
    Ok(applied(
        LifecycleVolumeTransitionApplied::DeleteDisposableRootDeleting {
            persistent_dispositions,
            authorization_id: authorization_id.clone(),
            authorization_consumed_receipt_digest: digest,
        },
    ))
}

fn materialize_disposition_inputs(
    transaction: &mut Transaction<'_>,
    requested: &[RequestedVolumeDispositionInput],
    locked: &[LockedVolumeSlot],
) -> AuthorityTxResult<Vec<LifecycleVolumeDispositionInput>> {
    requested
        .iter()
        .map(|input| match input {
            RequestedVolumeDispositionInput::OwnedRelease(release) => {
                Ok(LifecycleVolumeDispositionInput::OwnedRelease {
                    release: release.as_ref().clone(),
                })
            }
            RequestedVolumeDispositionInput::AlreadyUnowned {
                volume,
                expected_epoch,
                expected_head,
            } => {
                let current = &slot(locked, &volume.volume_id)?.stored.record;
                let provenance = match &current.last_transition {
                    None => AlreadyUnownedProvenance::Pristine,
                    Some(LastVolumeTransition::Release { source, .. }) => {
                        let VolumeTransitionSource::Lifecycle {
                            operation_id,
                            request_fingerprint,
                        } = source
                        else {
                            return Err(backend_unknown());
                        };
                        let stored = load_command_normal_release_receipt_for_update(
                            transaction,
                            operation_id,
                            &volume.volume_id,
                        )?
                        .ok_or_else(backend_unknown)?;
                        if stored.operation.request_fingerprint != *request_fingerprint
                            || stored.receipt.durability.volume.identity() != *volume
                        {
                            return Err(backend_unknown());
                        }
                        let encoded = encode_command_normal_release_receipt(
                            &stored.receipt.durability.scope,
                            &stored.receipt.durability.volume,
                            current,
                            &stored.receipt,
                        )
                        .map_err(|_| backend_unknown())?;
                        if encoded.receipt_digest != stored.receipt_digest {
                            return Err(backend_unknown());
                        }
                        AlreadyUnownedProvenance::NormalRelease {
                            receipt: Box::new(stored.receipt),
                            receipt_digest: stored.receipt_digest,
                        }
                    }
                    _ => return Err(backend_unknown()),
                };
                Ok(LifecycleVolumeDispositionInput::AlreadyUnowned {
                    volume: volume.clone(),
                    expected_epoch: *expected_epoch,
                    expected_head: expected_head.clone(),
                    provenance,
                })
            }
        })
        .collect()
}

fn collect_stored_dispositions(
    transaction: &mut Transaction<'_>,
    operation: &LifecycleCommandEnvelope,
    current: &[VolumeRecord],
    receipts: &[CommandVolumeDispositionReceipt],
) -> AuthorityTxResult<Vec<StoredVolumeDisposition>> {
    if current.len() != receipts.len() {
        return Err(backend_unknown());
    }
    current
        .iter()
        .zip(receipts)
        .map(|(record, receipt)| match receipt {
            CommandVolumeDispositionReceipt::NormallyReleased { receipt } => {
                update_volume_owner(transaction, record, None)?;
                Ok(StoredVolumeDisposition::NormallyReleased(Box::new(
                    StoredNormalReleaseReceipt {
                        receipt: receipt.as_ref().clone(),
                        receipt_digest: insert_command_normal_release_receipt(
                            transaction,
                            operation,
                            record,
                            receipt,
                        )?,
                    },
                )))
            }
            CommandVolumeDispositionReceipt::AlreadyUnowned { receipt } => Ok(
                StoredVolumeDisposition::AlreadyUnowned(Box::new(StoredAlreadyUnownedReceipt {
                    receipt: receipt.as_ref().clone(),
                    receipt_digest: insert_command_already_unowned_receipt(
                        transaction,
                        operation,
                        record,
                        receipt,
                    )?,
                })),
            ),
        })
        .collect()
}

fn records_in_target_order(
    targets: &[LifecycleVolumeIdentity],
    locked: &[LockedVolumeSlot],
) -> AuthorityTxResult<Vec<VolumeRecord>> {
    targets
        .iter()
        .map(|target| slot(locked, &target.volume_id).map(|slot| slot.stored.record.clone()))
        .collect()
}

fn disposable_authorization_id(command: &DeleteCommandVolumeSet) -> AuthorityTxResult<Id> {
    const DOMAIN: &[u8] = b"cats.volume-authority.disposable-root-authorization-id.v1";
    let value = serde_json::json!({
        "operation_id": command.scope.operation_id,
        "request_fingerprint": command.scope.request_fingerprint,
        "delete_id": command.root_disposition.delete_id,
        "disk_id": command.root_disposition.root.disk_id,
        "volume_id": command.root_disposition.root.volume_id,
    });
    let canonical = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update([0]);
    hasher.update(canonical);
    let hex = hex::encode(hasher.finalize());
    Id::new(format!("auth_{}", &hex[..32])).ok_or_else(backend_unknown)
}

fn slot<'a>(
    locked: &'a [LockedVolumeSlot],
    volume_id: &Id,
) -> AuthorityTxResult<&'a LockedVolumeSlot> {
    locked
        .iter()
        .find(|slot| slot.target.volume_id == *volume_id)
        .ok_or_else(backend_unknown)
}

fn validate_volume_slot(
    operation: &LifecycleCommandEnvelope,
    config: &cats_api::runtime_lifecycle::RuntimeVolumeConfig,
    target: &LifecycleVolumeIdentity,
    stored: &StoredVolume,
) -> AuthorityTxResult<()> {
    let admin_matches = matches!(stored.record.admin_state, VolumeAdminState::Active)
        || matches!(
            (&operation.command, &config.disk_role, &stored.record.admin_state),
            (
                LifecycleCommand::Delete(spec),
                LifecycleDiskRole::Root,
                VolumeAdminState::Deleting { delete_id }
            ) if delete_id == &spec.delete_id
        );
    if config.volume_id != target.volume_id
        || config.disk_id != target.disk_id
        || config.disk_role != target.disk_role
        || stored.record.volume_id != target.volume_id
        || stored.record.size_bytes != config.size_bytes
        || stored.record.durability != config.durability
        || !admin_matches
    {
        return Err(backend_unknown());
    }
    Ok(())
}

fn validate_disk_slot(
    operation: &LifecycleCommandEnvelope,
    config: &cats_api::runtime_lifecycle::RuntimeVolumeConfig,
    disk: &DiskRecord,
) -> AuthorityTxResult<()> {
    let role_matches = match (&config.disk_role, &disk.role) {
        (LifecycleDiskRole::Root, ProductDiskRole::Root { cat_id }) => cat_id == &operation.cat_id,
        (LifecycleDiskRole::Persistent, ProductDiskRole::Persistent { .. }) => true,
        _ => false,
    };
    if disk.disk_id != config.disk_id
        || disk.workspace_id != operation.workspace_id
        || disk.volume_id != config.volume_id
        || disk.size_bytes != config.size_bytes
        || disk.durability != config.durability
        || !role_matches
    {
        return Err(backend_unknown());
    }
    Ok(())
}

fn reject_live_root_snapshot(
    transaction: &mut Transaction<'_>,
    root: &LockedVolumeSlot,
) -> AuthorityTxResult<()> {
    if load_any_disk_snapshot_for_update(
        transaction,
        &root.disk.disk_id,
        &root.stored.record.volume_id,
        root.disk.size_bytes,
    )?
    .is_some()
    {
        return Err(cats_storage::authority::AuthorityError::SnapshotInUse.into());
    }
    Ok(())
}

fn scope_matches_operation(
    scope: &LifecycleVolumeCommandScope,
    operation: &LifecycleCommandEnvelope,
) -> bool {
    scope.operation_id == operation.operation_id
        && scope.request_fingerprint == operation.request_fingerprint
        && scope.cat_id == operation.cat_id
        && scope.node_id == operation.node_id
        && scope.placement_identity == operation.placement_identity
}

fn targets_match_runtime_config(
    targets: &[LifecycleVolumeIdentity],
    operation: &LifecycleCommandEnvelope,
) -> bool {
    targets.len() == operation.runtime_config.volumes.len()
        && targets
            .iter()
            .zip(&operation.runtime_config.volumes)
            .all(|(target, config)| {
                target.volume_id == config.volume_id
                    && target.disk_id == config.disk_id
                    && target.disk_role == config.disk_role
            })
}

fn delete_command_matches_operation(
    command: &DeleteCommandVolumeSet,
    operation: &LifecycleCommandEnvelope,
) -> bool {
    let LifecycleCommand::Delete(spec) = &operation.command else {
        return false;
    };
    let targets = delete_targets(command);
    command.root_disposition.delete_id == spec.delete_id
        && spec.volume_dispositions.len() == operation.runtime_config.volumes.len()
        && spec
            .volume_dispositions
            .iter()
            .zip(&operation.runtime_config.volumes)
            .all(
                |(disposition, config)| match (disposition, config.disk_role) {
                    (
                        RequestedVolumeDisposition::DiscardWithCat {
                            volume_id,
                            disk_id,
                            disk_role,
                        },
                        LifecycleDiskRole::Root,
                    ) => {
                        *disk_role == LifecycleDiskRole::Root
                            && volume_id == &config.volume_id
                            && disk_id == &config.disk_id
                            && volume_id == &command.root_disposition.root.volume_id
                            && disk_id == &command.root_disposition.root.disk_id
                    }
                    (
                        RequestedVolumeDisposition::RetainDetached {
                            volume_id,
                            disk_id,
                            disk_role,
                        },
                        LifecycleDiskRole::Persistent,
                    ) => {
                        *disk_role == LifecycleDiskRole::Persistent
                            && volume_id == &config.volume_id
                            && disk_id == &config.disk_id
                            && command.persistent_volumes.iter().any(|target| {
                                &target.volume_id == volume_id && &target.disk_id == disk_id
                            })
                    }
                    _ => false,
                },
            )
        && targets_match_runtime_config(&targets, operation)
}

fn delete_targets(command: &DeleteCommandVolumeSet) -> Vec<LifecycleVolumeIdentity> {
    let mut targets = delete_release_targets(command);
    targets.sort_by(|left, right| left.volume_id.as_str().cmp(right.volume_id.as_str()));
    targets
}

fn delete_release_targets(command: &DeleteCommandVolumeSet) -> Vec<LifecycleVolumeIdentity> {
    let mut targets = Vec::with_capacity(1 + command.persistent_volumes.len());
    targets.push(command.root_disposition.root.clone());
    targets.extend(command.persistent_volumes.iter().cloned());
    targets
}

fn invalid_command() -> LifecycleVolumeTransitionOutcome {
    LifecycleVolumeTransitionOutcome::Rejected(
        LifecycleVolumeTransitionRejection::InvalidCommandBinding,
    )
}

fn authority_rejected() -> LifecycleVolumeTransitionOutcome {
    LifecycleVolumeTransitionOutcome::Rejected(
        LifecycleVolumeTransitionRejection::AuthorityRejected,
    )
}

fn stale_inventory() -> LifecycleVolumeTransitionOutcome {
    LifecycleVolumeTransitionOutcome::Rejected(
        LifecycleVolumeTransitionRejection::StaleInventoryAttestation,
    )
}

fn backend_unknown() -> AuthorityTransactionError {
    cats_storage::authority::AuthorityError::BackendUnknown.into()
}
