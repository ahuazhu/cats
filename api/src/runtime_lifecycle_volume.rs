//! Signed, command-scoped Volume Authority transport for atomic lifecycle.
//!
//! This wire is deliberately separate from the retired Desired/revision
//! reconciliation API. Every mutation is bound to one immutable lifecycle
//! Operation and its exact runtime volume set. A disposable Root request
//! carries the full current-session post-strong-stop inventory attestation;
//! an opaque Node-claimed inventory hash is never authorization.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::runtime_lifecycle::{
    DiskRole, ExecutionAbsenceProof, PlacementIdentity, RuntimeVolumeConfig,
    RuntimeVolumeGuestBinding,
};
use crate::runtime_reconciliation::{
    BeginDisposableDeleteConsumedReceipt, ContractVersion, DeleteCompletionReceipt, Epoch,
    FenceEpoch, Generation, Id, NormalAcquireRequest, NormalAcquireResult, RandomId128,
    ReleaseRequest, ReleaseResult, RemoteHead, Sequence, SessionBinding, Sha256Digest, UnixMillis,
    VolumeTransitionSource, WireU64,
};

pub const LIFECYCLE_VOLUME_TRANSITION_METHOD: &str = "POST";
pub const LIFECYCLE_VOLUME_TRANSITION_PATH: &str =
    "/v1/internal/runtime/lifecycle-volume-transitions";
pub const LIFECYCLE_VOLUME_TRANSITION_REQUEST_MAX_WIRE_BYTES: usize = 2 * 1024 * 1024;
pub const LIFECYCLE_VOLUME_TRANSITION_RESPONSE_MAX_WIRE_BYTES: usize = 2 * 1024 * 1024;
pub const LIFECYCLE_VOLUME_TRANSITION_MAX_VOLUMES: usize = 64;

const EXECUTION_ABSENCE_PROOF_DIGEST_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.volume-transition.execution-absence.v1";
const PERSISTENT_INITIALIZATION_COMMIT_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.persistent-initialization-commit-receipt.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleVolumeCommandScope {
    pub operation_id: Id,
    pub request_fingerprint: Sha256Digest,
    pub cat_id: Id,
    pub node_id: Id,
    pub placement_identity: PlacementIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleVolumeTarget {
    pub disk_id: Id,
    pub disk_role: DiskRole,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleVolumeIdentity {
    pub disk_id: Id,
    pub disk_role: DiskRole,
    pub volume_id: Id,
}

impl LifecycleVolumeTarget {
    #[must_use]
    pub fn identity(&self) -> LifecycleVolumeIdentity {
        LifecycleVolumeIdentity {
            disk_id: self.disk_id.clone(),
            disk_role: self.disk_role,
            volume_id: self.volume_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleVolumeDurabilityProof {
    pub scope: LifecycleVolumeCommandScope,
    pub volume: LifecycleVolumeTarget,
    pub remote_head: RemoteHead,
    pub local_durable_generation: Generation,
    pub remote_durable_generation: Generation,
    pub pending_pack_count: WireU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleNormalReleaseInput {
    pub durability: LifecycleVolumeDurabilityProof,
    pub transition_id: RandomId128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCommandNormalReleaseReceipt {
    pub durability: LifecycleVolumeDurabilityProof,
    pub request: ReleaseRequest,
    pub result: ReleaseResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStoredNormalReleaseReceipt {
    pub receipt: LifecycleCommandNormalReleaseReceipt,
    pub receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleAlreadyUnownedProvenance {
    Pristine,
    NormalRelease {
        receipt: Box<LifecycleCommandNormalReleaseReceipt>,
        receipt_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCommandAlreadyUnownedReceipt {
    pub scope: LifecycleVolumeCommandScope,
    pub volume: LifecycleVolumeIdentity,
    pub expected_epoch: FenceEpoch,
    pub expected_head: RemoteHead,
    pub provenance: LifecycleAlreadyUnownedProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStoredAlreadyUnownedReceipt {
    pub receipt: LifecycleCommandAlreadyUnownedReceipt,
    pub receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleVolumeDispositionInput {
    OwnedRelease {
        release: Box<LifecycleNormalReleaseInput>,
    },
    AlreadyUnowned {
        volume: LifecycleVolumeIdentity,
        expected_epoch: FenceEpoch,
        expected_head: RemoteHead,
    },
}

impl LifecycleVolumeDispositionInput {
    pub fn volume(&self) -> LifecycleVolumeIdentity {
        match self {
            Self::OwnedRelease { release } => release.durability.volume.identity(),
            Self::AlreadyUnowned { volume, .. } => volume.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleStoredVolumeDisposition {
    NormallyReleased {
        release: Box<LifecycleStoredNormalReleaseReceipt>,
    },
    AlreadyUnowned {
        receipt: Box<LifecycleStoredAlreadyUnownedReceipt>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleColdVolumeSet {
    pub scope: LifecycleVolumeCommandScope,
    pub volumes: Vec<LifecycleVolumeIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleDefaultRootDiscardDisposition {
    pub root: LifecycleVolumeIdentity,
    pub delete_id: Id,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleDeleteVolumeSet {
    pub scope: LifecycleVolumeCommandScope,
    pub root_disposition: LifecycleDefaultRootDiscardDisposition,
    pub persistent_volumes: Vec<LifecycleVolumeIdentity>,
}

/// Session-bound attestation that one complete physical inventory scan was
/// accepted, carried by the disposable Root arm below.
///
/// This is the only surviving piece of the retired observation contract: the
/// disposable Root authorization compares it exactly, including its
/// AgentSession, and persists its `inventory_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInventoryAttestation {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub inventory_epoch: Epoch,
    pub scan_id: RandomId128,
    pub inventory_digest: Sha256Digest,
    pub source_report_id: RandomId128,
    pub source_sequence: Sequence,
    pub accepted_at_unix_ms: UnixMillis,
}

/// Exact evidence used by the reachable-Host disposable Root arm.
///
/// `post_stop_inventory_attestation` is the complete attestation returned by
/// Control after accepting a fresh Full report. The transition transaction
/// must load the current authoritative Full row and compare the attestation
/// exactly, including its AgentSession. Its `inventory_digest` is the value
/// persisted into the disposable authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleVolumeStrongStopEvidence {
    pub execution_absence: ExecutionAbsenceProof,
    pub post_stop_inventory_attestation: RuntimeInventoryAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleStartVolumeAction {
    NormalAcquire {
        volume: RuntimeVolumeConfig,
        expected_unowned_epoch: FenceEpoch,
        transition_id: RandomId128,
        requested_attachment_id: Id,
        lease_duration_ms: WireU64,
    },
    RenewSameNode {
        volume: RuntimeVolumeConfig,
        attachment_id: Id,
        attachment_epoch: FenceEpoch,
        lease_duration_ms: WireU64,
    },
    Takeover {
        volume: RuntimeVolumeConfig,
        authorization_id: Id,
    },
}

impl LifecycleStartVolumeAction {
    pub fn volume(&self) -> &RuntimeVolumeConfig {
        match self {
            Self::NormalAcquire { volume, .. }
            | Self::RenewSameNode { volume, .. }
            | Self::Takeover { volume, .. } => volume,
        }
    }

    pub fn lease_duration_ms(&self) -> Option<WireU64> {
        match self {
            Self::NormalAcquire {
                lease_duration_ms, ..
            }
            | Self::RenewSameNode {
                lease_duration_ms, ..
            } => Some(*lease_duration_ms),
            Self::Takeover { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStartVolumeBatch {
    pub scope: LifecycleVolumeCommandScope,
    /// Durable, strictly monotonic Start-local grant round. Sequence zero is
    /// the initial acquire/owned verification; every later renewal uses the
    /// exact checked successor and replays only its own immutable row set.
    pub grant_sequence: WireU64,
    pub renewal_lease_duration_ms: WireU64,
    pub actions: Vec<LifecycleStartVolumeAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRenewLeaseRequest {
    pub volume_id: Id,
    pub attachment_id: Id,
    pub expected_epoch: FenceEpoch,
    pub lease_duration_ms: WireU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRenewLeaseResult {
    pub volume_id: Id,
    pub attachment_id: Id,
    pub epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
    pub lease_expires_at: UnixMillis,
}

/// Immutable receipt written with one Start-owned acquire or renew. A renew
/// retains the exact prior acquire/takeover source rather than overwriting the
/// Volume row's lineage marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleServingAcquire {
    Normal {
        request: NormalAcquireRequest,
        result: NormalAcquireResult,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleStartVolumeGrantAuthority {
    NormalAcquire {
        request: NormalAcquireRequest,
        result: NormalAcquireResult,
    },
    RenewSameNode {
        expected_source: VolumeTransitionSource,
        /// Complete immutable acquire marker required by the Node to join
        /// this authority half with local lineage/object-write evidence into
        /// one `AuthorizedServingAttachment` after a renewal.
        serving_acquire: Box<LifecycleServingAcquire>,
        request: LifecycleRenewLeaseRequest,
        result: LifecycleRenewLeaseResult,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCommandStartVolumeGrantReceipt {
    pub scope: LifecycleVolumeCommandScope,
    pub grant_sequence: WireU64,
    pub volume: RuntimeVolumeConfig,
    pub authority: LifecycleStartVolumeGrantAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStoredStartVolumeGrant {
    pub receipt: LifecycleCommandStartVolumeGrantReceipt,
    pub receipt_digest: Sha256Digest,
}

/// Exact Start/config/authority identity used by both PersistentDisk
/// initialization reads and the one-way initialization commit.
///
/// AgentSession is deliberately absent: it authenticates each outer
/// transport request, but replacement of a session must not create a second
/// initialization identity or change an already committed result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecyclePersistentInitializationBinding {
    pub scope: LifecycleVolumeCommandScope,
    pub runtime_config_id: Id,
    pub runtime_config_digest: Sha256Digest,
    pub volume: RuntimeVolumeConfig,
    pub start_grant: LifecycleStoredStartVolumeGrant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecyclePersistentInitializationInspectRequest {
    pub binding: Box<LifecyclePersistentInitializationBinding>,
}

/// Closed product initialization lineage returned by the signed inspect.
/// Both variants retain the original create-time tuple, so a caller never
/// infers initialization from the current Volume head alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecyclePersistentInitializationState {
    Uninitialized {
        initialization_token: RandomId128,
        filesystem_uuid: RandomId128,
        expected_blank_head: RemoteHead,
    },
    Initialized {
        initialization_token: RandomId128,
        filesystem_uuid: RandomId128,
        expected_blank_head: RemoteHead,
        initialized_head: RemoteHead,
        initialized_at: UnixMillis,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecyclePersistentInitializationInspection {
    pub binding: Box<LifecyclePersistentInitializationBinding>,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub current_head: RemoteHead,
    pub initialization: LifecyclePersistentInitializationState,
}

/// Exact Guest-side filesystem state accepted immediately before the
/// initialization commit. The disk is still unmounted at this barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecyclePersistentGuestFilesystemState {
    ExactExt4Unmounted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecyclePersistentInitializationGuestProbe {
    pub challenge: RandomId128,
    pub runtime_incarnation: RandomId128,
    pub guest_device_serial: Id,
    pub guest_device_slot: u16,
    pub device_major: u32,
    pub device_minor: u32,
    pub size_bytes: u64,
    pub filesystem_uuid: RandomId128,
    pub filesystem_state: LifecyclePersistentGuestFilesystemState,
    pub guest_response_digest: Sha256Digest,
}

/// Complete post-format durability barrier. `durability` binds the exact
/// attachment and proves the nonblank new head has `L == R` with no pending
/// pack after the Guest device flush and blockd drain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecyclePersistentInitializationFlushDrainReceipt {
    pub guest_flush_challenge: RandomId128,
    pub guest_flush_response_digest: Sha256Digest,
    pub blockd_drain_receipt_digest: Sha256Digest,
    pub durability: LifecycleVolumeDurabilityProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecyclePersistentInitializationCommitRequest {
    pub binding: Box<LifecyclePersistentInitializationBinding>,
    /// Exact durable Node format-effect plan which owns the Guest evidence.
    /// Control treats it as signed evidence; the Node client must compare it
    /// with the journaled plan before sending.
    pub format_plan_digest: Sha256Digest,
    pub initialization_token: RandomId128,
    pub filesystem_uuid: RandomId128,
    pub expected_blank_head: RemoteHead,
    pub initialized_head: RemoteHead,
    pub guest_probe: Box<LifecyclePersistentInitializationGuestProbe>,
    pub flush_drain: Box<LifecyclePersistentInitializationFlushDrainReceipt>,
}

/// Exact replayable result. PostgreSQL stores the same tuple in the Disk row;
/// no second initialization ledger or Operation exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecyclePersistentInitializationCommitReceipt {
    pub request: Box<LifecyclePersistentInitializationCommitRequest>,
    pub initialized_at: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStoredPersistentInitializationCommit {
    pub receipt: LifecyclePersistentInitializationCommitReceipt,
    pub receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleVolumeTransitionRequestKind {
    StartVolumes {
        batch: Box<LifecycleStartVolumeBatch>,
    },
    InspectPersistentInitialization {
        inspect: Box<LifecyclePersistentInitializationInspectRequest>,
    },
    CommitPersistentInitialization {
        commit: Box<LifecyclePersistentInitializationCommitRequest>,
    },
    ColdRelease {
        command: LifecycleColdVolumeSet,
        volumes: Vec<LifecycleVolumeDispositionInput>,
        strong_stop: Box<LifecycleVolumeStrongStopEvidence>,
    },
    DeleteNormal {
        command: LifecycleDeleteVolumeSet,
        volumes: Vec<LifecycleVolumeDispositionInput>,
        strong_stop: Box<LifecycleVolumeStrongStopEvidence>,
    },
    DeleteDisposableRoot {
        command: LifecycleDeleteVolumeSet,
        persistent_volumes: Vec<LifecycleVolumeDispositionInput>,
        root_durability: Box<LifecycleVolumeDurabilityProof>,
        strong_stop: Box<LifecycleVolumeStrongStopEvidence>,
    },
    DiscoverDeleteCompletion {
        command: LifecycleDeleteVolumeSet,
    },
}

impl LifecycleVolumeTransitionRequestKind {
    pub fn scope(&self) -> &LifecycleVolumeCommandScope {
        match self {
            Self::StartVolumes { batch } => &batch.scope,
            Self::InspectPersistentInitialization { inspect } => &inspect.binding.scope,
            Self::CommitPersistentInitialization { commit } => &commit.binding.scope,
            Self::ColdRelease { command, .. } => &command.scope,
            Self::DeleteNormal { command, .. }
            | Self::DeleteDisposableRoot { command, .. }
            | Self::DiscoverDeleteCompletion { command } => &command.scope,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleVolumeTransitionRequest {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub transition: LifecycleVolumeTransitionRequestKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCommandDisposableAuthorizationConsumedReceipt {
    pub command: LifecycleDeleteVolumeSet,
    pub authorization_id: Id,
    pub persistent_dispositions_digest: Sha256Digest,
    pub receipt: BeginDisposableDeleteConsumedReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "receipt",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LifecycleCommandRootDeleteAuthorityReceipt {
    NormalRelease(LifecycleCommandNormalReleaseReceipt),
    AlreadyUnowned(LifecycleCommandAlreadyUnownedReceipt),
    DisposableAuthorizationConsumed(LifecycleCommandDisposableAuthorizationConsumedReceipt),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCommandDeleteCompletionReceipt {
    pub command: LifecycleDeleteVolumeSet,
    pub root_authority: LifecycleCommandRootDeleteAuthorityReceipt,
    pub completion: DeleteCompletionReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleDeleteCompletionEvidence {
    pub receipt: LifecycleCommandDeleteCompletionReceipt,
    pub receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleVolumeTransitionApplied {
    StartVolumesReady {
        grant_sequence: WireU64,
        grants: Vec<LifecycleStoredStartVolumeGrant>,
    },
    PersistentInitializationInspected {
        inspection: Box<LifecyclePersistentInitializationInspection>,
    },
    PersistentInitializationCommitted {
        committed: Box<LifecycleStoredPersistentInitializationCommit>,
    },
    ColdReleased {
        dispositions: Vec<LifecycleStoredVolumeDisposition>,
    },
    DeleteNormallyDeleting {
        dispositions: Vec<LifecycleStoredVolumeDisposition>,
    },
    DeleteDisposableRootDeleting {
        persistent_dispositions: Vec<LifecycleStoredVolumeDisposition>,
        authorization_id: Id,
        authorization_consumed_receipt_digest: Sha256Digest,
    },
    DeleteCompleted {
        completion: Box<LifecycleDeleteCompletionEvidence>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleVolumeTransitionRejection {
    StaleSession,
    StaleInventoryAttestation,
    InvalidCommandBinding,
    AuthorityRejected,
    CompletionPending,
    TakeoverUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleVolumeTransitionResult {
    Applied {
        applied: LifecycleVolumeTransitionApplied,
    },
    Rejected {
        reason: LifecycleVolumeTransitionRejection,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleVolumeTransitionResponse {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub operation_id: Id,
    pub request_fingerprint: Sha256Digest,
    pub result: LifecycleVolumeTransitionResult,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeLifecycleVolumeContractError {
    #[error("malformed lifecycle Volume transition wire")]
    Malformed,
    #[error("unsupported lifecycle Volume transition version")]
    UnsupportedVersion,
    #[error("invalid lifecycle Volume transition contract")]
    InvalidContract,
    #[error("lifecycle Volume transition wire exceeds its bounded size")]
    WireTooLarge,
}

pub fn execution_absence_proof_digest(
    scope: &LifecycleVolumeCommandScope,
    proof: &ExecutionAbsenceProof,
) -> Result<Sha256Digest, RuntimeLifecycleVolumeContractError> {
    validate_scope(scope)?;
    let value = serde_json::json!({ "scope": scope, "proof": proof });
    let canonical = crate::runtime_reconciliation::canonical_json_value_bytes(&value);
    let mut hasher = Sha256::new();
    hasher.update(EXECUTION_ABSENCE_PROOF_DIGEST_DOMAIN);
    hasher.update([0]);
    hasher.update(canonical);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

pub fn persistent_initialization_commit_receipt_digest(
    receipt: &LifecyclePersistentInitializationCommitReceipt,
) -> Result<Sha256Digest, RuntimeLifecycleVolumeContractError> {
    validate_persistent_initialization_commit(&receipt.request)?;
    let value = serde_json::to_value(receipt)
        .map_err(|_| RuntimeLifecycleVolumeContractError::InvalidContract)?;
    let canonical = crate::runtime_reconciliation::canonical_json_value_bytes(&value);
    let mut hasher = Sha256::new();
    hasher.update(PERSISTENT_INITIALIZATION_COMMIT_RECEIPT_DIGEST_DOMAIN);
    hasher.update([0]);
    hasher.update(canonical);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

pub fn encode_persistent_initialization_commit_receipt(
    receipt: &LifecyclePersistentInitializationCommitReceipt,
) -> Result<Vec<u8>, RuntimeLifecycleVolumeContractError> {
    persistent_initialization_commit_receipt_digest(receipt)?;
    encode_canonical(receipt, LIFECYCLE_VOLUME_TRANSITION_RESPONSE_MAX_WIRE_BYTES)
}

pub fn validate_lifecycle_persistent_initialization_binding(
    binding: &LifecyclePersistentInitializationBinding,
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    validate_persistent_initialization_binding(binding)
}

pub fn lifecycle_persistent_initialization_original_blank_head(
    binding: &LifecyclePersistentInitializationBinding,
) -> Result<RemoteHead, RuntimeLifecycleVolumeContractError> {
    validate_persistent_initialization_binding(binding)?;
    Ok(persistent_initialization_original_blank_head(&binding.start_grant.receipt)?.clone())
}

pub fn validate_lifecycle_persistent_initialization_commit(
    commit: &LifecyclePersistentInitializationCommitRequest,
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    validate_persistent_initialization_commit(commit)
}

pub fn encode_lifecycle_volume_transition_request(
    request: &LifecycleVolumeTransitionRequest,
) -> Result<Vec<u8>, RuntimeLifecycleVolumeContractError> {
    validate_lifecycle_volume_transition_request(request)?;
    encode_canonical(request, LIFECYCLE_VOLUME_TRANSITION_REQUEST_MAX_WIRE_BYTES)
}

pub fn decode_lifecycle_volume_transition_request(
    bytes: &[u8],
) -> Result<LifecycleVolumeTransitionRequest, RuntimeLifecycleVolumeContractError> {
    decode_canonical(
        bytes,
        LIFECYCLE_VOLUME_TRANSITION_REQUEST_MAX_WIRE_BYTES,
        validate_lifecycle_volume_transition_request,
    )
}

pub fn encode_lifecycle_volume_transition_response(
    response: &LifecycleVolumeTransitionResponse,
) -> Result<Vec<u8>, RuntimeLifecycleVolumeContractError> {
    validate_lifecycle_volume_transition_response(response)?;
    encode_canonical(
        response,
        LIFECYCLE_VOLUME_TRANSITION_RESPONSE_MAX_WIRE_BYTES,
    )
}

pub fn decode_lifecycle_volume_transition_response(
    bytes: &[u8],
) -> Result<LifecycleVolumeTransitionResponse, RuntimeLifecycleVolumeContractError> {
    decode_canonical(
        bytes,
        LIFECYCLE_VOLUME_TRANSITION_RESPONSE_MAX_WIRE_BYTES,
        validate_lifecycle_volume_transition_response,
    )
}

pub fn validate_lifecycle_volume_transition_request(
    request: &LifecycleVolumeTransitionRequest,
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    if request.version != ContractVersion::V1 {
        return Err(RuntimeLifecycleVolumeContractError::UnsupportedVersion);
    }
    let scope = request.transition.scope();
    validate_scope(scope)?;
    if scope.node_id != request.session.node_id
        || scope.placement_identity.node_id != request.session.node_id
    {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    }
    match &request.transition {
        LifecycleVolumeTransitionRequestKind::StartVolumes { batch } => validate_start_batch(batch),
        LifecycleVolumeTransitionRequestKind::InspectPersistentInitialization { inspect } => {
            validate_persistent_initialization_binding(&inspect.binding)
        }
        LifecycleVolumeTransitionRequestKind::CommitPersistentInitialization { commit } => {
            validate_persistent_initialization_commit(commit)
        }
        LifecycleVolumeTransitionRequestKind::ColdRelease {
            command,
            volumes,
            strong_stop,
        } => {
            validate_cold_command(command)?;
            validate_strong_stop(&request.session, strong_stop)?;
            validate_disposition_inputs(&command.scope, &command.volumes, volumes)
        }
        LifecycleVolumeTransitionRequestKind::DeleteNormal {
            command,
            volumes,
            strong_stop,
        } => {
            validate_delete_command(command)?;
            validate_strong_stop(&request.session, strong_stop)?;
            validate_disposition_inputs(&command.scope, &delete_release_targets(command), volumes)
        }
        LifecycleVolumeTransitionRequestKind::DeleteDisposableRoot {
            command,
            persistent_volumes,
            root_durability,
            strong_stop,
        } => {
            validate_delete_command(command)?;
            validate_strong_stop(&request.session, strong_stop)?;
            validate_disposition_inputs(
                &command.scope,
                &command.persistent_volumes,
                persistent_volumes,
            )?;
            validate_durability(
                &command.scope,
                &LifecycleVolumeTarget {
                    disk_id: root_durability.volume.disk_id.clone(),
                    disk_role: root_durability.volume.disk_role,
                    volume_id: root_durability.volume.volume_id.clone(),
                    attachment_id: root_durability.volume.attachment_id.clone(),
                    attachment_epoch: root_durability.volume.attachment_epoch,
                },
                root_durability,
            )?;
            if root_durability.volume.identity() != command.root_disposition.root
                || root_durability.remote_durable_generation
                    >= root_durability.local_durable_generation
            {
                return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
            }
            Ok(())
        }
        LifecycleVolumeTransitionRequestKind::DiscoverDeleteCompletion { command } => {
            validate_delete_command(command)
        }
    }
}

pub fn validate_lifecycle_volume_transition_response(
    response: &LifecycleVolumeTransitionResponse,
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    if response.version != ContractVersion::V1
        || response.session.node_id.as_str().is_empty()
        || response.operation_id.as_str().is_empty()
    {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    }
    match &response.result {
        LifecycleVolumeTransitionResult::Rejected { .. } => Ok(()),
        LifecycleVolumeTransitionResult::Applied { applied } => match applied {
            LifecycleVolumeTransitionApplied::StartVolumesReady {
                grant_sequence,
                grants,
            } => {
                if grants.is_empty()
                    || grants.len() > LIFECYCLE_VOLUME_TRANSITION_MAX_VOLUMES
                    || !grants.windows(2).all(|pair| {
                        pair[0].receipt.volume.volume_id.as_str()
                            < pair[1].receipt.volume.volume_id.as_str()
                    })
                    || grants.iter().any(|grant| {
                        grant.receipt.scope.operation_id != response.operation_id
                            || grant.receipt.scope.request_fingerprint
                                != response.request_fingerprint
                            || grant.receipt.grant_sequence != *grant_sequence
                    })
                {
                    return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
                }
                Ok(())
            }
            LifecycleVolumeTransitionApplied::PersistentInitializationInspected { inspection } => {
                if inspection.binding.scope.operation_id != response.operation_id
                    || inspection.binding.scope.request_fingerprint != response.request_fingerprint
                {
                    return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
                }
                validate_persistent_initialization_inspection(inspection)
            }
            LifecycleVolumeTransitionApplied::PersistentInitializationCommitted { committed } => {
                if committed.receipt.request.binding.scope.operation_id != response.operation_id
                    || committed.receipt.request.binding.scope.request_fingerprint
                        != response.request_fingerprint
                    || persistent_initialization_commit_receipt_digest(&committed.receipt)?
                        != committed.receipt_digest
                {
                    return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
                }
                Ok(())
            }
            LifecycleVolumeTransitionApplied::ColdReleased { dispositions }
            | LifecycleVolumeTransitionApplied::DeleteNormallyDeleting { dispositions } => {
                validate_stored_dispositions(dispositions)
            }
            LifecycleVolumeTransitionApplied::DeleteDisposableRootDeleting {
                persistent_dispositions,
                ..
            } => validate_stored_dispositions(persistent_dispositions),
            LifecycleVolumeTransitionApplied::DeleteCompleted { completion } => {
                if completion.receipt.command.scope.operation_id != response.operation_id
                    || completion.receipt.command.scope.request_fingerprint
                        != response.request_fingerprint
                {
                    return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
                }
                validate_delete_command(&completion.receipt.command)
            }
        },
    }
}

fn validate_scope(
    scope: &LifecycleVolumeCommandScope,
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    if scope.node_id != scope.placement_identity.node_id {
        Err(RuntimeLifecycleVolumeContractError::InvalidContract)
    } else {
        Ok(())
    }
}

fn validate_cold_command(
    command: &LifecycleColdVolumeSet,
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    validate_scope(&command.scope)?;
    if !valid_sorted_volume_set(&command.volumes)
        || command
            .volumes
            .iter()
            .filter(|target| target.disk_role == DiskRole::Root)
            .count()
            != 1
    {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    }
    Ok(())
}

fn validate_start_batch(
    batch: &LifecycleStartVolumeBatch,
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    validate_scope(&batch.scope)?;
    if batch.renewal_lease_duration_ms.get() == 0
        || batch.actions.is_empty()
        || batch.actions.len() > LIFECYCLE_VOLUME_TRANSITION_MAX_VOLUMES
        || !batch
            .actions
            .windows(2)
            .all(|pair| pair[0].volume().volume_id.as_str() < pair[1].volume().volume_id.as_str())
        || batch.actions.iter().enumerate().any(|(index, action)| {
            batch.actions[index + 1..]
                .iter()
                .any(|other| action.volume().disk_id == other.volume().disk_id)
        })
        || batch.actions.iter().any(|action| {
            action
                .lease_duration_ms()
                .is_some_and(|duration| duration != batch.renewal_lease_duration_ms)
        })
        || batch
            .actions
            .iter()
            .filter(|action| action.volume().disk_role == DiskRole::Root)
            .count()
            != 1
    {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    }
    Ok(())
}

fn validate_persistent_initialization_binding(
    binding: &LifecyclePersistentInitializationBinding,
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    validate_scope(&binding.scope)?;
    let RuntimeVolumeGuestBinding::PersistentExt4 {
        filesystem_uuid, ..
    } = &binding.volume.guest_binding
    else {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    };
    let grant = &binding.start_grant.receipt;
    if binding.volume.disk_role != DiskRole::Persistent
        || digest_is_zero(&binding.scope.request_fingerprint)
        || digest_is_zero(&binding.runtime_config_digest)
        || grant.scope != binding.scope
        || grant.volume != binding.volume
        || grant.volume.disk_role != DiskRole::Persistent
        || !matches!(
            &grant.volume.guest_binding,
            RuntimeVolumeGuestBinding::PersistentExt4 {
                filesystem_uuid: grant_uuid,
                ..
            } if grant_uuid == filesystem_uuid
        )
        || digest_is_zero(&binding.start_grant.receipt_digest)
    {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    }
    persistent_initialization_grant_attachment(grant)?;
    persistent_initialization_original_blank_head(grant).map(|_| ())
}

fn persistent_initialization_grant_attachment(
    grant: &LifecycleCommandStartVolumeGrantReceipt,
) -> Result<(Id, FenceEpoch, RemoteHead), RuntimeLifecycleVolumeContractError> {
    match &grant.authority {
        LifecycleStartVolumeGrantAuthority::NormalAcquire { request, result } => {
            let next_epoch = request
                .expected_unowned_epoch
                .get()
                .checked_add(1)
                .and_then(FenceEpoch::new);
            if grant.grant_sequence.get() != 0
                || request.volume_id != grant.volume.volume_id
                || request.placement_epoch != grant.scope.placement_identity.placement_epoch
                || request.lease_duration_ms == 0
                || result.volume_id != request.volume_id
                || result.transition_id != request.transition_id
                || result.attachment_id != request.attachment_id
                || Some(result.resulting_epoch) != next_epoch
                || !remote_head_valid(&result.resulting_head)
            {
                return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
            }
            Ok((
                result.attachment_id.clone(),
                result.resulting_epoch,
                result.resulting_head.clone(),
            ))
        }
        LifecycleStartVolumeGrantAuthority::RenewSameNode {
            serving_acquire,
            request,
            result,
            ..
        } => {
            let LifecycleServingAcquire::Normal {
                request: acquire_request,
                result: acquire_result,
            } = serving_acquire.as_ref();
            if grant.grant_sequence.get() == 0
                || request.volume_id != grant.volume.volume_id
                || request.lease_duration_ms.get() == 0
                || result.volume_id != request.volume_id
                || result.attachment_id != request.attachment_id
                || result.epoch != request.expected_epoch
                || !remote_head_valid(&result.resulting_head)
                || acquire_request.volume_id != grant.volume.volume_id
                || acquire_request.placement_epoch != grant.scope.placement_identity.placement_epoch
                || acquire_request.attachment_id != request.attachment_id
                || acquire_result.volume_id != acquire_request.volume_id
                || acquire_result.transition_id != acquire_request.transition_id
                || acquire_result.attachment_id != acquire_request.attachment_id
                || acquire_result.resulting_epoch != request.expected_epoch
                || !remote_head_valid(&acquire_result.resulting_head)
            {
                return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
            }
            Ok((
                result.attachment_id.clone(),
                result.epoch,
                result.resulting_head.clone(),
            ))
        }
    }
}

fn persistent_initialization_original_blank_head(
    grant: &LifecycleCommandStartVolumeGrantReceipt,
) -> Result<&RemoteHead, RuntimeLifecycleVolumeContractError> {
    let original = match &grant.authority {
        LifecycleStartVolumeGrantAuthority::NormalAcquire { result, .. } => &result.resulting_head,
        LifecycleStartVolumeGrantAuthority::RenewSameNode {
            serving_acquire, ..
        } => {
            let LifecycleServingAcquire::Normal { result, .. } = serving_acquire.as_ref();
            &result.resulting_head
        }
    };
    if original.generation.get() != 0 || !remote_head_valid(original) {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    }
    Ok(original)
}

fn validate_persistent_initialization_state(
    binding: &LifecyclePersistentInitializationBinding,
    current_head: &RemoteHead,
    state: &LifecyclePersistentInitializationState,
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    let RuntimeVolumeGuestBinding::PersistentExt4 {
        filesystem_uuid: configured_uuid,
        ..
    } = &binding.volume.guest_binding
    else {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    };
    let original_blank =
        persistent_initialization_original_blank_head(&binding.start_grant.receipt)?;
    match state {
        LifecyclePersistentInitializationState::Uninitialized {
            initialization_token,
            filesystem_uuid,
            expected_blank_head,
        } => {
            if initialization_token == filesystem_uuid
                || filesystem_uuid != configured_uuid
                || expected_blank_head.generation.get() != 0
                || !remote_head_valid(expected_blank_head)
                || expected_blank_head != original_blank
                || current_head != expected_blank_head
            {
                return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
            }
        }
        LifecyclePersistentInitializationState::Initialized {
            initialization_token,
            filesystem_uuid,
            expected_blank_head,
            initialized_head,
            ..
        } => {
            if initialization_token == filesystem_uuid
                || filesystem_uuid != configured_uuid
                || expected_blank_head.generation.get() != 0
                || !remote_head_valid(expected_blank_head)
                || expected_blank_head != original_blank
                || initialized_head.generation.get() == 0
                || !remote_head_valid(initialized_head)
                || !remote_head_same_or_later(current_head, initialized_head)
            {
                return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
            }
        }
    }
    Ok(())
}

fn validate_persistent_initialization_inspection(
    inspection: &LifecyclePersistentInitializationInspection,
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    validate_persistent_initialization_binding(&inspection.binding)?;
    let (attachment_id, attachment_epoch, grant_head) =
        persistent_initialization_grant_attachment(&inspection.binding.start_grant.receipt)?;
    if inspection.attachment_id != attachment_id
        || inspection.attachment_epoch != attachment_epoch
        || !remote_head_same_or_later(&inspection.current_head, &grant_head)
    {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    }
    validate_persistent_initialization_state(
        &inspection.binding,
        &inspection.current_head,
        &inspection.initialization,
    )
}

fn validate_persistent_initialization_commit(
    commit: &LifecyclePersistentInitializationCommitRequest,
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    validate_persistent_initialization_binding(&commit.binding)?;
    let RuntimeVolumeGuestBinding::PersistentExt4 {
        filesystem_uuid: configured_uuid,
        ..
    } = &commit.binding.volume.guest_binding
    else {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    };
    let (attachment_id, attachment_epoch, grant_head) =
        persistent_initialization_grant_attachment(&commit.binding.start_grant.receipt)?;
    let original_blank =
        persistent_initialization_original_blank_head(&commit.binding.start_grant.receipt)?;
    let target = LifecycleVolumeTarget {
        disk_id: commit.binding.volume.disk_id.clone(),
        disk_role: DiskRole::Persistent,
        volume_id: commit.binding.volume.volume_id.clone(),
        attachment_id,
        attachment_epoch,
    };
    let proof = &commit.flush_drain.durability;
    if commit.initialization_token == commit.filesystem_uuid
        || &commit.filesystem_uuid != configured_uuid
        || digest_is_zero(&commit.format_plan_digest)
        || digest_is_zero(&commit.guest_probe.guest_response_digest)
        || digest_is_zero(&commit.flush_drain.guest_flush_response_digest)
        || digest_is_zero(&commit.flush_drain.blockd_drain_receipt_digest)
        || commit.expected_blank_head.generation.get() != 0
        || !remote_head_valid(&commit.expected_blank_head)
        || &commit.expected_blank_head != original_blank
        || commit.initialized_head.generation.get() == 0
        || !remote_head_valid(&commit.initialized_head)
        || !remote_head_same_or_later(&commit.initialized_head, &grant_head)
        || commit.guest_probe.guest_device_serial != commit.binding.volume.guest_device_serial
        || commit.guest_probe.guest_device_slot != commit.binding.volume.guest_device_slot
        || commit.guest_probe.size_bytes != commit.binding.volume.size_bytes
        || commit.guest_probe.filesystem_uuid != commit.filesystem_uuid
        || (commit.guest_probe.device_major == 0 && commit.guest_probe.device_minor == 0)
        || proof.volume != target
        || proof.remote_head != commit.initialized_head
        || proof.local_durable_generation != commit.initialized_head.generation
        || proof.remote_durable_generation != commit.initialized_head.generation
        || proof.pending_pack_count.get() != 0
    {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    }
    validate_durability(&commit.binding.scope, &target, proof)
}

fn validate_delete_command(
    command: &LifecycleDeleteVolumeSet,
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    validate_scope(&command.scope)?;
    if command.root_disposition.root.disk_role != DiskRole::Root
        || command.persistent_volumes.len() >= LIFECYCLE_VOLUME_TRANSITION_MAX_VOLUMES
        || !command
            .persistent_volumes
            .iter()
            .all(|target| target.disk_role == DiskRole::Persistent)
        || !strictly_sorted_targets(&command.persistent_volumes)
        || command.persistent_volumes.iter().any(|target| {
            target.volume_id == command.root_disposition.root.volume_id
                || target.disk_id == command.root_disposition.root.disk_id
        })
    {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    }
    Ok(())
}

fn validate_disposition_inputs(
    scope: &LifecycleVolumeCommandScope,
    targets: &[LifecycleVolumeIdentity],
    inputs: &[LifecycleVolumeDispositionInput],
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    if targets.len() != inputs.len() {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    }
    for (target, input) in targets.iter().zip(inputs) {
        if input.volume() != *target {
            return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
        }
        match input {
            LifecycleVolumeDispositionInput::OwnedRelease { release } => {
                validate_durability(scope, &release.durability.volume, &release.durability)?;
                if release.durability.local_durable_generation
                    != release.durability.remote_durable_generation
                    || release.durability.pending_pack_count.get() != 0
                {
                    return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
                }
            }
            LifecycleVolumeDispositionInput::AlreadyUnowned { expected_head, .. } => {
                if !remote_head_valid(expected_head) {
                    return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
                }
            }
        }
    }
    Ok(())
}

fn validate_durability(
    scope: &LifecycleVolumeCommandScope,
    target: &LifecycleVolumeTarget,
    proof: &LifecycleVolumeDurabilityProof,
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    if proof.scope != *scope
        || proof.volume != *target
        || proof.remote_durable_generation != proof.remote_head.generation
        || !remote_head_valid(&proof.remote_head)
    {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    }
    Ok(())
}

fn validate_strong_stop(
    session: &SessionBinding,
    evidence: &LifecycleVolumeStrongStopEvidence,
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    let attestation = &evidence.post_stop_inventory_attestation;
    if attestation.version != ContractVersion::V1 || attestation.session != *session {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    }
    Ok(())
}

fn validate_stored_dispositions(
    dispositions: &[LifecycleStoredVolumeDisposition],
) -> Result<(), RuntimeLifecycleVolumeContractError> {
    if dispositions.len() > LIFECYCLE_VOLUME_TRANSITION_MAX_VOLUMES {
        return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
    }
    for disposition in dispositions {
        match disposition {
            LifecycleStoredVolumeDisposition::NormallyReleased { release } => {
                let target = &release.receipt.durability.volume;
                validate_durability(
                    &release.receipt.durability.scope,
                    target,
                    &release.receipt.durability,
                )?;
                if release.receipt.request.volume_id != target.volume_id
                    || release.receipt.result.volume_id != target.volume_id
                    || release.receipt.request.transition_id != release.receipt.result.transition_id
                {
                    return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
                }
            }
            LifecycleStoredVolumeDisposition::AlreadyUnowned { receipt } => {
                if receipt.receipt.scope.node_id != receipt.receipt.scope.placement_identity.node_id
                    || !remote_head_valid(&receipt.receipt.expected_head)
                {
                    return Err(RuntimeLifecycleVolumeContractError::InvalidContract);
                }
            }
        }
    }
    Ok(())
}

fn valid_sorted_volume_set(targets: &[LifecycleVolumeIdentity]) -> bool {
    !targets.is_empty()
        && targets.len() <= LIFECYCLE_VOLUME_TRANSITION_MAX_VOLUMES
        && strictly_sorted_targets(targets)
        && targets.iter().enumerate().all(|(index, target)| {
            targets[index + 1..]
                .iter()
                .all(|other| target.disk_id != other.disk_id)
        })
}

fn strictly_sorted_targets(targets: &[LifecycleVolumeIdentity]) -> bool {
    targets
        .windows(2)
        .all(|pair| pair[0].volume_id.as_str() < pair[1].volume_id.as_str())
}

fn delete_release_targets(command: &LifecycleDeleteVolumeSet) -> Vec<LifecycleVolumeIdentity> {
    let mut targets = Vec::with_capacity(1 + command.persistent_volumes.len());
    targets.push(command.root_disposition.root.clone());
    targets.extend(command.persistent_volumes.iter().cloned());
    targets
}

fn remote_head_valid(head: &RemoteHead) -> bool {
    match (head.generation.get(), &head.root_hash, &head.root_object_id) {
        (0, None, None) => true,
        (0, _, _) => false,
        (_, Some(_), Some(_)) => true,
        _ => false,
    }
}

fn remote_head_same_or_later(current: &RemoteHead, previous: &RemoteHead) -> bool {
    remote_head_valid(current)
        && remote_head_valid(previous)
        && (current.generation > previous.generation
            || (current.generation == previous.generation && current == previous))
}

fn digest_is_zero(digest: &Sha256Digest) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

fn encode_canonical<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, RuntimeLifecycleVolumeContractError> {
    let value = serde_json::to_value(value)
        .map_err(|_| RuntimeLifecycleVolumeContractError::InvalidContract)?;
    let bytes = crate::runtime_reconciliation::canonical_json_value_bytes(&value);
    if bytes.len() > maximum {
        return Err(RuntimeLifecycleVolumeContractError::WireTooLarge);
    }
    Ok(bytes)
}

fn decode_canonical<T>(
    bytes: &[u8],
    maximum: usize,
    validate: fn(&T) -> Result<(), RuntimeLifecycleVolumeContractError>,
) -> Result<T, RuntimeLifecycleVolumeContractError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.len() > maximum {
        return Err(RuntimeLifecycleVolumeContractError::WireTooLarge);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value =
        T::deserialize(&mut decoder).map_err(|_| RuntimeLifecycleVolumeContractError::Malformed)?;
    decoder
        .end()
        .map_err(|_| RuntimeLifecycleVolumeContractError::Malformed)?;
    validate(&value)?;
    if encode_canonical(&value, maximum)?.as_slice() != bytes {
        return Err(RuntimeLifecycleVolumeContractError::Malformed);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_lifecycle::RuntimeVolumeGuestBinding;
    use crate::runtime_reconciliation::{
        AsciiText, Durability, Epoch, NodeBootId, Sequence, UnixMillis,
    };

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    fn random(value: u128) -> RandomId128 {
        RandomId128::new(format!("{value:032x}")).unwrap()
    }

    fn session() -> SessionBinding {
        SessionBinding {
            node_id: id("node_a"),
            node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
            agent_instance_id: random(2),
            agent_session_epoch: Epoch::new(3).unwrap(),
        }
    }

    fn scope() -> LifecycleVolumeCommandScope {
        LifecycleVolumeCommandScope {
            operation_id: id("operation_delete"),
            request_fingerprint: digest(4),
            cat_id: id("cat_a"),
            node_id: id("node_a"),
            placement_identity: PlacementIdentity {
                node_id: id("node_a"),
                placement_epoch: Epoch::new(7).unwrap(),
            },
        }
    }

    fn absence() -> ExecutionAbsenceProof {
        ExecutionAbsenceProof {
            stop_fence_receipt_digest: digest(10),
            admission_closed_receipt_digest: digest(11),
            dedicated_scope_absence_receipt_digest: digest(12),
            frontend_absence_receipt_digest: digest(13),
            restart_source_absence_receipt_digest: digest(14),
        }
    }

    fn attestation() -> RuntimeInventoryAttestation {
        RuntimeInventoryAttestation {
            version: ContractVersion::V1,
            session: session(),
            inventory_epoch: Epoch::new(8).unwrap(),
            scan_id: random(9),
            inventory_digest: digest(15),
            source_report_id: random(10),
            source_sequence: Sequence::new(11).unwrap(),
            accepted_at_unix_ms: UnixMillis::new(12).unwrap(),
        }
    }

    fn blank_head() -> RemoteHead {
        RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        }
    }

    fn initialized_head(generation: u64) -> RemoteHead {
        RemoteHead {
            generation: Generation::new(generation).unwrap(),
            root_hash: Some(digest(generation as u8)),
            root_object_id: Some(AsciiText::new(format!("roots/{generation}")).unwrap()),
        }
    }

    fn persistent_binding() -> LifecyclePersistentInitializationBinding {
        let command_scope = scope();
        let volume = RuntimeVolumeConfig {
            volume_id: id("volume_persistent"),
            disk_id: id("disk_persistent"),
            disk_role: DiskRole::Persistent,
            size_bytes: 8 * 1024 * 1024,
            durability: Durability::Strict,
            guest_device_serial: id("persistent_data"),
            guest_device_slot: 1,
            guest_binding: RuntimeVolumeGuestBinding::PersistentExt4 {
                filesystem_uuid: random(40),
                mount_path: AsciiText::new("/data").unwrap(),
            },
        };
        let request = NormalAcquireRequest {
            volume_id: volume.volume_id.clone(),
            transition_id: random(41),
            attachment_id: id("attachment_persistent"),
            expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
            placement_epoch: command_scope.placement_identity.placement_epoch,
            lease_duration_ms: 30_000,
        };
        let result = NormalAcquireResult {
            volume_id: volume.volume_id.clone(),
            transition_id: request.transition_id.clone(),
            attachment_id: request.attachment_id.clone(),
            resulting_epoch: FenceEpoch::new(1).unwrap(),
            resulting_head: blank_head(),
            lease_expires_at: UnixMillis::new(60_000).unwrap(),
        };
        LifecyclePersistentInitializationBinding {
            scope: command_scope.clone(),
            runtime_config_id: id("config_a"),
            runtime_config_digest: digest(42),
            volume: volume.clone(),
            start_grant: LifecycleStoredStartVolumeGrant {
                receipt: LifecycleCommandStartVolumeGrantReceipt {
                    scope: command_scope,
                    grant_sequence: WireU64::new(0).unwrap(),
                    volume,
                    authority: LifecycleStartVolumeGrantAuthority::NormalAcquire {
                        request,
                        result,
                    },
                },
                receipt_digest: digest(43),
            },
        }
    }

    fn persistent_commit() -> LifecyclePersistentInitializationCommitRequest {
        let binding = persistent_binding();
        let initialized = initialized_head(1);
        let (_, attachment_epoch, _) =
            persistent_initialization_grant_attachment(&binding.start_grant.receipt).unwrap();
        LifecyclePersistentInitializationCommitRequest {
            format_plan_digest: digest(51),
            initialization_token: random(44),
            filesystem_uuid: random(40),
            expected_blank_head: blank_head(),
            initialized_head: initialized.clone(),
            guest_probe: Box::new(LifecyclePersistentInitializationGuestProbe {
                challenge: random(45),
                runtime_incarnation: random(46),
                guest_device_serial: binding.volume.guest_device_serial.clone(),
                guest_device_slot: binding.volume.guest_device_slot,
                device_major: 252,
                device_minor: 1,
                size_bytes: binding.volume.size_bytes,
                filesystem_uuid: random(40),
                filesystem_state: LifecyclePersistentGuestFilesystemState::ExactExt4Unmounted,
                guest_response_digest: digest(47),
            }),
            flush_drain: Box::new(LifecyclePersistentInitializationFlushDrainReceipt {
                guest_flush_challenge: random(48),
                guest_flush_response_digest: digest(49),
                blockd_drain_receipt_digest: digest(50),
                durability: LifecycleVolumeDurabilityProof {
                    scope: binding.scope.clone(),
                    volume: LifecycleVolumeTarget {
                        disk_id: binding.volume.disk_id.clone(),
                        disk_role: DiskRole::Persistent,
                        volume_id: binding.volume.volume_id.clone(),
                        attachment_id: id("attachment_persistent"),
                        attachment_epoch,
                    },
                    remote_head: initialized.clone(),
                    local_durable_generation: initialized.generation,
                    remote_durable_generation: initialized.generation,
                    pending_pack_count: WireU64::new(0).unwrap(),
                },
            }),
            binding: Box::new(binding),
        }
    }

    #[test]
    fn execution_absence_digest_is_stable_operation_scoped_and_mutation_sensitive() {
        let expected = execution_absence_proof_digest(&scope(), &absence()).unwrap();
        assert_eq!(
            expected.as_str(),
            "sha256:6baf6308f24478f5be45028d154da274fb67ca540b8e51e15c18c5c7e3fb9c89"
        );
        let mut changed = absence();
        changed.frontend_absence_receipt_digest = digest(99);
        assert_ne!(
            execution_absence_proof_digest(&scope(), &changed).unwrap(),
            expected
        );
        let mut other = scope();
        other.operation_id = id("operation_other");
        assert_ne!(
            execution_absence_proof_digest(&other, &absence()).unwrap(),
            expected
        );
    }

    #[test]
    fn strong_stop_requires_the_exact_current_session_attestation() {
        let evidence = LifecycleVolumeStrongStopEvidence {
            execution_absence: absence(),
            post_stop_inventory_attestation: attestation(),
        };
        assert!(validate_strong_stop(&session(), &evidence).is_ok());
        let mut stale = evidence.clone();
        stale
            .post_stop_inventory_attestation
            .session
            .agent_session_epoch = Epoch::new(4).unwrap();
        assert_eq!(
            validate_strong_stop(&session(), &stale),
            Err(RuntimeLifecycleVolumeContractError::InvalidContract)
        );
    }

    #[test]
    fn persistent_initialization_wire_is_canonical_and_mutation_sensitive() {
        let commit = persistent_commit();
        validate_lifecycle_persistent_initialization_commit(&commit).unwrap();
        let receipt = LifecyclePersistentInitializationCommitReceipt {
            request: Box::new(commit.clone()),
            initialized_at: UnixMillis::new(70_000).unwrap(),
        };
        let receipt_digest = persistent_initialization_commit_receipt_digest(&receipt).unwrap();
        let request = LifecycleVolumeTransitionRequest {
            version: ContractVersion::V1,
            session: session(),
            transition: LifecycleVolumeTransitionRequestKind::CommitPersistentInitialization {
                commit: Box::new(commit.clone()),
            },
        };
        let encoded = encode_lifecycle_volume_transition_request(&request).unwrap();
        assert_eq!(
            decode_lifecycle_volume_transition_request(&encoded).unwrap(),
            request
        );
        assert_eq!(
            receipt_digest,
            persistent_initialization_commit_receipt_digest(&receipt).unwrap()
        );
        assert_eq!(
            encode_persistent_initialization_commit_receipt(&receipt).unwrap(),
            crate::runtime_reconciliation::canonical_json_value_bytes(
                &serde_json::to_value(&receipt).unwrap()
            )
        );
        let mut changed_receipt = receipt.clone();
        changed_receipt.request.guest_probe.challenge = random(97);
        assert_ne!(
            persistent_initialization_commit_receipt_digest(&changed_receipt).unwrap(),
            receipt_digest
        );
        assert_eq!(
            decode_lifecycle_volume_transition_request(&vec![
                b' ';
                LIFECYCLE_VOLUME_TRANSITION_REQUEST_MAX_WIRE_BYTES
                    + 1
            ]),
            Err(RuntimeLifecycleVolumeContractError::WireTooLarge)
        );

        let mut wrong_uuid = commit.clone();
        wrong_uuid.guest_probe.filesystem_uuid = random(99);
        assert_eq!(
            validate_lifecycle_persistent_initialization_commit(&wrong_uuid),
            Err(RuntimeLifecycleVolumeContractError::InvalidContract)
        );
        let mut partial = commit.clone();
        partial.flush_drain.durability.pending_pack_count = WireU64::new(1).unwrap();
        assert_eq!(
            validate_lifecycle_persistent_initialization_commit(&partial),
            Err(RuntimeLifecycleVolumeContractError::InvalidContract)
        );
        for zero_evidence in [
            {
                let mut changed = commit.clone();
                changed.format_plan_digest = Sha256Digest::from_bytes([0; 32]);
                changed
            },
            {
                let mut changed = commit.clone();
                changed.guest_probe.guest_response_digest = Sha256Digest::from_bytes([0; 32]);
                changed
            },
            {
                let mut changed = commit.clone();
                changed.flush_drain.guest_flush_response_digest = Sha256Digest::from_bytes([0; 32]);
                changed
            },
            {
                let mut changed = commit.clone();
                changed.flush_drain.blockd_drain_receipt_digest = Sha256Digest::from_bytes([0; 32]);
                changed
            },
        ] {
            assert_eq!(
                validate_lifecycle_persistent_initialization_commit(&zero_evidence),
                Err(RuntimeLifecycleVolumeContractError::InvalidContract)
            );
        }
        let mut zero_config = commit.clone();
        zero_config.binding.runtime_config_digest = Sha256Digest::from_bytes([0; 32]);
        assert_eq!(
            validate_lifecycle_persistent_initialization_commit(&zero_config),
            Err(RuntimeLifecycleVolumeContractError::InvalidContract)
        );
        let mut zero_grant = commit.clone();
        zero_grant.binding.start_grant.receipt_digest = Sha256Digest::from_bytes([0; 32]);
        assert_eq!(
            validate_lifecycle_persistent_initialization_commit(&zero_grant),
            Err(RuntimeLifecycleVolumeContractError::InvalidContract)
        );
        let mut zero_fingerprint = commit.clone();
        let zero = Sha256Digest::from_bytes([0; 32]);
        zero_fingerprint.binding.scope.request_fingerprint = zero.clone();
        zero_fingerprint
            .binding
            .start_grant
            .receipt
            .scope
            .request_fingerprint = zero.clone();
        zero_fingerprint
            .flush_drain
            .durability
            .scope
            .request_fingerprint = zero;
        assert_eq!(
            validate_lifecycle_persistent_initialization_commit(&zero_fingerprint),
            Err(RuntimeLifecycleVolumeContractError::InvalidContract)
        );
        let mut wrong_lineage = commit.clone();
        let LifecycleStartVolumeGrantAuthority::NormalAcquire { result, .. } =
            &mut wrong_lineage.binding.start_grant.receipt.authority
        else {
            unreachable!()
        };
        result.resulting_head = initialized_head(1);
        assert_eq!(
            validate_lifecycle_persistent_initialization_commit(&wrong_lineage),
            Err(RuntimeLifecycleVolumeContractError::InvalidContract)
        );
        let mut wrong_head = commit;
        wrong_head.flush_drain.durability.remote_head = initialized_head(2);
        assert_eq!(
            validate_lifecycle_persistent_initialization_commit(&wrong_head),
            Err(RuntimeLifecycleVolumeContractError::InvalidContract)
        );
    }
}
