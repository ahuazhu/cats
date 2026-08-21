//! Checkpoint-first production `ColdCat` and `DeleteCat` handlers.
//!
//! Both commands enter through the shared strong-Stop barrier. Cold then
//! closes every immutable runtime-config slot as either an exact `R == L`
//! normal release or a Control-validated already-Unowned disposition; there
//! is deliberately no Root-tail discard arm. Delete first closes the complete
//! Persistent set the same way, then chooses exactly one Root branch: normal
//! release for owned `R == L`, exact already-Unowned deletion, or the
//! Control-derived disposable authorization for an owned `R < L` tail. The
//! latter never accepts an authorization payload supplied by this Node.
//!
//! Every provider call below is named by a durable journal step.  Implementors
//! must discover an ambiguous prior submission before reporting success.  A
//! transport error therefore leaves the same step executable; it is never
//! converted into a release, a disposable authorization, local absence, or a
//! completed Delete.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use cats_api::runtime_inventory::RuntimeInventoryAttestation;
use cats_api::runtime_lifecycle::{
    lifecycle_terminal_result_digest, ColdResult, ColdVolumeDisposition,
    CompletedVolumeDisposition, DeletedResult, DiskRole, ExecutionAbsenceProof, InterventionReason,
    InterventionTarget, LifecycleCommand, LifecycleCommandEnvelope, LifecycleCommandResponse,
    LifecycleTerminalResult, NeedsInterventionResult, NodeResult, RequestedVolumeDisposition,
    RetainedEvidence, RuntimeVolumeConfig, TerminalResultKind, VolumeTerminalReceipt,
};
use cats_api::runtime_lifecycle_volume as volume_wire;
use cats_api::runtime_reconciliation::{
    AcquireOrigin, ContractVersion, FenceEpoch, Generation, HostPath, Id, RandomId128, RemoteHead,
    Sha256Digest, UnixMillis, VolumeAdminState, WireU64,
};
use cats_storage::authority::{
    remote_head_is_same_or_later, remote_head_is_valid, validate_volume_owner_binding,
    validate_volume_record, AttachmentLineageIdentity, RuntimeVolumeInventoryAuthority,
};
use cats_storage::lifecycle_volume::{
    AlreadyUnownedProvenance, ColdCommandVolumeSet, CommandAlreadyUnownedReceipt,
    CommandDeleteCompletionReceipt, CommandNormalReleaseInput, CommandNormalReleaseReceipt,
    CommandRootDeleteAuthorityReceipt, CommandVolumeDurabilityProof, DefaultRootDiscardDisposition,
    DeleteCommandVolumeSet, LifecycleVolumeCommandScope, LifecycleVolumeIdentity,
    LifecycleVolumeTarget,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::super::executor::{
    LifecycleEffectAuthority, LifecycleEffectProgress, PlannedLifecycleEffect,
};
use super::super::journal::{ExactBytes, ExecutionStep};
use super::common::{InstalledLifecycleContext, StrongStopEvidence};
use super::suspend_warm::{
    rebind_retained_warm_for_removal, validate_retained_warm_removal_authority,
    validate_retained_warm_restart_source, validate_same_node_owned_predecessor_physical,
    InstalledSuspendWarmPlatform, RetainedWarmRestartSourceCarrier,
    SameNodeOwnedPredecessorPhysical, WarmSnapshotCleanupAttempt, WarmSnapshotCleanupAuthority,
    WarmSnapshotCleanupCompletion, WarmSnapshotCleanupMode, WarmSnapshotCleanupRequest,
};

use crate::admission_registry::LifecycleAdmissionRegistry;
use crate::lifecycle_volume_client::LifecycleVolumeHttpClient;
use crate::state_directory::StateDirectory;

pub(crate) use crate::runtime_inventory::RuntimeInventoryAttestationPort;

const STEP_NAME: &str = "atomic_cold_delete_v1";
const STEP_MAX_BYTES: usize = 2 * 1024 * 1024;
const STOP_FENCE_DOMAIN: &[u8] = b"cats.atomic-lifecycle.cold-delete-stop-fence.v1";
const TRANSITION_ID_DOMAIN: &[u8] = b"cats.atomic-lifecycle.cold-delete-transition.v1";
const DISPOSABLE_CONSUMED_DIGEST_DOMAIN: &[u8] =
    b"cats.volume-authority.command-disposable-authorization-consumed-receipt.v1";
const DELETE_COMPLETION_DIGEST_DOMAIN: &[u8] =
    b"cats.volume-authority.command-delete-completion-receipt.v1";
const LOCAL_CLEANUP_MARKER_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.cold-delete-local-cleanup-marker.v1";
const LOCAL_CLEANUP_REQUEST_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.cold-delete-local-cleanup-request.v1";
const LOCAL_CLEANUP_ABSENCE_DOMAIN: &[u8] = b"cats.atomic-lifecycle.cold-delete-local-absence.v1";
const OWNED_PREDECESSOR_CARRIER_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.cold-delete-owned-predecessor-carrier.v1";
const LOCAL_CLEANUP_MARKER_NAMESPACE: &str = "atomic-cold-delete-cleanup-v1";
const LOCAL_CLEANUP_MARKER_SUFFIX: &str = ".json";
const LOCAL_CLEANUP_MARKER_TEMP_SUFFIX: &str = ".tmp";
const LOCAL_CLEANUP_MARKER_MAX_BYTES: usize = 1024 * 1024;
const ATTACHMENT_IDENTITY_MAX_BYTES: usize = 4_096;
const PACK_HEADER_MAX_BYTES: usize = 1024 * 1024;

/// A provider result may be a discovered exact postcondition or a proven,
/// terminal data-safety block.  Unknown transport/provider outcomes are
/// returned as `Err`, so the current journal step remains executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomicColdDeleteAttempt<T> {
    Exact(T),
    Blocked(AtomicColdDeleteBlocked),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomicColdReleaseAttempt {
    Exact(AtomicColdReleaseReceipt),
    Blocked(AtomicColdDeleteBlocked),
    /// Control proved that the submitted current-session Full attestation was
    /// stale before any Volume or ledger mutation. Re-enter the durable
    /// ForceFull phase and retry the exact mixed set with a newly accepted
    /// attestation.
    FreshInventoryRequired,
}

/// Closed non-success returned only after fresh evidence proves the command
/// cannot safely advance by its frozen convergence deadline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicColdDeleteBlocked {
    pub reason: InterventionReason,
    pub retained_volume_receipts: Vec<VolumeTerminalReceipt>,
}

/// One exact target whose transition identity is fixed before convergence or
/// release is attempted.  Attachment identity is deliberately absent here:
/// the stopped blockd/authority inspection returns it in the durability proof
/// and that proof is fsynced in the next step before the release mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicVolumeConvergenceTarget {
    pub volume_id: Id,
    pub disk_id: Id,
    pub disk_role: DiskRole,
    pub transition_id: RandomId128,
}

/// Read-only physical carrier frozen before Cold/Delete strong-Stop mutates a
/// live Suspended/Warm predecessor. The carrier is not storage authority: the
/// local port still performs one fresh owner/head snapshot and descriptor-
/// safe lineage join after the Stop. Its purpose is to bind that later join
/// to the exact immediate predecessor without pretending the older Start
/// operation was the direct lifecycle predecessor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicOwnedPredecessorCarrier {
    predecessor_operation_id: Id,
    predecessor_request_fingerprint: Sha256Digest,
    predecessor_terminal_result_kind: TerminalResultKind,
    predecessor_terminal_result_digest: Sha256Digest,
    physical_manifest_digest: Sha256Digest,
    physical: Box<SameNodeOwnedPredecessorPhysical>,
    installed_runtime: Box<super::start::InstalledRuntimeManifest>,
    volumes: Vec<AtomicOwnedPredecessorVolume>,
    carrier_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AtomicOwnedPredecessorVolume {
    volume_id: Id,
    disk_id: Id,
    disk_role: DiskRole,
    attachment_id: Id,
    attachment_epoch: FenceEpoch,
    acquire_origin: AcquireOrigin,
    authoritative_head: RemoteHead,
    immutable_start_grant_receipt_digest: Sha256Digest,
    local_lineage_data_directory: HostPath,
}

/// Exact failed-Warm-Start bundle removal authority. The complete carrier is
/// retained rather than flattened so replay can revalidate the original Warm
/// descriptor/revocation chain before applying the rebound Remove authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicRetainedWarmCleanupAuthority {
    terminal_retained_manifest_digest: Sha256Digest,
    carrier: Box<RetainedWarmRestartSourceCarrier>,
    authority: Box<WarmSnapshotCleanupAuthority>,
}

/// Closed authority for interpreting Host-local Start artifacts after the
/// current command's strong-Stop. An immediate StartFailed response names the
/// original terminal-retained manifest directly. A later Killed response may
/// bridge to an older Start artifact only when its complete post-Stop
/// projection and retained Volume set are byte-for-byte equal to this
/// command's fresh strong-Stop evidence. Every other predecessor forbids a
/// terminal-retained Start artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtomicLocalRecoveryAuthority {
    TerminalRetainedForbidden {
        predecessor_operation_id: Id,
        predecessor_request_fingerprint: Sha256Digest,
        terminal_result_kind: TerminalResultKind,
    },
    DirectStartFailed {
        predecessor_operation_id: Id,
        predecessor_request_fingerprint: Sha256Digest,
        not_running: ExecutionAbsenceProof,
        retained_evidence: RetainedEvidence,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retained_warm_cleanup: Option<Box<AtomicRetainedWarmCleanupAuthority>>,
    },
    KilledRetained {
        predecessor_operation_id: Id,
        predecessor_request_fingerprint: Sha256Digest,
        stopped_runtime_incarnation: Option<RandomId128>,
        execution_absence: ExecutionAbsenceProof,
        stop_fence_receipt_digest: Sha256Digest,
        retained_evidence: RetainedEvidence,
        retained_volume_receipts: Vec<VolumeTerminalReceipt>,
    },
    SuspendWarmOwned {
        carrier: Box<AtomicOwnedPredecessorCarrier>,
    },
    NeedsInterventionRetry {
        predecessor_operation_id: Id,
        predecessor_request_fingerprint: Sha256Digest,
        predecessor_terminal_result_digest: Sha256Digest,
        attempted_target: InterventionTarget,
        retained_evidence: RetainedEvidence,
        retained_volume_receipts: Vec<VolumeTerminalReceipt>,
    },
}

/// Exact durable request for publisher convergence.  Implementations may
/// advance `R` only for these stopped, same-lineage volumes and must return a
/// complete proof set; they never release ownership in this call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicVolumeConvergenceRequest {
    pub scope: LifecycleVolumeCommandScope,
    pub expected_runtime_incarnation: Option<RandomId128>,
    pub local_recovery_authority: AtomicLocalRecoveryAuthority,
    pub targets: Vec<AtomicVolumeConvergenceTarget>,
    pub deadline_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicVolumeConvergenceReceipt {
    pub dispositions: Vec<AtomicVolumeDispositionInput>,
}

/// Node-observed input for one mixed command slot. The already-Unowned arm
/// deliberately omits provenance: Control derives and locks that provenance
/// from the current row and immutable release ledger in the same transaction.
// Cold-path exact-effect envelope, bounded to one entry per command volume.
// Keeping the authority proof inline avoids changing the effect-port API solely
// for an in-memory size ratio; serde still freezes the same tagged union.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtomicVolumeDispositionInput {
    OwnedRelease {
        release: CommandNormalReleaseInput,
    },
    AlreadyUnowned {
        volume: LifecycleVolumeIdentity,
        expected_epoch: FenceEpoch,
        expected_head: RemoteHead,
    },
}

impl AtomicVolumeDispositionInput {
    fn identity(&self) -> LifecycleVolumeIdentity {
        match self {
            Self::OwnedRelease { release } => release.durability.volume.identity(),
            Self::AlreadyUnowned { volume, .. } => volume.clone(),
        }
    }
}

/// Observation-only Root request.  Delete must not upload or release the Root
/// while discovering which exact branch is applicable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicDeleteRootInspectionRequest {
    pub scope: LifecycleVolumeCommandScope,
    pub expected_runtime_incarnation: Option<RandomId128>,
    pub local_recovery_authority: AtomicLocalRecoveryAuthority,
    pub volume_id: Id,
    pub disk_id: Id,
    pub deadline_unix_ms: UnixMillis,
}

// Cold-path inspection result, produced once for the command's single Root.
// The complete durability proof intentionally remains an inline atomic value.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtomicDeleteRootInspection {
    Owned {
        durability: CommandVolumeDurabilityProof,
    },
    AlreadyUnowned {
        volume: LifecycleVolumeIdentity,
        expected_epoch: FenceEpoch,
        expected_head: RemoteHead,
    },
}

enum PreparedDeleteRoot {
    Normal(AtomicVolumeDispositionInput),
    Disposable(CommandVolumeDurabilityProof),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicStoredNormalReleaseReceipt {
    pub receipt: CommandNormalReleaseReceipt,
    pub receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicStoredAlreadyUnownedReceipt {
    pub receipt: CommandAlreadyUnownedReceipt,
    pub receipt_digest: Sha256Digest,
}

// Cold-path stored authority receipt, bounded by the immutable volume set and
// retained inline so callers cannot accidentally split its exact proof.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtomicStoredVolumeDisposition {
    NormallyReleased {
        release: AtomicStoredNormalReleaseReceipt,
    },
    AlreadyUnowned {
        receipt: AtomicStoredAlreadyUnownedReceipt,
    },
}

impl AtomicStoredVolumeDisposition {
    fn identity(&self) -> LifecycleVolumeIdentity {
        match self {
            Self::NormallyReleased { release } => release.receipt.durability.volume.identity(),
            Self::AlreadyUnowned { receipt } => receipt.receipt.volume.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicColdReleaseRequest {
    pub command: ColdCommandVolumeSet,
    pub dispositions: Vec<AtomicVolumeDispositionInput>,
    pub strong_stop: AtomicDeleteStrongStopEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicColdReleaseReceipt {
    pub dispositions: Vec<AtomicStoredVolumeDisposition>,
}

/// Strong-Stop evidence admitted by the signed command-volume transition.
/// The Control transaction derives any disposable authorization itself; the
/// Node cannot choose or provide an authorization ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicDeleteStrongStopEvidence {
    pub execution_absence: ExecutionAbsenceProof,
    pub post_stop_inventory_attestation: RuntimeInventoryAttestation,
    pub local_recovery_authority: AtomicLocalRecoveryAuthority,
}

// One transient Delete plan exists per Cat command. Its exact Root proof is
// deliberately kept inline across the normal/disposable branch decision.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AtomicDeleteBeginPlan {
    Normal {
        command: DeleteCommandVolumeSet,
        volumes: Vec<AtomicVolumeDispositionInput>,
    },
    DisposableRoot {
        command: DeleteCommandVolumeSet,
        persistent_volumes: Vec<AtomicVolumeDispositionInput>,
        root_durability: CommandVolumeDurabilityProof,
    },
}

impl AtomicDeleteBeginPlan {
    fn with_strong_stop(
        self,
        strong_stop: AtomicDeleteStrongStopEvidence,
    ) -> AtomicDeleteBeginRequest {
        match self {
            Self::Normal { command, volumes } => AtomicDeleteBeginRequest::Normal {
                command,
                volumes,
                strong_stop,
            },
            Self::DisposableRoot {
                command,
                persistent_volumes,
                root_durability,
            } => AtomicDeleteBeginRequest::DisposableRoot {
                command,
                persistent_volumes,
                root_durability,
                strong_stop,
            },
        }
    }
}

// Cold-path signed request, emitted once after convergence. Keeping the exact
// evidence inline preserves the effect-port value API without material churn.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtomicDeleteBeginRequest {
    Normal {
        command: DeleteCommandVolumeSet,
        volumes: Vec<AtomicVolumeDispositionInput>,
        strong_stop: AtomicDeleteStrongStopEvidence,
    },
    DisposableRoot {
        command: DeleteCommandVolumeSet,
        persistent_volumes: Vec<AtomicVolumeDispositionInput>,
        root_durability: CommandVolumeDurabilityProof,
        strong_stop: AtomicDeleteStrongStopEvidence,
    },
}

impl AtomicDeleteBeginRequest {
    fn command(&self) -> &DeleteCommandVolumeSet {
        match self {
            Self::Normal { command, .. } | Self::DisposableRoot { command, .. } => command,
        }
    }

    fn strong_stop(&self) -> &AtomicDeleteStrongStopEvidence {
        match self {
            Self::Normal { strong_stop, .. } | Self::DisposableRoot { strong_stop, .. } => {
                strong_stop
            }
        }
    }
}

// Cold-path exact receipt, bounded to one Delete begin. The disposable Root
// proof remains a single inline value for validation and journal replay.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtomicDeleteBeginReceipt {
    NormallyDeleting {
        dispositions: Vec<AtomicStoredVolumeDisposition>,
    },
    DisposableRootDeleting {
        persistent_dispositions: Vec<AtomicStoredVolumeDisposition>,
        /// The signed response intentionally does not echo this potentially
        /// unique local-tail proof. Retain the exact journaled request value
        /// so descriptor-safe Root cleanup cannot infer an attachment.
        root_durability: CommandVolumeDurabilityProof,
        authorization_id: Id,
        authorization_consumed_receipt_digest: Sha256Digest,
    },
}

// One bounded Control transition attempt is live at a time; retaining its exact
// receipt inline avoids heap indirection throughout the effect-port boundary.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomicDeleteBeginAttempt {
    Exact(AtomicDeleteBeginReceipt),
    Blocked(AtomicColdDeleteBlocked),
    /// The prior attestation is no longer current and the signed Control
    /// transaction proved that this exact begin did not commit. The handler
    /// may therefore obtain a fresh Full acknowledgement before retrying.
    FreshInventoryRequired,
}

/// Exact local lineage cleanup request.  The production implementation opens
/// the configured lineage root once, walks beneath retained directory FDs
/// with no-follow semantics, revalidates the complete identity sidecar, and
/// unlinks only that exact Root attachment.  A path prefix or a missing path
/// alone is never success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicRootLineageCleanupRequest {
    pub command: DeleteCommandVolumeSet,
    pub begin: AtomicDeleteBeginReceipt,
    pub post_stop_inventory_attestation: RuntimeInventoryAttestation,
    pub expected_runtime_incarnation: Option<RandomId128>,
    pub local_recovery_authority: AtomicLocalRecoveryAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtomicRootLineageAbsenceReceipt {
    RemovedOwned {
        volume_id: Id,
        disk_id: Id,
        previous_attachment_id: Id,
        previous_attachment_epoch: FenceEpoch,
        authority_receipt_digest: Sha256Digest,
        local_lineage_absence_digest: Sha256Digest,
    },
    AlreadyUnowned {
        volume_id: Id,
        disk_id: Id,
        expected_epoch: FenceEpoch,
        expected_head: RemoteHead,
        authority_receipt_digest: Sha256Digest,
        local_lineage_absence_digest: Sha256Digest,
    },
}

impl AtomicRootLineageAbsenceReceipt {
    fn authority_receipt_digest(&self) -> &Sha256Digest {
        match self {
            Self::RemovedOwned {
                authority_receipt_digest,
                ..
            }
            | Self::AlreadyUnowned {
                authority_receipt_digest,
                ..
            } => authority_receipt_digest,
        }
    }

    fn local_lineage_absence_digest(&self) -> &Sha256Digest {
        match self {
            Self::RemovedOwned {
                local_lineage_absence_digest,
                ..
            }
            | Self::AlreadyUnowned {
                local_lineage_absence_digest,
                ..
            } => local_lineage_absence_digest,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicDeleteCompletionRequest {
    pub operation_id: Id,
    pub request_fingerprint: Sha256Digest,
    pub expected_runtime_incarnation: Option<RandomId128>,
    pub volume_id: Id,
    pub delete_id: Id,
    pub expected_command: DeleteCommandVolumeSet,
    pub expected_begin: AtomicDeleteBeginReceipt,
    pub post_stop_inventory_attestation: RuntimeInventoryAttestation,
    pub local_recovery_authority: AtomicLocalRecoveryAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicDeleteCompletionEvidence {
    pub receipt: CommandDeleteCompletionReceipt,
    pub receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicColdFinalizationRequest {
    pub command: ColdCommandVolumeSet,
    pub dispositions: Vec<AtomicStoredVolumeDisposition>,
    pub post_stop_inventory_attestation: RuntimeInventoryAttestation,
    pub expected_runtime_incarnation: Option<RandomId128>,
    pub local_recovery_authority: AtomicLocalRecoveryAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicDeleteFinalizationRequest {
    pub command: DeleteCommandVolumeSet,
    pub begin: AtomicDeleteBeginReceipt,
    pub root_lineage_absence: AtomicRootLineageAbsenceReceipt,
    pub completion: AtomicDeleteCompletionEvidence,
    pub execution_absence: ExecutionAbsenceProof,
    pub post_stop_inventory_attestation: RuntimeInventoryAttestation,
    pub expected_runtime_incarnation: Option<RandomId128>,
    pub local_recovery_authority: AtomicLocalRecoveryAuthority,
}

/// Production boundary for the Cold/Delete storage and local cleanup edges.
///
/// Each method is inspect-or-apply: it first discovers the exact postcondition
/// named by its request, submits at most that one effect if absent, and then
/// performs fresh discovery.  A response that cannot be closed is `Err`, not
/// `Blocked` and never `Exact`.  The signed Control adapter owns normal release,
/// disposable authorization derive/consume, and completion-ledger replay;
/// the installed local adapter owns descriptor-safe lineage/restart cleanup.
pub trait AtomicColdDeletePort: Send + Sync + 'static {
    fn inspect_or_converge(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicVolumeConvergenceRequest,
    ) -> Result<AtomicColdDeleteAttempt<AtomicVolumeConvergenceReceipt>>;

    fn inspect_delete_root(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicDeleteRootInspectionRequest,
    ) -> Result<AtomicColdDeleteAttempt<AtomicDeleteRootInspection>>;

    fn inspect_or_release_cold(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicColdReleaseRequest,
    ) -> Result<AtomicColdReleaseAttempt>;

    fn inspect_or_begin_delete(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicDeleteBeginRequest,
    ) -> Result<AtomicDeleteBeginAttempt>;

    fn inspect_or_remove_root_lineage(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicRootLineageCleanupRequest,
    ) -> Result<AtomicColdDeleteAttempt<AtomicRootLineageAbsenceReceipt>>;

    /// Return `Exact` only for the immutable command-scoped completion ledger
    /// after the Root Volume/Disk live rows are absent. `Deleting`, a queued
    /// sweeper, or an empty local directory are not completion.
    fn discover_delete_completion(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicDeleteCompletionRequest,
    ) -> Result<AtomicColdDeleteAttempt<AtomicDeleteCompletionEvidence>>;

    fn inspect_or_finalize_cold(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicColdFinalizationRequest,
    ) -> Result<AtomicColdDeleteAttempt<Sha256Digest>>;

    fn inspect_or_finalize_delete(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicDeleteFinalizationRequest,
    ) -> Result<AtomicColdDeleteAttempt<Sha256Digest>>;
}

/// Installed Host-local half of Cold/Delete. The production implementation
/// below owns descriptor-safe lineage discovery/removal and exact manifest
/// cleanup; the composite port owns all signed Control mutations.
pub trait AtomicColdDeleteLocalPort: Send + Sync + 'static {
    fn inspect_or_converge(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicVolumeConvergenceRequest,
    ) -> Result<AtomicColdDeleteAttempt<AtomicVolumeConvergenceReceipt>>;

    fn inspect_delete_root(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicDeleteRootInspectionRequest,
    ) -> Result<AtomicColdDeleteAttempt<AtomicDeleteRootInspection>>;

    fn inspect_or_remove_root_lineage(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicRootLineageCleanupRequest,
    ) -> Result<AtomicColdDeleteAttempt<AtomicRootLineageAbsenceReceipt>>;

    fn inspect_or_finalize_cold(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicColdFinalizationRequest,
    ) -> Result<AtomicColdDeleteAttempt<Sha256Digest>>;

    fn inspect_or_finalize_delete(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicDeleteFinalizationRequest,
    ) -> Result<AtomicColdDeleteAttempt<Sha256Digest>>;
}

/// Real production composite: Host-local effects are delegated to one
/// descriptor-safe installed port, while every release/delete transition uses
/// the new signed command-scoped Control client and the registry's current
/// AgentSession. No legacy Desired/reconciliation authority is reachable.
pub struct InstalledAtomicColdDeletePort {
    local: Arc<dyn AtomicColdDeleteLocalPort>,
    control: Arc<LifecycleVolumeHttpClient>,
    admission_registry: Arc<LifecycleAdmissionRegistry>,
    control_request_timeout: Duration,
}

impl std::fmt::Debug for InstalledAtomicColdDeletePort {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledAtomicColdDeletePort")
            .field("control", &self.control)
            .field("control_request_timeout", &self.control_request_timeout)
            .finish_non_exhaustive()
    }
}

impl InstalledAtomicColdDeletePort {
    pub fn new(
        local: Arc<dyn AtomicColdDeleteLocalPort>,
        control: Arc<LifecycleVolumeHttpClient>,
        admission_registry: Arc<LifecycleAdmissionRegistry>,
        control_request_timeout: Duration,
    ) -> Result<Arc<Self>> {
        anyhow::ensure!(
            !control_request_timeout.is_zero(),
            "Cold/Delete Control request timeout must be positive"
        );
        Ok(Arc::new(Self {
            local,
            control,
            admission_registry,
            control_request_timeout,
        }))
    }

    fn transition(
        &self,
        command: &LifecycleCommandEnvelope,
        transition: volume_wire::LifecycleVolumeTransitionRequestKind,
    ) -> Result<volume_wire::LifecycleVolumeTransitionResult> {
        let session = self
            .admission_registry
            .current_agent_session()
            .context("read current AgentSession for lifecycle Volume transition")?;
        anyhow::ensure!(
            session.node_id == command.node_id,
            "current AgentSession belongs to another Node"
        );
        let request = volume_wire::LifecycleVolumeTransitionRequest {
            version: ContractVersion::V1,
            session: session.clone(),
            transition,
        };
        let deadline = Instant::now()
            .checked_add(self.control_request_timeout)
            .context("Cold/Delete Control request timeout overflows monotonic time")?;
        let response = self
            .control
            .transition(&request, deadline)
            .context("submit signed lifecycle Volume transition")?;
        anyhow::ensure!(
            self.admission_registry.current_agent_session()? == session,
            "AgentSession changed during lifecycle Volume transition"
        );
        Ok(response.result)
    }
}

impl AtomicColdDeletePort for InstalledAtomicColdDeletePort {
    fn inspect_or_converge(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicVolumeConvergenceRequest,
    ) -> Result<AtomicColdDeleteAttempt<AtomicVolumeConvergenceReceipt>> {
        self.local.inspect_or_converge(command, request)
    }

    fn inspect_delete_root(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicDeleteRootInspectionRequest,
    ) -> Result<AtomicColdDeleteAttempt<AtomicDeleteRootInspection>> {
        self.local.inspect_delete_root(command, request)
    }

    fn inspect_or_release_cold(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicColdReleaseRequest,
    ) -> Result<AtomicColdReleaseAttempt> {
        match self.transition(command, cold_release_wire_transition(request))? {
            volume_wire::LifecycleVolumeTransitionResult::Applied { applied } => Ok(
                AtomicColdReleaseAttempt::Exact(cold_release_from_wire(&applied)?),
            ),
            volume_wire::LifecycleVolumeTransitionResult::Rejected {
                reason: volume_wire::LifecycleVolumeTransitionRejection::StaleInventoryAttestation,
            } => Ok(AtomicColdReleaseAttempt::FreshInventoryRequired),
            volume_wire::LifecycleVolumeTransitionResult::Rejected {
                reason: volume_wire::LifecycleVolumeTransitionRejection::AuthorityRejected,
            } => Ok(AtomicColdReleaseAttempt::Blocked(AtomicColdDeleteBlocked {
                reason: InterventionReason::NormalReleaseAmbiguous,
                retained_volume_receipts: retained_from_disposition_inputs(&request.dispositions)?,
            })),
            volume_wire::LifecycleVolumeTransitionResult::Rejected { reason } => {
                anyhow::bail!("Cold release remains unresolved after Control rejection {reason:?}")
            }
        }
    }

    fn inspect_or_begin_delete(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicDeleteBeginRequest,
    ) -> Result<AtomicDeleteBeginAttempt> {
        match self.transition(command, delete_begin_wire_transition(request))? {
            volume_wire::LifecycleVolumeTransitionResult::Applied { applied } => Ok(
                AtomicDeleteBeginAttempt::Exact(delete_begin_from_wire(&applied, request)?),
            ),
            volume_wire::LifecycleVolumeTransitionResult::Rejected {
                reason: volume_wire::LifecycleVolumeTransitionRejection::StaleInventoryAttestation,
            } => Ok(AtomicDeleteBeginAttempt::FreshInventoryRequired),
            volume_wire::LifecycleVolumeTransitionResult::Rejected {
                reason: volume_wire::LifecycleVolumeTransitionRejection::AuthorityRejected,
            } => {
                let (reason, dispositions) = match request {
                    AtomicDeleteBeginRequest::Normal { volumes, .. } => (
                        InterventionReason::NormalReleaseAmbiguous,
                        volumes.as_slice(),
                    ),
                    AtomicDeleteBeginRequest::DisposableRoot {
                        persistent_volumes, ..
                    } => (
                        InterventionReason::DestructiveAuthorizationRejected,
                        persistent_volumes.as_slice(),
                    ),
                };
                Ok(AtomicDeleteBeginAttempt::Blocked(AtomicColdDeleteBlocked {
                    reason,
                    retained_volume_receipts: retained_from_disposition_inputs(dispositions)?,
                }))
            }
            volume_wire::LifecycleVolumeTransitionResult::Rejected { reason } => {
                anyhow::bail!("Delete begin remains unresolved after Control rejection {reason:?}")
            }
        }
    }

    fn inspect_or_remove_root_lineage(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicRootLineageCleanupRequest,
    ) -> Result<AtomicColdDeleteAttempt<AtomicRootLineageAbsenceReceipt>> {
        self.local.inspect_or_remove_root_lineage(command, request)
    }

    fn discover_delete_completion(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicDeleteCompletionRequest,
    ) -> Result<AtomicColdDeleteAttempt<AtomicDeleteCompletionEvidence>> {
        match self.transition(command, delete_completion_wire_transition(request))? {
            volume_wire::LifecycleVolumeTransitionResult::Applied { applied } => Ok(
                AtomicColdDeleteAttempt::Exact(delete_completion_from_wire(&applied)?),
            ),
            volume_wire::LifecycleVolumeTransitionResult::Rejected {
                reason: volume_wire::LifecycleVolumeTransitionRejection::CompletionPending,
            } => anyhow::bail!("exact command Delete completion is still pending"),
            volume_wire::LifecycleVolumeTransitionResult::Rejected { reason } => {
                anyhow::bail!(
                    "Delete completion remains unresolved after Control rejection {reason:?}"
                )
            }
        }
    }

    fn inspect_or_finalize_cold(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicColdFinalizationRequest,
    ) -> Result<AtomicColdDeleteAttempt<Sha256Digest>> {
        self.local.inspect_or_finalize_cold(command, request)
    }

    fn inspect_or_finalize_delete(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicDeleteFinalizationRequest,
    ) -> Result<AtomicColdDeleteAttempt<Sha256Digest>> {
        self.local.inspect_or_finalize_delete(command, request)
    }
}

/// Concrete Host-local Cold/Delete implementation. It reads Volume Authority
/// only through the provider-neutral complete-snapshot port and reads or
/// removes local lineages only through retained no-follow descriptors. It has
/// no object-store credentials, so an exact `R < L` lineage becomes the
/// command's typed data-safety result instead of an invented upload.
pub struct InstalledColdDeleteLocalPort {
    state_directory: StateDirectory,
    volume_inventory_authority: Arc<dyn RuntimeVolumeInventoryAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstalledOwnedLineage {
    volume_id: Id,
    disk_id: Id,
    disk_role: DiskRole,
    attachment_id: Id,
    attachment_epoch: FenceEpoch,
    acquire_origin: AcquireOrigin,
    authority_receipt_digest: Option<Sha256Digest>,
    authority_head_at_install: RemoteHead,
    storage: InstalledLineageStorage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InstalledLineageStorage {
    Materialized(HostPath),
    /// A sealed failed Start retained an exact owner while its complete
    /// post-Stop scan proved that no local lineage was ever materialized.
    /// This covers both a current sequence-zero acquisition and a rejected
    /// sequence-zero renewal that inherited its predecessor owner. It is valid
    /// only for an exact `L == R == head` receipt; a missing directory alone
    /// can never construct this arm.
    ProvenAbsent,
}

impl std::fmt::Debug for InstalledColdDeleteLocalPort {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledColdDeleteLocalPort")
            .field("state_directory", &self.state_directory)
            .finish_non_exhaustive()
    }
}

impl InstalledColdDeleteLocalPort {
    pub fn new(
        state_directory: StateDirectory,
        volume_inventory_authority: Arc<dyn RuntimeVolumeInventoryAuthority>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state_directory,
            volume_inventory_authority,
        })
    }

    fn inspect_volume_slots(
        &self,
        command: &LifecycleCommandEnvelope,
        scope: &LifecycleVolumeCommandScope,
        expected_runtime_incarnation: Option<&RandomId128>,
        local_recovery_authority: &AtomicLocalRecoveryAuthority,
        targets: &[AtomicVolumeConvergenceTarget],
    ) -> Result<AtomicColdDeleteAttempt<Vec<AtomicVolumeDispositionInput>>> {
        validate_local_recovery_authority(command, local_recovery_authority)?;
        let candidates = targets
            .iter()
            .map(|target| target.volume_id.clone())
            .collect::<BTreeSet<_>>();
        let snapshot = self
            .volume_inventory_authority
            .load_node_volume_inventory(&command.node_id, &candidates)
            .context("load fresh Cold/Delete Volume authority snapshot")?;
        anyhow::ensure!(
            snapshot.node_id == command.node_id,
            "Cold/Delete Volume snapshot belongs to another Node"
        );
        let mut rows = BTreeMap::new();
        for row in &snapshot.records {
            validate_volume_record(&row.volume)
                .context("validate fresh Cold/Delete Volume authority row")?;
            anyhow::ensure!(
                rows.insert(row.volume.volume_id.clone(), row).is_none(),
                "fresh Cold/Delete Volume snapshot contains duplicate rows"
            );
        }
        let mut lineages = None;
        let mut dispositions = BTreeMap::new();
        // A terminal lineage inspection may remove only remote-covered pack
        // residue. Inspect every Persistent slot first so a unique Persistent
        // tail blocks before even that bounded Root mutation.
        let ordered_targets = targets
            .iter()
            .filter(|target| target.disk_role == DiskRole::Persistent)
            .chain(
                targets
                    .iter()
                    .filter(|target| target.disk_role == DiskRole::Root),
            );
        for target in ordered_targets {
            let config = command
                .runtime_config
                .volumes
                .iter()
                .find(|config| config.volume_id == target.volume_id)
                .context("Cold/Delete target is absent from immutable config")?;
            let row = match rows.get(&target.volume_id) {
                Some(row) => *row,
                None => {
                    return Ok(AtomicColdDeleteAttempt::Blocked(AtomicColdDeleteBlocked {
                        reason: InterventionReason::AuthorityAmbiguous,
                        retained_volume_receipts: Vec::new(),
                    }))
                }
            };
            if row.volume.size_bytes != config.size_bytes
                || row.volume.durability != config.durability
                || !matches!(row.volume.admin_state, VolumeAdminState::Active)
            {
                return Ok(AtomicColdDeleteAttempt::Blocked(AtomicColdDeleteBlocked {
                    reason: InterventionReason::AuthorityAmbiguous,
                    retained_volume_receipts: Vec::new(),
                }));
            }

            if row.binding.is_none()
                && row.volume.lease_owner.is_none()
                && row.volume.lease_expires_at.is_none()
            {
                let disposition = AtomicVolumeDispositionInput::AlreadyUnowned {
                    volume: LifecycleVolumeIdentity {
                        disk_id: target.disk_id.clone(),
                        disk_role: target.disk_role,
                        volume_id: target.volume_id.clone(),
                    },
                    expected_epoch: row.volume.lease_epoch,
                    expected_head: row.volume.head.clone(),
                };
                anyhow::ensure!(
                    dispositions
                        .insert(target.volume_id.clone(), disposition)
                        .is_none(),
                    "Cold/Delete Volume target is duplicated"
                );
                continue;
            }

            let binding = match row.binding.as_ref() {
                Some(binding) => binding,
                None => {
                    return Ok(local_cleanup_blocked(
                        InterventionReason::AuthorityAmbiguous,
                    ))
                }
            };
            if validate_volume_owner_binding(binding, &row.volume).is_err()
                || binding.owner_node_id != command.node_id
            {
                return Ok(local_cleanup_blocked(
                    InterventionReason::AuthorityAmbiguous,
                ));
            }
            if lineages.is_none() {
                lineages = Some(
                    match self.load_owned_lineages(
                        command,
                        expected_runtime_incarnation,
                        local_recovery_authority,
                    )? {
                        AtomicColdDeleteAttempt::Exact(lineages) => lineages,
                        AtomicColdDeleteAttempt::Blocked(blocked) => {
                            return Ok(AtomicColdDeleteAttempt::Blocked(blocked))
                        }
                    },
                );
            }
            let installed = match lineages
                .as_ref()
                .and_then(|lineages| lineages.get(&target.volume_id))
            {
                Some(installed) => installed,
                None => {
                    return Ok(local_cleanup_blocked(
                        InterventionReason::ForeignOrAmbiguousResidue,
                    ))
                }
            };
            if binding.attachment_id != installed.attachment_id
                || binding.attachment_epoch != installed.attachment_epoch
                || !remote_head_is_same_or_later(
                    &row.volume.head,
                    &installed.authority_head_at_install,
                )
            {
                return Ok(local_cleanup_blocked(
                    InterventionReason::AuthorityAmbiguous,
                ));
            }
            let identity = owned_lineage_identity(command, installed);
            let (local_durable_generation, pending_pack_count) =
                match inspect_installed_lineage_durability(installed, &identity, &row.volume.head) {
                    Ok(value) => value,
                    Err(_) => {
                        return Ok(AtomicColdDeleteAttempt::Blocked(AtomicColdDeleteBlocked {
                            reason: InterventionReason::ForeignOrAmbiguousResidue,
                            retained_volume_receipts: Vec::new(),
                        }))
                    }
                };
            let durability = CommandVolumeDurabilityProof {
                scope: scope.clone(),
                volume: LifecycleVolumeTarget {
                    volume_id: installed.volume_id.clone(),
                    disk_id: installed.disk_id.clone(),
                    disk_role: installed.disk_role,
                    attachment_id: installed.attachment_id.clone(),
                    attachment_epoch: installed.attachment_epoch,
                },
                remote_head: row.volume.head.clone(),
                local_durable_generation,
                remote_durable_generation: row.volume.head.generation,
                pending_pack_count,
            };
            if validate_owned_lineage_against_recovery_authority(
                installed,
                &durability,
                local_recovery_authority,
            )
            .is_err()
            {
                return Ok(local_cleanup_blocked(
                    InterventionReason::ForeignOrAmbiguousResidue,
                ));
            }
            if target.disk_role == DiskRole::Persistent && !durability_is_converged(&durability) {
                return Ok(AtomicColdDeleteAttempt::Blocked(AtomicColdDeleteBlocked {
                    reason: InterventionReason::PersistentDiskNotRemoteDurable,
                    retained_volume_receipts: vec![VolumeTerminalReceipt {
                        volume_id: durability.volume.volume_id.clone(),
                        disk_id: durability.volume.disk_id.clone(),
                        disk_role: durability.volume.disk_role,
                        attachment_id: durability.volume.attachment_id.clone(),
                        attachment_epoch: durability.volume.attachment_epoch,
                        local_durable_generation: durability.local_durable_generation,
                        remote_durable_generation: durability.remote_durable_generation,
                        authority_receipt_digest: None,
                    }],
                }));
            }
            let disposition = AtomicVolumeDispositionInput::OwnedRelease {
                release: CommandNormalReleaseInput {
                    durability,
                    transition_id: target.transition_id.clone(),
                },
            };
            anyhow::ensure!(
                dispositions
                    .insert(target.volume_id.clone(), disposition)
                    .is_none(),
                "Cold/Delete Volume target is duplicated"
            );
        }
        let dispositions = targets
            .iter()
            .map(|target| {
                dispositions
                    .remove(&target.volume_id)
                    .context("Cold/Delete Volume inspection omitted a configured slot")
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(AtomicColdDeleteAttempt::Exact(dispositions))
    }

    fn load_owned_lineages(
        &self,
        command: &LifecycleCommandEnvelope,
        expected_runtime_incarnation: Option<&RandomId128>,
        local_recovery_authority: &AtomicLocalRecoveryAuthority,
    ) -> Result<AtomicColdDeleteAttempt<BTreeMap<Id, InstalledOwnedLineage>>> {
        validate_local_recovery_authority(command, local_recovery_authority)?;
        let final_manifest = match super::start::load_installed_runtime_manifest(
            &self.state_directory,
            &command.cat_id,
        ) {
            Ok(manifest) => manifest,
            Err(_) => {
                return Ok(local_cleanup_blocked(
                    InterventionReason::ForeignOrAmbiguousResidue,
                ))
            }
        };
        let progress = match super::start::enumerate_installed_runtime_progress_manifests(
            &self.state_directory,
        ) {
            Ok(progress) => progress,
            Err(_) => {
                return Ok(local_cleanup_blocked(
                    InterventionReason::ForeignOrAmbiguousResidue,
                ))
            }
        };
        let cat_progress = progress
            .iter()
            .filter(|manifest| manifest.cat_id == command.cat_id)
            .collect::<Vec<_>>();
        let terminal_retained = match super::start::enumerate_terminal_retained_runtime_manifests(
            &self.state_directory,
        ) {
            Ok(manifests) => manifests,
            Err(_) => {
                return Ok(local_cleanup_blocked(
                    InterventionReason::ForeignOrAmbiguousResidue,
                ))
            }
        };
        let cat_terminal_retained = terminal_retained
            .iter()
            .filter(|manifest| manifest.cat_id == command.cat_id)
            .collect::<Vec<_>>();
        if validate_local_start_manifest_cardinality(
            final_manifest.is_some(),
            cat_progress.len(),
            cat_terminal_retained.len(),
            local_recovery_authority,
        )
        .is_err()
        {
            return Ok(local_cleanup_blocked(
                InterventionReason::ForeignOrAmbiguousResidue,
            ));
        }
        if let Some(manifest) = final_manifest {
            if validate_installed_manifest_binding(
                command,
                expected_runtime_incarnation,
                local_recovery_authority,
                &manifest,
            )
            .is_err()
            {
                return Ok(local_cleanup_blocked(
                    InterventionReason::ForeignOrAmbiguousResidue,
                ));
            }
            let lineages = manifest
                .volumes
                .iter()
                .map(|volume| {
                    (
                        volume.volume_id.clone(),
                        InstalledOwnedLineage {
                            volume_id: volume.volume_id.clone(),
                            disk_id: volume.disk_id.clone(),
                            disk_role: volume.disk_role,
                            attachment_id: volume.attachment_id.clone(),
                            attachment_epoch: volume.attachment_epoch,
                            acquire_origin: volume.acquire_origin.clone(),
                            authority_receipt_digest: volume.authority_receipt_digest.clone(),
                            authority_head_at_install: volume.launch_head.clone(),
                            storage: InstalledLineageStorage::Materialized(
                                volume.local_lineage_data_directory.clone(),
                            ),
                        },
                    )
                })
                .collect();
            return Ok(AtomicColdDeleteAttempt::Exact(lineages));
        }

        let (progress_manifest, authority_only_zero_mutation) = if let Some(manifest) =
            cat_progress.first()
        {
            if validate_progress_manifest_binding(
                command,
                expected_runtime_incarnation,
                local_recovery_authority,
                manifest,
            )
            .is_err()
            {
                return Ok(local_cleanup_blocked(
                    InterventionReason::ForeignOrAmbiguousResidue,
                ));
            }
            (Some(*manifest), false)
        } else {
            let retained = cat_terminal_retained[0];
            if validate_terminal_retained_cleanup_binding(
                command,
                retained,
                expected_runtime_incarnation,
                local_recovery_authority,
            )
            .is_err()
            {
                return Ok(local_cleanup_blocked(
                    InterventionReason::ForeignOrAmbiguousResidue,
                ));
            }
            (
                retained.runtime_progress.as_ref(),
                matches!(
                    &retained.retention_mode,
                    super::start::TerminalRetainedRuntimeMode::AuthorityOnlyOwnedZeroMutation { .. }
                ),
            )
        };
        if progress_manifest.is_none() {
            let retained = cat_terminal_retained[0];
            let super::start::TerminalRetainedRuntimeMode::InheritedPredecessorOwned { evidence } =
                &retained.retention_mode
            else {
                return Ok(local_cleanup_blocked(
                    InterventionReason::ForeignOrAmbiguousResidue,
                ));
            };
            let mut lineages = BTreeMap::new();
            let mut materialized_paths = BTreeSet::new();
            for (volume, config) in evidence.volumes.iter().zip(&command.runtime_config.volumes) {
                let receipt = &volume.retained_receipt;
                let storage = match &volume.local_lineage_data_directory {
                    Some(path) => {
                        if !materialized_paths.insert(path.clone()) {
                            return Ok(local_cleanup_blocked(
                                InterventionReason::ForeignOrAmbiguousResidue,
                            ));
                        }
                        InstalledLineageStorage::Materialized(path.clone())
                    }
                    None => InstalledLineageStorage::ProvenAbsent,
                };
                if receipt.volume_id != config.volume_id
                    || receipt.disk_id != config.disk_id
                    || receipt.disk_role != config.disk_role
                    || receipt.attachment_epoch.get() == 0
                    || receipt.authority_receipt_digest.as_ref()
                        != Some(&volume.immutable_start_grant_receipt_digest)
                    || !remote_head_is_valid(&volume.authoritative_head)
                    || lineages
                        .insert(
                            receipt.volume_id.clone(),
                            InstalledOwnedLineage {
                                volume_id: receipt.volume_id.clone(),
                                disk_id: receipt.disk_id.clone(),
                                disk_role: receipt.disk_role,
                                attachment_id: receipt.attachment_id.clone(),
                                attachment_epoch: receipt.attachment_epoch,
                                acquire_origin: volume.acquire_origin.clone(),
                                authority_receipt_digest: receipt.authority_receipt_digest.clone(),
                                authority_head_at_install: volume.authoritative_head.clone(),
                                storage,
                            },
                        )
                        .is_some()
                {
                    return Ok(local_cleanup_blocked(
                        InterventionReason::ForeignOrAmbiguousResidue,
                    ));
                }
            }
            if lineages.len() != command.runtime_config.volumes.len() {
                return Ok(local_cleanup_blocked(
                    InterventionReason::ForeignOrAmbiguousResidue,
                ));
            }
            return Ok(AtomicColdDeleteAttempt::Exact(lineages));
        }
        let Some(manifest) = progress_manifest else {
            return Ok(local_cleanup_blocked(
                InterventionReason::ForeignOrAmbiguousResidue,
            ));
        };
        let valid = manifest.version == ContractVersion::V1
            && manifest.node_id == command.node_id
            && manifest.placement_identity == command.placement_identity
            && manifest.runtime_config_id == command.runtime_config.config_id
            && manifest.runtime_config_digest == command.runtime_config.config_digest
            && expected_runtime_incarnation
                .is_none_or(|expected| manifest.runtime_incarnation == *expected)
            && manifest.volumes.len() == command.runtime_config.volumes.len();
        if !valid {
            return Ok(local_cleanup_blocked(
                InterventionReason::ForeignOrAmbiguousResidue,
            ));
        }
        let mut lineages = BTreeMap::new();
        for (volume, config) in manifest.volumes.iter().zip(&command.runtime_config.volumes) {
            let storage = match &volume.local_lineage_data_directory {
                Some(path) => InstalledLineageStorage::Materialized(path.clone()),
                None if authority_only_zero_mutation => InstalledLineageStorage::ProvenAbsent,
                None => continue,
            };
            if volume.volume_id != config.volume_id
                || volume.disk_id != config.disk_id
                || volume.disk_role != config.disk_role
                || volume.attachment_epoch.get() == 0
                || !remote_head_is_valid(&volume.authority_head)
                || lineages
                    .insert(
                        volume.volume_id.clone(),
                        InstalledOwnedLineage {
                            volume_id: volume.volume_id.clone(),
                            disk_id: volume.disk_id.clone(),
                            disk_role: volume.disk_role,
                            attachment_id: volume.attachment_id.clone(),
                            attachment_epoch: volume.attachment_epoch,
                            acquire_origin: volume.acquire_origin.clone(),
                            authority_receipt_digest: volume.authority_receipt_digest.clone(),
                            authority_head_at_install: volume.authority_head.clone(),
                            storage,
                        },
                    )
                    .is_some()
            {
                return Ok(local_cleanup_blocked(
                    InterventionReason::ForeignOrAmbiguousResidue,
                ));
            }
        }
        let unique_paths = lineages
            .values()
            .filter_map(|lineage| match &lineage.storage {
                InstalledLineageStorage::Materialized(path) => Some(path),
                InstalledLineageStorage::ProvenAbsent => None,
            })
            .collect::<BTreeSet<_>>();
        let materialized_count = lineages
            .values()
            .filter(|lineage| matches!(&lineage.storage, InstalledLineageStorage::Materialized(_)))
            .count();
        if unique_paths.len() != materialized_count {
            return Ok(local_cleanup_blocked(
                InterventionReason::ForeignOrAmbiguousResidue,
            ));
        }
        Ok(AtomicColdDeleteAttempt::Exact(lineages))
    }
}

fn validate_local_start_manifest_cardinality(
    has_installed_runtime: bool,
    progress_count: usize,
    terminal_retained_count: usize,
    local_recovery_authority: &AtomicLocalRecoveryAuthority,
) -> Result<()> {
    let valid = if has_installed_runtime {
        progress_count == 0 && terminal_retained_count == 0
    } else if matches!(
        local_recovery_authority,
        AtomicLocalRecoveryAuthority::DirectStartFailed { .. }
            | AtomicLocalRecoveryAuthority::KilledRetained { .. }
    ) {
        progress_count == 0 && terminal_retained_count == 1
    } else {
        progress_count + terminal_retained_count == 1
    };
    anyhow::ensure!(
        valid,
        "Cold/Delete lacks exactly one authorized local Start manifest"
    );
    Ok(())
}

impl AtomicColdDeleteLocalPort for InstalledColdDeleteLocalPort {
    fn inspect_or_converge(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicVolumeConvergenceRequest,
    ) -> Result<AtomicColdDeleteAttempt<AtomicVolumeConvergenceReceipt>> {
        let dispositions = match self.inspect_volume_slots(
            command,
            &request.scope,
            request.expected_runtime_incarnation.as_ref(),
            &request.local_recovery_authority,
            &request.targets,
        )? {
            AtomicColdDeleteAttempt::Exact(dispositions) => dispositions,
            AtomicColdDeleteAttempt::Blocked(blocked) => {
                return Ok(AtomicColdDeleteAttempt::Blocked(blocked))
            }
        };
        let mut retained = Vec::new();
        for disposition in &dispositions {
            let AtomicVolumeDispositionInput::OwnedRelease { release } = disposition else {
                continue;
            };
            let proof = &release.durability;
            if !durability_is_converged(proof) {
                retained.push(VolumeTerminalReceipt {
                    volume_id: proof.volume.volume_id.clone(),
                    disk_id: proof.volume.disk_id.clone(),
                    disk_role: proof.volume.disk_role,
                    attachment_id: proof.volume.attachment_id.clone(),
                    attachment_epoch: proof.volume.attachment_epoch,
                    local_durable_generation: proof.local_durable_generation,
                    remote_durable_generation: proof.remote_durable_generation,
                    authority_receipt_digest: None,
                });
            }
        }
        if !retained.is_empty() {
            retained.sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
            let reason = if retained
                .iter()
                .any(|receipt| receipt.disk_role == DiskRole::Persistent)
            {
                InterventionReason::PersistentDiskNotRemoteDurable
            } else {
                InterventionReason::RetainedLocalTail
            };
            return Ok(AtomicColdDeleteAttempt::Blocked(AtomicColdDeleteBlocked {
                reason,
                retained_volume_receipts: retained,
            }));
        }
        Ok(AtomicColdDeleteAttempt::Exact(
            AtomicVolumeConvergenceReceipt { dispositions },
        ))
    }

    fn inspect_delete_root(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicDeleteRootInspectionRequest,
    ) -> Result<AtomicColdDeleteAttempt<AtomicDeleteRootInspection>> {
        let target = AtomicVolumeConvergenceTarget {
            volume_id: request.volume_id.clone(),
            disk_id: request.disk_id.clone(),
            disk_role: DiskRole::Root,
            transition_id: transition_id(command, &request.volume_id, "delete-root-inspect")?,
        };
        match self.inspect_volume_slots(
            command,
            &request.scope,
            request.expected_runtime_incarnation.as_ref(),
            &request.local_recovery_authority,
            &[target],
        )? {
            AtomicColdDeleteAttempt::Exact(mut dispositions) => {
                let disposition = dispositions
                    .pop()
                    .context("Delete Root inspection returned no disposition")?;
                let inspection = match disposition {
                    AtomicVolumeDispositionInput::OwnedRelease { release } => {
                        AtomicDeleteRootInspection::Owned {
                            durability: release.durability,
                        }
                    }
                    AtomicVolumeDispositionInput::AlreadyUnowned {
                        volume,
                        expected_epoch,
                        expected_head,
                    } => AtomicDeleteRootInspection::AlreadyUnowned {
                        volume,
                        expected_epoch,
                        expected_head,
                    },
                };
                Ok(AtomicColdDeleteAttempt::Exact(inspection))
            }
            AtomicColdDeleteAttempt::Blocked(blocked) => {
                Ok(AtomicColdDeleteAttempt::Blocked(blocked))
            }
        }
    }

    fn inspect_or_remove_root_lineage(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicRootLineageCleanupRequest,
    ) -> Result<AtomicColdDeleteAttempt<AtomicRootLineageAbsenceReceipt>> {
        inspect_or_remove_root_lineage_local(self, command, request)
    }

    fn inspect_or_finalize_cold(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicColdFinalizationRequest,
    ) -> Result<AtomicColdDeleteAttempt<Sha256Digest>> {
        inspect_or_finalize_cold_local(self, command, request)
    }

    fn inspect_or_finalize_delete(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicDeleteFinalizationRequest,
    ) -> Result<AtomicColdDeleteAttempt<Sha256Digest>> {
        inspect_or_finalize_delete_local(self, command, request)
    }
}

fn validate_installed_manifest_binding(
    command: &LifecycleCommandEnvelope,
    expected_runtime_incarnation: Option<&RandomId128>,
    local_recovery_authority: &AtomicLocalRecoveryAuthority,
    manifest: &super::start::InstalledRuntimeManifest,
) -> Result<()> {
    validate_local_recovery_authority(command, local_recovery_authority)?;
    let runtime_incarnation_matches = match local_recovery_authority {
        AtomicLocalRecoveryAuthority::NeedsInterventionRetry { .. } => expected_runtime_incarnation
            .is_none_or(|expected| manifest.runtime_incarnation == *expected),
        AtomicLocalRecoveryAuthority::SuspendWarmOwned { carrier } => {
            expected_runtime_incarnation == Some(&carrier.installed_runtime.runtime_incarnation)
                && manifest.runtime_incarnation == carrier.installed_runtime.runtime_incarnation
        }
        _ => expected_runtime_incarnation
            .is_some_and(|expected| manifest.runtime_incarnation == *expected),
    };
    anyhow::ensure!(
        manifest.version == ContractVersion::V1
            && manifest.node_id == command.node_id
            && manifest.cat_id == command.cat_id
            && manifest.placement_identity == command.placement_identity
            && manifest.runtime_config_id == command.runtime_config.config_id
            && manifest.runtime_config_digest == command.runtime_config.config_digest
            && runtime_incarnation_matches
            && manifest.volumes.len() == command.runtime_config.volumes.len()
            && manifest.manifest_digest
                == super::start::installed_runtime_manifest_digest(manifest)?,
        "installed Runtime manifest does not bind the exact stopped command"
    );
    match local_recovery_authority {
        AtomicLocalRecoveryAuthority::TerminalRetainedForbidden {
            predecessor_operation_id,
            predecessor_request_fingerprint,
            ..
        } => anyhow::ensure!(
            manifest.source_lifecycle_operation_id == *predecessor_operation_id
                && manifest.request_fingerprint == *predecessor_request_fingerprint,
            "installed Runtime manifest is not the direct predecessor"
        ),
        AtomicLocalRecoveryAuthority::DirectStartFailed { .. } => {
            anyhow::bail!("StartFailed predecessor cannot authorize a RuntimeReady manifest")
        }
        AtomicLocalRecoveryAuthority::KilledRetained {
            stopped_runtime_incarnation,
            retained_volume_receipts,
            ..
        } => {
            anyhow::ensure!(
                stopped_runtime_incarnation.as_ref() == expected_runtime_incarnation,
                "Killed bridge changed the stopped runtime incarnation"
            );
            for receipt in retained_volume_receipts {
                let installed = manifest
                    .volumes
                    .iter()
                    .find(|volume| volume.volume_id == receipt.volume_id)
                    .context("Killed retained receipt is absent from installed Runtime manifest")?;
                validate_retained_receipt_identity(
                    receipt,
                    &installed.disk_id,
                    installed.disk_role,
                    &installed.attachment_id,
                    installed.attachment_epoch,
                    installed.authority_receipt_digest.as_ref(),
                )?;
            }
        }
        AtomicLocalRecoveryAuthority::SuspendWarmOwned { carrier } => anyhow::ensure!(
            manifest == carrier.installed_runtime.as_ref(),
            "Suspend/Warm carrier changed its exact installed Runtime manifest"
        ),
        AtomicLocalRecoveryAuthority::NeedsInterventionRetry {
            retained_volume_receipts,
            ..
        } => {
            for receipt in retained_volume_receipts {
                let installed = manifest.volumes.iter().find(|volume| {
                    volume.volume_id == receipt.volume_id
                }).context(
                    "NeedsIntervention retained receipt is absent from installed Runtime manifest",
                )?;
                validate_retained_receipt_identity(
                    receipt,
                    &installed.disk_id,
                    installed.disk_role,
                    &installed.attachment_id,
                    installed.attachment_epoch,
                    installed.authority_receipt_digest.as_ref(),
                )?;
            }
        }
    }
    let mut directories = BTreeSet::new();
    for (installed, configured) in manifest.volumes.iter().zip(&command.runtime_config.volumes) {
        anyhow::ensure!(
            installed.volume_id == configured.volume_id
                && installed.disk_id == configured.disk_id
                && installed.disk_role == configured.disk_role
                && installed.attachment_epoch.get() > 0
                && remote_head_is_valid(&installed.launch_head)
                && directories.insert(installed.local_lineage_data_directory.clone()),
            "installed Runtime manifest changed a configured Volume lineage"
        );
    }
    Ok(())
}

fn validate_progress_manifest_binding(
    command: &LifecycleCommandEnvelope,
    expected_runtime_incarnation: Option<&RandomId128>,
    local_recovery_authority: &AtomicLocalRecoveryAuthority,
    manifest: &super::start::InstalledRuntimeProgressManifest,
) -> Result<()> {
    validate_local_recovery_authority(command, local_recovery_authority)?;
    let AtomicLocalRecoveryAuthority::TerminalRetainedForbidden {
        predecessor_operation_id,
        predecessor_request_fingerprint,
        ..
    } = local_recovery_authority
    else {
        anyhow::bail!("StartFailed/Killed predecessor requires a sealed terminal-retained manifest")
    };
    anyhow::ensure!(
        manifest.version == ContractVersion::V1
            && manifest.node_id == command.node_id
            && manifest.cat_id == command.cat_id
            && manifest.placement_identity == command.placement_identity
            && manifest.source_lifecycle_operation_id == *predecessor_operation_id
            && manifest.request_fingerprint == *predecessor_request_fingerprint
            && manifest.runtime_config_id == command.runtime_config.config_id
            && manifest.runtime_config_digest == command.runtime_config.config_digest
            && expected_runtime_incarnation
                .is_none_or(|expected| manifest.runtime_incarnation == *expected)
            && manifest.volumes.len() == command.runtime_config.volumes.len()
            && manifest.manifest_digest
                == super::start::installed_runtime_progress_manifest_digest(manifest)?,
        "local Start progress is not the direct predecessor"
    );
    Ok(())
}

fn validate_retained_receipt_identity(
    receipt: &VolumeTerminalReceipt,
    disk_id: &Id,
    disk_role: DiskRole,
    attachment_id: &Id,
    attachment_epoch: FenceEpoch,
    authority_receipt_digest: Option<&Sha256Digest>,
) -> Result<()> {
    anyhow::ensure!(
        receipt.disk_id == *disk_id
            && receipt.disk_role == disk_role
            && receipt.attachment_id == *attachment_id
            && receipt.attachment_epoch == attachment_epoch
            && receipt.authority_receipt_digest.as_ref() == authority_receipt_digest
            && receipt.remote_durable_generation <= receipt.local_durable_generation,
        "Killed retained Volume changed its installed owner, epoch, or authority"
    );
    Ok(())
}

fn validate_owned_lineage_against_recovery_authority(
    installed: &InstalledOwnedLineage,
    durability: &CommandVolumeDurabilityProof,
    local_recovery_authority: &AtomicLocalRecoveryAuthority,
) -> Result<()> {
    let (retained_volume_receipts, receipt_is_required, authority_name) =
        match local_recovery_authority {
            AtomicLocalRecoveryAuthority::KilledRetained {
                retained_volume_receipts,
                ..
            } => (retained_volume_receipts, true, "Killed"),
            AtomicLocalRecoveryAuthority::NeedsInterventionRetry {
                retained_volume_receipts,
                ..
            } => (retained_volume_receipts, false, "NeedsIntervention"),
            _ => return Ok(()),
        };
    let Some(receipt) = retained_volume_receipts
        .iter()
        .find(|receipt| receipt.volume_id == installed.volume_id)
    else {
        anyhow::ensure!(
            !receipt_is_required,
            "fresh Owned lineage is missing from the {authority_name} retained set"
        );
        return Ok(());
    };
    validate_retained_receipt_identity(
        receipt,
        &installed.disk_id,
        installed.disk_role,
        &installed.attachment_id,
        installed.attachment_epoch,
        installed.authority_receipt_digest.as_ref(),
    )?;
    anyhow::ensure!(
        durability.local_durable_generation == receipt.local_durable_generation
            && durability.remote_durable_generation >= receipt.remote_durable_generation
            && durability.remote_durable_generation <= durability.local_durable_generation,
        "fresh Owned lineage does not monotonically close the {authority_name} L/R receipt"
    );
    Ok(())
}

fn owned_lineage_identity(
    command: &LifecycleCommandEnvelope,
    installed: &InstalledOwnedLineage,
) -> AttachmentLineageIdentity {
    AttachmentLineageIdentity {
        volume_id: installed.volume_id.clone(),
        attachment_id: installed.attachment_id.clone(),
        attachment_epoch: installed.attachment_epoch,
        acquire_origin: installed.acquire_origin.clone(),
        node_id: command.node_id.clone(),
        placement_epoch: command.placement_identity.placement_epoch,
    }
}

fn inspect_lineage_durability(
    path: &Path,
    expected_identity: &AttachmentLineageIdentity,
    remote_head: &RemoteHead,
) -> Result<(Generation, WireU64)> {
    inspect_lineage_durability_with_policy(
        path,
        expected_identity,
        remote_head,
        CoveredPackPolicy::RemoveCovered,
    )
}

fn inspect_installed_lineage_durability(
    installed: &InstalledOwnedLineage,
    expected_identity: &AttachmentLineageIdentity,
    remote_head: &RemoteHead,
) -> Result<(Generation, WireU64)> {
    match &installed.storage {
        InstalledLineageStorage::Materialized(path) => {
            inspect_lineage_durability(Path::new(path.as_str()), expected_identity, remote_head)
        }
        InstalledLineageStorage::ProvenAbsent => Ok((
            remote_head.generation,
            WireU64::new(0).context("zero is a valid wire u64")?,
        )),
    }
}

/// Strict observation-only lineage join shared with atomic Start. Covered
/// canonical packs are ignored because the exact remote head proves them
/// durable, but this variant never unlinks them. A torn temp is ambiguous.
pub(super) fn inspect_lineage_durability_read_only(
    path: &Path,
    expected_identity: &AttachmentLineageIdentity,
    remote_head: &RemoteHead,
) -> Result<(Generation, WireU64)> {
    inspect_lineage_durability_with_policy(
        path,
        expected_identity,
        remote_head,
        CoveredPackPolicy::ReadOnly,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoveredPackPolicy {
    ReadOnly,
    RemoveCovered,
}

fn inspect_lineage_durability_with_policy(
    path: &Path,
    expected_identity: &AttachmentLineageIdentity,
    remote_head: &RemoteHead,
    policy: CoveredPackPolicy,
) -> Result<(Generation, WireU64)> {
    anyhow::ensure!(
        path.is_absolute() && remote_head_is_valid(remote_head),
        "local durability inspection received an invalid path or remote head"
    );
    let (parent, name) = open_absolute_parent(path)?;
    let directory = openat_directory(&parent, &name)
        .with_context(|| format!("open local Volume lineage {}", path.display()))?;
    let directory_metadata = directory.metadata()?;
    anyhow::ensure!(
        directory_metadata.file_type().is_dir(),
        "local Volume lineage is not a directory"
    );
    let identity = read_attachment_identity(&directory)?;
    anyhow::ensure!(
        identity == *expected_identity,
        "local Volume identity sidecar changed lineage"
    );
    let pending_name = CString::new(cats_api::blockd::PENDING_PACK_DIR)?;
    let pending = openat_directory(&directory, &pending_name)
        .context("open local Volume pending-pack directory")?;
    anyhow::ensure!(
        pending.metadata()?.dev() == directory_metadata.dev(),
        "pending-pack directory crosses a filesystem boundary"
    );

    let remote_generation = remote_head.generation.get();
    let mut retained_bases = Vec::new();
    let mut removed = false;
    let mut names = directory_entry_names(&pending)?;
    names.sort();
    for raw_name in names {
        if raw_name == b"." || raw_name == b".." {
            continue;
        }
        let name = CString::new(raw_name.clone()).context("pending-pack filename contains NUL")?;
        let display_name =
            std::str::from_utf8(&raw_name).context("pending-pack filename is not UTF-8")?;
        if display_name.starts_with(".tmp-") {
            anyhow::ensure!(
                policy == CoveredPackPolicy::RemoveCovered,
                "read-only lineage inspection found an ambiguous pending-pack temp"
            );
            let file = openat_regular(&pending, &name)
                .context("open torn pending-pack temp without following links")?;
            verify_regular_single_link(&file)?;
            unlinkat_file(&pending, &name).context("remove unacknowledged pending-pack temp")?;
            removed = true;
            continue;
        }
        anyhow::ensure!(
            display_name.ends_with(cats_api::blockd::PACK_FILE_SUFFIX),
            "unknown entry in pending-pack directory"
        );
        let mut file =
            openat_regular(&pending, &name).context("open pending pack without following links")?;
        verify_regular_single_link(&file)?;
        let metadata_before = file.metadata()?;
        let file_len = usize::try_from(metadata_before.len())
            .context("pending-pack length overflows usize")?;
        anyhow::ensure!(
            file_len >= cats_blockd::format::ENCODED_PACK_PREFIX_LEN,
            "pending pack is truncated"
        );
        let mut prefix = [0_u8; cats_blockd::format::ENCODED_PACK_PREFIX_LEN];
        file.read_exact(&mut prefix)
            .context("read pending-pack fixed prefix")?;
        let header_len = cats_blockd::format::encoded_pack_header_len(&prefix)
            .context("decode pending-pack header length")?;
        anyhow::ensure!(
            header_len <= PACK_HEADER_MAX_BYTES && header_len <= file_len,
            "pending-pack header exceeds its bounded file"
        );
        let mut header_bytes = vec![0_u8; header_len];
        header_bytes[..prefix.len()].copy_from_slice(&prefix);
        file.read_exact(&mut header_bytes[prefix.len()..])
            .context("read pending-pack header")?;
        let (header, payload_offset) = cats_blockd::format::decode_pack_header(&header_bytes)
            .context("decode pending-pack header")?;
        anyhow::ensure!(
            payload_offset == header_len
                && file.metadata()?.len() == metadata_before.len()
                && header.volume_id == expected_identity.volume_id.as_str()
                && header.lease_epoch.is_none()
                && header.attachment_id.as_deref()
                    == Some(expected_identity.attachment_id.as_str())
                && header.attachment_epoch
                    == Some(i64::try_from(expected_identity.attachment_epoch.get())?)
                && header.acquire_origin.as_ref() == Some(&expected_identity.acquire_origin)
                && header.base_generation >= 0,
            "pending pack changed or does not bind the exact target-v2 lineage"
        );
        let canonical_name = format!(
            "{:020}-{}{}",
            header.base_generation,
            header.txn,
            cats_api::blockd::PACK_FILE_SUFFIX
        );
        anyhow::ensure!(
            canonical_name == display_name,
            "pending-pack filename and header identity differ"
        );
        let base = u64::try_from(header.base_generation)?;
        if base < remote_generation {
            if policy == CoveredPackPolicy::RemoveCovered {
                unlinkat_file(&pending, &name)
                    .context("remove exact remotely covered pending pack")?;
                removed = true;
            }
        } else {
            retained_bases.push(base);
        }
    }
    if removed {
        pending
            .sync_all()
            .context("fsync pending-pack cleanup discovery")?;
    }
    let mut expected = remote_generation;
    for base in &retained_bases {
        anyhow::ensure!(
            *base == expected,
            "retained pending-pack chain has a gap or duplicate"
        );
        expected = expected
            .checked_add(1)
            .context("local durable generation overflows")?;
    }
    let local_durable_generation =
        Generation::new(expected).context("local durable generation exceeds wire range")?;
    let pending_pack_count = WireU64::new(u64::try_from(retained_bases.len())?)
        .context("pending-pack count exceeds wire range")?;
    Ok((local_durable_generation, pending_pack_count))
}

fn read_attachment_identity(directory: &File) -> Result<AttachmentLineageIdentity> {
    let name = c"identity.json";
    let mut file = openat_regular(directory, name)
        .context("open attachment identity without following links")?;
    verify_regular_single_link(&file)?;
    let length = usize::try_from(file.metadata()?.len())
        .context("attachment identity length overflows usize")?;
    anyhow::ensure!(
        (1..=ATTACHMENT_IDENTITY_MAX_BYTES).contains(&length),
        "attachment identity has an invalid length"
    );
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)
        .context("read attachment identity")?;
    anyhow::ensure!(
        bytes.len() == length,
        "attachment identity changed while reading"
    );
    let identity: AttachmentLineageIdentity =
        serde_json::from_slice(&bytes).context("decode attachment identity")?;
    anyhow::ensure!(
        serde_json::to_vec(&identity)? == bytes,
        "attachment identity is not canonical JSON"
    );
    Ok(identity)
}

fn verify_regular_single_link(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_file() && metadata.nlink() == 1,
        "local cleanup target is not one regular single-link file"
    );
    Ok(())
}

fn open_absolute_parent(path: &Path) -> Result<(File, CString)> {
    anyhow::ensure!(path.is_absolute(), "local lineage path is not absolute");
    let mut components = path.components();
    anyhow::ensure!(
        matches!(components.next(), Some(Component::RootDir)),
        "local lineage path lacks a root component"
    );
    let mut names = components
        .map(|component| match component {
            Component::Normal(name) => {
                CString::new(name.as_bytes()).context("local lineage component contains NUL")
            }
            _ => anyhow::bail!("local lineage path contains a non-normal component"),
        })
        .collect::<Result<Vec<_>>>()?;
    let name = names
        .pop()
        .context("refuse to operate on filesystem root")?;
    let root = CString::new("/")?;
    let descriptor = loop {
        // SAFETY: `root` is a live NUL-terminated path and a successful fresh
        // descriptor is adopted exactly once below.
        let descriptor = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
            )
        };
        if descriptor >= 0 {
            break descriptor;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error).context("open filesystem root for descriptor traversal");
        }
    };
    // SAFETY: `descriptor` is a fresh owned descriptor from successful open.
    let mut current = unsafe { File::from_raw_fd(descriptor) };
    for component in names {
        current = openat_directory(&current, &component)
            .context("walk local lineage without following links")?;
    }
    Ok((current, name))
}

fn openat_directory(directory: &File, name: &CStr) -> Result<File> {
    openat_file(
        directory,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )
}

fn openat_regular(directory: &File, name: &CStr) -> Result<File> {
    openat_file(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )
}

fn openat_file(directory: &File, name: &CStr, flags: i32, mode: u32) -> Result<File> {
    loop {
        // SAFETY: descriptor/name remain live through openat. A successful
        // descriptor is transferred exactly once into `File`.
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
        if descriptor >= 0 {
            // SAFETY: successful openat returned a fresh owned descriptor.
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

fn unlinkat_file(directory: &File, name: &CStr) -> Result<()> {
    loop {
        // SAFETY: descriptor/name remain live and unlinkat retains neither.
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

fn directory_entry_names(directory: &File) -> Result<Vec<Vec<u8>>> {
    let duplicate = directory
        .try_clone()
        .context("duplicate local cleanup directory descriptor")?
        .into_raw_fd();
    // SAFETY: ownership of the duplicate transfers to fdopendir on success.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        // SAFETY: failed fdopendir did not consume the descriptor.
        unsafe { libc::close(duplicate) };
        return Err(error).context("open local cleanup directory stream");
    }
    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            // SAFETY: this wrapper uniquely owns the live DIR pointer.
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        clear_errno();
        // SAFETY: stream remains exclusively owned and live for this call.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error).context("read local cleanup directory entry");
            }
            break;
        }
        // SAFETY: d_name is NUL-terminated and copied before next readdir.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        names.push(name.to_bytes().to_vec());
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    // SAFETY: clears only this thread's errno for the immediately following
    // readdir EOF/error distinction.
    unsafe { *libc::__errno_location() = 0 }
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    // SAFETY: clears only this thread's errno for the immediately following
    // readdir EOF/error distinction.
    unsafe { *libc::__error() = 0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LocalCleanupPhase {
    ColdFinal,
    DeleteRoot,
    DeleteFinal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalCleanupTarget {
    absolute_path: String,
    identity: AttachmentLineageIdentity,
    parent_device: WireU64,
    parent_inode: WireU64,
    directory_device: WireU64,
    directory_inode: WireU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalCleanupMarker {
    version: ContractVersion,
    operation_id: Id,
    request_fingerprint: Sha256Digest,
    cat_id: Id,
    node_id: Id,
    placement_identity: cats_api::runtime_lifecycle::PlacementIdentity,
    runtime_config_digest: Sha256Digest,
    phase: LocalCleanupPhase,
    request_digest: Sha256Digest,
    targets: Vec<LocalCleanupTarget>,
    completed: bool,
    marker_digest: Sha256Digest,
}

#[derive(Serialize)]
struct LocalCleanupMarkerPreimage<'a> {
    version: ContractVersion,
    operation_id: &'a Id,
    request_fingerprint: &'a Sha256Digest,
    cat_id: &'a Id,
    node_id: &'a Id,
    placement_identity: &'a cats_api::runtime_lifecycle::PlacementIdentity,
    runtime_config_digest: &'a Sha256Digest,
    phase: LocalCleanupPhase,
    request_digest: &'a Sha256Digest,
    targets: &'a [LocalCleanupTarget],
    completed: bool,
}

impl LocalCleanupMarker {
    fn new(
        command: &LifecycleCommandEnvelope,
        phase: LocalCleanupPhase,
        request_digest: Sha256Digest,
        targets: Vec<LocalCleanupTarget>,
    ) -> Result<Self> {
        anyhow::ensure!(
            targets
                .windows(2)
                .all(|pair| pair[0].identity.volume_id < pair[1].identity.volume_id)
                && targets
                    .iter()
                    .map(|target| &target.absolute_path)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == targets.len(),
            "local cleanup target set is not strictly ordered"
        );
        let mut marker = Self {
            version: ContractVersion::V1,
            operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            cat_id: command.cat_id.clone(),
            node_id: command.node_id.clone(),
            placement_identity: command.placement_identity.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            phase,
            request_digest,
            targets,
            completed: false,
            marker_digest: Sha256Digest::from_bytes([0; 32]),
        };
        marker.marker_digest = local_cleanup_marker_digest(&marker)?;
        validate_local_cleanup_marker(command, &marker)?;
        Ok(marker)
    }

    fn mark_completed(&mut self) -> Result<()> {
        self.completed = true;
        self.marker_digest = local_cleanup_marker_digest(self)?;
        Ok(())
    }
}

fn local_cleanup_marker_digest(marker: &LocalCleanupMarker) -> Result<Sha256Digest> {
    canonical_digest(
        LOCAL_CLEANUP_MARKER_DOMAIN,
        &LocalCleanupMarkerPreimage {
            version: marker.version,
            operation_id: &marker.operation_id,
            request_fingerprint: &marker.request_fingerprint,
            cat_id: &marker.cat_id,
            node_id: &marker.node_id,
            placement_identity: &marker.placement_identity,
            runtime_config_digest: &marker.runtime_config_digest,
            phase: marker.phase,
            request_digest: &marker.request_digest,
            targets: &marker.targets,
            completed: marker.completed,
        },
    )
}

fn validate_local_cleanup_marker(
    command: &LifecycleCommandEnvelope,
    marker: &LocalCleanupMarker,
) -> Result<()> {
    anyhow::ensure!(
        marker.version == ContractVersion::V1
            && marker.operation_id == command.operation_id
            && marker.request_fingerprint == command.request_fingerprint
            && marker.cat_id == command.cat_id
            && marker.node_id == command.node_id
            && marker.placement_identity == command.placement_identity
            && marker.runtime_config_digest == command.runtime_config.config_digest
            && marker
                .targets
                .windows(2)
                .all(|pair| pair[0].identity.volume_id < pair[1].identity.volume_id)
            && marker
                .targets
                .iter()
                .map(|target| &target.absolute_path)
                .collect::<BTreeSet<_>>()
                .len()
                == marker.targets.len()
            && marker.marker_digest == local_cleanup_marker_digest(marker)?,
        "local cleanup marker identity, ordering, or digest is invalid"
    );
    Ok(())
}

fn local_cleanup_target(
    path: &Path,
    expected_identity: AttachmentLineageIdentity,
) -> Result<LocalCleanupTarget> {
    let (parent, name) = open_absolute_parent(path)?;
    let parent_metadata = parent.metadata()?;
    let directory = openat_directory(&parent, &name)
        .with_context(|| format!("open exact cleanup target {}", path.display()))?;
    let directory_metadata = directory.metadata()?;
    anyhow::ensure!(
        directory_metadata.file_type().is_dir()
            && directory_metadata.dev() == parent_metadata.dev()
            && read_attachment_identity(&directory)? == expected_identity,
        "local cleanup target changed filesystem or lineage identity"
    );
    Ok(LocalCleanupTarget {
        absolute_path: path
            .to_str()
            .context("local cleanup target path is not UTF-8")?
            .to_owned(),
        identity: expected_identity,
        parent_device: wire_u64(parent_metadata.dev(), "cleanup parent device")?,
        parent_inode: wire_u64(parent_metadata.ino(), "cleanup parent inode")?,
        directory_device: wire_u64(directory_metadata.dev(), "cleanup directory device")?,
        directory_inode: wire_u64(directory_metadata.ino(), "cleanup directory inode")?,
    })
}

fn wire_u64(value: u64, field: &str) -> Result<WireU64> {
    WireU64::new(value).with_context(|| format!("{field} exceeds wire range"))
}

fn open_cleanup_marker_namespace(state: &StateDirectory, create: bool) -> Result<Option<File>> {
    let base = state
        .try_clone_directory()
        .context("open retained Node state directory for cleanup marker")?;
    let name = CString::new(LOCAL_CLEANUP_MARKER_NAMESPACE)?;
    if create {
        loop {
            // SAFETY: descriptor/name are live and mkdirat retains neither.
            let result = unsafe { libc::mkdirat(base.as_raw_fd(), name.as_ptr(), 0o700) };
            if result == 0 {
                base.sync_all()
                    .context("fsync new local cleanup marker namespace")?;
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == ErrorKind::AlreadyExists {
                break;
            }
            return Err(error).context("create local cleanup marker namespace");
        }
    }
    match openat_directory(&base, &name) {
        Ok(directory) => Ok(Some(directory)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|source| source.kind() == ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).context("open local cleanup marker namespace"),
    }
}

fn cleanup_marker_name(
    command: &LifecycleCommandEnvelope,
    phase: LocalCleanupPhase,
    suffix: &str,
) -> Result<CString> {
    let digest = canonical_digest(
        LOCAL_CLEANUP_MARKER_DOMAIN,
        &serde_json::json!({
            "operation_id": command.operation_id,
            "request_fingerprint": command.request_fingerprint,
            "phase": phase,
        }),
    )?;
    let mut name = String::with_capacity(64 + suffix.len());
    for byte in digest.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut name, "{byte:02x}").expect("formatting into String is infallible");
    }
    name.push_str(suffix);
    CString::new(name).context("cleanup marker filename contains NUL")
}

fn load_cleanup_marker(
    state: &StateDirectory,
    command: &LifecycleCommandEnvelope,
    phase: LocalCleanupPhase,
) -> Result<Option<LocalCleanupMarker>> {
    let Some(directory) = open_cleanup_marker_namespace(state, false)? else {
        return Ok(None);
    };
    let name = cleanup_marker_name(command, phase, LOCAL_CLEANUP_MARKER_SUFFIX)?;
    let mut file = match openat_regular(&directory, &name) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|source| source.kind() == ErrorKind::NotFound) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error).context("open local cleanup marker"),
    };
    verify_regular_single_link(&file)?;
    let length = usize::try_from(file.metadata()?.len())
        .context("local cleanup marker length overflows usize")?;
    anyhow::ensure!(
        (1..=LOCAL_CLEANUP_MARKER_MAX_BYTES).contains(&length),
        "local cleanup marker has invalid length"
    );
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)
        .context("read local cleanup marker")?;
    anyhow::ensure!(
        bytes.len() == length,
        "local cleanup marker changed while reading"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("decode local cleanup marker JSON")?;
    anyhow::ensure!(
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&value) == bytes,
        "local cleanup marker is not canonical JSON"
    );
    let marker: LocalCleanupMarker =
        serde_json::from_value(value).context("decode local cleanup marker")?;
    validate_local_cleanup_marker(command, &marker)?;
    anyhow::ensure!(marker.phase == phase, "local cleanup marker phase changed");
    Ok(Some(marker))
}

fn publish_cleanup_marker(
    state: &StateDirectory,
    command: &LifecycleCommandEnvelope,
    marker: &LocalCleanupMarker,
) -> Result<()> {
    validate_local_cleanup_marker(command, marker)?;
    let directory = open_cleanup_marker_namespace(state, true)?
        .context("created local cleanup marker namespace disappeared")?;
    let target = cleanup_marker_name(command, marker.phase, LOCAL_CLEANUP_MARKER_SUFFIX)?;
    let temporary = cleanup_marker_name(command, marker.phase, LOCAL_CLEANUP_MARKER_TEMP_SUFFIX)?;
    unlinkat_if_exists(&directory, &temporary).context("remove stale local cleanup marker temp")?;
    let value = serde_json::to_value(marker).context("encode local cleanup marker")?;
    let bytes = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    anyhow::ensure!(
        (1..=LOCAL_CLEANUP_MARKER_MAX_BYTES).contains(&bytes.len()),
        "local cleanup marker exceeds byte cap"
    );
    let mut file = openat_file(
        &directory,
        &temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )?;
    file.write_all(&bytes)
        .context("write local cleanup marker temp")?;
    file.sync_all().context("fsync local cleanup marker temp")?;
    verify_regular_single_link(&file)?;
    renameat(&directory, &temporary, &target).context("publish local cleanup marker")?;
    directory
        .sync_all()
        .context("fsync local cleanup marker publication")?;
    let reloaded = load_cleanup_marker(state, command, marker.phase)?
        .context("published local cleanup marker disappeared")?;
    anyhow::ensure!(
        &reloaded == marker,
        "published local cleanup marker changed"
    );
    Ok(())
}

fn unlinkat_if_exists(directory: &File, name: &CStr) -> Result<bool> {
    loop {
        // SAFETY: descriptor/name remain live and unlinkat retains neither.
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == ErrorKind::NotFound {
            return Ok(false);
        }
        return Err(error.into());
    }
}

fn renameat(directory: &File, source: &CStr, target: &CStr) -> Result<()> {
    loop {
        // SAFETY: one live descriptor owns both NUL-terminated component
        // names and renameat retains none of them.
        let result = unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                source.as_ptr(),
                directory.as_raw_fd(),
                target.as_ptr(),
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

fn remove_cleanup_target(target: &LocalCleanupTarget) -> Result<()> {
    let path = Path::new(&target.absolute_path);
    let (parent, name) = open_absolute_parent(path)?;
    let parent_metadata = parent.metadata()?;
    anyhow::ensure!(
        parent_metadata.dev() == target.parent_device.get()
            && parent_metadata.ino() == target.parent_inode.get(),
        "local cleanup target parent changed identity"
    );
    let directory = match openat_directory(&parent, &name) {
        Ok(directory) => directory,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|source| source.kind() == ErrorKind::NotFound) =>
        {
            return Ok(())
        }
        Err(error) => return Err(error).context("reopen exact local cleanup target"),
    };
    let metadata = directory.metadata()?;
    anyhow::ensure!(
        metadata.dev() == target.directory_device.get()
            && metadata.ino() == target.directory_inode.get()
            && read_attachment_identity(&directory)? == target.identity,
        "local cleanup target changed after durable intent"
    );
    remove_directory_contents(&directory, metadata.dev())?;
    let current = fstatat_nofollow(&parent, &name)?
        .context("local cleanup target disappeared before final identity check")?;
    anyhow::ensure!(
        local_device_number(current.st_dev)? == target.directory_device.get()
            && current.st_ino == target.directory_inode.get(),
        "local cleanup target was substituted before unlink"
    );
    unlinkat_directory(&parent, &name).context("unlink exact local cleanup directory")?;
    parent
        .sync_all()
        .context("fsync exact local cleanup parent")?;
    Ok(())
}

fn verify_cleanup_target_absent(target: &LocalCleanupTarget) -> Result<()> {
    let (parent, name) = open_absolute_parent(Path::new(&target.absolute_path))?;
    let metadata = parent.metadata()?;
    anyhow::ensure!(
        metadata.dev() == target.parent_device.get()
            && metadata.ino() == target.parent_inode.get()
            && fstatat_nofollow(&parent, &name)?.is_none(),
        "local cleanup target absence is not exact"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn local_device_number(device: libc::dev_t) -> Result<u64> {
    Ok(device)
}

#[cfg(not(target_os = "linux"))]
fn local_device_number(device: libc::dev_t) -> Result<u64> {
    u64::try_from(device).context("local cleanup device is negative")
}

fn remove_directory_contents(directory: &File, root_device: u64) -> Result<()> {
    let mut names = directory_entry_names(directory)?;
    names.sort();
    for raw_name in names {
        if raw_name == b"." || raw_name == b".." {
            continue;
        }
        let name = CString::new(raw_name).context("local cleanup entry contains NUL")?;
        let before = fstatat_nofollow(directory, &name)?
            .context("local cleanup entry disappeared before inspection")?;
        let device = local_device_number(before.st_dev)?;
        anyhow::ensure!(
            device == root_device,
            "local cleanup entry crosses filesystem"
        );
        let kind = before.st_mode & libc::S_IFMT;
        if kind == libc::S_IFREG {
            let file = openat_regular(directory, &name)
                .context("open exact local cleanup regular file")?;
            let metadata = file.metadata()?;
            anyhow::ensure!(
                metadata.dev() == device
                    && metadata.ino() == before.st_ino
                    && metadata.nlink() == 1,
                "local cleanup regular file changed identity or has hard links"
            );
            let current = fstatat_nofollow(directory, &name)?
                .context("local cleanup regular file disappeared before unlink")?;
            anyhow::ensure!(
                current.st_dev == before.st_dev && current.st_ino == before.st_ino,
                "local cleanup regular file was substituted"
            );
            unlinkat_file(directory, &name)?;
        } else if kind == libc::S_IFDIR {
            let child = openat_directory(directory, &name)
                .context("open exact local cleanup subdirectory")?;
            let metadata = child.metadata()?;
            anyhow::ensure!(
                metadata.dev() == device && metadata.ino() == before.st_ino,
                "local cleanup subdirectory changed identity"
            );
            remove_directory_contents(&child, root_device)?;
            let current = fstatat_nofollow(directory, &name)?
                .context("local cleanup subdirectory disappeared before unlink")?;
            anyhow::ensure!(
                current.st_dev == before.st_dev && current.st_ino == before.st_ino,
                "local cleanup subdirectory was substituted"
            );
            unlinkat_directory(directory, &name)?;
        } else {
            anyhow::bail!("local cleanup refuses symlink or special-file residue")
        }
    }
    directory
        .sync_all()
        .context("fsync descriptor-safe directory cleanup")?;
    Ok(())
}

fn fstatat_nofollow(directory: &File, name: &CStr) -> Result<Option<libc::stat>> {
    loop {
        // SAFETY: stat is initialized by successful fstatat and descriptor/name
        // remain live. AT_SYMLINK_NOFOLLOW makes classification descriptor-safe.
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: `directory` and `name` remain live for the call, and `stat`
        // points to writable storage for the complete `libc::stat` result.
        let result = unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Ok(Some(stat));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error.into());
    }
}

fn unlinkat_directory(directory: &File, name: &CStr) -> Result<()> {
    loop {
        // SAFETY: descriptor/name remain live and unlinkat retains neither.
        let result =
            unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

fn complete_local_cleanup(
    port: &InstalledColdDeleteLocalPort,
    command: &LifecycleCommandEnvelope,
    mut marker: LocalCleanupMarker,
    remove_restart_manifests: bool,
    expected_runtime_incarnation: Option<&RandomId128>,
    local_recovery_authority: &AtomicLocalRecoveryAuthority,
) -> Result<Sha256Digest> {
    if remove_restart_manifests {
        validate_exact_cat_progress_manifests(
            port,
            command,
            expected_runtime_incarnation,
            local_recovery_authority,
        )?;
        if let Some(manifest) =
            super::start::load_installed_runtime_manifest(&port.state_directory, &command.cat_id)?
        {
            validate_installed_manifest_binding(
                command,
                expected_runtime_incarnation,
                local_recovery_authority,
                &manifest,
            )?;
        }
    }
    for target in &marker.targets {
        remove_cleanup_target(target)?;
    }
    for target in &marker.targets {
        verify_cleanup_target_absent(target)?;
    }
    if remove_restart_manifests {
        remove_exact_cat_progress_manifests(
            port,
            command,
            expected_runtime_incarnation,
            local_recovery_authority,
        )?;
        if let Some(manifest) =
            super::start::load_installed_runtime_manifest(&port.state_directory, &command.cat_id)?
        {
            validate_installed_manifest_binding(
                command,
                expected_runtime_incarnation,
                local_recovery_authority,
                &manifest,
            )?;
            anyhow::ensure!(
                super::start::remove_installed_runtime_manifest(
                    &port.state_directory,
                    &command.cat_id,
                )?,
                "installed Runtime manifest disappeared before exact removal"
            );
        }
    }
    marker.mark_completed()?;
    publish_cleanup_marker(&port.state_directory, command, &marker)?;
    canonical_digest(LOCAL_CLEANUP_ABSENCE_DOMAIN, &marker)
}

fn remove_exact_cat_progress_manifests(
    port: &InstalledColdDeleteLocalPort,
    command: &LifecycleCommandEnvelope,
    expected_runtime_incarnation: Option<&RandomId128>,
    local_recovery_authority: &AtomicLocalRecoveryAuthority,
) -> Result<()> {
    let progress =
        super::start::enumerate_installed_runtime_progress_manifests(&port.state_directory)?;
    for manifest in progress
        .iter()
        .filter(|manifest| manifest.cat_id == command.cat_id)
    {
        anyhow::ensure!(
            manifest.version == ContractVersion::V1
                && manifest.node_id == command.node_id
                && manifest.placement_identity == command.placement_identity
                && manifest.runtime_config_id == command.runtime_config.config_id
                && manifest.runtime_config_digest == command.runtime_config.config_digest
                && expected_runtime_incarnation
                    .is_none_or(|expected| manifest.runtime_incarnation == *expected),
            "local cleanup found foreign or ambiguous Start progress"
        );
        validate_progress_manifest_binding(
            command,
            expected_runtime_incarnation,
            local_recovery_authority,
            manifest,
        )?;
        anyhow::ensure!(
            super::start::remove_installed_runtime_progress_manifest_exact(
                &port.state_directory,
                manifest,
            )?,
            "exact Start progress disappeared before cleanup"
        );
    }
    let retained =
        super::start::enumerate_terminal_retained_runtime_manifests(&port.state_directory)?;
    for manifest in retained
        .iter()
        .filter(|manifest| manifest.cat_id == command.cat_id)
    {
        validate_terminal_retained_cleanup_binding(
            command,
            manifest,
            expected_runtime_incarnation,
            local_recovery_authority,
        )?;
        anyhow::ensure!(
            super::start::remove_terminal_retained_runtime_manifest_exact(
                &port.state_directory,
                manifest,
            )?,
            "exact terminal-retained Start evidence disappeared before cleanup"
        );
    }
    Ok(())
}

fn validate_exact_cat_progress_manifests(
    port: &InstalledColdDeleteLocalPort,
    command: &LifecycleCommandEnvelope,
    expected_runtime_incarnation: Option<&RandomId128>,
    local_recovery_authority: &AtomicLocalRecoveryAuthority,
) -> Result<()> {
    let progress =
        super::start::enumerate_installed_runtime_progress_manifests(&port.state_directory)?;
    for manifest in progress
        .iter()
        .filter(|manifest| manifest.cat_id == command.cat_id)
    {
        anyhow::ensure!(
            manifest.version == ContractVersion::V1
                && manifest.node_id == command.node_id
                && manifest.placement_identity == command.placement_identity
                && manifest.runtime_config_id == command.runtime_config.config_id
                && manifest.runtime_config_digest == command.runtime_config.config_digest
                && expected_runtime_incarnation
                    .is_none_or(|expected| manifest.runtime_incarnation == *expected),
            "local cleanup found foreign or ambiguous Start progress"
        );
        validate_progress_manifest_binding(
            command,
            expected_runtime_incarnation,
            local_recovery_authority,
            manifest,
        )?;
    }
    let retained =
        super::start::enumerate_terminal_retained_runtime_manifests(&port.state_directory)?;
    for manifest in retained
        .iter()
        .filter(|manifest| manifest.cat_id == command.cat_id)
    {
        validate_terminal_retained_cleanup_binding(
            command,
            manifest,
            expected_runtime_incarnation,
            local_recovery_authority,
        )?;
    }
    Ok(())
}

fn validate_terminal_retained_cleanup_binding(
    command: &LifecycleCommandEnvelope,
    manifest: &super::start::TerminalRetainedRuntimeManifest,
    expected_runtime_incarnation: Option<&RandomId128>,
    local_recovery_authority: &AtomicLocalRecoveryAuthority,
) -> Result<()> {
    validate_local_recovery_authority(command, local_recovery_authority)?;
    super::start::validate_terminal_retained_runtime_manifest(manifest, None)?;
    anyhow::ensure!(
        manifest.version == ContractVersion::V1
            && manifest.node_id == command.node_id
            && manifest.cat_id == command.cat_id
            && manifest.placement_identity == command.placement_identity
            && manifest.runtime_config_id == command.runtime_config.config_id
            && manifest.runtime_config_digest == command.runtime_config.config_digest
            && expected_runtime_incarnation
                .is_none_or(|expected| manifest.runtime_incarnation == *expected),
        "local cleanup found foreign terminal-retained Start evidence"
    );
    match local_recovery_authority {
        AtomicLocalRecoveryAuthority::TerminalRetainedForbidden { .. } => {
            anyhow::bail!("this predecessor cannot authorize terminal-retained Start evidence")
        }
        AtomicLocalRecoveryAuthority::DirectStartFailed {
            predecessor_operation_id,
            predecessor_request_fingerprint,
            retained_evidence,
            ..
        } => anyhow::ensure!(
            manifest.source_lifecycle_operation_id == *predecessor_operation_id
                && manifest.request_fingerprint == *predecessor_request_fingerprint
                && manifest.manifest_digest == retained_evidence.artifact_manifest_digest,
            "direct StartFailed response does not name this terminal-retained manifest"
        ),
        AtomicLocalRecoveryAuthority::KilledRetained {
            retained_volume_receipts,
            ..
        } => {
            anyhow::ensure!(
                retained_volume_receipts.len() == manifest.retained_volume_receipts.len(),
                "Killed bridge omitted or added a terminal-retained Volume"
            );
            for (sealed, killed) in manifest
                .retained_volume_receipts
                .iter()
                .zip(retained_volume_receipts)
            {
                anyhow::ensure!(
                    sealed.volume_id == killed.volume_id
                        && sealed.disk_id == killed.disk_id
                        && sealed.disk_role == killed.disk_role
                        && sealed.attachment_id == killed.attachment_id
                        && sealed.attachment_epoch == killed.attachment_epoch
                        && sealed.authority_receipt_digest == killed.authority_receipt_digest
                        && killed.local_durable_generation >= sealed.local_durable_generation
                        && killed.remote_durable_generation >= sealed.remote_durable_generation
                        && killed.remote_durable_generation <= killed.local_durable_generation,
                    "Killed bridge changed a terminal-retained Volume lineage"
                );
            }
        }
        AtomicLocalRecoveryAuthority::SuspendWarmOwned { .. } => {
            anyhow::bail!(
                "Suspend/Warm predecessor carrier cannot select terminal-retained Start evidence"
            )
        }
        AtomicLocalRecoveryAuthority::NeedsInterventionRetry {
            retained_volume_receipts,
            ..
        } => {
            for retained in retained_volume_receipts {
                let sealed = manifest
                    .retained_volume_receipts
                    .iter()
                    .find(|sealed| sealed.volume_id == retained.volume_id)
                    .context(
                        "NeedsIntervention receipt is absent from terminal-retained Start evidence",
                    )?;
                anyhow::ensure!(
                    retained.disk_id == sealed.disk_id
                        && retained.disk_role == sealed.disk_role
                        && retained.attachment_id == sealed.attachment_id
                        && retained.attachment_epoch == sealed.attachment_epoch
                        && retained.authority_receipt_digest == sealed.authority_receipt_digest
                        && retained.local_durable_generation >= sealed.local_durable_generation
                        && retained.remote_durable_generation >= sealed.remote_durable_generation
                        && retained.remote_durable_generation <= retained.local_durable_generation,
                    "NeedsIntervention retry changed terminal-retained Volume lineage"
                );
            }
        }
    }
    Ok(())
}

fn cleanup_targets_for_owned_lineages(
    port: &InstalledColdDeleteLocalPort,
    command: &LifecycleCommandEnvelope,
    expected_runtime_incarnation: Option<&RandomId128>,
    local_recovery_authority: &AtomicLocalRecoveryAuthority,
    expected: &[LifecycleVolumeTarget],
) -> Result<AtomicColdDeleteAttempt<Vec<LocalCleanupTarget>>> {
    if expected.is_empty() {
        return Ok(AtomicColdDeleteAttempt::Exact(Vec::new()));
    }
    let lineages = match port.load_owned_lineages(
        command,
        expected_runtime_incarnation,
        local_recovery_authority,
    )? {
        AtomicColdDeleteAttempt::Exact(lineages) => lineages,
        AtomicColdDeleteAttempt::Blocked(blocked) => {
            return Ok(AtomicColdDeleteAttempt::Blocked(blocked))
        }
    };
    let mut targets = Vec::with_capacity(expected.len());
    for expected in expected {
        let Some(installed) = lineages.get(&expected.volume_id) else {
            return Ok(local_cleanup_blocked(
                InterventionReason::ForeignOrAmbiguousResidue,
            ));
        };
        if installed.disk_id != expected.disk_id
            || installed.disk_role != expected.disk_role
            || installed.attachment_id != expected.attachment_id
            || installed.attachment_epoch != expected.attachment_epoch
        {
            return Ok(local_cleanup_blocked(
                InterventionReason::ForeignOrAmbiguousResidue,
            ));
        }
        match &installed.storage {
            InstalledLineageStorage::Materialized(path) => {
                let target = match local_cleanup_target(
                    Path::new(path.as_str()),
                    owned_lineage_identity(command, installed),
                ) {
                    Ok(target) => target,
                    Err(_) => {
                        return Ok(local_cleanup_blocked(
                            InterventionReason::LocalLineageAbsenceUnproven,
                        ))
                    }
                };
                targets.push(target);
            }
            InstalledLineageStorage::ProvenAbsent => {}
        }
    }
    targets.sort_by(|left, right| left.identity.volume_id.cmp(&right.identity.volume_id));
    Ok(AtomicColdDeleteAttempt::Exact(targets))
}

enum RootCleanupAuthority {
    Owned {
        target: LifecycleVolumeTarget,
        receipt_digest: Sha256Digest,
    },
    AlreadyUnowned {
        volume: LifecycleVolumeIdentity,
        expected_epoch: FenceEpoch,
        expected_head: RemoteHead,
        receipt_digest: Sha256Digest,
    },
}

fn root_cleanup_authority(
    request: &AtomicRootLineageCleanupRequest,
) -> Result<RootCleanupAuthority> {
    let root = &request.command.root_disposition.root;
    match &request.begin {
        AtomicDeleteBeginReceipt::NormallyDeleting { dispositions } => {
            let disposition = dispositions
                .iter()
                .find(|disposition| disposition.identity() == *root)
                .context("normal Delete lacks its Root disposition")?;
            match disposition {
                AtomicStoredVolumeDisposition::NormallyReleased { release } => {
                    Ok(RootCleanupAuthority::Owned {
                        target: release.receipt.durability.volume.clone(),
                        receipt_digest: release.receipt_digest.clone(),
                    })
                }
                AtomicStoredVolumeDisposition::AlreadyUnowned { receipt } => {
                    Ok(RootCleanupAuthority::AlreadyUnowned {
                        volume: receipt.receipt.volume.clone(),
                        expected_epoch: receipt.receipt.expected_epoch,
                        expected_head: receipt.receipt.expected_head.clone(),
                        receipt_digest: receipt.receipt_digest.clone(),
                    })
                }
            }
        }
        AtomicDeleteBeginReceipt::DisposableRootDeleting {
            root_durability,
            authorization_consumed_receipt_digest,
            ..
        } => Ok(RootCleanupAuthority::Owned {
            target: root_durability.volume.clone(),
            receipt_digest: authorization_consumed_receipt_digest.clone(),
        }),
    }
}

fn inspect_or_remove_root_lineage_local(
    port: &InstalledColdDeleteLocalPort,
    command: &LifecycleCommandEnvelope,
    request: &AtomicRootLineageCleanupRequest,
) -> Result<AtomicColdDeleteAttempt<AtomicRootLineageAbsenceReceipt>> {
    let request_digest = canonical_digest(LOCAL_CLEANUP_REQUEST_DOMAIN, request)?;
    let authority = root_cleanup_authority(request)?;
    let marker = match load_cleanup_marker(
        &port.state_directory,
        command,
        LocalCleanupPhase::DeleteRoot,
    ) {
        Ok(Some(marker)) => {
            if marker.request_digest != request_digest {
                return Ok(local_cleanup_blocked(
                    InterventionReason::LocalLineageAbsenceUnproven,
                ));
            }
            marker
        }
        Ok(None) => {
            let expected = match &authority {
                RootCleanupAuthority::Owned { target, .. } => std::slice::from_ref(target),
                RootCleanupAuthority::AlreadyUnowned { .. } => &[],
            };
            let targets = match cleanup_targets_for_owned_lineages(
                port,
                command,
                request.expected_runtime_incarnation.as_ref(),
                &request.local_recovery_authority,
                expected,
            )? {
                AtomicColdDeleteAttempt::Exact(targets) => targets,
                AtomicColdDeleteAttempt::Blocked(blocked) => {
                    return Ok(AtomicColdDeleteAttempt::Blocked(blocked))
                }
            };
            let marker = LocalCleanupMarker::new(
                command,
                LocalCleanupPhase::DeleteRoot,
                request_digest,
                targets,
            )?;
            publish_cleanup_marker(&port.state_directory, command, &marker)?;
            marker
        }
        Err(_) => {
            return Ok(local_cleanup_blocked(
                InterventionReason::LocalLineageAbsenceUnproven,
            ))
        }
    };
    let root = &request.command.root_disposition.root;
    match &authority {
        RootCleanupAuthority::Owned { target, .. } => anyhow::ensure!(
            marker.targets.len() == 1
                && marker.targets[0].identity.volume_id == root.volume_id
                && marker.targets[0].identity.attachment_id == target.attachment_id
                && marker.targets[0].identity.attachment_epoch == target.attachment_epoch,
            "durable Root cleanup marker changed its exact lineage"
        ),
        RootCleanupAuthority::AlreadyUnowned { .. } => anyhow::ensure!(
            marker.targets.is_empty(),
            "already-Unowned Root cleanup invented a local attachment"
        ),
    }
    let absence_digest = match complete_local_cleanup(
        port,
        command,
        marker,
        false,
        request.expected_runtime_incarnation.as_ref(),
        &request.local_recovery_authority,
    ) {
        Ok(digest) => digest,
        Err(_) => {
            return Ok(local_cleanup_blocked(
                InterventionReason::LocalLineageAbsenceUnproven,
            ))
        }
    };
    let receipt = match authority {
        RootCleanupAuthority::Owned {
            target,
            receipt_digest,
        } => AtomicRootLineageAbsenceReceipt::RemovedOwned {
            volume_id: root.volume_id.clone(),
            disk_id: root.disk_id.clone(),
            previous_attachment_id: target.attachment_id,
            previous_attachment_epoch: target.attachment_epoch,
            authority_receipt_digest: receipt_digest,
            local_lineage_absence_digest: absence_digest,
        },
        RootCleanupAuthority::AlreadyUnowned {
            volume,
            expected_epoch,
            expected_head,
            receipt_digest,
        } => AtomicRootLineageAbsenceReceipt::AlreadyUnowned {
            volume_id: volume.volume_id,
            disk_id: volume.disk_id,
            expected_epoch,
            expected_head,
            authority_receipt_digest: receipt_digest,
            local_lineage_absence_digest: absence_digest,
        },
    };
    Ok(AtomicColdDeleteAttempt::Exact(receipt))
}

fn inspect_or_finalize_cold_local(
    port: &InstalledColdDeleteLocalPort,
    command: &LifecycleCommandEnvelope,
    request: &AtomicColdFinalizationRequest,
) -> Result<AtomicColdDeleteAttempt<Sha256Digest>> {
    let request_digest = canonical_digest(LOCAL_CLEANUP_REQUEST_DOMAIN, request)?;
    let marker =
        match load_cleanup_marker(&port.state_directory, command, LocalCleanupPhase::ColdFinal) {
            Ok(Some(marker)) => {
                if marker.request_digest != request_digest {
                    return Ok(local_cleanup_blocked(
                        InterventionReason::LocalLineageAbsenceUnproven,
                    ));
                }
                marker
            }
            Ok(None) => {
                let expected = request
                    .dispositions
                    .iter()
                    .filter_map(|disposition| match disposition {
                        AtomicStoredVolumeDisposition::NormallyReleased { release } => {
                            Some(release.receipt.durability.volume.clone())
                        }
                        AtomicStoredVolumeDisposition::AlreadyUnowned { .. } => None,
                    })
                    .collect::<Vec<_>>();
                let targets = match cleanup_targets_for_owned_lineages(
                    port,
                    command,
                    request.expected_runtime_incarnation.as_ref(),
                    &request.local_recovery_authority,
                    &expected,
                )? {
                    AtomicColdDeleteAttempt::Exact(targets) => targets,
                    AtomicColdDeleteAttempt::Blocked(blocked) => {
                        return Ok(AtomicColdDeleteAttempt::Blocked(blocked))
                    }
                };
                let marker = LocalCleanupMarker::new(
                    command,
                    LocalCleanupPhase::ColdFinal,
                    request_digest,
                    targets,
                )?;
                publish_cleanup_marker(&port.state_directory, command, &marker)?;
                marker
            }
            Err(_) => {
                return Ok(local_cleanup_blocked(
                    InterventionReason::LocalLineageAbsenceUnproven,
                ))
            }
        };
    match complete_local_cleanup(
        port,
        command,
        marker,
        true,
        request.expected_runtime_incarnation.as_ref(),
        &request.local_recovery_authority,
    ) {
        Ok(digest) => Ok(AtomicColdDeleteAttempt::Exact(digest)),
        Err(_) => Ok(local_cleanup_blocked(
            InterventionReason::LocalLineageAbsenceUnproven,
        )),
    }
}

fn inspect_or_finalize_delete_local(
    port: &InstalledColdDeleteLocalPort,
    command: &LifecycleCommandEnvelope,
    request: &AtomicDeleteFinalizationRequest,
) -> Result<AtomicColdDeleteAttempt<Sha256Digest>> {
    let request_digest = canonical_digest(LOCAL_CLEANUP_REQUEST_DOMAIN, request)?;
    let root_marker = match load_cleanup_marker(
        &port.state_directory,
        command,
        LocalCleanupPhase::DeleteRoot,
    ) {
        Ok(Some(marker)) => marker,
        _ => {
            return Ok(local_cleanup_blocked(
                InterventionReason::LocalLineageAbsenceUnproven,
            ))
        }
    };
    if !root_marker.completed
        || canonical_digest(LOCAL_CLEANUP_ABSENCE_DOMAIN, &root_marker)?
            != *request.root_lineage_absence.local_lineage_absence_digest()
    {
        return Ok(local_cleanup_blocked(
            InterventionReason::LocalLineageAbsenceUnproven,
        ));
    }
    for target in &root_marker.targets {
        if verify_cleanup_target_absent(target).is_err() {
            return Ok(local_cleanup_blocked(
                InterventionReason::LocalLineageAbsenceUnproven,
            ));
        }
    }

    let marker = match load_cleanup_marker(
        &port.state_directory,
        command,
        LocalCleanupPhase::DeleteFinal,
    ) {
        Ok(Some(marker)) => {
            if marker.request_digest != request_digest {
                return Ok(local_cleanup_blocked(
                    InterventionReason::LocalLineageAbsenceUnproven,
                ));
            }
            marker
        }
        Ok(None) => {
            let persistent = persistent_stored_dispositions(&request.begin);
            let expected = persistent
                .iter()
                .filter_map(|disposition| match disposition {
                    AtomicStoredVolumeDisposition::NormallyReleased { release } => {
                        Some(release.receipt.durability.volume.clone())
                    }
                    AtomicStoredVolumeDisposition::AlreadyUnowned { .. } => None,
                })
                .collect::<Vec<_>>();
            let targets = match cleanup_targets_for_owned_lineages(
                port,
                command,
                request.expected_runtime_incarnation.as_ref(),
                &request.local_recovery_authority,
                &expected,
            )? {
                AtomicColdDeleteAttempt::Exact(targets) => targets,
                AtomicColdDeleteAttempt::Blocked(blocked) => {
                    return Ok(AtomicColdDeleteAttempt::Blocked(blocked))
                }
            };
            let marker = LocalCleanupMarker::new(
                command,
                LocalCleanupPhase::DeleteFinal,
                request_digest,
                targets,
            )?;
            publish_cleanup_marker(&port.state_directory, command, &marker)?;
            marker
        }
        Err(_) => {
            return Ok(local_cleanup_blocked(
                InterventionReason::LocalLineageAbsenceUnproven,
            ))
        }
    };
    match complete_local_cleanup(
        port,
        command,
        marker,
        true,
        request.expected_runtime_incarnation.as_ref(),
        &request.local_recovery_authority,
    ) {
        Ok(digest) => Ok(AtomicColdDeleteAttempt::Exact(digest)),
        Err(_) => Ok(local_cleanup_blocked(
            InterventionReason::LocalLineageAbsenceUnproven,
        )),
    }
}

fn local_cleanup_blocked<T>(reason: InterventionReason) -> AtomicColdDeleteAttempt<T> {
    AtomicColdDeleteAttempt::Blocked(AtomicColdDeleteBlocked {
        reason,
        retained_volume_receipts: Vec::new(),
    })
}

fn retained_from_release_inputs(
    releases: &[CommandNormalReleaseInput],
) -> Result<Vec<VolumeTerminalReceipt>> {
    let mut receipts = releases
        .iter()
        .map(|release| {
            let proof = &release.durability;
            anyhow::ensure!(
                remote_head_is_valid(&proof.remote_head)
                    && proof.remote_durable_generation <= proof.local_durable_generation,
                "Control rejection carries invalid retained durability evidence"
            );
            Ok(VolumeTerminalReceipt {
                volume_id: proof.volume.volume_id.clone(),
                disk_id: proof.volume.disk_id.clone(),
                disk_role: proof.volume.disk_role,
                attachment_id: proof.volume.attachment_id.clone(),
                attachment_epoch: proof.volume.attachment_epoch,
                local_durable_generation: proof.local_durable_generation,
                remote_durable_generation: proof.remote_durable_generation,
                authority_receipt_digest: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    receipts.sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
    anyhow::ensure!(
        receipts
            .windows(2)
            .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "Control rejection retained Volume set is duplicated"
    );
    Ok(receipts)
}

fn retained_from_disposition_inputs(
    dispositions: &[AtomicVolumeDispositionInput],
) -> Result<Vec<VolumeTerminalReceipt>> {
    let releases = dispositions
        .iter()
        .filter_map(|disposition| match disposition {
            AtomicVolumeDispositionInput::OwnedRelease { release } => Some(release.clone()),
            AtomicVolumeDispositionInput::AlreadyUnowned { .. } => None,
        })
        .collect::<Vec<_>>();
    retained_from_release_inputs(&releases)
}

/// Convert the already-journaled Cold mutation to the sole signed Control
/// wire. The production transport adds its current `AgentSession`; session
/// identity is intentionally absent from this durable value.
pub(crate) fn cold_release_wire_transition(
    request: &AtomicColdReleaseRequest,
) -> volume_wire::LifecycleVolumeTransitionRequestKind {
    volume_wire::LifecycleVolumeTransitionRequestKind::ColdRelease {
        command: cold_command_to_wire(&request.command),
        volumes: request
            .dispositions
            .iter()
            .map(disposition_input_to_wire)
            .collect(),
        strong_stop: Box::new(strong_stop_to_wire(&request.strong_stop)),
    }
}

/// Convert the exact Delete begin branch without accepting any Node-supplied
/// disposable authorization identifier. Control derives and consumes that
/// identifier in its complete-set transaction.
pub(crate) fn delete_begin_wire_transition(
    request: &AtomicDeleteBeginRequest,
) -> volume_wire::LifecycleVolumeTransitionRequestKind {
    match request {
        AtomicDeleteBeginRequest::Normal {
            command,
            volumes,
            strong_stop,
        } => volume_wire::LifecycleVolumeTransitionRequestKind::DeleteNormal {
            command: delete_command_to_wire(command),
            volumes: volumes.iter().map(disposition_input_to_wire).collect(),
            strong_stop: Box::new(strong_stop_to_wire(strong_stop)),
        },
        AtomicDeleteBeginRequest::DisposableRoot {
            command,
            persistent_volumes,
            root_durability,
            strong_stop,
        } => volume_wire::LifecycleVolumeTransitionRequestKind::DeleteDisposableRoot {
            command: delete_command_to_wire(command),
            persistent_volumes: persistent_volumes
                .iter()
                .map(disposition_input_to_wire)
                .collect(),
            root_durability: Box::new(durability_to_wire(root_durability)),
            strong_stop: Box::new(strong_stop_to_wire(strong_stop)),
        },
    }
}

pub(crate) fn delete_completion_wire_transition(
    request: &AtomicDeleteCompletionRequest,
) -> volume_wire::LifecycleVolumeTransitionRequestKind {
    volume_wire::LifecycleVolumeTransitionRequestKind::DiscoverDeleteCompletion {
        command: delete_command_to_wire(&request.expected_command),
    }
}

pub(crate) fn cold_release_from_wire(
    applied: &volume_wire::LifecycleVolumeTransitionApplied,
) -> Result<AtomicColdReleaseReceipt> {
    let volume_wire::LifecycleVolumeTransitionApplied::ColdReleased { dispositions } = applied
    else {
        anyhow::bail!("signed Volume response selected another lifecycle transition")
    };
    Ok(AtomicColdReleaseReceipt {
        dispositions: dispositions
            .iter()
            .map(stored_disposition_from_wire)
            .collect(),
    })
}

pub(crate) fn delete_begin_from_wire(
    applied: &volume_wire::LifecycleVolumeTransitionApplied,
    request: &AtomicDeleteBeginRequest,
) -> Result<AtomicDeleteBeginReceipt> {
    match (applied, request) {
        (
            volume_wire::LifecycleVolumeTransitionApplied::DeleteNormallyDeleting { dispositions },
            AtomicDeleteBeginRequest::Normal { .. },
        ) => Ok(AtomicDeleteBeginReceipt::NormallyDeleting {
            dispositions: dispositions
                .iter()
                .map(stored_disposition_from_wire)
                .collect(),
        }),
        (
            volume_wire::LifecycleVolumeTransitionApplied::DeleteDisposableRootDeleting {
                persistent_dispositions,
                authorization_id,
                authorization_consumed_receipt_digest,
            },
            AtomicDeleteBeginRequest::DisposableRoot {
                root_durability, ..
            },
        ) => Ok(AtomicDeleteBeginReceipt::DisposableRootDeleting {
            persistent_dispositions: persistent_dispositions
                .iter()
                .map(stored_disposition_from_wire)
                .collect(),
            root_durability: root_durability.clone(),
            authorization_id: authorization_id.clone(),
            authorization_consumed_receipt_digest: authorization_consumed_receipt_digest.clone(),
        }),
        _ => anyhow::bail!("signed Volume response selected another lifecycle transition"),
    }
}

pub(crate) fn delete_completion_from_wire(
    applied: &volume_wire::LifecycleVolumeTransitionApplied,
) -> Result<AtomicDeleteCompletionEvidence> {
    let volume_wire::LifecycleVolumeTransitionApplied::DeleteCompleted { completion } = applied
    else {
        anyhow::bail!("signed Volume response is not immutable Delete completion")
    };
    Ok(AtomicDeleteCompletionEvidence {
        receipt: delete_completion_receipt_from_wire(&completion.receipt),
        receipt_digest: completion.receipt_digest.clone(),
    })
}

fn scope_to_wire(scope: &LifecycleVolumeCommandScope) -> volume_wire::LifecycleVolumeCommandScope {
    volume_wire::LifecycleVolumeCommandScope {
        operation_id: scope.operation_id.clone(),
        request_fingerprint: scope.request_fingerprint.clone(),
        cat_id: scope.cat_id.clone(),
        node_id: scope.node_id.clone(),
        placement_identity: scope.placement_identity.clone(),
    }
}

fn scope_from_wire(
    scope: &volume_wire::LifecycleVolumeCommandScope,
) -> LifecycleVolumeCommandScope {
    LifecycleVolumeCommandScope {
        operation_id: scope.operation_id.clone(),
        request_fingerprint: scope.request_fingerprint.clone(),
        cat_id: scope.cat_id.clone(),
        node_id: scope.node_id.clone(),
        placement_identity: scope.placement_identity.clone(),
    }
}

fn target_to_wire(target: &LifecycleVolumeTarget) -> volume_wire::LifecycleVolumeTarget {
    volume_wire::LifecycleVolumeTarget {
        disk_id: target.disk_id.clone(),
        disk_role: target.disk_role,
        volume_id: target.volume_id.clone(),
        attachment_id: target.attachment_id.clone(),
        attachment_epoch: target.attachment_epoch,
    }
}

fn target_from_wire(target: &volume_wire::LifecycleVolumeTarget) -> LifecycleVolumeTarget {
    LifecycleVolumeTarget {
        disk_id: target.disk_id.clone(),
        disk_role: target.disk_role,
        volume_id: target.volume_id.clone(),
        attachment_id: target.attachment_id.clone(),
        attachment_epoch: target.attachment_epoch,
    }
}

fn durability_to_wire(
    proof: &CommandVolumeDurabilityProof,
) -> volume_wire::LifecycleVolumeDurabilityProof {
    volume_wire::LifecycleVolumeDurabilityProof {
        scope: scope_to_wire(&proof.scope),
        volume: target_to_wire(&proof.volume),
        remote_head: proof.remote_head.clone(),
        local_durable_generation: proof.local_durable_generation,
        remote_durable_generation: proof.remote_durable_generation,
        pending_pack_count: proof.pending_pack_count,
    }
}

fn durability_from_wire(
    proof: &volume_wire::LifecycleVolumeDurabilityProof,
) -> CommandVolumeDurabilityProof {
    CommandVolumeDurabilityProof {
        scope: scope_from_wire(&proof.scope),
        volume: target_from_wire(&proof.volume),
        remote_head: proof.remote_head.clone(),
        local_durable_generation: proof.local_durable_generation,
        remote_durable_generation: proof.remote_durable_generation,
        pending_pack_count: proof.pending_pack_count,
    }
}

fn release_to_wire(
    release: &CommandNormalReleaseInput,
) -> volume_wire::LifecycleNormalReleaseInput {
    volume_wire::LifecycleNormalReleaseInput {
        durability: durability_to_wire(&release.durability),
        transition_id: release.transition_id.clone(),
    }
}

fn identity_to_wire(identity: &LifecycleVolumeIdentity) -> volume_wire::LifecycleVolumeIdentity {
    volume_wire::LifecycleVolumeIdentity {
        disk_id: identity.disk_id.clone(),
        disk_role: identity.disk_role,
        volume_id: identity.volume_id.clone(),
    }
}

fn identity_from_wire(identity: &volume_wire::LifecycleVolumeIdentity) -> LifecycleVolumeIdentity {
    LifecycleVolumeIdentity {
        disk_id: identity.disk_id.clone(),
        disk_role: identity.disk_role,
        volume_id: identity.volume_id.clone(),
    }
}

fn disposition_input_to_wire(
    input: &AtomicVolumeDispositionInput,
) -> volume_wire::LifecycleVolumeDispositionInput {
    match input {
        AtomicVolumeDispositionInput::OwnedRelease { release } => {
            volume_wire::LifecycleVolumeDispositionInput::OwnedRelease {
                release: Box::new(release_to_wire(release)),
            }
        }
        AtomicVolumeDispositionInput::AlreadyUnowned {
            volume,
            expected_epoch,
            expected_head,
        } => volume_wire::LifecycleVolumeDispositionInput::AlreadyUnowned {
            volume: identity_to_wire(volume),
            expected_epoch: *expected_epoch,
            expected_head: expected_head.clone(),
        },
    }
}

fn cold_command_to_wire(command: &ColdCommandVolumeSet) -> volume_wire::LifecycleColdVolumeSet {
    volume_wire::LifecycleColdVolumeSet {
        scope: scope_to_wire(&command.scope),
        volumes: command.volumes.iter().map(identity_to_wire).collect(),
    }
}

fn delete_command_to_wire(
    command: &DeleteCommandVolumeSet,
) -> volume_wire::LifecycleDeleteVolumeSet {
    volume_wire::LifecycleDeleteVolumeSet {
        scope: scope_to_wire(&command.scope),
        root_disposition: volume_wire::LifecycleDefaultRootDiscardDisposition {
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

fn delete_command_from_wire(
    command: &volume_wire::LifecycleDeleteVolumeSet,
) -> DeleteCommandVolumeSet {
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

fn strong_stop_to_wire(
    evidence: &AtomicDeleteStrongStopEvidence,
) -> volume_wire::LifecycleVolumeStrongStopEvidence {
    volume_wire::LifecycleVolumeStrongStopEvidence {
        execution_absence: evidence.execution_absence.clone(),
        post_stop_inventory_attestation: evidence.post_stop_inventory_attestation.clone(),
    }
}

fn normal_release_from_wire(
    receipt: &volume_wire::LifecycleCommandNormalReleaseReceipt,
) -> CommandNormalReleaseReceipt {
    CommandNormalReleaseReceipt {
        durability: durability_from_wire(&receipt.durability),
        request: receipt.request.clone(),
        result: receipt.result.clone(),
    }
}

fn stored_release_from_wire(
    receipt: &volume_wire::LifecycleStoredNormalReleaseReceipt,
) -> AtomicStoredNormalReleaseReceipt {
    AtomicStoredNormalReleaseReceipt {
        receipt: normal_release_from_wire(&receipt.receipt),
        receipt_digest: receipt.receipt_digest.clone(),
    }
}

fn already_unowned_receipt_from_wire(
    receipt: &volume_wire::LifecycleCommandAlreadyUnownedReceipt,
) -> CommandAlreadyUnownedReceipt {
    CommandAlreadyUnownedReceipt {
        scope: scope_from_wire(&receipt.scope),
        volume: identity_from_wire(&receipt.volume),
        expected_epoch: receipt.expected_epoch,
        expected_head: receipt.expected_head.clone(),
        provenance: match &receipt.provenance {
            volume_wire::LifecycleAlreadyUnownedProvenance::Pristine => {
                AlreadyUnownedProvenance::Pristine
            }
            volume_wire::LifecycleAlreadyUnownedProvenance::NormalRelease {
                receipt,
                receipt_digest,
            } => AlreadyUnownedProvenance::NormalRelease {
                receipt: Box::new(normal_release_from_wire(receipt)),
                receipt_digest: receipt_digest.clone(),
            },
        },
    }
}

fn stored_disposition_from_wire(
    disposition: &volume_wire::LifecycleStoredVolumeDisposition,
) -> AtomicStoredVolumeDisposition {
    match disposition {
        volume_wire::LifecycleStoredVolumeDisposition::NormallyReleased { release } => {
            AtomicStoredVolumeDisposition::NormallyReleased {
                release: stored_release_from_wire(release),
            }
        }
        volume_wire::LifecycleStoredVolumeDisposition::AlreadyUnowned { receipt } => {
            AtomicStoredVolumeDisposition::AlreadyUnowned {
                receipt: AtomicStoredAlreadyUnownedReceipt {
                    receipt: already_unowned_receipt_from_wire(&receipt.receipt),
                    receipt_digest: receipt.receipt_digest.clone(),
                },
            }
        }
    }
}

fn delete_completion_receipt_from_wire(
    receipt: &volume_wire::LifecycleCommandDeleteCompletionReceipt,
) -> CommandDeleteCompletionReceipt {
    CommandDeleteCompletionReceipt {
        command: delete_command_from_wire(&receipt.command),
        root_authority: match &receipt.root_authority {
            volume_wire::LifecycleCommandRootDeleteAuthorityReceipt::NormalRelease(receipt) => {
                CommandRootDeleteAuthorityReceipt::NormalRelease(normal_release_from_wire(receipt))
            }
            volume_wire::LifecycleCommandRootDeleteAuthorityReceipt::AlreadyUnowned(receipt) => {
                CommandRootDeleteAuthorityReceipt::AlreadyUnowned(
                    already_unowned_receipt_from_wire(receipt),
                )
            }
            volume_wire::LifecycleCommandRootDeleteAuthorityReceipt::DisposableAuthorizationConsumed(
                receipt,
            ) => CommandRootDeleteAuthorityReceipt::DisposableAuthorizationConsumed(
                cats_storage::lifecycle_volume::CommandDisposableAuthorizationConsumedReceipt {
                    command: delete_command_from_wire(&receipt.command),
                    authorization_id: receipt.authorization_id.clone(),
                    persistent_dispositions_digest: receipt
                        .persistent_dispositions_digest
                        .clone(),
                    receipt: receipt.receipt.clone(),
                },
            ),
        },
        completion: receipt.completion.clone(),
    }
}

// This is the sole bounded, crash-replayable Cold/Delete step for one Cat. Its
// size is dominated by exact authority evidence that must move as one value;
// only one such state is decoded or persisted at a time.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum ColdDeleteStepState {
    BindSuspendWarmPredecessor,
    StrongStop,
    StrongStopWithOwnedPredecessor {
        carrier: AtomicOwnedPredecessorCarrier,
    },
    ColdConverge {
        strong_stop: StrongStopEvidence,
        request: AtomicVolumeConvergenceRequest,
    },
    ColdForceFull {
        strong_stop: StrongStopEvidence,
        command: ColdCommandVolumeSet,
        dispositions: Vec<AtomicVolumeDispositionInput>,
        local_recovery_authority: AtomicLocalRecoveryAuthority,
    },
    ColdRelease {
        strong_stop: StrongStopEvidence,
        request: AtomicColdReleaseRequest,
    },
    ColdPrepareWarmCleanup {
        strong_stop: StrongStopEvidence,
        finalization: AtomicColdFinalizationRequest,
        request: WarmSnapshotCleanupRequest,
    },
    ColdRemoveWarmCleanup {
        strong_stop: StrongStopEvidence,
        finalization: AtomicColdFinalizationRequest,
        authority: WarmSnapshotCleanupAuthority,
    },
    ColdFinalize {
        strong_stop: StrongStopEvidence,
        request: AtomicColdFinalizationRequest,
    },
    DeleteConvergePersistent {
        strong_stop: StrongStopEvidence,
        request: AtomicVolumeConvergenceRequest,
    },
    DeleteInspectRoot {
        strong_stop: StrongStopEvidence,
        persistent_dispositions: Vec<AtomicVolumeDispositionInput>,
        request: AtomicDeleteRootInspectionRequest,
    },
    DeleteForceFull {
        strong_stop: StrongStopEvidence,
        plan: AtomicDeleteBeginPlan,
        local_recovery_authority: AtomicLocalRecoveryAuthority,
    },
    DeleteBegin {
        strong_stop: StrongStopEvidence,
        request: AtomicDeleteBeginRequest,
    },
    DeleteCleanupRoot {
        strong_stop: StrongStopEvidence,
        request: AtomicRootLineageCleanupRequest,
    },
    DeleteAwaitCompletion {
        strong_stop: StrongStopEvidence,
        begin: AtomicDeleteBeginReceipt,
        root_lineage_absence: AtomicRootLineageAbsenceReceipt,
        request: AtomicDeleteCompletionRequest,
    },
    DeletePrepareWarmCleanup {
        strong_stop: StrongStopEvidence,
        finalization: AtomicDeleteFinalizationRequest,
        request: WarmSnapshotCleanupRequest,
    },
    DeleteRemoveWarmCleanup {
        strong_stop: StrongStopEvidence,
        finalization: AtomicDeleteFinalizationRequest,
        authority: WarmSnapshotCleanupAuthority,
    },
    DeleteFinalize {
        strong_stop: StrongStopEvidence,
        request: AtomicDeleteFinalizationRequest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdDeleteStepPayload {
    version: ContractVersion,
    operation_id: Id,
    request_fingerprint: Sha256Digest,
    state: ColdDeleteStepState,
}

pub(super) fn plan(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    inherited_stop_fence: bool,
) -> Result<PlannedLifecycleEffect> {
    validate_handler_command(ctx, command, predecessor)?;
    let bind_owned_predecessor = predecessor.is_some_and(|predecessor| {
        matches!(
            predecessor.result,
            NodeResult::SuspendDeclined(_)
                | NodeResult::Suspended(_)
                | NodeResult::Warm(_)
                | NodeResult::SuspendFailed(_)
                | NodeResult::WarmFailed(_)
        )
    });
    let initial = if bind_owned_predecessor {
        ColdDeleteStepState::BindSuspendWarmPredecessor
    } else {
        ColdDeleteStepState::StrongStop
    };
    let step = encode_step(command, initial)?;
    if inherited_stop_fence {
        Ok(PlannedLifecycleEffect::inherit_stop_fence(step))
    } else {
        Ok(PlannedLifecycleEffect::install_stop_fence(
            step,
            stop_fence_payload(command)?,
        ))
    }
}

pub(super) fn apply(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    step: &ExecutionStep,
    authority: LifecycleEffectAuthority<'_>,
) -> Result<LifecycleEffectProgress> {
    validate_handler_command(ctx, command, predecessor)?;
    let state = decode_step(command, step)?.state;
    let LifecycleEffectAuthority::StopFenced(fence) = authority else {
        anyhow::bail!("Cold/Delete effect lacks its durable Stop fence")
    };
    fence
        .assert_current()
        .context("Cold/Delete Stop fence is no longer current")?;

    let progress = match state {
        ColdDeleteStepState::BindSuspendWarmPredecessor => {
            let predecessor = predecessor
                .context("Suspend/Warm Cold/Delete binding lacks its predecessor response")?;
            let physical = ctx
                .config()
                .suspend_warm_platform
                .inspect_same_node_owned_predecessor(command, predecessor)
                .context("inspect exact Suspend/Warm predecessor before strong Stop")?;
            let carrier = owned_predecessor_carrier(command, predecessor, &physical)?;
            StateProgress::Next(ColdDeleteStepState::StrongStopWithOwnedPredecessor { carrier })
        }
        strong_stop_state @ (ColdDeleteStepState::StrongStop
        | ColdDeleteStepState::StrongStopWithOwnedPredecessor { .. }) => {
            let carrier = match &strong_stop_state {
                ColdDeleteStepState::StrongStopWithOwnedPredecessor { carrier } => {
                    let predecessor = predecessor.context(
                        "Suspend/Warm Cold/Delete strong Stop lacks its predecessor response",
                    )?;
                    validate_owned_predecessor_carrier(command, predecessor, carrier)?;
                    Some(carrier)
                }
                ColdDeleteStepState::StrongStop => None,
                _ => unreachable!("strong Stop variants were matched"),
            };
            let retained = predecessor.and_then(|predecessor| match &predecessor.result {
                NodeResult::Killed(killed) => Some(killed.retained_volume_receipts.as_slice()),
                NodeResult::NeedsIntervention(intervention) => {
                    Some(intervention.retained_volume_receipts.as_slice())
                }
                _ => None,
            });
            let strong_stop = if let Some(retained) = retained {
                ctx.execute_strong_stop_with_retained_receipts(
                    command,
                    predecessor,
                    LifecycleEffectAuthority::StopFenced(fence),
                    retained,
                )
            } else {
                ctx.execute_strong_stop(
                    command,
                    predecessor,
                    LifecycleEffectAuthority::StopFenced(fence),
                )
            }
            .context("execute Cold/Delete strong Stop barrier")?;
            validate_strong_stop(command, &strong_stop)?;
            let retained_warm_cleanup =
                retained_start_failed_warm_cleanup(ctx.state_directory(), command, predecessor)?;
            let local_recovery_authority = local_recovery_authority_with_carrier(
                command,
                predecessor,
                &strong_stop,
                carrier,
                retained_warm_cleanup.as_ref(),
            )?;
            let stopped_runtime_incarnation = match &local_recovery_authority {
                AtomicLocalRecoveryAuthority::SuspendWarmOwned { carrier } => {
                    Some(carrier.installed_runtime.runtime_incarnation.clone())
                }
                _ => strong_stop.stopped_runtime_incarnation.clone(),
            };
            let next = match &command.command {
                LifecycleCommand::Cold(spec) => ColdDeleteStepState::ColdConverge {
                    request: convergence_request(
                        command,
                        &command.runtime_config.volumes,
                        stopped_runtime_incarnation,
                        local_recovery_authority,
                        spec.convergence_deadline_unix_ms,
                        "cold",
                    )?,
                    strong_stop,
                },
                LifecycleCommand::Delete(spec) => {
                    let persistent = command
                        .runtime_config
                        .volumes
                        .iter()
                        .filter(|volume| volume.disk_role == DiskRole::Persistent)
                        .cloned()
                        .collect::<Vec<_>>();
                    ColdDeleteStepState::DeleteConvergePersistent {
                        request: convergence_request(
                            command,
                            &persistent,
                            stopped_runtime_incarnation,
                            local_recovery_authority,
                            spec.convergence_deadline_unix_ms,
                            "delete-persistent",
                        )?,
                        strong_stop,
                    }
                }
                _ => anyhow::bail!("Cold/Delete handler received another lifecycle command"),
            };
            StateProgress::Next(next)
        }
        state => advance_volume_state(
            ctx.cold_delete_port().as_ref(),
            ctx.inventory_attestation_port().as_ref(),
            Some(&ctx.config().suspend_warm_platform),
            Some(ctx.state_directory()),
            command,
            predecessor,
            state,
        )?,
    };

    fence
        .assert_current()
        .context("Cold/Delete Stop fence changed during physical effect")?;
    match progress {
        StateProgress::Next(next) => Ok(LifecycleEffectProgress::Next(
            PlannedLifecycleEffect::inherit_stop_fence(encode_step(command, next)?),
        )),
        StateProgress::Terminal(result) => Ok(LifecycleEffectProgress::Terminal(result)),
    }
}

// Ephemeral single-step result. The large arm is the already-bounded journal
// state above and exists only until it is encoded for the next durable step.
#[allow(clippy::large_enum_variant)]
enum StateProgress {
    Next(ColdDeleteStepState),
    Terminal(NodeResult),
}

fn predecessor_warm_cleanup_request(
    predecessor: Option<&LifecycleCommandResponse>,
) -> Result<Option<WarmSnapshotCleanupRequest>> {
    let predecessor = predecessor.context("Cold/Delete lacks its exact predecessor response")?;
    if !matches!(predecessor.result, NodeResult::Warm(_)) {
        return Ok(None);
    }
    WarmSnapshotCleanupRequest::from_warm_predecessor(predecessor).map(Some)
}

fn retained_start_failed_warm_cleanup(
    state_directory: &StateDirectory,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
) -> Result<Option<AtomicRetainedWarmCleanupAuthority>> {
    let predecessor = predecessor.context("Cold/Delete lacks its exact predecessor response")?;
    let NodeResult::StartFailed(failed) = &predecessor.result else {
        return Ok(None);
    };
    let cats_api::runtime_lifecycle::LifecyclePredecessor::SameNode {
        operation_id,
        terminal_result_kind,
        terminal_result_digest,
        node_id,
        placement_identity,
    } = &command.predecessor
    else {
        anyhow::bail!("retained Warm cleanup requires a same-Node StartFailed predecessor")
    };
    let actual_terminal_digest =
        lifecycle_terminal_result_digest(&LifecycleTerminalResult::NodeResult {
            response: Box::new(predecessor.clone()),
        })
        .context("digest retained Warm StartFailed predecessor")?;
    anyhow::ensure!(
        *terminal_result_kind == TerminalResultKind::StartFailed
            && operation_id == &predecessor.operation_id
            && terminal_result_digest == &actual_terminal_digest
            && node_id == &predecessor.node_id
            && placement_identity == &predecessor.placement_identity
            && command.expected_predecessor_operation_id.as_ref() == Some(operation_id),
        "retained Warm cleanup changed its immediate StartFailed predecessor"
    );

    let manifests = super::start::enumerate_terminal_retained_runtime_manifests(state_directory)
        .context("enumerate retained Warm StartFailed manifests")?;
    let manifests = manifests
        .iter()
        .filter(|manifest| manifest.cat_id == command.cat_id)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        manifests.len() == 1,
        "retained Warm StartFailed cleanup requires one exact terminal-retained manifest"
    );
    let manifest = manifests[0];
    super::start::validate_terminal_retained_runtime_manifest(manifest, None)
        .context("validate retained Warm StartFailed terminal manifest")?;
    let expected_retained_evidence = RetainedEvidence {
        artifact_manifest_digest: manifest.manifest_digest.clone(),
        ..manifest.physical_retained_evidence.clone()
    };
    anyhow::ensure!(
        predecessor.workspace_id == command.workspace_id
            && predecessor.cat_id == command.cat_id
            && predecessor.node_id == command.node_id
            && predecessor.placement_identity == command.placement_identity
            && manifest.version == ContractVersion::V1
            && manifest.source_lifecycle_operation_id == predecessor.operation_id
            && manifest.request_fingerprint == predecessor.request_fingerprint
            && manifest.node_id == command.node_id
            && manifest.cat_id == command.cat_id
            && manifest.placement_identity == command.placement_identity
            && manifest.runtime_config_id == command.runtime_config.config_id
            && manifest.runtime_config_digest == command.runtime_config.config_digest
            && manifest.execution_absence == failed.not_running
            && failed.retained_evidence == expected_retained_evidence,
        "retained Warm StartFailed terminal manifest changed its exact response binding"
    );
    let Some(carrier) = manifest.retained_warm_restart_source.as_deref() else {
        return Ok(None);
    };
    validate_retained_warm_restart_source(carrier)
        .context("validate retained Warm StartFailed carrier")?;
    let authority = rebind_retained_warm_for_removal(
        command,
        predecessor,
        &manifest.manifest_digest,
        Some(carrier),
    )
    .context("rebind retained Warm StartFailed carrier for removal")?;
    validate_retained_warm_removal_authority(
        command,
        predecessor,
        &manifest.manifest_digest,
        Some(carrier),
        &authority,
    )
    .context("validate rebound retained Warm removal authority")?;
    Ok(Some(AtomicRetainedWarmCleanupAuthority {
        terminal_retained_manifest_digest: manifest.manifest_digest.clone(),
        carrier: Box::new(carrier.clone()),
        authority: Box::new(authority),
    }))
}

fn validate_retained_start_failed_warm_cleanup(
    state_directory: &StateDirectory,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    cleanup: &AtomicRetainedWarmCleanupAuthority,
) -> Result<()> {
    let expected = retained_start_failed_warm_cleanup(state_directory, command, predecessor)?
        .context("journaled retained Warm cleanup lost its terminal manifest carrier")?;
    anyhow::ensure!(
        cleanup == &expected,
        "journaled retained Warm cleanup changed after authority publication"
    );
    Ok(())
}

fn validate_retained_warm_cleanup_binding(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    cleanup: &AtomicRetainedWarmCleanupAuthority,
) -> Result<()> {
    anyhow::ensure!(
        cleanup.terminal_retained_manifest_digest.as_bytes() != &[0; 32],
        "retained Warm cleanup lacks its StartFailed terminal manifest digest"
    );
    validate_retained_warm_restart_source(&cleanup.carrier)?;
    validate_warm_cleanup_authority_binding(&cleanup.authority)?;
    validate_retained_warm_removal_authority(
        command,
        predecessor,
        &cleanup.terminal_retained_manifest_digest,
        Some(&cleanup.carrier),
        &cleanup.authority,
    )
}

fn validate_warm_cleanup_request(
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    request: &WarmSnapshotCleanupRequest,
) -> Result<()> {
    validate_warm_cleanup_request_binding(command, request)?;
    let expected = predecessor_warm_cleanup_request(predecessor)?
        .context("Warm cleanup step has a non-Warm predecessor")?;
    anyhow::ensure!(
        request == &expected,
        "Warm cleanup request changed its exact predecessor authority"
    );
    Ok(())
}

fn validate_warm_cleanup_request_binding(
    command: &LifecycleCommandEnvelope,
    request: &WarmSnapshotCleanupRequest,
) -> Result<()> {
    anyhow::ensure!(
        command.expected_predecessor_operation_id.as_ref()
            == Some(&request.predecessor_operation_id)
            && request.terminal_manifest_digest.as_bytes() != &[0; 32]
            && request.warm_receipt_digest.as_bytes() != &[0; 32],
        "Warm cleanup request does not bind the command predecessor"
    );
    Ok(())
}

fn validate_warm_cleanup_authority(
    state_directory: Option<&StateDirectory>,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    local_recovery_authority: &AtomicLocalRecoveryAuthority,
    authority: &WarmSnapshotCleanupAuthority,
) -> Result<()> {
    validate_warm_cleanup_authority_binding(authority)?;
    let predecessor = predecessor.context("Warm cleanup lacks its exact predecessor response")?;
    match &predecessor.result {
        NodeResult::Warm(_) => {
            let expected = predecessor_warm_cleanup_request(Some(predecessor))?
                .context("Warm cleanup authority has a non-Warm predecessor")?;
            anyhow::ensure!(
                authority.terminal_manifest_digest() == &expected.terminal_manifest_digest
                    && authority.source_runtime_incarnation()
                        == &expected.source_runtime_incarnation
                    && command.expected_predecessor_operation_id.as_ref()
                        == Some(&expected.predecessor_operation_id),
                "Warm cleanup authority changed its exact predecessor bundle"
            );
            Ok(())
        }
        NodeResult::StartFailed(_) => {
            let AtomicLocalRecoveryAuthority::DirectStartFailed {
                retained_warm_cleanup: Some(cleanup),
                ..
            } = local_recovery_authority
            else {
                anyhow::bail!(
                    "StartFailed Warm cleanup lacks its journaled retained-source authority"
                )
            };
            validate_retained_warm_cleanup_binding(command, predecessor, cleanup)?;
            anyhow::ensure!(
                cleanup.authority.as_ref() == authority,
                "Warm cleanup authority changed its retained StartFailed bundle"
            );
            validate_retained_start_failed_warm_cleanup(
                state_directory.context(
                    "retained StartFailed Warm cleanup lacks its terminal manifest directory",
                )?,
                command,
                Some(predecessor),
                cleanup,
            )
        }
        _ => anyhow::bail!("Warm cleanup authority has a non-Warm predecessor"),
    }
}

fn validate_warm_cleanup_authority_binding(authority: &WarmSnapshotCleanupAuthority) -> Result<()> {
    anyhow::ensure!(
        authority.terminal_manifest_digest().as_bytes() != &[0; 32]
            && authority.mode() == WarmSnapshotCleanupMode::Remove,
        "Cold/Delete Warm cleanup authority lacks its terminal manifest or Remove mode"
    );
    Ok(())
}

fn retained_warm_cleanup_authority(
    local_recovery_authority: &AtomicLocalRecoveryAuthority,
) -> Option<&AtomicRetainedWarmCleanupAuthority> {
    match local_recovery_authority {
        AtomicLocalRecoveryAuthority::DirectStartFailed {
            retained_warm_cleanup,
            ..
        } => retained_warm_cleanup.as_deref(),
        _ => None,
    }
}

fn local_cleanup_intervention() -> AtomicColdDeleteBlocked {
    AtomicColdDeleteBlocked {
        reason: InterventionReason::LocalLineageAbsenceUnproven,
        retained_volume_receipts: Vec::new(),
    }
}

fn advance_volume_state(
    port: &dyn AtomicColdDeletePort,
    attestation_port: &dyn RuntimeInventoryAttestationPort,
    warm_platform: Option<&InstalledSuspendWarmPlatform>,
    state_directory: Option<&StateDirectory>,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    state: ColdDeleteStepState,
) -> Result<StateProgress> {
    match state {
        ColdDeleteStepState::BindSuspendWarmPredecessor
        | ColdDeleteStepState::StrongStop
        | ColdDeleteStepState::StrongStopWithOwnedPredecessor { .. } => {
            anyhow::bail!("pre-Stop binding/strong Stop state must run through the shared barrier")
        }
        ColdDeleteStepState::ColdConverge {
            strong_stop,
            request,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &request.local_recovery_authority,
            )?;
            let deadline = cold_spec(command)?.convergence_deadline_unix_ms;
            validate_convergence_request(
                command,
                &request,
                &command.runtime_config.volumes,
                local_recovery_runtime_incarnation(&request.local_recovery_authority, &strong_stop)
                    .as_ref(),
                &request.local_recovery_authority,
                deadline,
                "cold",
            )?;
            match port.inspect_or_converge(command, &request)? {
                AtomicColdDeleteAttempt::Exact(receipt) => {
                    validate_convergence_receipt(command, &request, &receipt)?;
                    let volume_set = ColdCommandVolumeSet {
                        scope: request.scope.clone(),
                        volumes: receipt
                            .dispositions
                            .iter()
                            .map(AtomicVolumeDispositionInput::identity)
                            .collect(),
                    };
                    validate_cold_release_plan(command, &volume_set, &receipt.dispositions)?;
                    Ok(StateProgress::Next(ColdDeleteStepState::ColdForceFull {
                        strong_stop,
                        command: volume_set,
                        dispositions: receipt.dispositions,
                        local_recovery_authority: request.local_recovery_authority,
                    }))
                }
                AtomicColdDeleteAttempt::Blocked(blocked) => {
                    intervention(command, strong_stop, InterventionTarget::Cold, blocked)
                }
            }
        }
        ColdDeleteStepState::ColdForceFull {
            strong_stop,
            command: volume_set,
            dispositions,
            local_recovery_authority,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &local_recovery_authority,
            )?;
            validate_cold_release_plan(command, &volume_set, &dispositions)?;
            let deadline = cold_spec(command)?.convergence_deadline_unix_ms;
            let attestation = attestation_port
                .force_full_and_wait(command, deadline)
                .context("force post-Stop Full inventory for atomic Cold release")?;
            validate_post_stop_attestation(command, &attestation)?;
            let request = AtomicColdReleaseRequest {
                command: volume_set,
                dispositions,
                strong_stop: AtomicDeleteStrongStopEvidence {
                    execution_absence: strong_stop.execution_absence.clone(),
                    post_stop_inventory_attestation: attestation,
                    local_recovery_authority,
                },
            };
            validate_cold_release_request(command, &strong_stop, &request)?;
            Ok(StateProgress::Next(ColdDeleteStepState::ColdRelease {
                strong_stop,
                request,
            }))
        }
        ColdDeleteStepState::ColdRelease {
            strong_stop,
            request,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &request.strong_stop.local_recovery_authority,
            )?;
            validate_cold_release_request(command, &strong_stop, &request)?;
            match port.inspect_or_release_cold(command, &request)? {
                AtomicColdReleaseAttempt::Exact(receipt) => {
                    validate_cold_release_receipt(&request, &receipt)?;
                    let finalization = AtomicColdFinalizationRequest {
                        command: request.command,
                        dispositions: receipt.dispositions,
                        post_stop_inventory_attestation: request
                            .strong_stop
                            .post_stop_inventory_attestation,
                        expected_runtime_incarnation: local_recovery_runtime_incarnation(
                            &request.strong_stop.local_recovery_authority,
                            &strong_stop,
                        ),
                        local_recovery_authority: request.strong_stop.local_recovery_authority,
                    };
                    let retained_warm_authority =
                        retained_warm_cleanup_authority(&finalization.local_recovery_authority)
                            .map(|cleanup| cleanup.authority.as_ref().clone());
                    if let Some(request) = predecessor_warm_cleanup_request(predecessor)? {
                        Ok(StateProgress::Next(
                            ColdDeleteStepState::ColdPrepareWarmCleanup {
                                strong_stop,
                                finalization,
                                request,
                            },
                        ))
                    } else if let Some(authority) = retained_warm_authority {
                        Ok(StateProgress::Next(
                            ColdDeleteStepState::ColdRemoveWarmCleanup {
                                strong_stop,
                                finalization,
                                authority,
                            },
                        ))
                    } else {
                        Ok(StateProgress::Next(ColdDeleteStepState::ColdFinalize {
                            strong_stop,
                            request: finalization,
                        }))
                    }
                }
                AtomicColdReleaseAttempt::Blocked(blocked) => {
                    intervention(command, strong_stop, InterventionTarget::Cold, blocked)
                }
                AtomicColdReleaseAttempt::FreshInventoryRequired => {
                    let AtomicColdReleaseRequest {
                        command: volume_set,
                        dispositions,
                        strong_stop:
                            AtomicDeleteStrongStopEvidence {
                                local_recovery_authority,
                                ..
                            },
                    } = request;
                    validate_cold_release_plan(command, &volume_set, &dispositions)?;
                    Ok(StateProgress::Next(ColdDeleteStepState::ColdForceFull {
                        strong_stop,
                        command: volume_set,
                        dispositions,
                        local_recovery_authority,
                    }))
                }
            }
        }
        ColdDeleteStepState::ColdPrepareWarmCleanup {
            strong_stop,
            finalization,
            request,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &finalization.local_recovery_authority,
            )?;
            validate_cold_finalization_request(command, &finalization)?;
            validate_warm_cleanup_request(command, predecessor, &request)?;
            let warm_platform = warm_platform.context("Warm cleanup platform is not composed")?;
            match warm_platform.prepare_warm_snapshot_cleanup(command, &request)? {
                WarmSnapshotCleanupAttempt::Exact(authority) => Ok(StateProgress::Next(
                    ColdDeleteStepState::ColdRemoveWarmCleanup {
                        strong_stop,
                        finalization,
                        authority,
                    },
                )),
                WarmSnapshotCleanupAttempt::Blocked => intervention(
                    command,
                    strong_stop,
                    InterventionTarget::Cold,
                    local_cleanup_intervention(),
                ),
            }
        }
        ColdDeleteStepState::ColdRemoveWarmCleanup {
            strong_stop,
            finalization,
            authority,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &finalization.local_recovery_authority,
            )?;
            validate_cold_finalization_request(command, &finalization)?;
            validate_warm_cleanup_authority(
                state_directory,
                command,
                predecessor,
                &finalization.local_recovery_authority,
                &authority,
            )?;
            let warm_platform = warm_platform.context("Warm cleanup platform is not composed")?;
            match warm_platform.inspect_or_remove_warm_snapshot(
                command,
                &authority,
                &WarmSnapshotCleanupCompletion::Remove,
            )? {
                WarmSnapshotCleanupAttempt::Exact(_) => {
                    Ok(StateProgress::Next(ColdDeleteStepState::ColdFinalize {
                        strong_stop,
                        request: finalization,
                    }))
                }
                WarmSnapshotCleanupAttempt::Blocked => intervention(
                    command,
                    strong_stop,
                    InterventionTarget::Cold,
                    local_cleanup_intervention(),
                ),
            }
        }
        ColdDeleteStepState::ColdFinalize {
            strong_stop,
            request,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &request.local_recovery_authority,
            )?;
            anyhow::ensure!(
                request.expected_runtime_incarnation
                    == local_recovery_runtime_incarnation(
                        &request.local_recovery_authority,
                        &strong_stop,
                    ),
                "Cold finalization changed its stopped runtime incarnation"
            );
            validate_cold_finalization_request(command, &request)?;
            match port.inspect_or_finalize_cold(command, &request)? {
                AtomicColdDeleteAttempt::Exact(local_absence_digest) => {
                    let dispositions = cold_terminal_dispositions(&request.dispositions)?;
                    Ok(StateProgress::Terminal(NodeResult::Cold(Box::new(
                        ColdResult {
                            runtime_config_digest: command.runtime_config.config_digest.clone(),
                            execution_absence: strong_stop.execution_absence,
                            volume_dispositions: dispositions,
                            local_recovery_dependency_absent_digest: local_absence_digest,
                        },
                    ))))
                }
                AtomicColdDeleteAttempt::Blocked(blocked) => {
                    intervention(command, strong_stop, InterventionTarget::Cold, blocked)
                }
            }
        }
        ColdDeleteStepState::DeleteConvergePersistent {
            strong_stop,
            request,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &request.local_recovery_authority,
            )?;
            let spec = delete_spec(command)?;
            let persistent = command
                .runtime_config
                .volumes
                .iter()
                .filter(|volume| volume.disk_role == DiskRole::Persistent)
                .cloned()
                .collect::<Vec<_>>();
            validate_convergence_request(
                command,
                &request,
                &persistent,
                local_recovery_runtime_incarnation(&request.local_recovery_authority, &strong_stop)
                    .as_ref(),
                &request.local_recovery_authority,
                spec.convergence_deadline_unix_ms,
                "delete-persistent",
            )?;
            let receipt = if request.targets.is_empty() {
                AtomicVolumeConvergenceReceipt {
                    dispositions: Vec::new(),
                }
            } else {
                match port.inspect_or_converge(command, &request)? {
                    AtomicColdDeleteAttempt::Exact(receipt) => receipt,
                    AtomicColdDeleteAttempt::Blocked(blocked) => {
                        return intervention(
                            command,
                            strong_stop,
                            InterventionTarget::Delete,
                            blocked,
                        )
                    }
                }
            };
            validate_convergence_receipt(command, &request, &receipt)?;
            let root = root_config(command)?;
            let expected_runtime_incarnation =
                local_recovery_runtime_incarnation(&request.local_recovery_authority, &strong_stop);
            let inspect = AtomicDeleteRootInspectionRequest {
                scope: request.scope,
                expected_runtime_incarnation: expected_runtime_incarnation.clone(),
                local_recovery_authority: request.local_recovery_authority,
                volume_id: root.volume_id.clone(),
                disk_id: root.disk_id.clone(),
                deadline_unix_ms: spec.convergence_deadline_unix_ms,
            };
            validate_root_inspection_request(
                command,
                &inspect,
                expected_runtime_incarnation.as_ref(),
            )?;
            Ok(StateProgress::Next(
                ColdDeleteStepState::DeleteInspectRoot {
                    strong_stop,
                    persistent_dispositions: receipt.dispositions,
                    request: inspect,
                },
            ))
        }
        ColdDeleteStepState::DeleteInspectRoot {
            strong_stop,
            persistent_dispositions,
            request,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &request.local_recovery_authority,
            )?;
            validate_root_inspection_request(
                command,
                &request,
                local_recovery_runtime_incarnation(&request.local_recovery_authority, &strong_stop)
                    .as_ref(),
            )?;
            validate_persistent_disposition_inputs(command, &persistent_dispositions)?;
            match port.inspect_delete_root(command, &request)? {
                AtomicColdDeleteAttempt::Exact(root) => {
                    let (root_identity, plan_root) = match root {
                        AtomicDeleteRootInspection::Owned { durability } => {
                            validate_root_durability(command, &request, &durability)?;
                            let identity = durability.volume.identity();
                            if durability_is_converged(&durability) {
                                let release = CommandNormalReleaseInput {
                                    durability,
                                    transition_id: transition_id(
                                        command,
                                        &request.volume_id,
                                        "delete-root-normal",
                                    )?,
                                };
                                (
                                    identity,
                                    PreparedDeleteRoot::Normal(
                                        AtomicVolumeDispositionInput::OwnedRelease { release },
                                    ),
                                )
                            } else {
                                validate_disposable_root_durability(&durability)?;
                                (identity, PreparedDeleteRoot::Disposable(durability))
                            }
                        }
                        AtomicDeleteRootInspection::AlreadyUnowned {
                            volume,
                            expected_epoch,
                            expected_head,
                        } => {
                            validate_root_unowned(command, &request, &volume, &expected_head)?;
                            let identity = volume.clone();
                            (
                                identity,
                                PreparedDeleteRoot::Normal(
                                    AtomicVolumeDispositionInput::AlreadyUnowned {
                                        volume,
                                        expected_epoch,
                                        expected_head,
                                    },
                                ),
                            )
                        }
                    };
                    let delete_command = delete_command_volume_set(command, root_identity)?;
                    let plan = match plan_root {
                        PreparedDeleteRoot::Normal(root_disposition) => {
                            let volumes = complete_delete_disposition_inputs(
                                &delete_command,
                                root_disposition,
                                persistent_dispositions,
                            )?;
                            AtomicDeleteBeginPlan::Normal {
                                command: delete_command,
                                volumes,
                            }
                        }
                        PreparedDeleteRoot::Disposable(root_durability) => {
                            AtomicDeleteBeginPlan::DisposableRoot {
                                command: delete_command,
                                persistent_volumes: persistent_dispositions,
                                root_durability,
                            }
                        }
                    };
                    validate_delete_begin_plan(command, &plan)?;
                    Ok(StateProgress::Next(ColdDeleteStepState::DeleteForceFull {
                        strong_stop,
                        plan,
                        local_recovery_authority: request.local_recovery_authority,
                    }))
                }
                AtomicColdDeleteAttempt::Blocked(blocked) => {
                    intervention(command, strong_stop, InterventionTarget::Delete, blocked)
                }
            }
        }
        ColdDeleteStepState::DeleteForceFull {
            strong_stop,
            plan,
            local_recovery_authority,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &local_recovery_authority,
            )?;
            validate_delete_begin_plan(command, &plan)?;
            let deadline = delete_spec(command)?.convergence_deadline_unix_ms;
            let attestation = attestation_port
                .force_full_and_wait(command, deadline)
                .context("force post-Stop Full inventory and wait for Control acceptance")?;
            validate_post_stop_attestation(command, &attestation)?;
            let request = plan.with_strong_stop(AtomicDeleteStrongStopEvidence {
                execution_absence: strong_stop.execution_absence.clone(),
                post_stop_inventory_attestation: attestation,
                local_recovery_authority,
            });
            validate_delete_begin_request(command, &strong_stop, &request)?;
            Ok(StateProgress::Next(ColdDeleteStepState::DeleteBegin {
                strong_stop,
                request,
            }))
        }
        ColdDeleteStepState::DeleteBegin {
            strong_stop,
            request,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &request.strong_stop().local_recovery_authority,
            )?;
            validate_delete_begin_request(command, &strong_stop, &request)?;
            match port.inspect_or_begin_delete(command, &request)? {
                AtomicDeleteBeginAttempt::Exact(begin) => {
                    validate_delete_begin_receipt(&request, &begin)?;
                    let request_stop = request.strong_stop();
                    let cleanup = AtomicRootLineageCleanupRequest {
                        command: request.command().clone(),
                        begin,
                        post_stop_inventory_attestation: request_stop
                            .post_stop_inventory_attestation
                            .clone(),
                        expected_runtime_incarnation: local_recovery_runtime_incarnation(
                            &request_stop.local_recovery_authority,
                            &strong_stop,
                        ),
                        local_recovery_authority: request_stop.local_recovery_authority.clone(),
                    };
                    validate_root_cleanup_request(command, &cleanup)?;
                    Ok(StateProgress::Next(
                        ColdDeleteStepState::DeleteCleanupRoot {
                            strong_stop,
                            request: cleanup,
                        },
                    ))
                }
                AtomicDeleteBeginAttempt::Blocked(blocked) => {
                    intervention(command, strong_stop, InterventionTarget::Delete, blocked)
                }
                AtomicDeleteBeginAttempt::FreshInventoryRequired => {
                    let plan = delete_begin_plan(&request);
                    let local_recovery_authority =
                        request.strong_stop().local_recovery_authority.clone();
                    validate_delete_begin_plan(command, &plan)?;
                    Ok(StateProgress::Next(ColdDeleteStepState::DeleteForceFull {
                        strong_stop,
                        plan,
                        local_recovery_authority,
                    }))
                }
            }
        }
        ColdDeleteStepState::DeleteCleanupRoot {
            strong_stop,
            request,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &request.local_recovery_authority,
            )?;
            anyhow::ensure!(
                request.expected_runtime_incarnation
                    == local_recovery_runtime_incarnation(
                        &request.local_recovery_authority,
                        &strong_stop,
                    ),
                "Delete Root cleanup changed its stopped runtime incarnation"
            );
            validate_root_cleanup_request(command, &request)?;
            match port.inspect_or_remove_root_lineage(command, &request)? {
                AtomicColdDeleteAttempt::Exact(absence) => {
                    validate_root_lineage_absence(&request, &absence)?;
                    let completion = AtomicDeleteCompletionRequest {
                        operation_id: command.operation_id.clone(),
                        request_fingerprint: command.request_fingerprint.clone(),
                        expected_runtime_incarnation: request.expected_runtime_incarnation.clone(),
                        volume_id: request.command.root_disposition.root.volume_id.clone(),
                        delete_id: request.command.root_disposition.delete_id.clone(),
                        expected_command: request.command.clone(),
                        expected_begin: request.begin.clone(),
                        post_stop_inventory_attestation: request
                            .post_stop_inventory_attestation
                            .clone(),
                        local_recovery_authority: request.local_recovery_authority.clone(),
                    };
                    validate_completion_request(command, &completion)?;
                    Ok(StateProgress::Next(
                        ColdDeleteStepState::DeleteAwaitCompletion {
                            strong_stop,
                            begin: request.begin,
                            root_lineage_absence: absence,
                            request: completion,
                        },
                    ))
                }
                AtomicColdDeleteAttempt::Blocked(blocked) => {
                    intervention(command, strong_stop, InterventionTarget::Delete, blocked)
                }
            }
        }
        ColdDeleteStepState::DeleteAwaitCompletion {
            strong_stop,
            begin,
            root_lineage_absence,
            request,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &request.local_recovery_authority,
            )?;
            validate_completion_request(command, &request)?;
            anyhow::ensure!(
                request.expected_begin == begin,
                "Delete completion step changed its exact begin receipt"
            );
            validate_root_lineage_absence(
                &AtomicRootLineageCleanupRequest {
                    command: request.expected_command.clone(),
                    begin: begin.clone(),
                    post_stop_inventory_attestation: request
                        .post_stop_inventory_attestation
                        .clone(),
                    expected_runtime_incarnation: request.expected_runtime_incarnation.clone(),
                    local_recovery_authority: request.local_recovery_authority.clone(),
                },
                &root_lineage_absence,
            )?;
            match port.discover_delete_completion(command, &request)? {
                AtomicColdDeleteAttempt::Exact(completion) => {
                    validate_delete_completion(&request, &root_lineage_absence, &completion)?;
                    let finalize = AtomicDeleteFinalizationRequest {
                        command: request.expected_command,
                        begin,
                        root_lineage_absence,
                        completion,
                        execution_absence: strong_stop.execution_absence.clone(),
                        post_stop_inventory_attestation: request.post_stop_inventory_attestation,
                        expected_runtime_incarnation: local_recovery_runtime_incarnation(
                            &request.local_recovery_authority,
                            &strong_stop,
                        ),
                        local_recovery_authority: request.local_recovery_authority,
                    };
                    let retained_warm_authority =
                        retained_warm_cleanup_authority(&finalize.local_recovery_authority)
                            .map(|cleanup| cleanup.authority.as_ref().clone());
                    if let Some(request) = predecessor_warm_cleanup_request(predecessor)? {
                        Ok(StateProgress::Next(
                            ColdDeleteStepState::DeletePrepareWarmCleanup {
                                strong_stop,
                                finalization: finalize,
                                request,
                            },
                        ))
                    } else if let Some(authority) = retained_warm_authority {
                        Ok(StateProgress::Next(
                            ColdDeleteStepState::DeleteRemoveWarmCleanup {
                                strong_stop,
                                finalization: finalize,
                                authority,
                            },
                        ))
                    } else {
                        Ok(StateProgress::Next(ColdDeleteStepState::DeleteFinalize {
                            strong_stop,
                            request: finalize,
                        }))
                    }
                }
                AtomicColdDeleteAttempt::Blocked(blocked) => {
                    intervention(command, strong_stop, InterventionTarget::Delete, blocked)
                }
            }
        }
        ColdDeleteStepState::DeletePrepareWarmCleanup {
            strong_stop,
            finalization,
            request,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &finalization.local_recovery_authority,
            )?;
            validate_delete_finalization_request(command, &finalization)?;
            validate_warm_cleanup_request(command, predecessor, &request)?;
            let warm_platform = warm_platform.context("Warm cleanup platform is not composed")?;
            match warm_platform.prepare_warm_snapshot_cleanup(command, &request)? {
                WarmSnapshotCleanupAttempt::Exact(authority) => Ok(StateProgress::Next(
                    ColdDeleteStepState::DeleteRemoveWarmCleanup {
                        strong_stop,
                        finalization,
                        authority,
                    },
                )),
                WarmSnapshotCleanupAttempt::Blocked => intervention(
                    command,
                    strong_stop,
                    InterventionTarget::Delete,
                    local_cleanup_intervention(),
                ),
            }
        }
        ColdDeleteStepState::DeleteRemoveWarmCleanup {
            strong_stop,
            finalization,
            authority,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &finalization.local_recovery_authority,
            )?;
            validate_delete_finalization_request(command, &finalization)?;
            validate_warm_cleanup_authority(
                state_directory,
                command,
                predecessor,
                &finalization.local_recovery_authority,
                &authority,
            )?;
            let warm_platform = warm_platform.context("Warm cleanup platform is not composed")?;
            match warm_platform.inspect_or_remove_warm_snapshot(
                command,
                &authority,
                &WarmSnapshotCleanupCompletion::Remove,
            )? {
                WarmSnapshotCleanupAttempt::Exact(_) => {
                    Ok(StateProgress::Next(ColdDeleteStepState::DeleteFinalize {
                        strong_stop,
                        request: finalization,
                    }))
                }
                WarmSnapshotCleanupAttempt::Blocked => intervention(
                    command,
                    strong_stop,
                    InterventionTarget::Delete,
                    local_cleanup_intervention(),
                ),
            }
        }
        ColdDeleteStepState::DeleteFinalize {
            strong_stop,
            request,
        } => {
            validate_strong_stop(command, &strong_stop)?;
            validate_expected_local_recovery_authority(
                command,
                predecessor,
                &strong_stop,
                &request.local_recovery_authority,
            )?;
            anyhow::ensure!(
                request.execution_absence == strong_stop.execution_absence,
                "Delete finalization changed its strong-Stop absence proof"
            );
            anyhow::ensure!(
                request.expected_runtime_incarnation
                    == local_recovery_runtime_incarnation(
                        &request.local_recovery_authority,
                        &strong_stop,
                    ),
                "Delete finalization changed its stopped runtime incarnation"
            );
            validate_delete_finalization_request(command, &request)?;
            match port.inspect_or_finalize_delete(command, &request)? {
                AtomicColdDeleteAttempt::Exact(destructive_cleanup_absent_digest) => {
                    let dispositions = completed_dispositions(&request)?;
                    Ok(StateProgress::Terminal(NodeResult::Deleted(Box::new(
                        DeletedResult {
                            execution_absence: strong_stop.execution_absence,
                            volume_dispositions: dispositions,
                            destructive_cleanup_absent_digest,
                        },
                    ))))
                }
                AtomicColdDeleteAttempt::Blocked(blocked) => {
                    intervention(command, strong_stop, InterventionTarget::Delete, blocked)
                }
            }
        }
    }
}

fn intervention(
    command: &LifecycleCommandEnvelope,
    strong_stop: StrongStopEvidence,
    attempted_target: InterventionTarget,
    blocked: AtomicColdDeleteBlocked,
) -> Result<StateProgress> {
    anyhow::ensure!(
        !matches!(blocked.reason, InterventionReason::WarmSnapshotAmbiguous),
        "Cold/Delete port returned a Warm-only intervention reason"
    );
    validate_retained_volume_receipts(command, &blocked.retained_volume_receipts)?;
    Ok(StateProgress::Terminal(NodeResult::NeedsIntervention(
        Box::new(NeedsInterventionResult {
            attempted_target,
            reason: blocked.reason,
            not_running: strong_stop.execution_absence,
            retained_evidence: strong_stop.retained_evidence,
            retained_volume_receipts: blocked.retained_volume_receipts,
        }),
    )))
}

fn validate_handler_command(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
) -> Result<()> {
    anyhow::ensure!(
        ctx.node_id() == &command.node_id && command.placement_identity.node_id == command.node_id,
        "Cold/Delete command belongs to another Node"
    );
    anyhow::ensure!(
        matches!(
            command.command,
            LifecycleCommand::Cold(_) | LifecycleCommand::Delete(_)
        ),
        "Cold/Delete handler received another lifecycle command"
    );
    let predecessor = predecessor.context("Cold/Delete lacks its exact same-Node predecessor")?;
    anyhow::ensure!(
        predecessor.workspace_id == command.workspace_id
            && predecessor.cat_id == command.cat_id
            && predecessor.node_id == command.node_id
            && predecessor.placement_identity == command.placement_identity
            && command.expected_predecessor_operation_id.as_ref()
                == Some(&predecessor.operation_id),
        "Cold/Delete predecessor response does not bind the command"
    );
    let cats_api::runtime_lifecycle::LifecyclePredecessor::SameNode {
        operation_id,
        terminal_result_kind,
        node_id,
        placement_identity,
        ..
    } = &command.predecessor
    else {
        anyhow::bail!("Cold/Delete may execute only on the exact same Node")
    };
    anyhow::ensure!(
        operation_id == &predecessor.operation_id
            && terminal_result_kind == &predecessor.result.kind()
            && node_id == &command.node_id
            && placement_identity == &command.placement_identity,
        "Cold/Delete typed predecessor differs from its durable response"
    );
    if let LifecycleCommand::Delete(spec) = &command.command {
        validate_delete_dispositions(command, spec)?;
    }
    Ok(())
}

fn validate_strong_stop(
    command: &LifecycleCommandEnvelope,
    evidence: &StrongStopEvidence,
) -> Result<()> {
    validate_retained_volume_receipts(command, &evidence.retained_volume_receipts)?;
    validate_retained_evidence(&evidence.retained_evidence)?;
    validate_execution_absence(&evidence.execution_absence)?;
    anyhow::ensure!(
        evidence
            .post_stop_physical_projection_digest
            .as_bytes()
            .iter()
            .any(|byte| *byte != 0),
        "Cold/Delete strong Stop lacks a physical projection digest"
    );
    Ok(())
}

fn validate_retained_evidence(evidence: &RetainedEvidence) -> Result<()> {
    let counts = [
        evidence.adoptable_count,
        evidence.gc_candidate_count,
        evidence.retained_authority_or_data_count,
        evidence.quarantined_count,
    ];
    anyhow::ensure!(
        evidence
            .artifact_manifest_digest
            .as_bytes()
            .iter()
            .any(|byte| *byte != 0)
            && counts.iter().all(|count| *count <= 1_024)
            && counts
                .iter()
                .try_fold(0_u16, |sum, value| sum.checked_add(*value))
                .is_some_and(|sum| sum <= 1_024),
        "Cold/Delete retained evidence is empty or exceeds the closed artifact bound"
    );
    Ok(())
}

fn validate_execution_absence(absence: &ExecutionAbsenceProof) -> Result<()> {
    anyhow::ensure!(
        [
            &absence.stop_fence_receipt_digest,
            &absence.admission_closed_receipt_digest,
            &absence.dedicated_scope_absence_receipt_digest,
            &absence.frontend_absence_receipt_digest,
            &absence.restart_source_absence_receipt_digest,
        ]
        .iter()
        .all(|digest| digest.as_bytes().iter().any(|byte| *byte != 0)),
        "Cold/Delete execution absence contains an empty receipt digest"
    );
    Ok(())
}

fn owned_predecessor_carrier(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    physical: &SameNodeOwnedPredecessorPhysical,
) -> Result<AtomicOwnedPredecessorCarrier> {
    let installed = physical.installed_runtime()?.clone();
    anyhow::ensure!(
        physical.runtime_incarnation.as_ref() == Some(&installed.runtime_incarnation),
        "Suspend/Warm predecessor carrier changed its runtime incarnation"
    );
    let volumes = physical
        .volumes
        .iter()
        .map(|volume| {
            Ok(AtomicOwnedPredecessorVolume {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                disk_role: volume.disk_role,
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch: volume.attachment_epoch,
                acquire_origin: volume.acquire_origin.clone(),
                authoritative_head: volume.authoritative_head.clone(),
                immutable_start_grant_receipt_digest: volume
                    .immutable_start_grant_receipt_digest
                    .clone(),
                local_lineage_data_directory: volume
                    .local_lineage_data_directory
                    .clone()
                    .context("Suspend/Warm predecessor carrier lacks a materialized lineage")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let terminal = LifecycleTerminalResult::NodeResult {
        response: Box::new(predecessor.clone()),
    };
    let mut carrier = AtomicOwnedPredecessorCarrier {
        predecessor_operation_id: predecessor.operation_id.clone(),
        predecessor_request_fingerprint: predecessor.request_fingerprint.clone(),
        predecessor_terminal_result_kind: predecessor.result.kind(),
        predecessor_terminal_result_digest: lifecycle_terminal_result_digest(&terminal)
            .context("digest Suspend/Warm predecessor terminal result")?,
        physical_manifest_digest: physical.physical_manifest_digest.clone(),
        physical: Box::new(physical.clone()),
        installed_runtime: Box::new(installed),
        volumes,
        carrier_digest: Sha256Digest::from_bytes([0; 32]),
    };
    carrier.carrier_digest = owned_predecessor_carrier_digest(&carrier)?;
    validate_owned_predecessor_carrier(command, predecessor, &carrier)?;
    Ok(carrier)
}

fn owned_predecessor_carrier_digest(
    carrier: &AtomicOwnedPredecessorCarrier,
) -> Result<Sha256Digest> {
    let mut unsigned = carrier.clone();
    unsigned.carrier_digest = Sha256Digest::from_bytes([0; 32]);
    canonical_digest(OWNED_PREDECESSOR_CARRIER_DOMAIN, &unsigned)
}

fn validate_owned_predecessor_carrier(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    carrier: &AtomicOwnedPredecessorCarrier,
) -> Result<()> {
    validate_owned_predecessor_carrier_structure(command, carrier)?;
    validate_same_node_owned_predecessor_physical(command, predecessor, &carrier.physical)?;
    let cats_api::runtime_lifecycle::LifecyclePredecessor::SameNode {
        operation_id,
        terminal_result_kind,
        terminal_result_digest,
        node_id,
        placement_identity,
    } = &command.predecessor
    else {
        anyhow::bail!("Suspend/Warm carrier requires a same-Node predecessor")
    };
    let installed = carrier.installed_runtime.as_ref();
    anyhow::ensure!(
        matches!(
            command.command,
            LifecycleCommand::Cold(_) | LifecycleCommand::Delete(_)
        ) && matches!(
            carrier.predecessor_terminal_result_kind,
            TerminalResultKind::SuspendDeclined
                | TerminalResultKind::Suspended
                | TerminalResultKind::Warm
                | TerminalResultKind::SuspendFailed
                | TerminalResultKind::WarmFailed
        ) && carrier.predecessor_operation_id == *operation_id
            && carrier.predecessor_operation_id == predecessor.operation_id
            && carrier.predecessor_request_fingerprint == predecessor.request_fingerprint
            && carrier.predecessor_terminal_result_kind == *terminal_result_kind
            && carrier.predecessor_terminal_result_kind == predecessor.result.kind()
            && carrier.predecessor_terminal_result_digest == *terminal_result_digest
            && carrier.predecessor_terminal_result_digest
                == lifecycle_terminal_result_digest(&LifecycleTerminalResult::NodeResult {
                    response: Box::new(predecessor.clone()),
                })?
            && *node_id == command.node_id
            && *placement_identity == command.placement_identity
            && carrier.physical_manifest_digest == carrier.physical.physical_manifest_digest
            && carrier.installed_runtime.as_ref() == carrier.physical.installed_runtime()?
            && carrier.carrier_digest == owned_predecessor_carrier_digest(carrier)?
            && installed.version == ContractVersion::V1
            && installed.node_id == command.node_id
            && installed.cat_id == command.cat_id
            && installed.placement_identity == command.placement_identity
            && installed.runtime_config_id == command.runtime_config.config_id
            && installed.runtime_config_digest == command.runtime_config.config_digest
            && installed.manifest_digest
                == super::start::installed_runtime_manifest_digest(installed)?
            && carrier.volumes.len() == command.runtime_config.volumes.len()
            && installed.volumes.len() == command.runtime_config.volumes.len(),
        "Suspend/Warm carrier changed its predecessor or installed runtime identity"
    );
    for (((volume, physical), configured), manifest) in carrier
        .volumes
        .iter()
        .zip(&carrier.physical.volumes)
        .zip(&command.runtime_config.volumes)
        .zip(&installed.volumes)
    {
        anyhow::ensure!(
            volume.volume_id == physical.volume_id
                && volume.disk_id == physical.disk_id
                && volume.disk_role == physical.disk_role
                && volume.attachment_id == physical.attachment_id
                && volume.attachment_epoch == physical.attachment_epoch
                && volume.acquire_origin == physical.acquire_origin
                && volume.authoritative_head == physical.authoritative_head
                && volume.immutable_start_grant_receipt_digest
                    == physical.immutable_start_grant_receipt_digest
                && physical.local_lineage_data_directory.as_ref()
                    == Some(&volume.local_lineage_data_directory)
                && volume.volume_id == configured.volume_id
                && volume.disk_id == configured.disk_id
                && volume.disk_role == configured.disk_role
                && manifest.volume_id == configured.volume_id
                && manifest.disk_id == configured.disk_id
                && manifest.disk_role == configured.disk_role
                && volume.attachment_id == manifest.attachment_id
                && volume.attachment_epoch == manifest.attachment_epoch
                && volume.acquire_origin == manifest.acquire_origin
                && manifest.authority_receipt_digest.as_ref()
                    == Some(&volume.immutable_start_grant_receipt_digest)
                && volume.local_lineage_data_directory == manifest.local_lineage_data_directory
                && remote_head_is_same_or_later(
                    &volume.authoritative_head,
                    &manifest.current_authority_head,
                ),
            "Suspend/Warm carrier changed a configured Volume lineage"
        );
    }
    let terminal_receipts = match &predecessor.result {
        NodeResult::Suspended(result) => Some(result.local_durability_receipts.as_slice()),
        NodeResult::Warm(result) => Some(result.volume_receipts.as_slice()),
        NodeResult::SuspendDeclined(result) => {
            anyhow::ensure!(
                result.effective_runtime_ready.source_lifecycle_operation_id
                    == installed.source_lifecycle_operation_id
                    && result.effective_runtime_ready.runtime_incarnation
                        == installed.runtime_incarnation
                    && result.effective_runtime_ready.runtime_config_digest
                        == installed.runtime_config_digest,
                "SuspendDeclined carrier changed its effective RuntimeReady source"
            );
            None
        }
        NodeResult::SuspendFailed(_) | NodeResult::WarmFailed(_) => None,
        _ => anyhow::bail!("owned predecessor carrier has another terminal result"),
    };
    if let Some(receipts) = terminal_receipts {
        anyhow::ensure!(
            receipts.len() == carrier.volumes.len(),
            "Suspend/Warm carrier lost a terminal Volume receipt"
        );
        for (receipt, volume) in receipts.iter().zip(&carrier.volumes) {
            anyhow::ensure!(
                receipt.volume_id == volume.volume_id
                    && receipt.disk_id == volume.disk_id
                    && receipt.disk_role == volume.disk_role
                    && receipt.attachment_id == volume.attachment_id
                    && receipt.attachment_epoch == volume.attachment_epoch
                    && receipt.authority_receipt_digest.as_ref()
                        == Some(&volume.immutable_start_grant_receipt_digest)
                    && receipt.remote_durable_generation <= volume.authoritative_head.generation
                    && volume.authoritative_head.generation <= receipt.local_durable_generation,
                "Suspend/Warm carrier changed terminal Volume durability"
            );
        }
    }
    Ok(())
}

fn validate_owned_predecessor_carrier_structure(
    command: &LifecycleCommandEnvelope,
    carrier: &AtomicOwnedPredecessorCarrier,
) -> Result<()> {
    let cats_api::runtime_lifecycle::LifecyclePredecessor::SameNode {
        operation_id,
        terminal_result_kind,
        terminal_result_digest,
        ..
    } = &command.predecessor
    else {
        anyhow::bail!("owned predecessor carrier requires a same-Node command")
    };
    let installed = carrier.installed_runtime.as_ref();
    let physical_installed = carrier.physical.installed_runtime()?;
    anyhow::ensure!(
        carrier.predecessor_operation_id == *operation_id
            && carrier.predecessor_terminal_result_kind == *terminal_result_kind
            && carrier.predecessor_terminal_result_digest == *terminal_result_digest
            && carrier.physical_manifest_digest == carrier.physical.physical_manifest_digest
            && carrier.physical.runtime_incarnation.as_ref()
                == Some(&installed.runtime_incarnation)
            && physical_installed == installed
            && carrier.carrier_digest == owned_predecessor_carrier_digest(carrier)?
            && installed.node_id == command.node_id
            && installed.cat_id == command.cat_id
            && installed.placement_identity == command.placement_identity
            && installed.runtime_config_id == command.runtime_config.config_id
            && installed.runtime_config_digest == command.runtime_config.config_digest
            && installed.manifest_digest
                == super::start::installed_runtime_manifest_digest(installed)?
            && carrier.volumes.len() == command.runtime_config.volumes.len()
            && carrier.physical.volumes.len() == carrier.volumes.len()
            && carrier
                .volumes
                .iter()
                .zip(&carrier.physical.volumes)
                .zip(&command.runtime_config.volumes)
                .all(|((volume, physical), configured)| {
                    volume.volume_id == physical.volume_id
                        && volume.disk_id == physical.disk_id
                        && volume.disk_role == physical.disk_role
                        && volume.attachment_id == physical.attachment_id
                        && volume.attachment_epoch == physical.attachment_epoch
                        && volume.acquire_origin == physical.acquire_origin
                        && volume.authoritative_head == physical.authoritative_head
                        && volume.immutable_start_grant_receipt_digest
                            == physical.immutable_start_grant_receipt_digest
                        && physical.local_lineage_data_directory.as_ref()
                            == Some(&volume.local_lineage_data_directory)
                        && volume.volume_id == configured.volume_id
                        && volume.disk_id == configured.disk_id
                        && volume.disk_role == configured.disk_role
                        && volume.attachment_epoch.get() > 0
                        && volume
                            .immutable_start_grant_receipt_digest
                            .as_bytes()
                            .iter()
                            .any(|byte| *byte != 0)
                        && remote_head_is_valid(&volume.authoritative_head)
                }),
        "owned predecessor carrier changed after its pre-Stop publication"
    );
    Ok(())
}

#[cfg(test)]
fn local_recovery_authority(
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    fresh: &StrongStopEvidence,
) -> Result<AtomicLocalRecoveryAuthority> {
    local_recovery_authority_with_carrier(command, predecessor, fresh, None, None)
}

fn local_recovery_authority_with_carrier(
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    fresh: &StrongStopEvidence,
    owned_predecessor_carrier: Option<&AtomicOwnedPredecessorCarrier>,
    retained_warm_cleanup: Option<&AtomicRetainedWarmCleanupAuthority>,
) -> Result<AtomicLocalRecoveryAuthority> {
    let predecessor = predecessor.context("Cold/Delete lacks its exact predecessor response")?;
    anyhow::ensure!(
        command.expected_predecessor_operation_id.as_ref() == Some(&predecessor.operation_id),
        "local recovery authority belongs to another predecessor"
    );
    let authority = match &predecessor.result {
        NodeResult::StartFailed(failed) => {
            if let Some(cleanup) = retained_warm_cleanup {
                validate_retained_warm_cleanup_binding(command, predecessor, cleanup)?;
            }
            AtomicLocalRecoveryAuthority::DirectStartFailed {
                predecessor_operation_id: predecessor.operation_id.clone(),
                predecessor_request_fingerprint: predecessor.request_fingerprint.clone(),
                not_running: failed.not_running.clone(),
                retained_evidence: failed.retained_evidence.clone(),
                retained_warm_cleanup: retained_warm_cleanup.cloned().map(Box::new),
            }
        }
        NodeResult::Killed(killed) => {
            anyhow::ensure!(
                killed.stop_fence_receipt_digest
                    == killed.execution_absence.stop_fence_receipt_digest
                    && killed.stopped_runtime_incarnation == fresh.stopped_runtime_incarnation
                    && killed.retained_evidence == fresh.retained_evidence
                    && killed.retained_volume_receipts == fresh.retained_volume_receipts,
                "Killed predecessor does not close against the fresh strong-Stop retained set"
            );
            AtomicLocalRecoveryAuthority::KilledRetained {
                predecessor_operation_id: predecessor.operation_id.clone(),
                predecessor_request_fingerprint: predecessor.request_fingerprint.clone(),
                stopped_runtime_incarnation: killed.stopped_runtime_incarnation.clone(),
                execution_absence: killed.execution_absence.clone(),
                stop_fence_receipt_digest: killed.stop_fence_receipt_digest.clone(),
                retained_evidence: killed.retained_evidence.clone(),
                retained_volume_receipts: killed.retained_volume_receipts.clone(),
            }
        }
        NodeResult::SuspendDeclined(_)
        | NodeResult::Suspended(_)
        | NodeResult::Warm(_)
        | NodeResult::SuspendFailed(_)
        | NodeResult::WarmFailed(_) => {
            let carrier = owned_predecessor_carrier
                .context("Suspend/Warm Cold/Delete transition lacks its pre-Stop carrier")?;
            validate_owned_predecessor_carrier(command, predecessor, carrier)?;
            AtomicLocalRecoveryAuthority::SuspendWarmOwned {
                carrier: Box::new(carrier.clone()),
            }
        }
        NodeResult::NeedsIntervention(intervention) => {
            let predecessor_terminal_result_digest =
                lifecycle_terminal_result_digest(&LifecycleTerminalResult::NodeResult {
                    response: Box::new(predecessor.clone()),
                })
                .context("digest NeedsIntervention retry predecessor")?;
            let cats_api::runtime_lifecycle::LifecyclePredecessor::SameNode {
                terminal_result_digest,
                ..
            } = &command.predecessor
            else {
                anyhow::bail!("NeedsIntervention retry requires a same-Node predecessor")
            };
            let exact_target = matches!(
                (&command.command, intervention.attempted_target),
                (LifecycleCommand::Cold(_), InterventionTarget::Cold)
                    | (LifecycleCommand::Delete(_), InterventionTarget::Delete)
            );
            anyhow::ensure!(
                exact_target
                    && predecessor_terminal_result_digest == *terminal_result_digest
                    && intervention.not_running == fresh.execution_absence
                    && intervention.reason != InterventionReason::ForeignOrAmbiguousResidue
                    && fresh.retained_evidence.quarantined_count == 0
                    && intervention.retained_evidence == fresh.retained_evidence
                    && intervention.retained_volume_receipts == fresh.retained_volume_receipts,
                "NeedsIntervention retry is not the exact same-command fresh retained projection"
            );
            AtomicLocalRecoveryAuthority::NeedsInterventionRetry {
                predecessor_operation_id: predecessor.operation_id.clone(),
                predecessor_request_fingerprint: predecessor.request_fingerprint.clone(),
                predecessor_terminal_result_digest,
                attempted_target: intervention.attempted_target,
                retained_evidence: intervention.retained_evidence.clone(),
                retained_volume_receipts: intervention.retained_volume_receipts.clone(),
            }
        }
        result => AtomicLocalRecoveryAuthority::TerminalRetainedForbidden {
            predecessor_operation_id: predecessor.operation_id.clone(),
            predecessor_request_fingerprint: predecessor.request_fingerprint.clone(),
            terminal_result_kind: result.kind(),
        },
    };
    validate_local_recovery_authority(command, &authority)?;
    Ok(authority)
}

fn validate_local_recovery_authority(
    command: &LifecycleCommandEnvelope,
    authority: &AtomicLocalRecoveryAuthority,
) -> Result<()> {
    let cats_api::runtime_lifecycle::LifecyclePredecessor::SameNode {
        operation_id,
        terminal_result_kind,
        ..
    } = &command.predecessor
    else {
        anyhow::bail!("local recovery authority requires a same-Node predecessor")
    };
    let (authority_operation_id, fingerprint) = match authority {
        AtomicLocalRecoveryAuthority::TerminalRetainedForbidden {
            predecessor_operation_id,
            predecessor_request_fingerprint,
            terminal_result_kind: authority_kind,
        } => {
            anyhow::ensure!(
                authority_kind == terminal_result_kind
                    && !matches!(
                        authority_kind,
                        TerminalResultKind::StartFailed
                            | TerminalResultKind::Killed
                            | TerminalResultKind::SuspendDeclined
                            | TerminalResultKind::Suspended
                            | TerminalResultKind::Warm
                            | TerminalResultKind::SuspendFailed
                            | TerminalResultKind::WarmFailed
                            | TerminalResultKind::NeedsIntervention
                    ),
                "terminal-retained-forbidden authority changed its predecessor kind"
            );
            (predecessor_operation_id, predecessor_request_fingerprint)
        }
        AtomicLocalRecoveryAuthority::DirectStartFailed {
            predecessor_operation_id,
            predecessor_request_fingerprint,
            not_running,
            retained_evidence,
            retained_warm_cleanup,
        } => {
            anyhow::ensure!(
                *terminal_result_kind == TerminalResultKind::StartFailed,
                "direct StartFailed authority has another predecessor kind"
            );
            validate_execution_absence(not_running)?;
            validate_retained_evidence(retained_evidence)?;
            if let Some(cleanup) = retained_warm_cleanup.as_deref() {
                validate_retained_warm_restart_source(&cleanup.carrier)?;
                validate_warm_cleanup_authority_binding(&cleanup.authority)?;
                anyhow::ensure!(
                    cleanup.terminal_retained_manifest_digest
                        == retained_evidence.artifact_manifest_digest,
                    "retained Warm cleanup changed its StartFailed manifest digest"
                );
            }
            (predecessor_operation_id, predecessor_request_fingerprint)
        }
        AtomicLocalRecoveryAuthority::KilledRetained {
            predecessor_operation_id,
            predecessor_request_fingerprint,
            execution_absence,
            stop_fence_receipt_digest,
            retained_evidence,
            retained_volume_receipts,
            ..
        } => {
            anyhow::ensure!(
                *terminal_result_kind == TerminalResultKind::Killed
                    && stop_fence_receipt_digest == &execution_absence.stop_fence_receipt_digest,
                "Killed recovery authority changed its terminal kind or Stop fence"
            );
            validate_execution_absence(execution_absence)?;
            validate_retained_evidence(retained_evidence)?;
            validate_retained_volume_receipts(command, retained_volume_receipts)?;
            (predecessor_operation_id, predecessor_request_fingerprint)
        }
        AtomicLocalRecoveryAuthority::SuspendWarmOwned { carrier } => {
            validate_owned_predecessor_carrier_structure(command, carrier)?;
            anyhow::ensure!(
                carrier.predecessor_terminal_result_kind == *terminal_result_kind,
                "Suspend/Warm recovery carrier changed its terminal kind"
            );
            (
                &carrier.predecessor_operation_id,
                &carrier.predecessor_request_fingerprint,
            )
        }
        AtomicLocalRecoveryAuthority::NeedsInterventionRetry {
            predecessor_operation_id,
            predecessor_request_fingerprint,
            predecessor_terminal_result_digest,
            attempted_target,
            retained_evidence,
            retained_volume_receipts,
        } => {
            let cats_api::runtime_lifecycle::LifecyclePredecessor::SameNode {
                terminal_result_digest,
                ..
            } = &command.predecessor
            else {
                anyhow::bail!("NeedsIntervention recovery requires a same-Node predecessor")
            };
            anyhow::ensure!(
                *terminal_result_kind == TerminalResultKind::NeedsIntervention
                    && predecessor_terminal_result_digest == terminal_result_digest
                    && matches!(
                        (&command.command, attempted_target),
                        (LifecycleCommand::Cold(_), InterventionTarget::Cold)
                            | (LifecycleCommand::Delete(_), InterventionTarget::Delete)
                    ),
                "NeedsIntervention recovery changed its same-command target"
            );
            validate_retained_evidence(retained_evidence)?;
            validate_retained_volume_receipts(command, retained_volume_receipts)?;
            (predecessor_operation_id, predecessor_request_fingerprint)
        }
    };
    anyhow::ensure!(
        authority_operation_id == operation_id
            && command.expected_predecessor_operation_id.as_ref() == Some(operation_id)
            && fingerprint.as_bytes().iter().any(|byte| *byte != 0),
        "local recovery authority changed its predecessor identity"
    );
    Ok(())
}

fn validate_expected_local_recovery_authority(
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    fresh: &StrongStopEvidence,
    authority: &AtomicLocalRecoveryAuthority,
) -> Result<()> {
    let (carrier, retained_warm_cleanup) = match authority {
        AtomicLocalRecoveryAuthority::SuspendWarmOwned { carrier } => {
            (Some(carrier.as_ref()), None)
        }
        AtomicLocalRecoveryAuthority::DirectStartFailed {
            retained_warm_cleanup,
            ..
        } => (None, retained_warm_cleanup.as_deref()),
        _ => (None, None),
    };
    anyhow::ensure!(
        authority
            == &local_recovery_authority_with_carrier(
                command,
                predecessor,
                fresh,
                carrier,
                retained_warm_cleanup,
            )?,
        "durable local recovery authority changed after strong Stop"
    );
    Ok(())
}

fn local_recovery_runtime_incarnation(
    authority: &AtomicLocalRecoveryAuthority,
    strong_stop: &StrongStopEvidence,
) -> Option<RandomId128> {
    match authority {
        AtomicLocalRecoveryAuthority::SuspendWarmOwned { carrier } => {
            Some(carrier.installed_runtime.runtime_incarnation.clone())
        }
        _ => strong_stop.stopped_runtime_incarnation.clone(),
    }
}

fn cold_spec(command: &LifecycleCommandEnvelope) -> Result<&cats_api::runtime_lifecycle::ColdSpec> {
    let LifecycleCommand::Cold(spec) = &command.command else {
        anyhow::bail!("Cold phase is bound to a non-Cold command")
    };
    Ok(spec)
}

fn delete_spec(
    command: &LifecycleCommandEnvelope,
) -> Result<&cats_api::runtime_lifecycle::DeleteSpec> {
    let LifecycleCommand::Delete(spec) = &command.command else {
        anyhow::bail!("Delete phase is bound to a non-Delete command")
    };
    Ok(spec)
}

fn root_config(command: &LifecycleCommandEnvelope) -> Result<&RuntimeVolumeConfig> {
    command
        .runtime_config
        .volumes
        .iter()
        .find(|volume| volume.disk_role == DiskRole::Root)
        .context("immutable runtime config has no Root volume")
}

fn command_scope(command: &LifecycleCommandEnvelope) -> LifecycleVolumeCommandScope {
    LifecycleVolumeCommandScope {
        operation_id: command.operation_id.clone(),
        request_fingerprint: command.request_fingerprint.clone(),
        cat_id: command.cat_id.clone(),
        node_id: command.node_id.clone(),
        placement_identity: command.placement_identity.clone(),
    }
}

fn convergence_request(
    command: &LifecycleCommandEnvelope,
    volumes: &[RuntimeVolumeConfig],
    expected_runtime_incarnation: Option<RandomId128>,
    local_recovery_authority: AtomicLocalRecoveryAuthority,
    deadline_unix_ms: UnixMillis,
    purpose: &str,
) -> Result<AtomicVolumeConvergenceRequest> {
    let targets = volumes
        .iter()
        .map(|volume| {
            Ok(AtomicVolumeConvergenceTarget {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                disk_role: volume.disk_role,
                transition_id: transition_id(command, &volume.volume_id, purpose)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(AtomicVolumeConvergenceRequest {
        scope: command_scope(command),
        expected_runtime_incarnation,
        local_recovery_authority,
        targets,
        deadline_unix_ms,
    })
}

fn transition_id(
    command: &LifecycleCommandEnvelope,
    volume_id: &Id,
    purpose: &str,
) -> Result<RandomId128> {
    let mut digest = Sha256::new();
    digest.update(TRANSITION_ID_DOMAIN);
    digest.update([0]);
    for part in [
        command.operation_id.as_str().as_bytes(),
        command.request_fingerprint.as_bytes(),
        volume_id.as_str().as_bytes(),
        purpose.as_bytes(),
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    let bytes: [u8; 32] = digest.finalize().into();
    let value = bytes[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    RandomId128::new(value).context("derive command-scoped Volume transition ID")
}

fn validate_convergence_request(
    command: &LifecycleCommandEnvelope,
    request: &AtomicVolumeConvergenceRequest,
    expected: &[RuntimeVolumeConfig],
    expected_runtime_incarnation: Option<&RandomId128>,
    expected_local_recovery_authority: &AtomicLocalRecoveryAuthority,
    deadline: UnixMillis,
    purpose: &str,
) -> Result<()> {
    anyhow::ensure!(
        request.scope == command_scope(command)
            && request.expected_runtime_incarnation.as_ref() == expected_runtime_incarnation
            && &request.local_recovery_authority == expected_local_recovery_authority
            && request.deadline_unix_ms == deadline
            && request.targets.len() == expected.len(),
        "Volume convergence request changed its command scope or complete set"
    );
    let mut transition_ids = BTreeSet::new();
    for (target, volume) in request.targets.iter().zip(expected) {
        anyhow::ensure!(
            target.volume_id == volume.volume_id
                && target.disk_id == volume.disk_id
                && target.disk_role == volume.disk_role
                && target.transition_id == transition_id(command, &volume.volume_id, purpose)?
                && transition_ids.insert(target.transition_id.clone()),
            "Volume convergence target is incomplete, reordered, or duplicated"
        );
    }
    Ok(())
}

fn validate_convergence_receipt(
    command: &LifecycleCommandEnvelope,
    request: &AtomicVolumeConvergenceRequest,
    receipt: &AtomicVolumeConvergenceReceipt,
) -> Result<()> {
    anyhow::ensure!(
        receipt.dispositions.len() == request.targets.len(),
        "Volume convergence receipt omitted a target"
    );
    for (input, expected) in receipt.dispositions.iter().zip(&request.targets) {
        validate_disposition_input(command, &request.scope, expected, input)?;
    }
    Ok(())
}

fn validate_disposition_input(
    command: &LifecycleCommandEnvelope,
    scope: &LifecycleVolumeCommandScope,
    expected: &AtomicVolumeConvergenceTarget,
    input: &AtomicVolumeDispositionInput,
) -> Result<()> {
    match input {
        AtomicVolumeDispositionInput::OwnedRelease { release } => {
            validate_release_input(command, scope, expected, release)
        }
        AtomicVolumeDispositionInput::AlreadyUnowned {
            volume,
            expected_epoch: _,
            expected_head,
        } => {
            anyhow::ensure!(
                volume.volume_id == expected.volume_id
                    && volume.disk_id == expected.disk_id
                    && volume.disk_role == expected.disk_role
                    && remote_head_is_valid(expected_head),
                "already-Unowned input differs from its immutable command slot"
            );
            Ok(())
        }
    }
}

fn validate_release_input(
    _command: &LifecycleCommandEnvelope,
    scope: &LifecycleVolumeCommandScope,
    expected: &AtomicVolumeConvergenceTarget,
    input: &CommandNormalReleaseInput,
) -> Result<()> {
    let proof = &input.durability;
    anyhow::ensure!(
        proof.scope == *scope
            && proof.volume.volume_id == expected.volume_id
            && proof.volume.disk_id == expected.disk_id
            && proof.volume.disk_role == expected.disk_role
            && proof.volume.attachment_epoch.get() > 0
            && input.transition_id == expected.transition_id,
        "normal release input differs from its durable convergence target"
    );
    validate_converged_durability(proof)
}

fn validate_converged_durability(proof: &CommandVolumeDurabilityProof) -> Result<()> {
    anyhow::ensure!(
        remote_head_is_valid(&proof.remote_head)
            && proof.remote_durable_generation == proof.remote_head.generation
            && proof.local_durable_generation == proof.remote_durable_generation
            && proof.pending_pack_count.get() == 0,
        "normal release lacks an exact R == L, pending=0 proof"
    );
    Ok(())
}

fn durability_is_converged(proof: &CommandVolumeDurabilityProof) -> bool {
    remote_head_is_valid(&proof.remote_head)
        && proof.remote_durable_generation == proof.remote_head.generation
        && proof.local_durable_generation == proof.remote_durable_generation
        && proof.pending_pack_count.get() == 0
}

fn validate_disposable_root_durability(proof: &CommandVolumeDurabilityProof) -> Result<()> {
    anyhow::ensure!(
        proof.volume.disk_role == DiskRole::Root
            && remote_head_is_valid(&proof.remote_head)
            && proof.remote_durable_generation == proof.remote_head.generation
            && proof.local_durable_generation > proof.remote_durable_generation
            && proof.pending_pack_count.get() > 0,
        "disposable Root requires an exact R < L tail and nonempty pending set"
    );
    Ok(())
}

fn validate_root_inspection_request(
    command: &LifecycleCommandEnvelope,
    request: &AtomicDeleteRootInspectionRequest,
    expected_runtime_incarnation: Option<&RandomId128>,
) -> Result<()> {
    let spec = delete_spec(command)?;
    let root = root_config(command)?;
    validate_local_recovery_authority(command, &request.local_recovery_authority)?;
    anyhow::ensure!(
        request.scope == command_scope(command)
            && request.expected_runtime_incarnation.as_ref() == expected_runtime_incarnation
            && request.volume_id == root.volume_id
            && request.disk_id == root.disk_id
            && request.deadline_unix_ms == spec.convergence_deadline_unix_ms,
        "Delete Root inspection changed its exact command or Root identity"
    );
    Ok(())
}

fn validate_root_durability(
    command: &LifecycleCommandEnvelope,
    request: &AtomicDeleteRootInspectionRequest,
    proof: &CommandVolumeDurabilityProof,
) -> Result<()> {
    let root = root_config(command)?;
    anyhow::ensure!(
        proof.scope == request.scope
            && proof.volume.volume_id == root.volume_id
            && proof.volume.disk_id == root.disk_id
            && proof.volume.disk_role == DiskRole::Root
            && proof.volume.attachment_epoch.get() > 0
            && remote_head_is_valid(&proof.remote_head)
            && proof.remote_durable_generation == proof.remote_head.generation
            && proof.remote_durable_generation <= proof.local_durable_generation,
        "Delete Root durability evidence is not the exact configured lineage"
    );
    if proof.local_durable_generation == proof.remote_durable_generation {
        anyhow::ensure!(
            proof.pending_pack_count.get() == 0,
            "R == L Root still reports pending packs"
        );
    } else {
        anyhow::ensure!(
            proof.pending_pack_count.get() > 0,
            "R < L Root lacks its retained local-tail evidence"
        );
    }
    Ok(())
}

fn validate_root_unowned(
    command: &LifecycleCommandEnvelope,
    request: &AtomicDeleteRootInspectionRequest,
    volume: &LifecycleVolumeIdentity,
    expected_head: &RemoteHead,
) -> Result<()> {
    let root = root_config(command)?;
    anyhow::ensure!(
        request.scope == command_scope(command)
            && volume.volume_id == root.volume_id
            && volume.disk_id == root.disk_id
            && volume.disk_role == DiskRole::Root
            && remote_head_is_valid(expected_head),
        "Delete Root already-Unowned observation changed its configured identity"
    );
    Ok(())
}

fn validate_cold_release_plan(
    command: &LifecycleCommandEnvelope,
    volume_set: &ColdCommandVolumeSet,
    dispositions: &[AtomicVolumeDispositionInput],
) -> Result<()> {
    cold_spec(command)?;
    anyhow::ensure!(
        volume_set.scope == command_scope(command)
            && volume_set.volumes.len() == command.runtime_config.volumes.len()
            && dispositions.len() == command.runtime_config.volumes.len(),
        "Cold release request changed its command scope or complete volume set"
    );
    for ((target, input), config) in volume_set
        .volumes
        .iter()
        .zip(dispositions)
        .zip(&command.runtime_config.volumes)
    {
        anyhow::ensure!(
            target.volume_id == config.volume_id
                && target.disk_id == config.disk_id
                && target.disk_role == config.disk_role
                && input.identity() == *target,
            "Cold release target or transition identity differs from immutable config"
        );
        let expected = AtomicVolumeConvergenceTarget {
            volume_id: config.volume_id.clone(),
            disk_id: config.disk_id.clone(),
            disk_role: config.disk_role,
            transition_id: transition_id(command, &config.volume_id, "cold")?,
        };
        validate_disposition_input(command, &volume_set.scope, &expected, input)?;
    }
    Ok(())
}

fn validate_cold_release_request(
    command: &LifecycleCommandEnvelope,
    strong_stop: &StrongStopEvidence,
    request: &AtomicColdReleaseRequest,
) -> Result<()> {
    validate_cold_release_plan(command, &request.command, &request.dispositions)?;
    validate_local_recovery_authority(command, &request.strong_stop.local_recovery_authority)?;
    anyhow::ensure!(
        request.strong_stop.execution_absence == strong_stop.execution_absence,
        "Cold release changed its exact execution-absence proof"
    );
    validate_post_stop_attestation(
        command,
        &request.strong_stop.post_stop_inventory_attestation,
    )
}

fn validate_cold_release_receipt(
    request: &AtomicColdReleaseRequest,
    receipt: &AtomicColdReleaseReceipt,
) -> Result<()> {
    validate_stored_disposition_set(
        &request.command.scope,
        &request.command.volumes,
        &request.dispositions,
        &receipt.dispositions,
        StoredDispositionUse::Cold,
    )
}

fn validate_cold_finalization_request(
    command: &LifecycleCommandEnvelope,
    request: &AtomicColdFinalizationRequest,
) -> Result<()> {
    validate_local_recovery_authority(command, &request.local_recovery_authority)?;
    let inputs = disposition_inputs_from_stored(&request.dispositions);
    validate_cold_release_plan(command, &request.command, &inputs)?;
    validate_post_stop_attestation(command, &request.post_stop_inventory_attestation)?;
    validate_stored_disposition_set(
        &request.command.scope,
        &request.command.volumes,
        &inputs,
        &request.dispositions,
        StoredDispositionUse::Cold,
    )
}

fn validate_persistent_disposition_inputs(
    command: &LifecycleCommandEnvelope,
    inputs: &[AtomicVolumeDispositionInput],
) -> Result<()> {
    delete_spec(command)?;
    let expected = command
        .runtime_config
        .volumes
        .iter()
        .filter(|volume| volume.disk_role == DiskRole::Persistent)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        inputs.len() == expected.len(),
        "Delete Persistent release proof set is incomplete"
    );
    for (input, config) in inputs.iter().zip(expected) {
        let target = AtomicVolumeConvergenceTarget {
            volume_id: config.volume_id.clone(),
            disk_id: config.disk_id.clone(),
            disk_role: config.disk_role,
            transition_id: transition_id(command, &config.volume_id, "delete-persistent")?,
        };
        validate_disposition_input(command, &command_scope(command), &target, input)?;
    }
    Ok(())
}

fn delete_command_volume_set(
    command: &LifecycleCommandEnvelope,
    root: LifecycleVolumeIdentity,
) -> Result<DeleteCommandVolumeSet> {
    let spec = delete_spec(command)?;
    let persistent_volumes = command
        .runtime_config
        .volumes
        .iter()
        .filter(|volume| volume.disk_role == DiskRole::Persistent)
        .map(|volume| LifecycleVolumeIdentity {
            disk_id: volume.disk_id.clone(),
            disk_role: volume.disk_role,
            volume_id: volume.volume_id.clone(),
        })
        .collect::<Vec<_>>();
    let set = DeleteCommandVolumeSet {
        scope: command_scope(command),
        root_disposition: DefaultRootDiscardDisposition {
            root,
            delete_id: spec.delete_id.clone(),
        },
        persistent_volumes,
    };
    validate_delete_command_set(command, &set)?;
    Ok(set)
}

fn validate_delete_command_set(
    command: &LifecycleCommandEnvelope,
    set: &DeleteCommandVolumeSet,
) -> Result<()> {
    let spec = delete_spec(command)?;
    let root = root_config(command)?;
    anyhow::ensure!(
        set.scope == command_scope(command)
            && set.root_disposition.delete_id == spec.delete_id
            && set.root_disposition.root.volume_id == root.volume_id
            && set.root_disposition.root.disk_id == root.disk_id
            && set.root_disposition.root.disk_role == DiskRole::Root,
        "Delete command Volume set changed its Root disposition"
    );
    let persistent = command
        .runtime_config
        .volumes
        .iter()
        .filter(|volume| volume.disk_role == DiskRole::Persistent)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        set.persistent_volumes.len() == persistent.len(),
        "Delete command Volume set omitted a Persistent volume"
    );
    let mut volume_ids = BTreeSet::new();
    anyhow::ensure!(volume_ids.insert(set.root_disposition.root.volume_id.clone()));
    for (target, config) in set.persistent_volumes.iter().zip(persistent) {
        anyhow::ensure!(
            target.volume_id == config.volume_id
                && target.disk_id == config.disk_id
                && target.disk_role == DiskRole::Persistent
                && volume_ids.insert(target.volume_id.clone()),
            "Delete Persistent Volume set is incomplete, reordered, or duplicated"
        );
    }
    Ok(())
}

fn complete_delete_disposition_inputs(
    command: &DeleteCommandVolumeSet,
    root: AtomicVolumeDispositionInput,
    persistent: Vec<AtomicVolumeDispositionInput>,
) -> Result<Vec<AtomicVolumeDispositionInput>> {
    anyhow::ensure!(
        root.identity() == command.root_disposition.root
            && persistent.len() == command.persistent_volumes.len(),
        "Delete disposition set does not bind its canonical command"
    );
    let mut by_volume = persistent
        .into_iter()
        .map(|input| (input.identity().volume_id, input))
        .collect::<BTreeMap<_, _>>();
    anyhow::ensure!(
        by_volume
            .insert(root.identity().volume_id.clone(), root)
            .is_none(),
        "Delete Root disposition duplicates a Persistent slot"
    );
    complete_delete_config_order(command)?
        .into_iter()
        .map(|identity| {
            by_volume
                .remove(&identity.volume_id)
                .context("Delete disposition set omitted a configured slot")
        })
        .collect()
}

fn validate_delete_begin_request(
    command: &LifecycleCommandEnvelope,
    strong_stop: &StrongStopEvidence,
    request: &AtomicDeleteBeginRequest,
) -> Result<()> {
    validate_delete_command_set(command, request.command())?;
    let request_stop = match request {
        AtomicDeleteBeginRequest::Normal { strong_stop, .. }
        | AtomicDeleteBeginRequest::DisposableRoot { strong_stop, .. } => strong_stop,
    };
    validate_local_recovery_authority(command, &request_stop.local_recovery_authority)?;
    anyhow::ensure!(
        request_stop.execution_absence == strong_stop.execution_absence,
        "Delete begin changed its exact execution-absence proof"
    );
    validate_post_stop_attestation(command, &request_stop.post_stop_inventory_attestation)?;
    validate_delete_begin_plan(command, &delete_begin_plan(request))?;
    match request {
        AtomicDeleteBeginRequest::Normal {
            command: delete,
            volumes,
            strong_stop: _,
        } => validate_delete_normal_disposition_inputs(command, delete, volumes)?,
        AtomicDeleteBeginRequest::DisposableRoot {
            command: delete,
            persistent_volumes,
            root_durability,
            strong_stop: _,
        } => {
            anyhow::ensure!(
                root_durability.scope == delete.scope
                    && root_durability.volume.identity() == delete.root_disposition.root,
                "disposable Delete changed its command or strong-Stop evidence"
            );
            validate_persistent_disposition_inputs(command, persistent_volumes)?;
            anyhow::ensure!(
                persistent_volumes
                    .iter()
                    .map(AtomicVolumeDispositionInput::identity)
                    .eq(delete.persistent_volumes.iter().cloned()),
                "disposable Delete Persistent releases differ from its canonical set"
            );
            validate_disposable_root_durability(root_durability)?;
        }
    }
    Ok(())
}

fn validate_delete_normal_disposition_inputs(
    command: &LifecycleCommandEnvelope,
    delete: &DeleteCommandVolumeSet,
    inputs: &[AtomicVolumeDispositionInput],
) -> Result<()> {
    let expected = complete_delete_config_order(delete)?;
    anyhow::ensure!(
        inputs.len() == expected.len(),
        "normal Delete disposition set is incomplete"
    );
    for (input, identity) in inputs.iter().zip(expected) {
        let purpose = match identity.disk_role {
            DiskRole::Root => "delete-root-normal",
            DiskRole::Persistent => "delete-persistent",
        };
        let target = AtomicVolumeConvergenceTarget {
            volume_id: identity.volume_id.clone(),
            disk_id: identity.disk_id.clone(),
            disk_role: identity.disk_role,
            transition_id: transition_id(command, &identity.volume_id, purpose)?,
        };
        validate_disposition_input(command, &delete.scope, &target, input)?;
    }
    Ok(())
}

fn delete_begin_plan(request: &AtomicDeleteBeginRequest) -> AtomicDeleteBeginPlan {
    match request {
        AtomicDeleteBeginRequest::Normal {
            command, volumes, ..
        } => AtomicDeleteBeginPlan::Normal {
            command: command.clone(),
            volumes: volumes.clone(),
        },
        AtomicDeleteBeginRequest::DisposableRoot {
            command,
            persistent_volumes,
            root_durability,
            ..
        } => AtomicDeleteBeginPlan::DisposableRoot {
            command: command.clone(),
            persistent_volumes: persistent_volumes.clone(),
            root_durability: root_durability.clone(),
        },
    }
}

fn validate_delete_begin_plan(
    command: &LifecycleCommandEnvelope,
    plan: &AtomicDeleteBeginPlan,
) -> Result<()> {
    match plan {
        AtomicDeleteBeginPlan::Normal {
            command: delete,
            volumes,
        } => {
            validate_delete_command_set(command, delete)?;
            validate_delete_normal_disposition_inputs(command, delete, volumes)?;
        }
        AtomicDeleteBeginPlan::DisposableRoot {
            command: delete,
            persistent_volumes,
            root_durability,
        } => {
            validate_delete_command_set(command, delete)?;
            validate_persistent_disposition_inputs(command, persistent_volumes)?;
            anyhow::ensure!(
                root_durability.scope == delete.scope
                    && root_durability.volume.identity() == delete.root_disposition.root,
                "disposable Delete plan changed the Root lineage"
            );
            validate_disposable_root_durability(root_durability)?;
        }
    }
    Ok(())
}

fn validate_post_stop_attestation(
    command: &LifecycleCommandEnvelope,
    attestation: &RuntimeInventoryAttestation,
) -> Result<()> {
    anyhow::ensure!(
        attestation.version == ContractVersion::V1
            && attestation.session.node_id == command.node_id
            && attestation.inventory_epoch.get() > 0
            && attestation.source_sequence.get() > 0,
        "post-Stop Full inventory attestation is not current for this Node"
    );
    // The attestation deliberately does not repeat Cat facts. The signed
    // Control transition must lock and re-read its exact source Full report,
    // then close Cat/op/fingerprint/placement, physical Absent and incarnation
    // None in the same transaction before deriving disposable authority.
    Ok(())
}

fn validate_delete_begin_receipt(
    request: &AtomicDeleteBeginRequest,
    receipt: &AtomicDeleteBeginReceipt,
) -> Result<()> {
    match (request, receipt) {
        (
            AtomicDeleteBeginRequest::Normal {
                command, volumes, ..
            },
            AtomicDeleteBeginReceipt::NormallyDeleting { dispositions },
        ) => validate_stored_disposition_set(
            &command.scope,
            &complete_delete_config_order(command)?,
            volumes,
            dispositions,
            StoredDispositionUse::Delete,
        ),
        (
            AtomicDeleteBeginRequest::DisposableRoot {
                command,
                persistent_volumes,
                root_durability,
                ..
            },
            AtomicDeleteBeginReceipt::DisposableRootDeleting {
                persistent_dispositions,
                root_durability: stored_root,
                authorization_id: _,
                authorization_consumed_receipt_digest: _,
            },
        ) => {
            anyhow::ensure!(
                stored_root == root_durability,
                "disposable Delete response changed its exact Root durability proof"
            );
            validate_stored_disposition_set(
                &command.scope,
                &command.persistent_volumes,
                persistent_volumes,
                persistent_dispositions,
                StoredDispositionUse::Delete,
            )
        }
        _ => anyhow::bail!("Delete begin response selected a different Root authority branch"),
    }
}

#[derive(Clone, Copy)]
enum StoredDispositionUse {
    Cold,
    Delete,
}

impl StoredDispositionUse {
    fn already_unowned_receipt_digest(
        self,
        receipt: &CommandAlreadyUnownedReceipt,
    ) -> Result<Sha256Digest> {
        Ok(match self {
            Self::Cold => cats_storage::lifecycle_volume::command_cold_already_unowned_receipt_digest_from_closed_receipt(receipt)?,
            Self::Delete => cats_storage::lifecycle_volume::command_delete_already_unowned_receipt_digest_from_closed_receipt(receipt)?,
        })
    }
}

fn disposition_inputs_from_stored(
    stored: &[AtomicStoredVolumeDisposition],
) -> Vec<AtomicVolumeDispositionInput> {
    stored
        .iter()
        .map(|stored| match stored {
            AtomicStoredVolumeDisposition::NormallyReleased { release } => {
                AtomicVolumeDispositionInput::OwnedRelease {
                    release: CommandNormalReleaseInput {
                        durability: release.receipt.durability.clone(),
                        transition_id: release.receipt.request.transition_id.clone(),
                    },
                }
            }
            AtomicStoredVolumeDisposition::AlreadyUnowned { receipt } => {
                AtomicVolumeDispositionInput::AlreadyUnowned {
                    volume: receipt.receipt.volume.clone(),
                    expected_epoch: receipt.receipt.expected_epoch,
                    expected_head: receipt.receipt.expected_head.clone(),
                }
            }
        })
        .collect()
}

fn validate_stored_disposition_set(
    scope: &LifecycleVolumeCommandScope,
    identities: &[LifecycleVolumeIdentity],
    inputs: &[AtomicVolumeDispositionInput],
    stored: &[AtomicStoredVolumeDisposition],
    receipt_use: StoredDispositionUse,
) -> Result<()> {
    anyhow::ensure!(
        identities.len() == inputs.len() && inputs.len() == stored.len(),
        "Volume disposition receipt set is incomplete"
    );
    for ((identity, input), stored) in identities.iter().zip(inputs).zip(stored) {
        anyhow::ensure!(
            input.identity() == *identity && stored.identity() == *identity,
            "stored Volume disposition changed or reordered a command slot"
        );
        match (input, stored) {
            (
                AtomicVolumeDispositionInput::OwnedRelease { release },
                AtomicStoredVolumeDisposition::NormallyReleased { release: stored },
            ) => validate_stored_release(scope, &release.durability.volume, release, stored)?,
            (
                AtomicVolumeDispositionInput::AlreadyUnowned {
                    volume,
                    expected_epoch,
                    expected_head,
                },
                AtomicStoredVolumeDisposition::AlreadyUnowned { receipt: stored },
            ) => validate_stored_already_unowned(
                scope,
                volume,
                *expected_epoch,
                expected_head,
                stored,
                receipt_use,
            )?,
            _ => anyhow::bail!("stored Volume disposition selected another authority branch"),
        }
    }
    Ok(())
}

fn validate_stored_already_unowned(
    scope: &LifecycleVolumeCommandScope,
    identity: &LifecycleVolumeIdentity,
    expected_epoch: FenceEpoch,
    expected_head: &RemoteHead,
    stored: &AtomicStoredAlreadyUnownedReceipt,
    receipt_use: StoredDispositionUse,
) -> Result<()> {
    let receipt = &stored.receipt;
    anyhow::ensure!(
        receipt.scope == *scope
            && receipt.volume == *identity
            && receipt.expected_epoch == expected_epoch
            && receipt.expected_head == *expected_head
            && remote_head_is_valid(expected_head),
        "already-Unowned receipt changed its exact authority tuple"
    );
    if let AlreadyUnownedProvenance::NormalRelease {
        receipt: prior,
        receipt_digest,
    } = &receipt.provenance
    {
        validate_normal_release_receipt_self(identity, prior)?;
        anyhow::ensure!(
            prior.result.resulting_epoch == receipt.expected_epoch
                && prior.result.resulting_head == receipt.expected_head
                && *receipt_digest
                    == cats_storage::lifecycle_volume::command_normal_release_receipt_digest_from_closed_receipt(prior.as_ref())?,
            "already-Unowned prior release provenance digest is not canonical"
        );
    }
    anyhow::ensure!(
        stored.receipt_digest == receipt_use.already_unowned_receipt_digest(receipt)?,
        "already-Unowned receipt digest uses another command domain"
    );
    Ok(())
}

fn validate_normal_release_receipt_self(
    identity: &LifecycleVolumeIdentity,
    receipt: &CommandNormalReleaseReceipt,
) -> Result<()> {
    let target = &receipt.durability.volume;
    anyhow::ensure!(
        target.identity() == *identity
            && receipt.request.volume_id == identity.volume_id
            && receipt.request.attachment_id == target.attachment_id
            && receipt.request.expected_epoch == target.attachment_epoch
            && receipt.result.volume_id == identity.volume_id
            && receipt.result.transition_id == receipt.request.transition_id
            && receipt.result.released_attachment_id == target.attachment_id
            && receipt.result.resulting_head == receipt.durability.remote_head
            && receipt.result.resulting_epoch == next_epoch(target.attachment_epoch)?,
        "already-Unowned provenance contains a mismatched prior normal release"
    );
    validate_converged_durability(&receipt.durability)
}

fn validate_stored_release(
    scope: &LifecycleVolumeCommandScope,
    target: &LifecycleVolumeTarget,
    input: &CommandNormalReleaseInput,
    stored: &AtomicStoredNormalReleaseReceipt,
) -> Result<()> {
    let receipt = &stored.receipt;
    anyhow::ensure!(
        receipt.durability == input.durability
            && receipt.durability.scope == *scope
            && receipt.durability.volume == *target
            && receipt.request.volume_id == target.volume_id
            && receipt.request.transition_id == input.transition_id
            && receipt.request.attachment_id == target.attachment_id
            && receipt.request.expected_epoch == target.attachment_epoch
            && receipt.result.volume_id == target.volume_id
            && receipt.result.transition_id == input.transition_id
            && receipt.result.released_attachment_id == target.attachment_id
            && receipt.result.resulting_head == input.durability.remote_head
            && receipt.result.resulting_epoch == next_epoch(target.attachment_epoch)?,
        "normal release receipt does not close its exact request/result pair"
    );
    validate_converged_durability(&receipt.durability)?;
    anyhow::ensure!(
        stored.receipt_digest
            == cats_storage::lifecycle_volume::command_normal_release_receipt_digest_from_closed_receipt(receipt)?,
        "normal release receipt digest is not the frozen command-scoped digest"
    );
    Ok(())
}

fn next_epoch(epoch: FenceEpoch) -> Result<FenceEpoch> {
    let next = epoch
        .get()
        .checked_add(1)
        .context("Volume attachment epoch is exhausted")?;
    FenceEpoch::new(next).context("construct next Volume attachment epoch")
}

fn validate_root_cleanup_request(
    command: &LifecycleCommandEnvelope,
    request: &AtomicRootLineageCleanupRequest,
) -> Result<()> {
    validate_local_recovery_authority(command, &request.local_recovery_authority)?;
    validate_delete_command_set(command, &request.command)?;
    validate_post_stop_attestation(command, &request.post_stop_inventory_attestation)?;
    match &request.begin {
        AtomicDeleteBeginReceipt::NormallyDeleting { dispositions } => {
            let inputs = disposition_inputs_from_stored(dispositions);
            validate_delete_normal_disposition_inputs(command, &request.command, &inputs)?;
            validate_stored_disposition_set(
                &request.command.scope,
                &complete_delete_config_order(&request.command)?,
                &inputs,
                dispositions,
                StoredDispositionUse::Delete,
            )?;
        }
        AtomicDeleteBeginReceipt::DisposableRootDeleting {
            persistent_dispositions,
            root_durability,
            authorization_id: _,
            authorization_consumed_receipt_digest: _,
        } => {
            let inputs = disposition_inputs_from_stored(persistent_dispositions);
            validate_persistent_disposition_inputs(command, &inputs)?;
            validate_stored_disposition_set(
                &request.command.scope,
                &request.command.persistent_volumes,
                &inputs,
                persistent_dispositions,
                StoredDispositionUse::Delete,
            )?;
            anyhow::ensure!(
                root_durability.scope == request.command.scope
                    && root_durability.volume.identity() == request.command.root_disposition.root,
                "disposable Root cleanup changed its exact local-tail lineage"
            );
            validate_disposable_root_durability(root_durability)?;
        }
    }
    let authority = root_cleanup_authority(request)?;
    match authority {
        RootCleanupAuthority::Owned { target, .. } => anyhow::ensure!(
            target.identity() == request.command.root_disposition.root,
            "Root cleanup authority changed its configured identity"
        ),
        RootCleanupAuthority::AlreadyUnowned { volume, .. } => anyhow::ensure!(
            volume == request.command.root_disposition.root,
            "already-Unowned Root cleanup changed its configured identity"
        ),
    }
    Ok(())
}

fn validate_root_lineage_absence(
    request: &AtomicRootLineageCleanupRequest,
    absence: &AtomicRootLineageAbsenceReceipt,
) -> Result<()> {
    let root = &request.command.root_disposition.root;
    match (root_cleanup_authority(request)?, absence) {
        (
            RootCleanupAuthority::Owned {
                target,
                receipt_digest,
            },
            AtomicRootLineageAbsenceReceipt::RemovedOwned {
                volume_id,
                disk_id,
                previous_attachment_id,
                previous_attachment_epoch,
                authority_receipt_digest,
                ..
            },
        ) => anyhow::ensure!(
            volume_id == &root.volume_id
                && disk_id == &root.disk_id
                && previous_attachment_id == &target.attachment_id
                && *previous_attachment_epoch == target.attachment_epoch
                && authority_receipt_digest == &receipt_digest,
            "owned Root lineage absence does not bind the exact fenced attachment"
        ),
        (
            RootCleanupAuthority::AlreadyUnowned {
                volume,
                expected_epoch,
                expected_head,
                receipt_digest,
            },
            AtomicRootLineageAbsenceReceipt::AlreadyUnowned {
                volume_id,
                disk_id,
                expected_epoch: absent_epoch,
                expected_head: absent_head,
                authority_receipt_digest,
                ..
            },
        ) => anyhow::ensure!(
            volume_id == &volume.volume_id
                && disk_id == &volume.disk_id
                && *absent_epoch == expected_epoch
                && absent_head == &expected_head
                && authority_receipt_digest == &receipt_digest,
            "already-Unowned Root absence changed its exact authority tuple"
        ),
        _ => anyhow::bail!("Root lineage absence selected another authority branch"),
    }
    Ok(())
}

fn validate_completion_request(
    command: &LifecycleCommandEnvelope,
    request: &AtomicDeleteCompletionRequest,
) -> Result<()> {
    validate_local_recovery_authority(command, &request.local_recovery_authority)?;
    validate_delete_command_set(command, &request.expected_command)?;
    validate_root_cleanup_request(
        command,
        &AtomicRootLineageCleanupRequest {
            command: request.expected_command.clone(),
            begin: request.expected_begin.clone(),
            post_stop_inventory_attestation: request.post_stop_inventory_attestation.clone(),
            expected_runtime_incarnation: request.expected_runtime_incarnation.clone(),
            local_recovery_authority: request.local_recovery_authority.clone(),
        },
    )?;
    anyhow::ensure!(
        request.operation_id == command.operation_id
            && request.request_fingerprint == command.request_fingerprint
            && request.volume_id == request.expected_command.root_disposition.root.volume_id
            && request.delete_id == request.expected_command.root_disposition.delete_id,
        "Delete completion discovery changed its exact ledger identity"
    );
    Ok(())
}

fn validate_delete_completion(
    request: &AtomicDeleteCompletionRequest,
    local_absence: &AtomicRootLineageAbsenceReceipt,
    evidence: &AtomicDeleteCompletionEvidence,
) -> Result<()> {
    anyhow::ensure!(
        evidence.receipt.command == request.expected_command,
        "Delete completion ledger belongs to another command"
    );
    let canonical_completion_digest =
        canonical_digest(DELETE_COMPLETION_DIGEST_DOMAIN, &evidence.receipt)?;
    anyhow::ensure!(
        evidence.receipt_digest == canonical_completion_digest,
        "Delete completion ledger digest is not canonical"
    );
    let root = &request.expected_command.root_disposition.root;
    match (&request.expected_begin, &evidence.receipt.root_authority) {
        (AtomicDeleteBeginReceipt::NormallyDeleting { dispositions }, root_authority) => {
            let stored_root = dispositions
                .iter()
                .find(|stored| stored.identity() == *root)
                .context("normal Delete completion lacks a Root disposition")?;
            match (stored_root, root_authority, local_absence) {
                (
                    AtomicStoredVolumeDisposition::NormallyReleased { release: stored },
                    CommandRootDeleteAuthorityReceipt::NormalRelease(release),
                    AtomicRootLineageAbsenceReceipt::RemovedOwned {
                        authority_receipt_digest,
                        ..
                    },
                ) => {
                    anyhow::ensure!(
                        release == &stored.receipt
                            && authority_receipt_digest == &stored.receipt_digest,
                        "normal Delete completion changed the Root release authority"
                    );
                    let nested = cats_storage::lifecycle_volume::command_normal_release_receipt_digest_from_delete_completion(
                        &request.expected_command,
                        &evidence.receipt,
                    )?;
                    anyhow::ensure!(nested == stored.receipt_digest);
                }
                (
                    AtomicStoredVolumeDisposition::AlreadyUnowned { receipt: stored },
                    CommandRootDeleteAuthorityReceipt::AlreadyUnowned(receipt),
                    AtomicRootLineageAbsenceReceipt::AlreadyUnowned {
                        authority_receipt_digest,
                        ..
                    },
                ) => {
                    anyhow::ensure!(
                        receipt == &stored.receipt
                            && authority_receipt_digest == &stored.receipt_digest,
                        "already-Unowned Delete completion changed its Root authority"
                    );
                    let nested = cats_storage::lifecycle_volume::command_delete_already_unowned_receipt_digest_from_delete_completion(
                        &request.expected_command,
                        &evidence.receipt,
                    )?;
                    anyhow::ensure!(nested == stored.receipt_digest);
                }
                _ => anyhow::bail!(
                    "normal Delete completion selected another Root disposition authority"
                ),
            }
            let expected =
                cats_storage::lifecycle_volume::command_delete_completion_receipt_digest(
                    &request.expected_command,
                    None,
                    None,
                    &evidence.receipt,
                )
                .context("validate normal Root command delete-completion chain")?;
            anyhow::ensure!(
                expected == evidence.receipt_digest,
                "normal Delete completion helper and signed ledger digest differ"
            );
        }
        (
            AtomicDeleteBeginReceipt::DisposableRootDeleting {
                authorization_id,
                authorization_consumed_receipt_digest,
                root_durability,
                ..
            },
            CommandRootDeleteAuthorityReceipt::DisposableAuthorizationConsumed(consumed),
        ) => {
            anyhow::ensure!(
                consumed.command == request.expected_command
                    && &consumed.authorization_id == authorization_id
                    && consumed.receipt.authorization_id == *authorization_id
                    && consumed.receipt.volume_id == root.volume_id
                    && consumed.receipt.disk_id == root.disk_id
                    && consumed.receipt.cat_id == request.expected_command.scope.cat_id
                    && consumed.receipt.delete_id
                        == request.expected_command.root_disposition.delete_id
                    && consumed.receipt.prior_attachment_id == root_durability.volume.attachment_id
                    && consumed.receipt.resulting_epoch
                        == next_epoch(root_durability.volume.attachment_epoch)?
                    && local_absence.authority_receipt_digest()
                        == authorization_consumed_receipt_digest
                    && canonical_digest(DISPOSABLE_CONSUMED_DIGEST_DOMAIN, consumed)?
                        == *authorization_consumed_receipt_digest,
                "disposable Delete completion changed its consumed authorization chain"
            );
            let cats_api::runtime_reconciliation::DeleteCompletionReceipt::DisposableRoot {
                disk_id,
                volume_id,
                delete_id,
                authorization_id: completion_authorization_id,
                prior_attachment_id,
                deleting_epoch,
                deleting_head,
                ..
            } = &evidence.receipt.completion
            else {
                anyhow::bail!("disposable Root ledger contains a normal completion")
            };
            anyhow::ensure!(
                disk_id == &root.disk_id
                    && volume_id == &root.volume_id
                    && delete_id == &request.expected_command.root_disposition.delete_id
                    && completion_authorization_id == authorization_id
                    && prior_attachment_id == &root_durability.volume.attachment_id
                    && deleting_epoch == &consumed.receipt.resulting_epoch
                    && deleting_head == &consumed.receipt.resulting_head,
                "disposable Root generic completion differs from its consumed receipt"
            );
        }
        _ => anyhow::bail!("Delete completion ledger selected another Root authority branch"),
    }
    Ok(())
}

fn validate_delete_finalization_request(
    command: &LifecycleCommandEnvelope,
    request: &AtomicDeleteFinalizationRequest,
) -> Result<()> {
    validate_local_recovery_authority(command, &request.local_recovery_authority)?;
    validate_delete_command_set(command, &request.command)?;
    let cleanup = AtomicRootLineageCleanupRequest {
        command: request.command.clone(),
        begin: request.begin.clone(),
        post_stop_inventory_attestation: request.post_stop_inventory_attestation.clone(),
        expected_runtime_incarnation: request.expected_runtime_incarnation.clone(),
        local_recovery_authority: request.local_recovery_authority.clone(),
    };
    validate_root_cleanup_request(command, &cleanup)?;
    validate_root_lineage_absence(&cleanup, &request.root_lineage_absence)?;
    let completion_request = AtomicDeleteCompletionRequest {
        operation_id: command.operation_id.clone(),
        request_fingerprint: command.request_fingerprint.clone(),
        expected_runtime_incarnation: request.expected_runtime_incarnation.clone(),
        volume_id: request.command.root_disposition.root.volume_id.clone(),
        delete_id: request.command.root_disposition.delete_id.clone(),
        expected_command: request.command.clone(),
        expected_begin: request.begin.clone(),
        post_stop_inventory_attestation: request.post_stop_inventory_attestation.clone(),
        local_recovery_authority: request.local_recovery_authority.clone(),
    };
    validate_delete_completion(
        &completion_request,
        &request.root_lineage_absence,
        &request.completion,
    )
}

fn completed_dispositions(
    request: &AtomicDeleteFinalizationRequest,
) -> Result<Vec<CompletedVolumeDisposition>> {
    let persistent = persistent_stored_dispositions(&request.begin);
    let mut persistent_by_volume = persistent
        .into_iter()
        .map(|stored| (stored.identity().volume_id, stored))
        .collect::<BTreeMap<_, _>>();
    let mut dispositions = Vec::with_capacity(1 + persistent_by_volume.len());
    for volume in complete_delete_config_order(&request.command)? {
        if volume.disk_role == DiskRole::Persistent {
            let stored = persistent_by_volume
                .remove(&volume.volume_id)
                .context("Deleted result lacks a Persistent disposition receipt")?;
            match stored {
                AtomicStoredVolumeDisposition::NormallyReleased { release } => {
                    dispositions.push(CompletedVolumeDisposition::PersistentRetainedDetached {
                        volume: Box::new(volume_terminal_receipt(release)?),
                        normal_release_receipt_digest: release.receipt_digest.clone(),
                    });
                }
                AtomicStoredVolumeDisposition::AlreadyUnowned { receipt } => {
                    dispositions.push(CompletedVolumeDisposition::PersistentAlreadyDetached {
                        volume_id: receipt.receipt.volume.volume_id.clone(),
                        disk_id: receipt.receipt.volume.disk_id.clone(),
                        already_unowned_receipt_digest: receipt.receipt_digest.clone(),
                    });
                }
            }
            continue;
        }
        match &request.begin {
            AtomicDeleteBeginReceipt::NormallyDeleting {
                dispositions: stored,
            } => {
                let root = stored
                    .iter()
                    .find(|stored| stored.identity() == volume)
                    .context("Deleted result lacks its Root disposition")?;
                match root {
                    AtomicStoredVolumeDisposition::NormallyReleased { release } => {
                        dispositions.push(CompletedVolumeDisposition::RootNormallyDeleted {
                            volume: Box::new(volume_terminal_receipt(release)?),
                            delete_completion_receipt_digest: request
                                .completion
                                .receipt_digest
                                .clone(),
                        });
                    }
                    AtomicStoredVolumeDisposition::AlreadyUnowned { receipt } => {
                        dispositions.push(CompletedVolumeDisposition::RootAlreadyUnownedDeleted {
                            volume_id: receipt.receipt.volume.volume_id.clone(),
                            disk_id: receipt.receipt.volume.disk_id.clone(),
                            already_unowned_receipt_digest: receipt.receipt_digest.clone(),
                            delete_completion_receipt_digest: request
                                .completion
                                .receipt_digest
                                .clone(),
                        });
                    }
                }
            }
            AtomicDeleteBeginReceipt::DisposableRootDeleting {
                authorization_id,
                authorization_consumed_receipt_digest,
                ..
            } => {
                let AtomicRootLineageAbsenceReceipt::RemovedOwned {
                    previous_attachment_id,
                    previous_attachment_epoch,
                    local_lineage_absence_digest,
                    ..
                } = &request.root_lineage_absence
                else {
                    anyhow::bail!("disposable Root lacks its owned-lineage absence receipt")
                };
                dispositions.push(CompletedVolumeDisposition::RootDisposableTailDeleted {
                    volume_id: volume.volume_id.clone(),
                    disk_id: volume.disk_id.clone(),
                    previous_attachment_id: previous_attachment_id.clone(),
                    previous_attachment_epoch: *previous_attachment_epoch,
                    disposable_authorization_id: authorization_id.clone(),
                    authorization_consumed_receipt_digest: authorization_consumed_receipt_digest
                        .clone(),
                    delete_completion_receipt_digest: request.completion.receipt_digest.clone(),
                    local_lineage_absence_digest: local_lineage_absence_digest.clone(),
                });
            }
        }
    }
    anyhow::ensure!(
        persistent_by_volume.is_empty(),
        "Deleted result has an extra Persistent release receipt"
    );
    Ok(dispositions)
}

fn persistent_stored_dispositions(
    begin: &AtomicDeleteBeginReceipt,
) -> Vec<&AtomicStoredVolumeDisposition> {
    match begin {
        AtomicDeleteBeginReceipt::NormallyDeleting { dispositions } => dispositions
            .iter()
            .filter(|disposition| disposition.identity().disk_role == DiskRole::Persistent)
            .collect(),
        AtomicDeleteBeginReceipt::DisposableRootDeleting {
            persistent_dispositions,
            ..
        } => persistent_dispositions.iter().collect(),
    }
}

fn complete_delete_config_order(
    command: &DeleteCommandVolumeSet,
) -> Result<Vec<LifecycleVolumeIdentity>> {
    let mut volumes = Vec::with_capacity(1 + command.persistent_volumes.len());
    volumes.push(command.root_disposition.root.clone());
    volumes.extend(command.persistent_volumes.iter().cloned());
    volumes.sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
    anyhow::ensure!(
        volumes
            .windows(2)
            .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "Delete result Volume identities are not unique"
    );
    Ok(volumes)
}

fn cold_terminal_dispositions(
    dispositions: &[AtomicStoredVolumeDisposition],
) -> Result<Vec<ColdVolumeDisposition>> {
    dispositions
        .iter()
        .map(|disposition| match disposition {
            AtomicStoredVolumeDisposition::NormallyReleased { release } => {
                Ok(ColdVolumeDisposition::NormallyReleased {
                    volume: Box::new(volume_terminal_receipt(release)?),
                    normal_release_receipt_digest: release.receipt_digest.clone(),
                })
            }
            AtomicStoredVolumeDisposition::AlreadyUnowned { receipt } => {
                Ok(ColdVolumeDisposition::AlreadyUnowned {
                    volume_id: receipt.receipt.volume.volume_id.clone(),
                    disk_id: receipt.receipt.volume.disk_id.clone(),
                    disk_role: receipt.receipt.volume.disk_role,
                    unowned_epoch: receipt.receipt.expected_epoch,
                    remote_head: receipt.receipt.expected_head.clone(),
                    already_unowned_receipt_digest: receipt.receipt_digest.clone(),
                })
            }
        })
        .collect()
}

fn volume_terminal_receipt(
    stored: &AtomicStoredNormalReleaseReceipt,
) -> Result<VolumeTerminalReceipt> {
    validate_converged_durability(&stored.receipt.durability)?;
    let proof = &stored.receipt.durability;
    Ok(VolumeTerminalReceipt {
        volume_id: proof.volume.volume_id.clone(),
        disk_id: proof.volume.disk_id.clone(),
        disk_role: proof.volume.disk_role,
        attachment_id: proof.volume.attachment_id.clone(),
        attachment_epoch: proof.volume.attachment_epoch,
        local_durable_generation: proof.local_durable_generation,
        remote_durable_generation: proof.remote_durable_generation,
        authority_receipt_digest: Some(stored.receipt_digest.clone()),
    })
}

fn validate_delete_dispositions(
    command: &LifecycleCommandEnvelope,
    spec: &cats_api::runtime_lifecycle::DeleteSpec,
) -> Result<()> {
    anyhow::ensure!(
        spec.volume_dispositions.len() == command.runtime_config.volumes.len(),
        "Delete request does not contain the complete immutable volume set"
    );
    for (disposition, volume) in spec
        .volume_dispositions
        .iter()
        .zip(&command.runtime_config.volumes)
    {
        let valid = match (disposition, volume.disk_role) {
            (
                RequestedVolumeDisposition::DiscardWithCat {
                    volume_id,
                    disk_id,
                    disk_role: DiskRole::Root,
                },
                DiskRole::Root,
            ) => volume_id == &volume.volume_id && disk_id == &volume.disk_id,
            (
                RequestedVolumeDisposition::RetainDetached {
                    volume_id,
                    disk_id,
                    disk_role: DiskRole::Persistent,
                },
                DiskRole::Persistent,
            ) => volume_id == &volume.volume_id && disk_id == &volume.disk_id,
            _ => false,
        };
        anyhow::ensure!(
            valid,
            "Delete disposition changed a volume role or identity"
        );
    }
    Ok(())
}

fn validate_retained_volume_receipts(
    command: &LifecycleCommandEnvelope,
    receipts: &[VolumeTerminalReceipt],
) -> Result<()> {
    anyhow::ensure!(
        receipts.len() <= command.runtime_config.volumes.len()
            && receipts
                .windows(2)
                .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "retained Volume receipts are not a sorted immutable-config subset"
    );
    for receipt in receipts {
        let index = command
            .runtime_config
            .volumes
            .binary_search_by(|volume| volume.volume_id.cmp(&receipt.volume_id))
            .map_err(|_| anyhow::anyhow!("retained Volume is absent from immutable config"))?;
        let config = &command.runtime_config.volumes[index];
        anyhow::ensure!(
            receipt.disk_id == config.disk_id
                && receipt.disk_role == config.disk_role
                && receipt.attachment_epoch.get() > 0
                && receipt.remote_durable_generation <= receipt.local_durable_generation,
            "retained Volume receipt is not a closed config lineage"
        );
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<Sha256Digest> {
    let value = serde_json::to_value(value).context("encode receipt for canonical digest")?;
    let canonical = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(canonical);
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

fn stop_fence_payload(command: &LifecycleCommandEnvelope) -> Result<ExactBytes> {
    #[derive(Serialize)]
    struct FenceBinding<'a> {
        version: ContractVersion,
        operation_id: &'a Id,
        request_fingerprint: &'a Sha256Digest,
        cat_id: &'a Id,
        node_id: &'a Id,
    }
    let value = serde_json::to_value(FenceBinding {
        version: ContractVersion::V1,
        operation_id: &command.operation_id,
        request_fingerprint: &command.request_fingerprint,
        cat_id: &command.cat_id,
        node_id: &command.node_id,
    })
    .context("encode Cold/Delete Stop-fence binding")?;
    let canonical = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    let mut bytes = Vec::with_capacity(STOP_FENCE_DOMAIN.len() + 1 + canonical.len());
    bytes.extend_from_slice(STOP_FENCE_DOMAIN);
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(ExactBytes::new(bytes))
}

fn encode_step(
    command: &LifecycleCommandEnvelope,
    state: ColdDeleteStepState,
) -> Result<ExecutionStep> {
    let payload = ColdDeleteStepPayload {
        version: ContractVersion::V1,
        operation_id: command.operation_id.clone(),
        request_fingerprint: command.request_fingerprint.clone(),
        state,
    };
    validate_step_payload(command, &payload)?;
    let value = serde_json::to_value(&payload).context("encode Cold/Delete durable step")?;
    let bytes = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= STEP_MAX_BYTES,
        "Cold/Delete durable step exceeds its closed byte bound"
    );
    Ok(ExecutionStep {
        name: Id::new(STEP_NAME).context("Cold/Delete step name is invalid")?,
        recovery_payload: ExactBytes::new(bytes),
    })
}

fn decode_step(
    command: &LifecycleCommandEnvelope,
    step: &ExecutionStep,
) -> Result<ColdDeleteStepPayload> {
    anyhow::ensure!(
        step.name.as_str() == STEP_NAME
            && !step.recovery_payload.as_slice().is_empty()
            && step.recovery_payload.as_slice().len() <= STEP_MAX_BYTES,
        "Cold/Delete received another handler's step or an invalid byte length"
    );
    let value: serde_json::Value = serde_json::from_slice(step.recovery_payload.as_slice())
        .context("decode Cold/Delete durable step JSON")?;
    anyhow::ensure!(
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&value)
            == step.recovery_payload.as_slice(),
        "Cold/Delete durable step is not canonical JSON"
    );
    let payload: ColdDeleteStepPayload =
        serde_json::from_value(value).context("decode Cold/Delete durable step")?;
    validate_step_payload(command, &payload)?;
    Ok(payload)
}

fn validate_step_payload(
    command: &LifecycleCommandEnvelope,
    payload: &ColdDeleteStepPayload,
) -> Result<()> {
    anyhow::ensure!(
        payload.version == ContractVersion::V1
            && payload.operation_id == command.operation_id
            && payload.request_fingerprint == command.request_fingerprint,
        "Cold/Delete durable step belongs to another command"
    );
    match (&command.command, &payload.state) {
        (LifecycleCommand::Cold(_), ColdDeleteStepState::BindSuspendWarmPredecessor)
        | (LifecycleCommand::Delete(_), ColdDeleteStepState::BindSuspendWarmPredecessor)
        | (LifecycleCommand::Cold(_), ColdDeleteStepState::StrongStop)
        | (LifecycleCommand::Delete(_), ColdDeleteStepState::StrongStop) => Ok(()),
        (
            LifecycleCommand::Cold(_) | LifecycleCommand::Delete(_),
            ColdDeleteStepState::StrongStopWithOwnedPredecessor { carrier },
        ) => validate_owned_predecessor_carrier_structure(command, carrier),
        (
            LifecycleCommand::Cold(spec),
            ColdDeleteStepState::ColdConverge {
                strong_stop,
                request,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            validate_convergence_request(
                command,
                request,
                &command.runtime_config.volumes,
                local_recovery_runtime_incarnation(&request.local_recovery_authority, strong_stop)
                    .as_ref(),
                &request.local_recovery_authority,
                spec.convergence_deadline_unix_ms,
                "cold",
            )
        }
        (
            LifecycleCommand::Cold(_),
            ColdDeleteStepState::ColdForceFull {
                strong_stop,
                command: volume_set,
                dispositions,
                local_recovery_authority,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            validate_local_recovery_authority(command, local_recovery_authority)?;
            validate_cold_release_plan(command, volume_set, dispositions)
        }
        (
            LifecycleCommand::Cold(_),
            ColdDeleteStepState::ColdRelease {
                strong_stop,
                request,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            validate_cold_release_request(command, strong_stop, request)
        }
        (
            LifecycleCommand::Cold(_),
            ColdDeleteStepState::ColdPrepareWarmCleanup {
                strong_stop,
                finalization,
                request,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            anyhow::ensure!(
                finalization.expected_runtime_incarnation
                    == local_recovery_runtime_incarnation(
                        &finalization.local_recovery_authority,
                        strong_stop,
                    ),
                "Cold Warm-cleanup step changed its stopped runtime incarnation"
            );
            validate_cold_finalization_request(command, finalization)?;
            validate_warm_cleanup_request_binding(command, request)
        }
        (
            LifecycleCommand::Cold(_),
            ColdDeleteStepState::ColdRemoveWarmCleanup {
                strong_stop,
                finalization,
                authority,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            anyhow::ensure!(
                finalization.expected_runtime_incarnation
                    == local_recovery_runtime_incarnation(
                        &finalization.local_recovery_authority,
                        strong_stop,
                    ),
                "Cold Warm-removal step changed its stopped runtime incarnation"
            );
            validate_cold_finalization_request(command, finalization)?;
            validate_warm_cleanup_authority_binding(authority)
        }
        (
            LifecycleCommand::Cold(_),
            ColdDeleteStepState::ColdFinalize {
                strong_stop,
                request,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            anyhow::ensure!(
                request.expected_runtime_incarnation
                    == local_recovery_runtime_incarnation(
                        &request.local_recovery_authority,
                        strong_stop,
                    ),
                "Cold finalization step changed its stopped runtime incarnation"
            );
            validate_cold_finalization_request(command, request)
        }
        (
            LifecycleCommand::Delete(spec),
            ColdDeleteStepState::DeleteConvergePersistent {
                strong_stop,
                request,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            let persistent = command
                .runtime_config
                .volumes
                .iter()
                .filter(|volume| volume.disk_role == DiskRole::Persistent)
                .cloned()
                .collect::<Vec<_>>();
            validate_convergence_request(
                command,
                request,
                &persistent,
                local_recovery_runtime_incarnation(&request.local_recovery_authority, strong_stop)
                    .as_ref(),
                &request.local_recovery_authority,
                spec.convergence_deadline_unix_ms,
                "delete-persistent",
            )
        }
        (
            LifecycleCommand::Delete(_),
            ColdDeleteStepState::DeletePrepareWarmCleanup {
                strong_stop,
                finalization,
                request,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            anyhow::ensure!(
                finalization.expected_runtime_incarnation
                    == local_recovery_runtime_incarnation(
                        &finalization.local_recovery_authority,
                        strong_stop,
                    ),
                "Delete Warm-cleanup step changed its stopped runtime incarnation"
            );
            validate_delete_finalization_request(command, finalization)?;
            validate_warm_cleanup_request_binding(command, request)
        }
        (
            LifecycleCommand::Delete(_),
            ColdDeleteStepState::DeleteRemoveWarmCleanup {
                strong_stop,
                finalization,
                authority,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            anyhow::ensure!(
                finalization.expected_runtime_incarnation
                    == local_recovery_runtime_incarnation(
                        &finalization.local_recovery_authority,
                        strong_stop,
                    ),
                "Delete Warm-removal step changed its stopped runtime incarnation"
            );
            validate_delete_finalization_request(command, finalization)?;
            validate_warm_cleanup_authority_binding(authority)
        }
        (
            LifecycleCommand::Delete(_),
            ColdDeleteStepState::DeleteInspectRoot {
                strong_stop,
                persistent_dispositions,
                request,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            validate_persistent_disposition_inputs(command, persistent_dispositions)?;
            validate_root_inspection_request(
                command,
                request,
                local_recovery_runtime_incarnation(&request.local_recovery_authority, strong_stop)
                    .as_ref(),
            )
        }
        (
            LifecycleCommand::Delete(_),
            ColdDeleteStepState::DeleteForceFull {
                strong_stop,
                plan,
                local_recovery_authority,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            validate_local_recovery_authority(command, local_recovery_authority)?;
            validate_delete_begin_plan(command, plan)
        }
        (
            LifecycleCommand::Delete(_),
            ColdDeleteStepState::DeleteBegin {
                strong_stop,
                request,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            validate_delete_begin_request(command, strong_stop, request)
        }
        (
            LifecycleCommand::Delete(_),
            ColdDeleteStepState::DeleteCleanupRoot {
                strong_stop,
                request,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            anyhow::ensure!(
                request.expected_runtime_incarnation
                    == local_recovery_runtime_incarnation(
                        &request.local_recovery_authority,
                        strong_stop,
                    ),
                "Delete completion step changed its stopped runtime incarnation"
            );
            anyhow::ensure!(
                request.expected_runtime_incarnation
                    == local_recovery_runtime_incarnation(
                        &request.local_recovery_authority,
                        strong_stop,
                    ),
                "Delete Root cleanup step changed its stopped runtime incarnation"
            );
            validate_root_cleanup_request(command, request)
        }
        (
            LifecycleCommand::Delete(_),
            ColdDeleteStepState::DeleteAwaitCompletion {
                strong_stop,
                begin,
                root_lineage_absence,
                request,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            anyhow::ensure!(
                begin == &request.expected_begin,
                "Delete completion step changed its begin receipt"
            );
            validate_completion_request(command, request)?;
            validate_root_lineage_absence(
                &AtomicRootLineageCleanupRequest {
                    command: request.expected_command.clone(),
                    begin: begin.clone(),
                    post_stop_inventory_attestation: request
                        .post_stop_inventory_attestation
                        .clone(),
                    expected_runtime_incarnation: request.expected_runtime_incarnation.clone(),
                    local_recovery_authority: request.local_recovery_authority.clone(),
                },
                root_lineage_absence,
            )
        }
        (
            LifecycleCommand::Delete(_),
            ColdDeleteStepState::DeleteFinalize {
                strong_stop,
                request,
            },
        ) => {
            validate_strong_stop(command, strong_stop)?;
            anyhow::ensure!(
                request.execution_absence == strong_stop.execution_absence,
                "Delete finalization changed its strong-Stop absence proof"
            );
            anyhow::ensure!(
                request.expected_runtime_incarnation
                    == local_recovery_runtime_incarnation(
                        &request.local_recovery_authority,
                        strong_stop,
                    ),
                "Delete finalization step changed its stopped runtime incarnation"
            );
            validate_delete_finalization_request(command, request)
        }
        _ => anyhow::bail!("Cold/Delete durable phase is invalid for this command"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use cats_api::runtime_lifecycle::{
        ColdSpec, DeleteSpec, ImmutableRuntimeConfig, LifecyclePredecessor, PlacementIdentity,
        RuntimeNetworkConfig, RuntimeVolumeGuestBinding, TerminalResultKind,
    };
    use cats_api::runtime_reconciliation::{
        AsciiText, BeginDeleteRequest, DeleteCompletionReceipt, Durability, Epoch, HostPath,
        Ipv4Address, IsolatedIpv4Kind, MacAddress, NetworkConfig, NodeBootId, NormalAcquireRequest,
        NormalAcquireResult, ReleaseRequest, ReleaseResult, RuntimeLaunchArtifact,
        RuntimeLaunchIdentity, RuntimeNetworkIdentity, Sequence, SessionBinding, VmmBootProvenance,
    };

    use super::super::suspend_warm::{
        SameNodeOwnedPredecessorSource, SameNodeOwnedPredecessorVolume,
    };
    use super::*;

    #[derive(Default)]
    struct ScriptedPort {
        convergence:
            Mutex<VecDeque<Result<AtomicColdDeleteAttempt<AtomicVolumeConvergenceReceipt>>>>,
        roots: Mutex<VecDeque<Result<AtomicColdDeleteAttempt<AtomicDeleteRootInspection>>>>,
        cold_releases: Mutex<VecDeque<Result<AtomicColdReleaseAttempt>>>,
        delete_begins: Mutex<VecDeque<Result<AtomicDeleteBeginAttempt>>>,
        root_cleanups:
            Mutex<VecDeque<Result<AtomicColdDeleteAttempt<AtomicRootLineageAbsenceReceipt>>>>,
        completions:
            Mutex<VecDeque<Result<AtomicColdDeleteAttempt<AtomicDeleteCompletionEvidence>>>>,
        cold_finalizations: Mutex<VecDeque<Result<AtomicColdDeleteAttempt<Sha256Digest>>>>,
        delete_finalizations: Mutex<VecDeque<Result<AtomicColdDeleteAttempt<Sha256Digest>>>>,
        convergence_requests: Mutex<Vec<AtomicVolumeConvergenceRequest>>,
        root_requests: Mutex<Vec<AtomicDeleteRootInspectionRequest>>,
        cold_release_requests: Mutex<Vec<AtomicColdReleaseRequest>>,
        delete_begin_requests: Mutex<Vec<AtomicDeleteBeginRequest>>,
        cleanup_requests: Mutex<Vec<AtomicRootLineageCleanupRequest>>,
        completion_requests: Mutex<Vec<AtomicDeleteCompletionRequest>>,
        delete_finalization_requests: Mutex<Vec<AtomicDeleteFinalizationRequest>>,
    }

    impl AtomicColdDeletePort for ScriptedPort {
        fn inspect_or_converge(
            &self,
            _command: &LifecycleCommandEnvelope,
            request: &AtomicVolumeConvergenceRequest,
        ) -> Result<AtomicColdDeleteAttempt<AtomicVolumeConvergenceReceipt>> {
            self.convergence_requests
                .lock()
                .unwrap()
                .push(request.clone());
            pop(&self.convergence, "convergence")
        }

        fn inspect_delete_root(
            &self,
            _command: &LifecycleCommandEnvelope,
            request: &AtomicDeleteRootInspectionRequest,
        ) -> Result<AtomicColdDeleteAttempt<AtomicDeleteRootInspection>> {
            self.root_requests.lock().unwrap().push(request.clone());
            pop(&self.roots, "Root inspection")
        }

        fn inspect_or_release_cold(
            &self,
            _command: &LifecycleCommandEnvelope,
            request: &AtomicColdReleaseRequest,
        ) -> Result<AtomicColdReleaseAttempt> {
            self.cold_release_requests
                .lock()
                .unwrap()
                .push(request.clone());
            pop(&self.cold_releases, "Cold release")
        }

        fn inspect_or_begin_delete(
            &self,
            _command: &LifecycleCommandEnvelope,
            request: &AtomicDeleteBeginRequest,
        ) -> Result<AtomicDeleteBeginAttempt> {
            self.delete_begin_requests
                .lock()
                .unwrap()
                .push(request.clone());
            pop(&self.delete_begins, "Delete begin")
        }

        fn inspect_or_remove_root_lineage(
            &self,
            _command: &LifecycleCommandEnvelope,
            request: &AtomicRootLineageCleanupRequest,
        ) -> Result<AtomicColdDeleteAttempt<AtomicRootLineageAbsenceReceipt>> {
            self.cleanup_requests.lock().unwrap().push(request.clone());
            pop(&self.root_cleanups, "Root cleanup")
        }

        fn discover_delete_completion(
            &self,
            _command: &LifecycleCommandEnvelope,
            request: &AtomicDeleteCompletionRequest,
        ) -> Result<AtomicColdDeleteAttempt<AtomicDeleteCompletionEvidence>> {
            self.completion_requests
                .lock()
                .unwrap()
                .push(request.clone());
            pop(&self.completions, "Delete completion")
        }

        fn inspect_or_finalize_cold(
            &self,
            _command: &LifecycleCommandEnvelope,
            _request: &AtomicColdFinalizationRequest,
        ) -> Result<AtomicColdDeleteAttempt<Sha256Digest>> {
            pop(&self.cold_finalizations, "Cold finalization")
        }

        fn inspect_or_finalize_delete(
            &self,
            _command: &LifecycleCommandEnvelope,
            request: &AtomicDeleteFinalizationRequest,
        ) -> Result<AtomicColdDeleteAttempt<Sha256Digest>> {
            self.delete_finalization_requests
                .lock()
                .unwrap()
                .push(request.clone());
            pop(&self.delete_finalizations, "Delete finalization")
        }
    }

    struct ScriptedAttestation {
        responses: Mutex<VecDeque<Result<RuntimeInventoryAttestation>>>,
    }

    impl ScriptedAttestation {
        fn returning(response: RuntimeInventoryAttestation) -> Self {
            Self {
                responses: Mutex::new(VecDeque::from([Ok(response)])),
            }
        }
    }

    impl RuntimeInventoryAttestationPort for ScriptedAttestation {
        fn force_full_and_wait(
            &self,
            _command: &LifecycleCommandEnvelope,
            _deadline_unix_ms: UnixMillis,
        ) -> Result<RuntimeInventoryAttestation> {
            pop(&self.responses, "post-Stop Full inventory")
        }
    }

    fn pop<T>(queue: &Mutex<VecDeque<Result<T>>>, name: &str) -> Result<T> {
        queue
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(anyhow::anyhow!("unexpected {name} call")))
    }

    fn advance_test(
        port: &dyn AtomicColdDeletePort,
        inventory: &dyn RuntimeInventoryAttestationPort,
        command: &LifecycleCommandEnvelope,
        state: ColdDeleteStepState,
    ) -> Result<StateProgress> {
        let predecessor = non_warm_predecessor_response(command, state_strong_stop(&state));
        advance_volume_state(
            port,
            inventory,
            None,
            None,
            command,
            Some(&predecessor),
            state,
        )
    }

    fn state_strong_stop(state: &ColdDeleteStepState) -> Option<&StrongStopEvidence> {
        match state {
            ColdDeleteStepState::BindSuspendWarmPredecessor
            | ColdDeleteStepState::StrongStop
            | ColdDeleteStepState::StrongStopWithOwnedPredecessor { .. } => None,
            ColdDeleteStepState::ColdConverge { strong_stop, .. }
            | ColdDeleteStepState::ColdForceFull { strong_stop, .. }
            | ColdDeleteStepState::ColdRelease { strong_stop, .. }
            | ColdDeleteStepState::ColdPrepareWarmCleanup { strong_stop, .. }
            | ColdDeleteStepState::ColdRemoveWarmCleanup { strong_stop, .. }
            | ColdDeleteStepState::ColdFinalize { strong_stop, .. }
            | ColdDeleteStepState::DeleteConvergePersistent { strong_stop, .. }
            | ColdDeleteStepState::DeleteInspectRoot { strong_stop, .. }
            | ColdDeleteStepState::DeleteForceFull { strong_stop, .. }
            | ColdDeleteStepState::DeleteBegin { strong_stop, .. }
            | ColdDeleteStepState::DeleteCleanupRoot { strong_stop, .. }
            | ColdDeleteStepState::DeleteAwaitCompletion { strong_stop, .. }
            | ColdDeleteStepState::DeletePrepareWarmCleanup { strong_stop, .. }
            | ColdDeleteStepState::DeleteRemoveWarmCleanup { strong_stop, .. }
            | ColdDeleteStepState::DeleteFinalize { strong_stop, .. } => Some(strong_stop),
        }
    }

    fn non_warm_predecessor_response(
        command: &LifecycleCommandEnvelope,
        strong_stop: Option<&StrongStopEvidence>,
    ) -> LifecycleCommandResponse {
        let terminal_result_kind = match &command.predecessor {
            LifecyclePredecessor::SameNode {
                terminal_result_kind,
                ..
            } => *terminal_result_kind,
            _ => unreachable!(),
        };
        let result = match terminal_result_kind {
            TerminalResultKind::RuntimeReady => NodeResult::RuntimeReady(Box::new(
                cats_api::runtime_lifecycle::RuntimeReadyResult {
                    runtime_incarnation: random(15),
                    runtime_config_digest: command.runtime_config.config_digest.clone(),
                    execution_receipt_digest: digest(117),
                    guest_ready_receipt_digest: digest(118),
                    volume_receipts: Vec::new(),
                },
            )),
            TerminalResultKind::StartFailed => NodeResult::StartFailed(Box::new(
                cats_api::runtime_lifecycle::CommandFailedResult {
                    reason: cats_api::runtime_lifecycle::CommandFailureReason::LocalCleanupFailed,
                    not_running: absence(),
                    retained_evidence: RetainedEvidence {
                        artifact_manifest_digest: digest(121),
                        adoptable_count: 0,
                        gc_candidate_count: 0,
                        retained_authority_or_data_count: 0,
                        quarantined_count: 0,
                    },
                    retained_volume_receipts: Vec::new(),
                },
            )),
            TerminalResultKind::Cold => NodeResult::Cold(Box::new(ColdResult {
                runtime_config_digest: command.runtime_config.config_digest.clone(),
                execution_absence: absence(),
                volume_dispositions: Vec::new(),
                local_recovery_dependency_absent_digest: digest(119),
            })),
            TerminalResultKind::Killed => {
                let strong_stop = strong_stop.expect("Killed test predecessor needs strong Stop");
                NodeResult::Killed(Box::new(cats_api::runtime_lifecycle::KilledResult {
                    stopped_runtime_incarnation: strong_stop.stopped_runtime_incarnation.clone(),
                    execution_absence: absence(),
                    stop_fence_receipt_digest: absence().stop_fence_receipt_digest,
                    retained_evidence: strong_stop.retained_evidence.clone(),
                    retained_volume_receipts: strong_stop.retained_volume_receipts.clone(),
                }))
            }
            other => panic!("unsupported non-Warm test predecessor {other:?}"),
        };
        LifecycleCommandResponse {
            version: ContractVersion::V1,
            operation_id: command.expected_predecessor_operation_id.clone().unwrap(),
            workspace_id: command.workspace_id.clone(),
            cat_id: command.cat_id.clone(),
            node_id: command.node_id.clone(),
            placement_identity: command.placement_identity.clone(),
            request_fingerprint: digest(120),
            result,
        }
    }

    fn test_local_recovery_authority(
        command: &LifecycleCommandEnvelope,
        strong_stop: &StrongStopEvidence,
    ) -> AtomicLocalRecoveryAuthority {
        let predecessor = non_warm_predecessor_response(command, Some(strong_stop));
        local_recovery_authority(command, Some(&predecessor), strong_stop).unwrap()
    }

    fn needs_intervention_predecessor_response(
        command: &LifecycleCommandEnvelope,
        strong_stop: &StrongStopEvidence,
        attempted_target: InterventionTarget,
        reason: InterventionReason,
    ) -> LifecycleCommandResponse {
        LifecycleCommandResponse {
            version: ContractVersion::V1,
            operation_id: command.expected_predecessor_operation_id.clone().unwrap(),
            workspace_id: command.workspace_id.clone(),
            cat_id: command.cat_id.clone(),
            node_id: command.node_id.clone(),
            placement_identity: command.placement_identity.clone(),
            request_fingerprint: digest(220),
            result: NodeResult::NeedsIntervention(Box::new(NeedsInterventionResult {
                attempted_target,
                reason,
                not_running: strong_stop.execution_absence.clone(),
                retained_evidence: strong_stop.retained_evidence.clone(),
                retained_volume_receipts: strong_stop.retained_volume_receipts.clone(),
            })),
        }
    }

    fn bind_predecessor_terminal_digest(
        command: &mut LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
    ) {
        let digest = lifecycle_terminal_result_digest(&LifecycleTerminalResult::NodeResult {
            response: Box::new(predecessor.clone()),
        })
        .unwrap();
        let LifecyclePredecessor::SameNode {
            operation_id,
            terminal_result_kind,
            node_id,
            placement_identity,
            ..
        } = &command.predecessor
        else {
            unreachable!()
        };
        *command = LifecycleCommandEnvelope::new(
            command.operation_id.clone(),
            command.workspace_id.clone(),
            command.cat_id.clone(),
            command.node_id.clone(),
            command.placement_identity.clone(),
            command.runtime_config.as_ref().clone(),
            command.expected_predecessor_operation_id.clone(),
            LifecyclePredecessor::SameNode {
                operation_id: operation_id.clone(),
                terminal_result_kind: *terminal_result_kind,
                terminal_result_digest: digest,
                node_id: node_id.clone(),
                placement_identity: placement_identity.clone(),
            },
            command.command.clone(),
        )
        .unwrap();
    }

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(value: u128) -> RandomId128 {
        RandomId128::new(format!("{value:032x}")).unwrap()
    }

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    fn epoch(value: u64) -> Epoch {
        Epoch::new(value).unwrap()
    }

    fn fence_epoch(value: u64) -> FenceEpoch {
        FenceEpoch::new(value).unwrap()
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).unwrap()
    }

    fn millis(value: u64) -> UnixMillis {
        UnixMillis::new(value).unwrap()
    }

    fn runtime_config() -> ImmutableRuntimeConfig {
        ImmutableRuntimeConfig::new(
            id("config.001"),
            digest(1),
            2,
            2 * 1024 * 1024 * 1024,
            digest(2),
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id: id("network.001"),
                guest_mac: MacAddress::new("02:ca:00:00:00:01").unwrap(),
                guest_ipv4: Ipv4Address::new("10.0.0.1").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.2").unwrap(),
            },
            vec![
                RuntimeVolumeConfig {
                    volume_id: id("volume.00.root"),
                    disk_id: id("disk.00.root"),
                    disk_role: DiskRole::Root,
                    size_bytes: 8 * 1024 * 1024 * 1024,
                    durability: Durability::Relaxed,
                    guest_device_serial: id("root.serial"),
                    guest_device_slot: 0,
                    guest_binding: RuntimeVolumeGuestBinding::RootBoot,
                },
                RuntimeVolumeConfig {
                    volume_id: id("volume.01.data"),
                    disk_id: id("disk.01.data"),
                    disk_role: DiskRole::Persistent,
                    size_bytes: 16 * 1024 * 1024 * 1024,
                    durability: Durability::Strict,
                    guest_device_serial: id("data.serial"),
                    guest_device_slot: 1,
                    guest_binding: RuntimeVolumeGuestBinding::PersistentExt4 {
                        filesystem_uuid: random(3),
                        mount_path: AsciiText::new("/srv/data").unwrap(),
                    },
                },
            ],
        )
        .unwrap()
    }

    fn command(delete: bool) -> LifecycleCommandEnvelope {
        command_after(delete, TerminalResultKind::RuntimeReady)
    }

    fn command_after(
        delete: bool,
        predecessor_kind: TerminalResultKind,
    ) -> LifecycleCommandEnvelope {
        let config = runtime_config();
        let node_id = id("node.a");
        let placement = PlacementIdentity {
            node_id: node_id.clone(),
            placement_epoch: epoch(1),
        };
        let predecessor = LifecyclePredecessor::SameNode {
            operation_id: id("operation.predecessor"),
            terminal_result_kind: predecessor_kind,
            terminal_result_digest: digest(3),
            node_id: node_id.clone(),
            placement_identity: placement.clone(),
        };
        let command = if delete {
            LifecycleCommand::Delete(DeleteSpec {
                delete_id: id("delete.001"),
                grace_deadline_unix_ms: millis(1_000),
                convergence_deadline_unix_ms: millis(2_000),
                volume_dispositions: vec![
                    RequestedVolumeDisposition::DiscardWithCat {
                        volume_id: config.volumes[0].volume_id.clone(),
                        disk_id: config.volumes[0].disk_id.clone(),
                        disk_role: DiskRole::Root,
                    },
                    RequestedVolumeDisposition::RetainDetached {
                        volume_id: config.volumes[1].volume_id.clone(),
                        disk_id: config.volumes[1].disk_id.clone(),
                        disk_role: DiskRole::Persistent,
                    },
                ],
            })
        } else {
            LifecycleCommand::Cold(ColdSpec {
                grace_deadline_unix_ms: millis(1_000),
                convergence_deadline_unix_ms: millis(2_000),
            })
        };
        LifecycleCommandEnvelope::new(
            id(if delete {
                "operation.delete"
            } else {
                "operation.cold"
            }),
            id("workspace.001"),
            id("cat.001"),
            node_id,
            placement,
            config,
            Some(id("operation.predecessor")),
            predecessor,
            command,
        )
        .unwrap()
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

    fn strong_stop() -> StrongStopEvidence {
        StrongStopEvidence {
            execution_absence: absence(),
            restart_source_cleanup_receipt_digest: None,
            retained_warm_restart_source: None,
            stopped_runtime_incarnation: Some(random(15)),
            retained_volume_receipts: Vec::new(),
            retained_evidence: RetainedEvidence {
                artifact_manifest_digest: digest(16),
                adoptable_count: 0,
                gc_candidate_count: 0,
                retained_authority_or_data_count: 0,
                quarantined_count: 0,
            },
            post_stop_physical_projection_digest: digest(17),
        }
    }

    fn carrier_installed_runtime(
        command: &LifecycleCommandEnvelope,
        runtime_incarnation: RandomId128,
    ) -> super::super::start::InstalledRuntimeManifest {
        let RuntimeNetworkConfig::IsolatedIpv4 {
            network_id,
            guest_mac,
            guest_ipv4,
            prefix_length,
            gateway_ipv4,
        } = &command.runtime_config.network_config;
        let network_identity = RuntimeNetworkIdentity {
            network_config: NetworkConfig {
                kind: IsolatedIpv4Kind::IsolatedIpv4,
                network_id: network_id.clone(),
                guest_mac: guest_mac.clone(),
                guest_ipv4: guest_ipv4.clone(),
                prefix_length: *prefix_length,
                gateway_ipv4: gateway_ipv4.clone(),
            },
            tap_name: id("tap.carrier"),
            ownership_token: random(230),
        };
        let launch_artifact = |path: &str, byte| RuntimeLaunchArtifact {
            path: HostPath::new(path).unwrap(),
            length: WireU64::new(4_096).unwrap(),
            content_sha256: digest(byte),
        };
        let api_socket_path = HostPath::new("/run/cats/carrier-api.sock").unwrap();
        let vsock_socket_path = HostPath::new("/run/cats/carrier-vsock.sock").unwrap();
        let memory_file_path = HostPath::new("/var/lib/cats/carrier-memory").unwrap();
        let vmm = super::super::start::InstalledRuntimeVmmManifest {
            process: super::super::start::InstalledRuntimeProcessIdentity {
                pid: 5_001,
                start_time_ticks: WireU64::new(50_001).unwrap(),
            },
            parent_slice_id: id("cats.carrier.slice"),
            systemd_unit_id: id("cats.carrier.vmm"),
            api_socket_path: api_socket_path.clone(),
            vsock_socket_path: vsock_socket_path.clone(),
            memory_file_path: memory_file_path.clone(),
            launch_identity: Box::new(RuntimeLaunchIdentity {
                runtime_incarnation: runtime_incarnation.clone(),
                scope_id: id("cats.carrier.slice"),
                launcher_executable: Box::new(launch_artifact("/usr/lib/cats/vmm-launcher", 231)),
                boot: Box::new(VmmBootProvenance {
                    vmm_executable: launch_artifact("/usr/bin/cloud-hypervisor", 232),
                    kernel: launch_artifact("/usr/lib/cats/vmlinux", 233),
                    initramfs: None,
                    kernel_cmdline: AsciiText::new("console=hvc0").unwrap(),
                }),
                process_identity_token: random(234),
                vcpus: command.runtime_config.vcpus,
                memory_bytes: command.runtime_config.memory_bytes,
                boot_image_digest: command.runtime_config.boot_image_digest.clone(),
                guest_config_digest: command.runtime_config.guest_runtime_profile_digest.clone(),
                api_socket_path,
                vsock_socket_path,
                guest_cid: 9,
                memory_file_path,
                serial_log_path: HostPath::new("/var/log/cats/carrier-serial.log").unwrap(),
                vmm_log_path: HostPath::new("/var/log/cats/carrier-vmm.log").unwrap(),
                network: Box::new(network_identity.clone()),
                devices: Vec::new(),
            }),
        };
        let volumes = command
            .runtime_config
            .volumes
            .iter()
            .enumerate()
            .map(|(index, configured)| {
                let head = remote_head(4 + index as u64);
                super::super::start::InstalledRuntimeVolumeManifest {
                    volume_id: configured.volume_id.clone(),
                    disk_id: configured.disk_id.clone(),
                    disk_role: configured.disk_role,
                    attachment_id: id(&format!("attachment.carrier.{index}")),
                    attachment_epoch: fence_epoch(31 + index as u64),
                    acquire_origin: AcquireOrigin::Normal {
                        transition_id: random(240 + index as u128),
                    },
                    launch_head: head.clone(),
                    current_authority_head: head,
                    authority_receipt_digest: Some(digest(240 + index as u8)),
                    local_lineage_data_directory: HostPath::new(format!(
                        "/var/lib/cats/carrier-lineage-{index}"
                    ))
                    .unwrap(),
                    blockd: super::super::start::InstalledRuntimeProcessIdentity {
                        pid: 5_100 + index as u32,
                        start_time_ticks: WireU64::new(51_000 + index as u64).unwrap(),
                    },
                    blockd_control_socket_path: HostPath::new(format!(
                        "/run/cats/carrier-blockd-{index}.sock"
                    ))
                    .unwrap(),
                    frontend: super::super::start::InstalledRuntimeBlockFrontend::VhostUserBlk {
                        socket_path: HostPath::new(format!("/run/cats/carrier-vhost-{index}.sock"))
                            .unwrap(),
                    },
                }
            })
            .collect::<Vec<_>>();
        let mut manifest = super::super::start::InstalledRuntimeManifest {
            version: ContractVersion::V1,
            node_id: command.node_id.clone(),
            cat_id: command.cat_id.clone(),
            placement_identity: command.placement_identity.clone(),
            source_lifecycle_operation_id: id("operation.original.start"),
            request_fingerprint: digest(250),
            runtime_config_id: command.runtime_config.config_id.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            runtime_incarnation,
            execution_receipt_digest: digest(251),
            guest_ready_receipt_digest: digest(252),
            retired_restart_source_absence_digest: None,
            vmm,
            network: super::super::start::InstalledRuntimeNetworkManifest {
                identity: Box::new(network_identity),
            },
            volumes,
            manifest_digest: Sha256Digest::from_bytes([0; 32]),
        };
        manifest.manifest_digest =
            super::super::start::installed_runtime_manifest_digest(&manifest).unwrap();
        manifest
    }

    fn carrier_physical(
        installed: &super::super::start::InstalledRuntimeManifest,
        predecessor: &LifecycleCommandResponse,
        failed: bool,
        predecessor_terminal_result_digest: Sha256Digest,
    ) -> SameNodeOwnedPredecessorPhysical {
        let volumes = installed
            .volumes
            .iter()
            .map(|volume| SameNodeOwnedPredecessorVolume {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                disk_role: volume.disk_role,
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch: volume.attachment_epoch,
                acquire_origin: volume.acquire_origin.clone(),
                authoritative_head: volume.current_authority_head.clone(),
                immutable_start_grant_receipt_digest: volume
                    .authority_receipt_digest
                    .clone()
                    .unwrap(),
                local_lineage_data_directory: Some(volume.local_lineage_data_directory.clone()),
            })
            .collect::<Vec<_>>();
        let volume_receipts = installed
            .volumes
            .iter()
            .map(|volume| VolumeTerminalReceipt {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                disk_role: volume.disk_role,
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch: volume.attachment_epoch,
                local_durable_generation: volume.current_authority_head.generation,
                remote_durable_generation: volume.current_authority_head.generation,
                authority_receipt_digest: volume.authority_receipt_digest.clone(),
            })
            .collect::<Vec<_>>();
        let physical_manifest_digest = if failed {
            let NodeResult::SuspendFailed(failed_result) = &predecessor.result else {
                unreachable!()
            };
            super::super::suspend_warm::failed_predecessor_physical_digest(
                predecessor,
                &predecessor_terminal_result_digest,
                failed_result,
                installed,
                &volumes,
                &volume_receipts,
            )
            .unwrap()
        } else {
            installed.manifest_digest.clone()
        };
        let source = if failed {
            SameNodeOwnedPredecessorSource::Failed {
                installed_runtime: Box::new(installed.clone()),
                execution_absence: absence(),
                retained_evidence: RetainedEvidence {
                    artifact_manifest_digest: digest(253),
                    adoptable_count: 0,
                    gc_candidate_count: 0,
                    retained_authority_or_data_count: 2,
                    quarantined_count: 0,
                },
                predecessor_terminal_result_digest,
                volume_receipts,
            }
        } else {
            SameNodeOwnedPredecessorSource::Suspended {
                installed_runtime: Box::new(installed.clone()),
                physical_identity_digest: digest(254),
                pause_receipt_digest: digest(255),
                volume_receipts,
            }
        };
        SameNodeOwnedPredecessorPhysical {
            physical_manifest_digest,
            runtime_incarnation: Some(installed.runtime_incarnation.clone()),
            volumes,
            source,
        }
    }

    fn carrier_predecessor_response(
        command: &LifecycleCommandEnvelope,
        installed: &super::super::start::InstalledRuntimeManifest,
        failed: bool,
    ) -> LifecycleCommandResponse {
        let receipts: Vec<VolumeTerminalReceipt> = installed
            .volumes
            .iter()
            .map(|volume| VolumeTerminalReceipt {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                disk_role: volume.disk_role,
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch: volume.attachment_epoch,
                local_durable_generation: volume.current_authority_head.generation,
                remote_durable_generation: volume.current_authority_head.generation,
                authority_receipt_digest: volume.authority_receipt_digest.clone(),
            })
            .collect();
        let result = if failed {
            NodeResult::SuspendFailed(Box::new(cats_api::runtime_lifecycle::CommandFailedResult {
                reason: cats_api::runtime_lifecycle::CommandFailureReason::LocalCleanupFailed,
                not_running: absence(),
                retained_evidence: RetainedEvidence {
                    artifact_manifest_digest: digest(253),
                    adoptable_count: 0,
                    gc_candidate_count: 0,
                    retained_authority_or_data_count: 2,
                    quarantined_count: 0,
                },
                retained_volume_receipts: receipts.clone(),
            }))
        } else {
            NodeResult::Suspended(Box::new(cats_api::runtime_lifecycle::SuspendedResult {
                runtime_incarnation: installed.runtime_incarnation.clone(),
                runtime_config_digest: installed.runtime_config_digest.clone(),
                pause_receipt_digest: digest(255),
                local_durability_receipts: receipts,
            }))
        };
        LifecycleCommandResponse {
            version: ContractVersion::V1,
            operation_id: command.expected_predecessor_operation_id.clone().unwrap(),
            workspace_id: command.workspace_id.clone(),
            cat_id: command.cat_id.clone(),
            node_id: command.node_id.clone(),
            placement_identity: command.placement_identity.clone(),
            request_fingerprint: digest(248),
            result,
        }
    }

    fn terminal_retained_manifest(
        successor: &LifecycleCommandEnvelope,
        source_operation_id: Id,
        source_request_fingerprint: Sha256Digest,
        runtime_incarnation: RandomId128,
    ) -> super::super::start::TerminalRetainedRuntimeManifest {
        let mut source = successor.clone();
        source.operation_id = source_operation_id;
        source.request_fingerprint = source_request_fingerprint;
        let mut grants = Vec::new();
        let mut progress_volumes = Vec::new();
        let mut retained = Vec::new();
        for (index, config) in source.runtime_config.volumes.iter().enumerate() {
            let transition_id = random(130 + index as u128);
            let attachment_id = Id::new(format!("attachment.bridge.{index}")).unwrap();
            let attachment_epoch = fence_epoch(7 + index as u64);
            let head = remote_head(3 + index as u64);
            let grant_receipt_digest = digest(140 + index as u8);
            let volume = VolumeTerminalReceipt {
                volume_id: config.volume_id.clone(),
                disk_id: config.disk_id.clone(),
                disk_role: config.disk_role,
                attachment_id: attachment_id.clone(),
                attachment_epoch,
                local_durable_generation: head.generation,
                remote_durable_generation: head.generation,
                authority_receipt_digest: Some(grant_receipt_digest.clone()),
            };
            let acquire_origin = AcquireOrigin::Normal {
                transition_id: transition_id.clone(),
            };
            grants.push(super::super::start::AtomicStartVolumeGrant::new(
                volume.clone(),
                acquire_origin.clone(),
                head.clone(),
                millis(20_000),
                grant_receipt_digest.clone(),
                cats_api::runtime_lifecycle_volume::LifecycleCommandStartVolumeGrantReceipt {
                    scope: cats_api::runtime_lifecycle_volume::LifecycleVolumeCommandScope {
                        operation_id: source.operation_id.clone(),
                        request_fingerprint: source.request_fingerprint.clone(),
                        cat_id: source.cat_id.clone(),
                        node_id: source.node_id.clone(),
                        placement_identity: source.placement_identity.clone(),
                    },
                    grant_sequence: WireU64::new(0).unwrap(),
                    volume: config.clone(),
                    authority: cats_api::runtime_lifecycle_volume::LifecycleStartVolumeGrantAuthority::NormalAcquire {
                        request: NormalAcquireRequest {
                            volume_id: config.volume_id.clone(),
                            transition_id: transition_id.clone(),
                            attachment_id: attachment_id.clone(),
                            expected_unowned_epoch: fence_epoch(6 + index as u64),
                            placement_epoch: source.placement_identity.placement_epoch,
                            lease_duration_ms: 60_000,
                        },
                        result: NormalAcquireResult {
                            volume_id: config.volume_id.clone(),
                            transition_id: transition_id.clone(),
                            attachment_id: attachment_id.clone(),
                            resulting_epoch: attachment_epoch,
                            resulting_head: head.clone(),
                            lease_expires_at: millis(20_000),
                        },
                    },
                },
                HostPath::new(format!("/var/lib/cats/bridge-{index}")).unwrap(),
            ));
            progress_volumes.push(
                super::super::start::InstalledRuntimeProgressVolumeManifest {
                    volume_id: config.volume_id.clone(),
                    disk_id: config.disk_id.clone(),
                    disk_role: config.disk_role,
                    attachment_id,
                    attachment_epoch,
                    acquire_origin,
                    authority_head: head,
                    authority_receipt_digest: Some(grant_receipt_digest),
                    local_lineage_data_directory: Some(
                        HostPath::new(format!("/var/lib/cats/bridge-{index}")).unwrap(),
                    ),
                    blockd: None,
                    blockd_control_socket_path: None,
                    frontend: None,
                },
            );
            retained.push(volume);
        }
        let runtime_progress = super::super::start::InstalledRuntimeProgressManifest::new(
            &source,
            runtime_incarnation.clone(),
            None,
            None,
            progress_volumes,
            Vec::new(),
        )
        .unwrap();
        let mut manifest = super::super::start::TerminalRetainedRuntimeManifest {
            version: ContractVersion::V1,
            disposition: super::super::start::TerminalRetainedRuntimeDisposition::NonExecutable,
            node_id: source.node_id.clone(),
            cat_id: source.cat_id.clone(),
            placement_identity: source.placement_identity.clone(),
            source_lifecycle_operation_id: source.operation_id.clone(),
            request_fingerprint: source.request_fingerprint.clone(),
            runtime_config_id: source.runtime_config.config_id.clone(),
            runtime_config_digest: source.runtime_config.config_digest.clone(),
            runtime_incarnation,
            retention_mode:
                super::super::start::TerminalRetainedRuntimeMode::MaterializedOrAmbiguous,
            execution_absence: absence(),
            post_stop_physical_projection_digest: digest(180),
            volume_grants: grants,
            retained_volume_receipts: retained,
            runtime_progress: Some(runtime_progress),
            physical_retained_evidence: RetainedEvidence {
                artifact_manifest_digest: digest(181),
                adoptable_count: 0,
                gc_candidate_count: 0,
                retained_authority_or_data_count: 2,
                quarantined_count: 0,
            },
            retained_warm_restart_source: None,
            manifest_digest: Sha256Digest::from_bytes([0; 32]),
        };
        manifest.manifest_digest =
            super::super::start::terminal_retained_runtime_manifest_digest(&manifest).unwrap();
        super::super::start::validate_terminal_retained_runtime_manifest(&manifest, None).unwrap();
        manifest
    }

    struct RetainedWarmStartFailedFixture {
        _directory: tempfile::TempDir,
        state_directory: StateDirectory,
        command: LifecycleCommandEnvelope,
        predecessor: LifecycleCommandResponse,
        strong_stop: StrongStopEvidence,
        manifest: super::super::start::TerminalRetainedRuntimeManifest,
        cleanup: Option<AtomicRetainedWarmCleanupAuthority>,
        local_recovery_authority: AtomicLocalRecoveryAuthority,
    }

    fn retained_warm_start_failed_fixture(
        delete: bool,
        with_retained_warm: bool,
    ) -> RetainedWarmStartFailedFixture {
        let directory = tempfile::tempdir().unwrap();
        let state_directory = StateDirectory::unanchored(directory.path().to_path_buf());
        let mut command = command_after(delete, TerminalResultKind::StartFailed);
        let mut predecessor = non_warm_predecessor_response(&command, None);
        bind_predecessor_terminal_digest(&mut command, &predecessor);

        let runtime_incarnation = random(263);
        let retained_warm_carrier = if with_retained_warm {
            let (installed, carrier, _initial_authority) =
                super::super::suspend_warm::retained_warm_restart_source_chain_for_test(
                    &command,
                    &predecessor,
                )
                .unwrap();
            assert_eq!(
                installed.runtime_config_digest,
                command.runtime_config.config_digest
            );
            Some((installed.runtime_incarnation, carrier))
        } else {
            None
        };
        let runtime_incarnation = retained_warm_carrier
            .as_ref()
            .map_or(runtime_incarnation, |(incarnation, _)| incarnation.clone());
        let mut manifest = terminal_retained_manifest(
            &command,
            predecessor.operation_id.clone(),
            predecessor.request_fingerprint.clone(),
            runtime_incarnation,
        );
        manifest.retained_warm_restart_source =
            retained_warm_carrier.map(|(_, carrier)| Box::new(carrier));
        manifest.manifest_digest =
            super::super::start::terminal_retained_runtime_manifest_digest(&manifest).unwrap();
        super::super::start::validate_terminal_retained_runtime_manifest(&manifest, None).unwrap();

        let NodeResult::StartFailed(failed) = &mut predecessor.result else {
            unreachable!()
        };
        failed.not_running = manifest.execution_absence.clone();
        failed.retained_evidence = RetainedEvidence {
            artifact_manifest_digest: manifest.manifest_digest.clone(),
            ..manifest.physical_retained_evidence.clone()
        };
        bind_predecessor_terminal_digest(&mut command, &predecessor);

        super::super::start::publish_installed_runtime_progress_manifest(
            &state_directory,
            manifest.runtime_progress.as_ref().unwrap(),
        )
        .unwrap();
        super::super::start::seal_terminal_retained_runtime_manifest(&state_directory, &manifest)
            .unwrap();
        let cleanup =
            retained_start_failed_warm_cleanup(&state_directory, &command, Some(&predecessor))
                .unwrap();
        assert_eq!(cleanup.is_some(), with_retained_warm);

        let mut strong_stop = strong_stop();
        strong_stop.execution_absence = manifest.execution_absence.clone();
        strong_stop.stopped_runtime_incarnation = Some(manifest.runtime_incarnation.clone());
        let local_recovery_authority = local_recovery_authority_with_carrier(
            &command,
            Some(&predecessor),
            &strong_stop,
            None,
            cleanup.as_ref(),
        )
        .unwrap();
        validate_expected_local_recovery_authority(
            &command,
            Some(&predecessor),
            &strong_stop,
            &local_recovery_authority,
        )
        .unwrap();

        RetainedWarmStartFailedFixture {
            _directory: directory,
            state_directory,
            command,
            predecessor,
            strong_stop,
            manifest,
            cleanup,
            local_recovery_authority,
        }
    }

    fn attestation(command: &LifecycleCommandEnvelope) -> RuntimeInventoryAttestation {
        RuntimeInventoryAttestation {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: command.node_id.clone(),
                node_boot_id: NodeBootId::new(format!("{:032x}", 20_u128)).unwrap(),
                agent_instance_id: random(21),
                agent_session_epoch: epoch(1),
            },
            inventory_epoch: epoch(2),
            scan_id: random(22),
            inventory_digest: digest(23),
            source_report_id: random(24),
            source_sequence: Sequence::new(1).unwrap(),
            accepted_at_unix_ms: millis(1_500),
        }
    }

    fn remote_head(value: u64) -> RemoteHead {
        RemoteHead {
            generation: generation(value),
            root_hash: Some(digest(value as u8)),
            root_object_id: Some(AsciiText::new(format!("root-object-{value}")).unwrap()),
        }
    }

    fn durability(
        command: &LifecycleCommandEnvelope,
        index: usize,
        local: u64,
        remote: u64,
        pending: u64,
    ) -> CommandVolumeDurabilityProof {
        let config = &command.runtime_config.volumes[index];
        CommandVolumeDurabilityProof {
            scope: command_scope(command),
            volume: LifecycleVolumeTarget {
                disk_id: config.disk_id.clone(),
                disk_role: config.disk_role,
                volume_id: config.volume_id.clone(),
                attachment_id: id(&format!("attachment.{index}")),
                attachment_epoch: fence_epoch(10 + index as u64),
            },
            remote_head: remote_head(remote),
            local_durable_generation: generation(local),
            remote_durable_generation: generation(remote),
            pending_pack_count: WireU64::new(pending).unwrap(),
        }
    }

    fn release_input(
        command: &LifecycleCommandEnvelope,
        index: usize,
        purpose: &str,
    ) -> CommandNormalReleaseInput {
        CommandNormalReleaseInput {
            durability: durability(command, index, 7, 7, 0),
            transition_id: transition_id(
                command,
                &command.runtime_config.volumes[index].volume_id,
                purpose,
            )
            .unwrap(),
        }
    }

    fn stored_release(input: &CommandNormalReleaseInput) -> AtomicStoredNormalReleaseReceipt {
        let target = &input.durability.volume;
        let receipt = CommandNormalReleaseReceipt {
            durability: input.durability.clone(),
            request: ReleaseRequest {
                volume_id: target.volume_id.clone(),
                transition_id: input.transition_id.clone(),
                attachment_id: target.attachment_id.clone(),
                expected_epoch: target.attachment_epoch,
            },
            result: ReleaseResult {
                volume_id: target.volume_id.clone(),
                transition_id: input.transition_id.clone(),
                released_attachment_id: target.attachment_id.clone(),
                resulting_epoch: next_epoch(target.attachment_epoch).unwrap(),
                resulting_head: input.durability.remote_head.clone(),
            },
        };
        AtomicStoredNormalReleaseReceipt {
            receipt_digest: cats_storage::lifecycle_volume::command_normal_release_receipt_digest_from_closed_receipt(&receipt).unwrap(),
            receipt,
        }
    }

    fn unowned_input(
        command: &LifecycleCommandEnvelope,
        index: usize,
    ) -> AtomicVolumeDispositionInput {
        let volume = &command.runtime_config.volumes[index];
        AtomicVolumeDispositionInput::AlreadyUnowned {
            volume: LifecycleVolumeIdentity {
                disk_id: volume.disk_id.clone(),
                disk_role: volume.disk_role,
                volume_id: volume.volume_id.clone(),
            },
            expected_epoch: fence_epoch(30 + index as u64),
            expected_head: remote_head(7),
        }
    }

    fn stored_unowned(
        scope: &LifecycleVolumeCommandScope,
        input: &AtomicVolumeDispositionInput,
        receipt_use: StoredDispositionUse,
    ) -> AtomicStoredAlreadyUnownedReceipt {
        let AtomicVolumeDispositionInput::AlreadyUnowned {
            volume,
            expected_epoch,
            expected_head,
        } = input
        else {
            panic!("stored already-Unowned fixture requires the matching input")
        };
        let receipt = CommandAlreadyUnownedReceipt {
            scope: scope.clone(),
            volume: volume.clone(),
            expected_epoch: *expected_epoch,
            expected_head: expected_head.clone(),
            provenance: AlreadyUnownedProvenance::Pristine,
        };
        AtomicStoredAlreadyUnownedReceipt {
            receipt_digest: receipt_use
                .already_unowned_receipt_digest(&receipt)
                .unwrap(),
            receipt,
        }
    }

    fn delete_set(
        command: &LifecycleCommandEnvelope,
        root: &CommandVolumeDurabilityProof,
        _persistent: &[CommandNormalReleaseInput],
    ) -> DeleteCommandVolumeSet {
        delete_command_volume_set(command, root.volume.identity()).unwrap()
    }

    fn root_absence(
        command: &DeleteCommandVolumeSet,
        begin: &AtomicDeleteBeginReceipt,
    ) -> AtomicRootLineageAbsenceReceipt {
        let root = &command.root_disposition.root;
        match begin {
            AtomicDeleteBeginReceipt::NormallyDeleting { dispositions } => {
                match dispositions
                    .iter()
                    .find(|disposition| disposition.identity().disk_role == DiskRole::Root)
                    .unwrap()
                {
                    AtomicStoredVolumeDisposition::NormallyReleased { release } => {
                        let target = &release.receipt.durability.volume;
                        AtomicRootLineageAbsenceReceipt::RemovedOwned {
                            volume_id: root.volume_id.clone(),
                            disk_id: root.disk_id.clone(),
                            previous_attachment_id: target.attachment_id.clone(),
                            previous_attachment_epoch: target.attachment_epoch,
                            authority_receipt_digest: release.receipt_digest.clone(),
                            local_lineage_absence_digest: digest(90),
                        }
                    }
                    AtomicStoredVolumeDisposition::AlreadyUnowned { receipt } => {
                        AtomicRootLineageAbsenceReceipt::AlreadyUnowned {
                            volume_id: root.volume_id.clone(),
                            disk_id: root.disk_id.clone(),
                            expected_epoch: receipt.receipt.expected_epoch,
                            expected_head: receipt.receipt.expected_head.clone(),
                            authority_receipt_digest: receipt.receipt_digest.clone(),
                            local_lineage_absence_digest: digest(90),
                        }
                    }
                }
            }
            AtomicDeleteBeginReceipt::DisposableRootDeleting {
                root_durability,
                authorization_consumed_receipt_digest,
                ..
            } => AtomicRootLineageAbsenceReceipt::RemovedOwned {
                volume_id: root.volume_id.clone(),
                disk_id: root.disk_id.clone(),
                previous_attachment_id: root_durability.volume.attachment_id.clone(),
                previous_attachment_epoch: root_durability.volume.attachment_epoch,
                authority_receipt_digest: authorization_consumed_receipt_digest.clone(),
                local_lineage_absence_digest: digest(90),
            },
        }
    }

    fn normal_completion(
        command: &DeleteCommandVolumeSet,
        begin: &AtomicDeleteBeginReceipt,
    ) -> AtomicDeleteCompletionEvidence {
        let AtomicDeleteBeginReceipt::NormallyDeleting { dispositions } = begin else {
            panic!("normal completion fixture requires the normal Delete branch")
        };
        let root = dispositions
            .iter()
            .find(|disposition| disposition.identity().disk_role == DiskRole::Root)
            .unwrap();
        let (authority, expected_epoch, expected_head) = match root {
            AtomicStoredVolumeDisposition::NormallyReleased { release } => (
                CommandRootDeleteAuthorityReceipt::NormalRelease(release.receipt.clone()),
                release.receipt.result.resulting_epoch,
                release.receipt.result.resulting_head.clone(),
            ),
            AtomicStoredVolumeDisposition::AlreadyUnowned { receipt } => (
                CommandRootDeleteAuthorityReceipt::AlreadyUnowned(receipt.receipt.clone()),
                receipt.receipt.expected_epoch,
                receipt.receipt.expected_head.clone(),
            ),
        };
        let receipt = CommandDeleteCompletionReceipt {
            command: command.clone(),
            root_authority: authority,
            completion: DeleteCompletionReceipt::Normal {
                request: BeginDeleteRequest {
                    delete_id: command.root_disposition.delete_id.clone(),
                    disk_id: command.root_disposition.root.disk_id.clone(),
                    volume_id: command.root_disposition.root.volume_id.clone(),
                    expected_unowned_epoch: expected_epoch,
                    expected_head: expected_head.clone(),
                },
                deleting_epoch: next_epoch(expected_epoch).unwrap(),
                deleting_head: expected_head,
                completed_at: millis(1_900),
            },
        };
        AtomicDeleteCompletionEvidence {
            receipt_digest: canonical_digest(DELETE_COMPLETION_DIGEST_DOMAIN, &receipt).unwrap(),
            receipt,
        }
    }

    #[test]
    fn persistent_block_terminates_before_any_root_call() {
        let command = command(true);
        let strong_stop = strong_stop();
        let persistent = command
            .runtime_config
            .volumes
            .iter()
            .filter(|volume| volume.disk_role == DiskRole::Persistent)
            .cloned()
            .collect::<Vec<_>>();
        let request = convergence_request(
            &command,
            &persistent,
            strong_stop.stopped_runtime_incarnation.clone(),
            test_local_recovery_authority(&command, &strong_stop),
            delete_spec(&command).unwrap().convergence_deadline_unix_ms,
            "delete-persistent",
        )
        .unwrap();
        let port = ScriptedPort::default();
        port.convergence
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Blocked(
                AtomicColdDeleteBlocked {
                    reason: InterventionReason::PersistentDiskNotRemoteDurable,
                    retained_volume_receipts: Vec::new(),
                },
            )));
        let inventory = ScriptedAttestation::returning(attestation(&command));

        let progress = advance_test(
            &port,
            &inventory,
            &command,
            ColdDeleteStepState::DeleteConvergePersistent {
                strong_stop,
                request,
            },
        )
        .unwrap();
        assert!(matches!(
            progress,
            StateProgress::Terminal(NodeResult::NeedsIntervention(_))
        ));
        assert!(port.root_requests.lock().unwrap().is_empty());
        assert!(port.delete_begin_requests.lock().unwrap().is_empty());
        assert!(port.cleanup_requests.lock().unwrap().is_empty());
    }

    #[test]
    fn cold_rejects_root_tail_before_release_mutation() {
        let command = command(false);
        let strong_stop = strong_stop();
        let request = convergence_request(
            &command,
            &command.runtime_config.volumes,
            strong_stop.stopped_runtime_incarnation.clone(),
            test_local_recovery_authority(&command, &strong_stop),
            cold_spec(&command).unwrap().convergence_deadline_unix_ms,
            "cold",
        )
        .unwrap();
        let root_tail = CommandNormalReleaseInput {
            durability: durability(&command, 0, 8, 7, 1),
            transition_id: request.targets[0].transition_id.clone(),
        };
        let persistent = release_input(&command, 1, "cold");
        let port = ScriptedPort::default();
        port.convergence
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(
                AtomicVolumeConvergenceReceipt {
                    dispositions: vec![
                        AtomicVolumeDispositionInput::OwnedRelease { release: root_tail },
                        AtomicVolumeDispositionInput::OwnedRelease {
                            release: persistent,
                        },
                    ],
                },
            )));
        let inventory = ScriptedAttestation {
            responses: Mutex::new(VecDeque::new()),
        };

        assert!(advance_test(
            &port,
            &inventory,
            &command,
            ColdDeleteStepState::ColdConverge {
                strong_stop,
                request,
            },
        )
        .is_err());
        assert!(port.cold_release_requests.lock().unwrap().is_empty());
        assert!(port.delete_begin_requests.lock().unwrap().is_empty());
    }

    #[test]
    fn disposable_root_begin_and_cleanup_replay_exact_journaled_requests() {
        let command = command(true);
        let strong_stop = strong_stop();
        let local_recovery_authority = test_local_recovery_authority(&command, &strong_stop);
        let persistent = release_input(&command, 1, "delete-persistent");
        let root_tail = durability(&command, 0, 8, 7, 1);
        let delete = delete_set(&command, &root_tail, std::slice::from_ref(&persistent));
        let plan = AtomicDeleteBeginPlan::DisposableRoot {
            command: delete.clone(),
            persistent_volumes: vec![AtomicVolumeDispositionInput::OwnedRelease {
                release: persistent.clone(),
            }],
            root_durability: root_tail.clone(),
        };
        let accepted = attestation(&command);
        let inventory = ScriptedAttestation::returning(accepted.clone());
        let stored_persistent = stored_release(&persistent);
        let begin_receipt = AtomicDeleteBeginReceipt::DisposableRootDeleting {
            persistent_dispositions: vec![AtomicStoredVolumeDisposition::NormallyReleased {
                release: stored_persistent,
            }],
            root_durability: root_tail,
            authorization_id: id("authorization.control-derived"),
            authorization_consumed_receipt_digest: digest(80),
        };
        let port = ScriptedPort::default();
        port.delete_begins
            .lock()
            .unwrap()
            .push_back(Err(anyhow::anyhow!("response lost")));
        port.delete_begins
            .lock()
            .unwrap()
            .push_back(Ok(AtomicDeleteBeginAttempt::Exact(begin_receipt.clone())));

        let StateProgress::Next(begin_state) = advance_test(
            &port,
            &inventory,
            &command,
            ColdDeleteStepState::DeleteForceFull {
                strong_stop,
                plan,
                local_recovery_authority,
            },
        )
        .unwrap() else {
            panic!("force-Full did not advance to Delete begin")
        };
        let durable_step = encode_step(&command, begin_state.clone()).unwrap();
        assert!(advance_test(&port, &inventory, &command, begin_state.clone()).is_err());
        assert_eq!(
            encode_step(&command, begin_state.clone()).unwrap(),
            durable_step
        );
        let StateProgress::Next(cleanup_state) =
            advance_test(&port, &inventory, &command, begin_state).unwrap()
        else {
            panic!("Delete begin did not advance to Root cleanup")
        };

        let begin_requests = port.delete_begin_requests.lock().unwrap().clone();
        assert_eq!(begin_requests.len(), 2);
        assert_eq!(begin_requests[0], begin_requests[1]);
        let AtomicDeleteBeginRequest::DisposableRoot {
            strong_stop: request_stop,
            ..
        } = &begin_requests[0]
        else {
            panic!("R < L Root did not select disposable authority")
        };
        assert_eq!(request_stop.post_stop_inventory_attestation, accepted);
        let volume_wire::LifecycleVolumeTransitionRequestKind::DeleteDisposableRoot { .. } =
            delete_begin_wire_transition(&begin_requests[0])
        else {
            panic!("wire mapping changed the disposable branch")
        };

        let ColdDeleteStepState::DeleteCleanupRoot {
            request: cleanup_request,
            ..
        } = &cleanup_state
        else {
            panic!("Delete begin produced another successor")
        };
        assert_eq!(cleanup_request.begin, begin_receipt);
        let absence = root_absence(&delete, &begin_receipt);
        port.root_cleanups
            .lock()
            .unwrap()
            .push_back(Err(anyhow::anyhow!("cleanup response lost")));
        port.root_cleanups
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(absence.clone())));
        assert!(advance_test(&port, &inventory, &command, cleanup_state.clone()).is_err());
        let StateProgress::Next(await_state) =
            advance_test(&port, &inventory, &command, cleanup_state).unwrap()
        else {
            panic!("Root cleanup did not advance to completion discovery")
        };
        assert!(matches!(
            await_state,
            ColdDeleteStepState::DeleteAwaitCompletion { .. }
        ));
        let cleanup_requests = port.cleanup_requests.lock().unwrap();
        assert_eq!(cleanup_requests.len(), 2);
        assert_eq!(cleanup_requests[0], cleanup_requests[1]);
    }

    #[test]
    fn delete_stale_inventory_reenters_force_full_with_exact_plan() {
        let command = command(true);
        let strong_stop = strong_stop();
        let local_recovery_authority = test_local_recovery_authority(&command, &strong_stop);
        let persistent = AtomicVolumeDispositionInput::OwnedRelease {
            release: release_input(&command, 1, "delete-persistent"),
        };
        let root_tail = durability(&command, 0, 8, 7, 1);
        let command_set = delete_command_volume_set(&command, root_tail.volume.identity()).unwrap();
        let plan = AtomicDeleteBeginPlan::DisposableRoot {
            command: command_set.clone(),
            persistent_volumes: vec![persistent.clone()],
            root_durability: root_tail.clone(),
        };
        let stale = attestation(&command);
        let mut fresh = stale.clone();
        fresh.inventory_epoch = epoch(3);
        fresh.inventory_digest = digest(105);
        fresh.source_report_id = random(106);
        fresh.source_sequence = Sequence::new(2).unwrap();
        let inventory = ScriptedAttestation {
            responses: Mutex::new(VecDeque::from([Ok(stale), Ok(fresh.clone())])),
        };
        let port = ScriptedPort::default();
        port.delete_begins
            .lock()
            .unwrap()
            .push_back(Ok(AtomicDeleteBeginAttempt::FreshInventoryRequired));

        let StateProgress::Next(first_begin) = advance_test(
            &port,
            &inventory,
            &command,
            ColdDeleteStepState::DeleteForceFull {
                strong_stop,
                plan: plan.clone(),
                local_recovery_authority,
            },
        )
        .unwrap() else {
            panic!("Delete ForceFull did not journal begin")
        };
        let StateProgress::Next(retry_force_full) =
            advance_test(&port, &inventory, &command, first_begin).unwrap()
        else {
            panic!("stale Delete attestation did not return to ForceFull")
        };
        let ColdDeleteStepState::DeleteForceFull {
            plan: replayed_plan,
            ..
        } = &retry_force_full
        else {
            panic!("stale Delete attestation selected another retry phase")
        };
        assert_eq!(replayed_plan, &plan);
        let StateProgress::Next(second_begin) =
            advance_test(&port, &inventory, &command, retry_force_full).unwrap()
        else {
            panic!("fresh Delete attestation did not journal retry")
        };
        let ColdDeleteStepState::DeleteBegin { request, .. } = second_begin else {
            panic!("fresh Delete attestation selected another mutation")
        };
        let AtomicDeleteBeginRequest::DisposableRoot {
            command: retried_command,
            persistent_volumes,
            root_durability,
            strong_stop,
        } = request
        else {
            panic!("Delete retry changed the disposable Root branch")
        };
        assert_eq!(retried_command, command_set);
        assert_eq!(persistent_volumes, vec![persistent]);
        assert_eq!(root_durability, root_tail);
        assert_eq!(strong_stop.post_stop_inventory_attestation, fresh);
    }

    #[test]
    fn delete_waits_for_immutable_completion_before_deleted() {
        let command = command(true);
        let strong_stop = strong_stop();
        let root_input = release_input(&command, 0, "delete-root-normal");
        let persistent_input = release_input(&command, 1, "delete-persistent");
        let delete = delete_set(
            &command,
            &root_input.durability,
            std::slice::from_ref(&persistent_input),
        );
        let root_stored = stored_release(&root_input);
        let persistent_stored = stored_release(&persistent_input);
        let begin = AtomicDeleteBeginReceipt::NormallyDeleting {
            dispositions: vec![
                AtomicStoredVolumeDisposition::NormallyReleased {
                    release: root_stored.clone(),
                },
                AtomicStoredVolumeDisposition::NormallyReleased {
                    release: persistent_stored,
                },
            ],
        };
        let local_absence = root_absence(&delete, &begin);
        let completion_receipt = CommandDeleteCompletionReceipt {
            command: delete.clone(),
            root_authority: CommandRootDeleteAuthorityReceipt::NormalRelease(
                root_stored.receipt.clone(),
            ),
            completion: DeleteCompletionReceipt::Normal {
                request: BeginDeleteRequest {
                    delete_id: delete.root_disposition.delete_id.clone(),
                    disk_id: delete.root_disposition.root.disk_id.clone(),
                    volume_id: delete.root_disposition.root.volume_id.clone(),
                    expected_unowned_epoch: root_stored.receipt.result.resulting_epoch,
                    expected_head: root_stored.receipt.result.resulting_head.clone(),
                },
                deleting_epoch: next_epoch(root_stored.receipt.result.resulting_epoch).unwrap(),
                deleting_head: root_stored.receipt.result.resulting_head.clone(),
                completed_at: millis(1_900),
            },
        };
        let completion = AtomicDeleteCompletionEvidence {
            receipt_digest: canonical_digest(DELETE_COMPLETION_DIGEST_DOMAIN, &completion_receipt)
                .unwrap(),
            receipt: completion_receipt,
        };
        let completion_request = AtomicDeleteCompletionRequest {
            operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            expected_runtime_incarnation: strong_stop.stopped_runtime_incarnation.clone(),
            volume_id: delete.root_disposition.root.volume_id.clone(),
            delete_id: delete.root_disposition.delete_id.clone(),
            expected_command: delete,
            expected_begin: begin.clone(),
            post_stop_inventory_attestation: attestation(&command),
            local_recovery_authority: test_local_recovery_authority(&command, &strong_stop),
        };
        let state = ColdDeleteStepState::DeleteAwaitCompletion {
            strong_stop,
            begin,
            root_lineage_absence: local_absence,
            request: completion_request,
        };
        let port = ScriptedPort::default();
        port.completions
            .lock()
            .unwrap()
            .push_back(Err(anyhow::anyhow!("completion pending/response lost")));
        port.completions
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(completion.clone())));
        port.delete_finalizations
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(digest(99))));
        let inventory = ScriptedAttestation {
            responses: Mutex::new(VecDeque::new()),
        };

        assert!(advance_test(&port, &inventory, &command, state.clone()).is_err());
        assert!(port.delete_finalization_requests.lock().unwrap().is_empty());
        let StateProgress::Next(finalize) =
            advance_test(&port, &inventory, &command, state).unwrap()
        else {
            panic!("exact immutable completion did not advance to finalization")
        };
        let StateProgress::Terminal(NodeResult::Deleted(deleted)) =
            advance_test(&port, &inventory, &command, finalize).unwrap()
        else {
            panic!("Delete did not terminate as Deleted after exact completion")
        };
        assert_eq!(deleted.volume_dispositions.len(), 2);
        assert_eq!(port.completion_requests.lock().unwrap().len(), 2);
    }

    #[test]
    fn cold_releases_complete_set_and_never_uses_delete_authority() {
        let command = command(false);
        let strong_stop = strong_stop();
        let request = convergence_request(
            &command,
            &command.runtime_config.volumes,
            strong_stop.stopped_runtime_incarnation.clone(),
            test_local_recovery_authority(&command, &strong_stop),
            cold_spec(&command).unwrap().convergence_deadline_unix_ms,
            "cold",
        )
        .unwrap();
        let inputs = vec![
            release_input(&command, 0, "cold"),
            release_input(&command, 1, "cold"),
        ];
        let stored = inputs.iter().map(stored_release).collect::<Vec<_>>();
        let port = ScriptedPort::default();
        port.convergence
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(
                AtomicVolumeConvergenceReceipt {
                    dispositions: inputs
                        .into_iter()
                        .map(|release| AtomicVolumeDispositionInput::OwnedRelease { release })
                        .collect(),
                },
            )));
        port.cold_releases
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdReleaseAttempt::Exact(
                AtomicColdReleaseReceipt {
                    dispositions: stored
                        .into_iter()
                        .map(|release| AtomicStoredVolumeDisposition::NormallyReleased { release })
                        .collect(),
                },
            )));
        port.cold_finalizations
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(digest(100))));
        let inventory = ScriptedAttestation::returning(attestation(&command));

        let StateProgress::Next(force_full) = advance_test(
            &port,
            &inventory,
            &command,
            ColdDeleteStepState::ColdConverge {
                strong_stop,
                request,
            },
        )
        .unwrap() else {
            panic!("Cold convergence did not advance")
        };
        let StateProgress::Next(release) =
            advance_test(&port, &inventory, &command, force_full).unwrap()
        else {
            panic!("Cold force-Full did not advance")
        };
        let StateProgress::Next(finalize) =
            advance_test(&port, &inventory, &command, release).unwrap()
        else {
            panic!("Cold release did not advance")
        };
        let StateProgress::Terminal(NodeResult::Cold(result)) =
            advance_test(&port, &inventory, &command, finalize).unwrap()
        else {
            panic!("Cold finalization did not return Cold")
        };
        assert_eq!(result.volume_dispositions.len(), 2);
        assert!(result
            .volume_dispositions
            .iter()
            .all(|disposition| matches!(
                disposition,
                ColdVolumeDisposition::NormallyReleased { volume, .. }
                    if volume.local_durable_generation == volume.remote_durable_generation
                        && volume.authority_receipt_digest.is_some()
            )));
        assert!(port.delete_begin_requests.lock().unwrap().is_empty());
    }

    #[test]
    fn cold_mixed_set_force_full_and_returns_closed_dispositions() {
        let command = command_after(false, TerminalResultKind::Killed);
        let strong_stop = strong_stop();
        let request = convergence_request(
            &command,
            &command.runtime_config.volumes,
            strong_stop.stopped_runtime_incarnation.clone(),
            test_local_recovery_authority(&command, &strong_stop),
            cold_spec(&command).unwrap().convergence_deadline_unix_ms,
            "cold",
        )
        .unwrap();
        let root = unowned_input(&command, 0);
        let persistent_release = release_input(&command, 1, "cold");
        let persistent = AtomicVolumeDispositionInput::OwnedRelease {
            release: persistent_release.clone(),
        };
        let stored_root =
            stored_unowned(&command_scope(&command), &root, StoredDispositionUse::Cold);
        let stored_persistent = stored_release(&persistent_release);
        let port = ScriptedPort::default();
        port.convergence
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(
                AtomicVolumeConvergenceReceipt {
                    dispositions: vec![root.clone(), persistent.clone()],
                },
            )));
        port.cold_releases
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdReleaseAttempt::Exact(
                AtomicColdReleaseReceipt {
                    dispositions: vec![
                        AtomicStoredVolumeDisposition::AlreadyUnowned {
                            receipt: stored_root.clone(),
                        },
                        AtomicStoredVolumeDisposition::NormallyReleased {
                            release: stored_persistent.clone(),
                        },
                    ],
                },
            )));
        port.cold_finalizations
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(digest(101))));
        let accepted = attestation(&command);
        let inventory = ScriptedAttestation::returning(accepted.clone());

        let StateProgress::Next(force_full) = advance_test(
            &port,
            &inventory,
            &command,
            ColdDeleteStepState::ColdConverge {
                strong_stop,
                request,
            },
        )
        .unwrap() else {
            panic!("mixed Cold convergence did not reach ForceFull")
        };
        let StateProgress::Next(release) =
            advance_test(&port, &inventory, &command, force_full).unwrap()
        else {
            panic!("mixed Cold ForceFull did not journal a release")
        };
        let ColdDeleteStepState::ColdRelease {
            request: release_request,
            ..
        } = &release
        else {
            panic!("mixed Cold selected another mutation")
        };
        assert_eq!(release_request.dispositions, vec![root, persistent]);
        assert_eq!(
            release_request.strong_stop.post_stop_inventory_attestation,
            accepted
        );
        let StateProgress::Next(finalize) =
            advance_test(&port, &inventory, &command, release).unwrap()
        else {
            panic!("mixed Cold release did not reach local finalization")
        };
        let StateProgress::Terminal(NodeResult::Cold(result)) =
            advance_test(&port, &inventory, &command, finalize).unwrap()
        else {
            panic!("mixed Cold did not settle Cold")
        };
        assert!(matches!(
            &result.volume_dispositions[0],
            ColdVolumeDisposition::AlreadyUnowned {
                volume_id,
                already_unowned_receipt_digest,
                ..
            } if volume_id == &command.runtime_config.volumes[0].volume_id
                && already_unowned_receipt_digest == &stored_root.receipt_digest
        ));
        assert!(matches!(
            &result.volume_dispositions[1],
            ColdVolumeDisposition::NormallyReleased {
                normal_release_receipt_digest,
                ..
            } if normal_release_receipt_digest == &stored_persistent.receipt_digest
        ));
    }

    #[test]
    fn cold_stale_inventory_reenters_force_full_without_changing_mixed_set() {
        let command = command(false);
        let strong_stop = strong_stop();
        let root = unowned_input(&command, 0);
        let persistent = AtomicVolumeDispositionInput::OwnedRelease {
            release: release_input(&command, 1, "cold"),
        };
        let volume_set = ColdCommandVolumeSet {
            scope: command_scope(&command),
            volumes: vec![root.identity(), persistent.identity()],
        };
        let stale = attestation(&command);
        let mut fresh = stale.clone();
        fresh.inventory_epoch = epoch(3);
        fresh.inventory_digest = digest(102);
        fresh.source_report_id = random(103);
        fresh.source_sequence = Sequence::new(2).unwrap();
        let request = AtomicColdReleaseRequest {
            command: volume_set.clone(),
            dispositions: vec![root.clone(), persistent.clone()],
            strong_stop: AtomicDeleteStrongStopEvidence {
                execution_absence: strong_stop.execution_absence.clone(),
                post_stop_inventory_attestation: stale,
                local_recovery_authority: test_local_recovery_authority(&command, &strong_stop),
            },
        };
        let port = ScriptedPort::default();
        port.cold_releases
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdReleaseAttempt::FreshInventoryRequired));
        let inventory = ScriptedAttestation::returning(fresh.clone());

        let StateProgress::Next(force_full) = advance_test(
            &port,
            &inventory,
            &command,
            ColdDeleteStepState::ColdRelease {
                strong_stop,
                request,
            },
        )
        .unwrap() else {
            panic!("stale Cold attestation did not return to ForceFull")
        };
        let ColdDeleteStepState::ColdForceFull {
            command: replayed_set,
            dispositions: replayed_dispositions,
            ..
        } = &force_full
        else {
            panic!("stale Cold attestation selected another retry phase")
        };
        assert_eq!(replayed_set, &volume_set);
        assert_eq!(
            replayed_dispositions,
            &vec![root.clone(), persistent.clone()]
        );
        let StateProgress::Next(release) =
            advance_test(&port, &inventory, &command, force_full).unwrap()
        else {
            panic!("fresh Cold attestation did not journal a retry")
        };
        let ColdDeleteStepState::ColdRelease { request, .. } = release else {
            panic!("fresh Cold attestation selected another mutation")
        };
        assert_eq!(request.command, volume_set);
        assert_eq!(request.dispositions, vec![root, persistent]);
        assert_eq!(request.strong_stop.post_stop_inventory_attestation, fresh);
    }

    #[test]
    fn already_unowned_receipt_rejects_prior_release_from_another_epoch() {
        let command = command(false);
        let prior = stored_release(&release_input(&command, 0, "cold"));
        let identity = prior.receipt.durability.volume.identity();
        let mut receipt = CommandAlreadyUnownedReceipt {
            scope: command_scope(&command),
            volume: identity.clone(),
            expected_epoch: prior.receipt.result.resulting_epoch,
            expected_head: prior.receipt.result.resulting_head.clone(),
            provenance: AlreadyUnownedProvenance::NormalRelease {
                receipt: Box::new(prior.receipt.clone()),
                receipt_digest: prior.receipt_digest,
            },
        };
        let receipt_digest = cats_storage::lifecycle_volume::
            command_cold_already_unowned_receipt_digest_from_closed_receipt(&receipt)
            .unwrap();
        receipt.expected_epoch = next_epoch(receipt.expected_epoch).unwrap();
        let stored = AtomicStoredAlreadyUnownedReceipt {
            receipt_digest,
            receipt,
        };

        assert!(validate_stored_already_unowned(
            &command_scope(&command),
            &identity,
            stored.receipt.expected_epoch,
            &stored.receipt.expected_head,
            &stored,
            StoredDispositionUse::Cold,
        )
        .is_err());
    }

    #[test]
    fn start_failed_then_killed_then_delete_closes_original_terminal_manifest() {
        let command = command_after(true, TerminalResultKind::Killed);
        let runtime_incarnation = random(15);
        let manifest = terminal_retained_manifest(
            &command,
            id("operation.original.start"),
            digest(190),
            runtime_incarnation.clone(),
        );
        let mut fresh = strong_stop();
        fresh.stopped_runtime_incarnation = Some(runtime_incarnation);
        fresh.retained_volume_receipts = manifest.retained_volume_receipts.clone();
        fresh.retained_evidence = RetainedEvidence {
            artifact_manifest_digest: digest(191),
            adoptable_count: 0,
            gc_candidate_count: 0,
            retained_authority_or_data_count: 2,
            quarantined_count: 0,
        };
        let predecessor = non_warm_predecessor_response(&command, Some(&fresh));
        let authority = local_recovery_authority(&command, Some(&predecessor), &fresh).unwrap();

        assert_ne!(
            manifest.source_lifecycle_operation_id,
            predecessor.operation_id
        );
        validate_terminal_retained_cleanup_binding(
            &command,
            &manifest,
            fresh.stopped_runtime_incarnation.as_ref(),
            &authority,
        )
        .unwrap();
        validate_local_start_manifest_cardinality(false, 0, 1, &authority).unwrap();
    }

    #[test]
    fn killed_bridge_rejects_replaced_projection_and_missing_volume() {
        let command = command_after(true, TerminalResultKind::Killed);
        let manifest = terminal_retained_manifest(
            &command,
            id("operation.original.start"),
            digest(192),
            random(15),
        );
        let mut fresh = strong_stop();
        fresh.retained_volume_receipts = manifest.retained_volume_receipts.clone();
        fresh.retained_evidence = RetainedEvidence {
            artifact_manifest_digest: digest(193),
            adoptable_count: 0,
            gc_candidate_count: 0,
            retained_authority_or_data_count: 2,
            quarantined_count: 0,
        };
        let predecessor = non_warm_predecessor_response(&command, Some(&fresh));
        let mut replaced_projection = fresh.clone();
        replaced_projection
            .retained_evidence
            .artifact_manifest_digest = digest(194);
        assert!(
            local_recovery_authority(&command, Some(&predecessor), &replaced_projection,).is_err()
        );

        let mut missing = local_recovery_authority(&command, Some(&predecessor), &fresh).unwrap();
        let AtomicLocalRecoveryAuthority::KilledRetained {
            retained_volume_receipts,
            ..
        } = &mut missing
        else {
            unreachable!()
        };
        retained_volume_receipts.pop();
        assert!(validate_terminal_retained_cleanup_binding(
            &command,
            &manifest,
            fresh.stopped_runtime_incarnation.as_ref(),
            &missing,
        )
        .is_err());
    }

    #[test]
    fn killed_bridge_rejects_multiple_terminal_manifests() {
        let command = command_after(true, TerminalResultKind::Killed);
        let fresh = strong_stop();
        let authority = test_local_recovery_authority(&command, &fresh);

        assert!(validate_local_start_manifest_cardinality(false, 0, 2, &authority).is_err());
        assert!(validate_local_start_manifest_cardinality(false, 1, 1, &authority).is_err());
    }

    #[test]
    fn killed_bridge_requires_current_operation_terminal_progress_when_not_inherited() {
        let command = command_after(true, TerminalResultKind::Killed);
        let mut manifest = terminal_retained_manifest(
            &command,
            id("operation.original.start"),
            digest(195),
            random(15),
        );
        let mut fresh = strong_stop();
        fresh.retained_volume_receipts = manifest.retained_volume_receipts.clone();
        fresh.retained_evidence = RetainedEvidence {
            artifact_manifest_digest: digest(196),
            adoptable_count: 0,
            gc_candidate_count: 0,
            retained_authority_or_data_count: 2,
            quarantined_count: 0,
        };
        let predecessor = non_warm_predecessor_response(&command, Some(&fresh));
        let authority = local_recovery_authority(&command, Some(&predecessor), &fresh).unwrap();
        validate_terminal_retained_cleanup_binding(
            &command,
            &manifest,
            fresh.stopped_runtime_incarnation.as_ref(),
            &authority,
        )
        .unwrap();

        manifest.runtime_progress = None;
        manifest.manifest_digest =
            super::super::start::terminal_retained_runtime_manifest_digest(&manifest).unwrap();
        assert!(validate_terminal_retained_cleanup_binding(
            &command,
            &manifest,
            fresh.stopped_runtime_incarnation.as_ref(),
            &authority,
        )
        .is_err());
    }

    #[test]
    fn suspended_predecessor_carrier_keeps_original_start_manifest_and_rejects_tamper() {
        let mut command = command_after(false, TerminalResultKind::Suspended);
        let installed = carrier_installed_runtime(&command, random(260));
        let predecessor = carrier_predecessor_response(&command, &installed, false);
        bind_predecessor_terminal_digest(&mut command, &predecessor);
        let predecessor_digest = match &command.predecessor {
            LifecyclePredecessor::SameNode {
                terminal_result_digest,
                ..
            } => terminal_result_digest.clone(),
            _ => unreachable!(),
        };
        let physical = carrier_physical(&installed, &predecessor, false, predecessor_digest);
        let carrier = owned_predecessor_carrier(&command, &predecessor, &physical).unwrap();
        let mut fresh = strong_stop();
        fresh.stopped_runtime_incarnation = None;
        let authority = local_recovery_authority_with_carrier(
            &command,
            Some(&predecessor),
            &fresh,
            Some(&carrier),
            None,
        )
        .unwrap();

        assert_ne!(
            carrier.installed_runtime.source_lifecycle_operation_id,
            predecessor.operation_id
        );
        assert_eq!(
            local_recovery_runtime_incarnation(&authority, &fresh),
            Some(installed.runtime_incarnation.clone())
        );
        validate_expected_local_recovery_authority(
            &command,
            Some(&predecessor),
            &fresh,
            &authority,
        )
        .unwrap();

        let mut tampered = carrier;
        tampered.volumes[0].local_lineage_data_directory =
            HostPath::new("/var/lib/cats/replaced-lineage").unwrap();
        assert!(validate_owned_predecessor_carrier(&command, &predecessor, &tampered).is_err());
    }

    #[test]
    fn failed_suspend_predecessor_carrier_binds_exact_terminal_response() {
        let mut command = command_after(false, TerminalResultKind::SuspendFailed);
        let installed = carrier_installed_runtime(&command, random(261));
        let predecessor = carrier_predecessor_response(&command, &installed, true);
        bind_predecessor_terminal_digest(&mut command, &predecessor);
        let predecessor_digest = match &command.predecessor {
            LifecyclePredecessor::SameNode {
                terminal_result_digest,
                ..
            } => terminal_result_digest.clone(),
            _ => unreachable!(),
        };
        let physical = carrier_physical(&installed, &predecessor, true, predecessor_digest);
        let carrier = owned_predecessor_carrier(&command, &predecessor, &physical).unwrap();
        let mut fresh = strong_stop();
        fresh.stopped_runtime_incarnation = None;
        local_recovery_authority_with_carrier(
            &command,
            Some(&predecessor),
            &fresh,
            Some(&carrier),
            None,
        )
        .unwrap();

        let mut replaced = predecessor;
        let NodeResult::SuspendFailed(failed) = &mut replaced.result else {
            unreachable!()
        };
        failed.retained_evidence.artifact_manifest_digest = digest(247);
        assert!(validate_owned_predecessor_carrier(&command, &replaced, &carrier).is_err());
    }

    #[test]
    fn same_command_needs_intervention_retry_binds_exact_r_less_than_l_projection() {
        let mut command = command_after(false, TerminalResultKind::NeedsIntervention);
        let mut fresh = strong_stop();
        let volume = &command.runtime_config.volumes[1];
        fresh.retained_volume_receipts = vec![VolumeTerminalReceipt {
            volume_id: volume.volume_id.clone(),
            disk_id: volume.disk_id.clone(),
            disk_role: volume.disk_role,
            attachment_id: id("attachment.needs-intervention"),
            attachment_epoch: fence_epoch(23),
            local_durable_generation: generation(9),
            remote_durable_generation: generation(8),
            authority_receipt_digest: Some(digest(221)),
        }];
        fresh.retained_evidence.retained_authority_or_data_count = 1;
        let predecessor = needs_intervention_predecessor_response(
            &command,
            &fresh,
            InterventionTarget::Cold,
            InterventionReason::PersistentDiskNotRemoteDurable,
        );
        bind_predecessor_terminal_digest(&mut command, &predecessor);

        let authority = local_recovery_authority(&command, Some(&predecessor), &fresh).unwrap();
        validate_expected_local_recovery_authority(
            &command,
            Some(&predecessor),
            &fresh,
            &authority,
        )
        .unwrap();
        assert!(matches!(
            &authority,
            AtomicLocalRecoveryAuthority::NeedsInterventionRetry { .. }
        ));

        let mut changed_watermark = fresh.clone();
        changed_watermark.retained_volume_receipts[0].remote_durable_generation = generation(7);
        assert!(
            local_recovery_authority(&command, Some(&predecessor), &changed_watermark,).is_err()
        );

        let mut changed_digest = authority;
        let AtomicLocalRecoveryAuthority::NeedsInterventionRetry {
            predecessor_terminal_result_digest,
            ..
        } = &mut changed_digest
        else {
            unreachable!()
        };
        *predecessor_terminal_result_digest = digest(222);
        assert!(validate_local_recovery_authority(&command, &changed_digest).is_err());
    }

    #[test]
    fn needs_intervention_retry_rejects_cross_target_and_foreign_residue() {
        let mut cross_target_command = command_after(false, TerminalResultKind::NeedsIntervention);
        let fresh = strong_stop();
        let cross_target = needs_intervention_predecessor_response(
            &cross_target_command,
            &fresh,
            InterventionTarget::Delete,
            InterventionReason::LocalLineageAbsenceUnproven,
        );
        bind_predecessor_terminal_digest(&mut cross_target_command, &cross_target);
        assert!(
            local_recovery_authority(&cross_target_command, Some(&cross_target), &fresh,).is_err()
        );

        let mut foreign_command = command_after(false, TerminalResultKind::NeedsIntervention);
        let foreign = needs_intervention_predecessor_response(
            &foreign_command,
            &fresh,
            InterventionTarget::Cold,
            InterventionReason::ForeignOrAmbiguousResidue,
        );
        bind_predecessor_terminal_digest(&mut foreign_command, &foreign);
        assert!(local_recovery_authority(&foreign_command, Some(&foreign), &fresh).is_err());

        let mut quarantined_command = command_after(false, TerminalResultKind::NeedsIntervention);
        let mut quarantined_fresh = fresh;
        quarantined_fresh.retained_evidence.quarantined_count = 1;
        let quarantined = needs_intervention_predecessor_response(
            &quarantined_command,
            &quarantined_fresh,
            InterventionTarget::Cold,
            InterventionReason::LocalLineageAbsenceUnproven,
        );
        bind_predecessor_terminal_digest(&mut quarantined_command, &quarantined);
        assert!(local_recovery_authority(
            &quarantined_command,
            Some(&quarantined),
            &quarantined_fresh,
        )
        .is_err());
    }

    #[test]
    fn direct_start_failed_keeps_exact_source_and_manifest_digest() {
        let command = command_after(true, TerminalResultKind::StartFailed);
        let mut fresh = strong_stop();
        let predecessor = non_warm_predecessor_response(&command, Some(&fresh));
        let mut manifest = terminal_retained_manifest(
            &command,
            predecessor.operation_id.clone(),
            predecessor.request_fingerprint.clone(),
            random(15),
        );
        fresh.stopped_runtime_incarnation = Some(manifest.runtime_incarnation.clone());
        let mut predecessor = predecessor;
        let NodeResult::StartFailed(failed) = &mut predecessor.result else {
            unreachable!()
        };
        failed.retained_evidence.artifact_manifest_digest = manifest.manifest_digest.clone();
        let authority = local_recovery_authority(&command, Some(&predecessor), &fresh).unwrap();
        validate_terminal_retained_cleanup_binding(
            &command,
            &manifest,
            fresh.stopped_runtime_incarnation.as_ref(),
            &authority,
        )
        .unwrap();

        manifest.source_lifecycle_operation_id = id("operation.replaced.start");
        let runtime_progress = manifest.runtime_progress.as_mut().unwrap();
        runtime_progress.source_lifecycle_operation_id =
            manifest.source_lifecycle_operation_id.clone();
        runtime_progress.manifest_digest =
            super::super::start::installed_runtime_progress_manifest_digest(runtime_progress)
                .unwrap();
        manifest.manifest_digest =
            super::super::start::terminal_retained_runtime_manifest_digest(&manifest).unwrap();
        super::super::start::validate_terminal_retained_runtime_manifest(&manifest, None).unwrap();
        assert!(validate_terminal_retained_cleanup_binding(
            &command,
            &manifest,
            fresh.stopped_runtime_incarnation.as_ref(),
            &authority,
        )
        .is_err());
    }

    #[test]
    fn warm_start_failed_cold_journals_retained_remove_and_replays_exactly() {
        let fixture = retained_warm_start_failed_fixture(false, true);
        let command = &fixture.command;
        let inputs = [
            release_input(command, 0, "cold"),
            release_input(command, 1, "cold"),
        ];
        let dispositions = inputs
            .iter()
            .cloned()
            .map(|release| AtomicVolumeDispositionInput::OwnedRelease { release })
            .collect::<Vec<_>>();
        let stored = inputs
            .iter()
            .map(stored_release)
            .map(|release| AtomicStoredVolumeDisposition::NormallyReleased { release })
            .collect::<Vec<_>>();
        let request = AtomicColdReleaseRequest {
            command: ColdCommandVolumeSet {
                scope: command_scope(command),
                volumes: dispositions
                    .iter()
                    .map(AtomicVolumeDispositionInput::identity)
                    .collect(),
            },
            dispositions,
            strong_stop: AtomicDeleteStrongStopEvidence {
                execution_absence: fixture.strong_stop.execution_absence.clone(),
                post_stop_inventory_attestation: attestation(command),
                local_recovery_authority: fixture.local_recovery_authority.clone(),
            },
        };
        let port = ScriptedPort::default();
        port.cold_releases
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdReleaseAttempt::Exact(
                AtomicColdReleaseReceipt {
                    dispositions: stored,
                },
            )));
        let inventory = ScriptedAttestation {
            responses: Mutex::new(VecDeque::new()),
        };
        let StateProgress::Next(remove) = advance_volume_state(
            &port,
            &inventory,
            None,
            Some(&fixture.state_directory),
            command,
            Some(&fixture.predecessor),
            ColdDeleteStepState::ColdRelease {
                strong_stop: fixture.strong_stop.clone(),
                request,
            },
        )
        .unwrap() else {
            panic!("Cold release did not journal retained Warm removal")
        };
        let ColdDeleteStepState::ColdRemoveWarmCleanup {
            finalization,
            authority,
            ..
        } = &remove
        else {
            panic!("retained Warm Cold incorrectly skipped to finalization")
        };
        assert_eq!(
            authority,
            fixture.cleanup.as_ref().unwrap().authority.as_ref()
        );
        assert_eq!(
            super::super::start::enumerate_terminal_retained_runtime_manifests(
                &fixture.state_directory,
            )
            .unwrap(),
            vec![fixture.manifest.clone()]
        );

        let durable = encode_step(command, remove.clone()).unwrap();
        for _ in 0..2 {
            let replay = decode_step(command, &durable).unwrap().state;
            let ColdDeleteStepState::ColdRemoveWarmCleanup {
                finalization,
                authority,
                ..
            } = replay
            else {
                panic!("Cold retained Warm replay changed durable phase")
            };
            validate_warm_cleanup_authority(
                Some(&fixture.state_directory),
                command,
                Some(&fixture.predecessor),
                &finalization.local_recovery_authority,
                &authority,
            )
            .unwrap();
        }
        assert_eq!(
            finalization.local_recovery_authority,
            fixture.local_recovery_authority
        );
    }

    #[test]
    fn warm_start_failed_delete_journals_retained_remove_before_terminal_cleanup() {
        let fixture = retained_warm_start_failed_fixture(true, true);
        let command = &fixture.command;
        let root_input = release_input(command, 0, "delete-root-normal");
        let persistent_input = release_input(command, 1, "delete-persistent");
        let delete = delete_set(
            command,
            &root_input.durability,
            std::slice::from_ref(&persistent_input),
        );
        let begin = AtomicDeleteBeginReceipt::NormallyDeleting {
            dispositions: vec![
                AtomicStoredVolumeDisposition::NormallyReleased {
                    release: stored_release(&root_input),
                },
                AtomicStoredVolumeDisposition::NormallyReleased {
                    release: stored_release(&persistent_input),
                },
            ],
        };
        let root_lineage_absence = root_absence(&delete, &begin);
        let completion = normal_completion(&delete, &begin);
        let request = AtomicDeleteCompletionRequest {
            operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            expected_runtime_incarnation: fixture.strong_stop.stopped_runtime_incarnation.clone(),
            volume_id: delete.root_disposition.root.volume_id.clone(),
            delete_id: delete.root_disposition.delete_id.clone(),
            expected_command: delete,
            expected_begin: begin.clone(),
            post_stop_inventory_attestation: attestation(command),
            local_recovery_authority: fixture.local_recovery_authority.clone(),
        };
        let port = ScriptedPort::default();
        port.completions
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(completion)));
        let inventory = ScriptedAttestation {
            responses: Mutex::new(VecDeque::new()),
        };
        let StateProgress::Next(remove) = advance_volume_state(
            &port,
            &inventory,
            None,
            Some(&fixture.state_directory),
            command,
            Some(&fixture.predecessor),
            ColdDeleteStepState::DeleteAwaitCompletion {
                strong_stop: fixture.strong_stop.clone(),
                begin,
                root_lineage_absence,
                request,
            },
        )
        .unwrap() else {
            panic!("Delete completion did not journal retained Warm removal")
        };
        let ColdDeleteStepState::DeleteRemoveWarmCleanup {
            finalization,
            authority,
            ..
        } = &remove
        else {
            panic!("retained Warm Delete incorrectly skipped to finalization")
        };
        assert_eq!(
            authority,
            fixture.cleanup.as_ref().unwrap().authority.as_ref()
        );
        validate_warm_cleanup_authority(
            Some(&fixture.state_directory),
            command,
            Some(&fixture.predecessor),
            &finalization.local_recovery_authority,
            authority,
        )
        .unwrap();
        assert_eq!(
            super::super::start::enumerate_terminal_retained_runtime_manifests(
                &fixture.state_directory,
            )
            .unwrap(),
            vec![fixture.manifest]
        );
        assert!(matches!(
            decode_step(command, &encode_step(command, remove).unwrap())
                .unwrap()
                .state,
            ColdDeleteStepState::DeleteRemoveWarmCleanup { .. }
        ));
    }

    #[test]
    fn retained_warm_start_failed_cleanup_rejects_carrier_tamper_and_missing_manifest() {
        for delete in [false, true] {
            let fixture = retained_warm_start_failed_fixture(delete, true);
            let mut tampered = fixture.cleanup.clone().unwrap();
            let mut encoded = serde_json::to_value(tampered.carrier.as_ref()).unwrap();
            encoded["carrier_digest"] = serde_json::to_value(digest(241)).unwrap();
            *tampered.carrier = serde_json::from_value(encoded).unwrap();
            assert!(local_recovery_authority_with_carrier(
                &fixture.command,
                Some(&fixture.predecessor),
                &fixture.strong_stop,
                None,
                Some(&tampered),
            )
            .is_err());

            assert!(
                super::super::start::remove_terminal_retained_runtime_manifest_exact(
                    &fixture.state_directory,
                    &fixture.manifest,
                )
                .unwrap()
            );
            assert!(validate_retained_start_failed_warm_cleanup(
                &fixture.state_directory,
                &fixture.command,
                Some(&fixture.predecessor),
                fixture.cleanup.as_ref().unwrap(),
            )
            .is_err());
        }
    }

    #[test]
    fn start_failed_without_retained_warm_carrier_keeps_normal_cold_delete_path() {
        for delete in [false, true] {
            let fixture = retained_warm_start_failed_fixture(delete, false);
            assert!(fixture.cleanup.is_none());
            assert!(retained_warm_cleanup_authority(&fixture.local_recovery_authority).is_none());
            validate_expected_local_recovery_authority(
                &fixture.command,
                Some(&fixture.predecessor),
                &fixture.strong_stop,
                &fixture.local_recovery_authority,
            )
            .unwrap();
        }
    }

    #[test]
    fn delete_from_cold_all_unowned_never_synthesizes_an_attachment() {
        let command = command_after(true, TerminalResultKind::Cold);
        let mut strong_stop = strong_stop();
        strong_stop.stopped_runtime_incarnation = None;
        let persistent = unowned_input(&command, 1);
        let root = unowned_input(&command, 0);
        let convergence = convergence_request(
            &command,
            &command
                .runtime_config
                .volumes
                .iter()
                .filter(|volume| volume.disk_role == DiskRole::Persistent)
                .cloned()
                .collect::<Vec<_>>(),
            None,
            test_local_recovery_authority(&command, &strong_stop),
            delete_spec(&command).unwrap().convergence_deadline_unix_ms,
            "delete-persistent",
        )
        .unwrap();
        let root_identity = root.identity();
        let AtomicVolumeDispositionInput::AlreadyUnowned {
            expected_epoch: root_epoch,
            expected_head: root_head,
            ..
        } = &root
        else {
            unreachable!()
        };
        let delete = delete_command_volume_set(&command, root_identity.clone()).unwrap();
        let stored_root = stored_unowned(&delete.scope, &root, StoredDispositionUse::Delete);
        let stored_persistent =
            stored_unowned(&delete.scope, &persistent, StoredDispositionUse::Delete);
        let begin = AtomicDeleteBeginReceipt::NormallyDeleting {
            dispositions: vec![
                AtomicStoredVolumeDisposition::AlreadyUnowned {
                    receipt: stored_root.clone(),
                },
                AtomicStoredVolumeDisposition::AlreadyUnowned {
                    receipt: stored_persistent.clone(),
                },
            ],
        };
        let absence = root_absence(&delete, &begin);
        let completion = normal_completion(&delete, &begin);
        let port = ScriptedPort::default();
        port.convergence
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(
                AtomicVolumeConvergenceReceipt {
                    dispositions: vec![persistent.clone()],
                },
            )));
        port.roots
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(
                AtomicDeleteRootInspection::AlreadyUnowned {
                    volume: root_identity,
                    expected_epoch: *root_epoch,
                    expected_head: root_head.clone(),
                },
            )));
        port.delete_begins
            .lock()
            .unwrap()
            .push_back(Ok(AtomicDeleteBeginAttempt::Exact(begin.clone())));
        port.root_cleanups
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(absence.clone())));
        port.completions
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(completion)));
        port.delete_finalizations
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(digest(104))));
        let inventory = ScriptedAttestation::returning(attestation(&command));

        let mut state = ColdDeleteStepState::DeleteConvergePersistent {
            strong_stop,
            request: convergence,
        };
        for expected_phase in [
            "inspect-root",
            "force-full",
            "begin",
            "cleanup-root",
            "await-completion",
            "finalize",
        ] {
            let StateProgress::Next(next) =
                advance_test(&port, &inventory, &command, state).unwrap()
            else {
                panic!("Delete from Cold terminated before {expected_phase}")
            };
            state = next;
        }
        let StateProgress::Terminal(NodeResult::Deleted(result)) =
            advance_test(&port, &inventory, &command, state).unwrap()
        else {
            panic!("all-unowned Delete did not settle Deleted")
        };
        assert!(matches!(
            &result.volume_dispositions[0],
            CompletedVolumeDisposition::RootAlreadyUnownedDeleted {
                already_unowned_receipt_digest,
                ..
            } if already_unowned_receipt_digest == &stored_root.receipt_digest
        ));
        assert!(matches!(
            &result.volume_dispositions[1],
            CompletedVolumeDisposition::PersistentAlreadyDetached {
                already_unowned_receipt_digest,
                ..
            } if already_unowned_receipt_digest == &stored_persistent.receipt_digest
        ));
        assert!(matches!(
            absence,
            AtomicRootLineageAbsenceReceipt::AlreadyUnowned { .. }
        ));
        let requests = port.delete_begin_requests.lock().unwrap();
        let AtomicDeleteBeginRequest::Normal { volumes, .. } = &requests[0] else {
            panic!("already-Unowned Root incorrectly selected disposable Delete")
        };
        assert!(volumes
            .iter()
            .all(|volume| matches!(volume, AtomicVolumeDispositionInput::AlreadyUnowned { .. })));
    }

    #[test]
    fn start_failed_zero_acquire_delete_plans_complete_unowned_set() {
        let command = command_after(true, TerminalResultKind::StartFailed);
        let mut strong_stop = strong_stop();
        strong_stop.stopped_runtime_incarnation = None;
        let persistent = unowned_input(&command, 1);
        let root = unowned_input(&command, 0);
        let request = convergence_request(
            &command,
            &command.runtime_config.volumes[1..],
            None,
            test_local_recovery_authority(&command, &strong_stop),
            delete_spec(&command).unwrap().convergence_deadline_unix_ms,
            "delete-persistent",
        )
        .unwrap();
        let port = ScriptedPort::default();
        port.convergence
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(
                AtomicVolumeConvergenceReceipt {
                    dispositions: vec![persistent.clone()],
                },
            )));
        let AtomicVolumeDispositionInput::AlreadyUnowned {
            volume,
            expected_epoch,
            expected_head,
        } = root.clone()
        else {
            unreachable!()
        };
        port.roots
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(
                AtomicDeleteRootInspection::AlreadyUnowned {
                    volume,
                    expected_epoch,
                    expected_head,
                },
            )));
        let inventory = ScriptedAttestation {
            responses: Mutex::new(VecDeque::new()),
        };

        let StateProgress::Next(inspect_root) = advance_test(
            &port,
            &inventory,
            &command,
            ColdDeleteStepState::DeleteConvergePersistent {
                strong_stop,
                request,
            },
        )
        .unwrap() else {
            panic!("zero-acquire Delete did not inspect Root")
        };
        let StateProgress::Next(force_full) =
            advance_test(&port, &inventory, &command, inspect_root).unwrap()
        else {
            panic!("zero-acquire Delete did not form a mixed plan")
        };
        let ColdDeleteStepState::DeleteForceFull {
            plan: AtomicDeleteBeginPlan::Normal { volumes, .. },
            ..
        } = force_full
        else {
            panic!("zero-acquire Delete selected a disposable/owned-only branch")
        };
        assert_eq!(volumes, vec![root, persistent]);
    }

    #[test]
    fn killed_partial_owned_delete_preserves_each_closed_slot_branch() {
        let command = command_after(true, TerminalResultKind::Killed);
        let strong_stop = strong_stop();
        let persistent = unowned_input(&command, 1);
        let root_release = release_input(&command, 0, "delete-root-normal");
        let request = convergence_request(
            &command,
            &command.runtime_config.volumes[1..],
            strong_stop.stopped_runtime_incarnation.clone(),
            test_local_recovery_authority(&command, &strong_stop),
            delete_spec(&command).unwrap().convergence_deadline_unix_ms,
            "delete-persistent",
        )
        .unwrap();
        let port = ScriptedPort::default();
        port.convergence
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(
                AtomicVolumeConvergenceReceipt {
                    dispositions: vec![persistent.clone()],
                },
            )));
        port.roots
            .lock()
            .unwrap()
            .push_back(Ok(AtomicColdDeleteAttempt::Exact(
                AtomicDeleteRootInspection::Owned {
                    durability: root_release.durability.clone(),
                },
            )));
        let inventory = ScriptedAttestation {
            responses: Mutex::new(VecDeque::new()),
        };

        let StateProgress::Next(inspect_root) = advance_test(
            &port,
            &inventory,
            &command,
            ColdDeleteStepState::DeleteConvergePersistent {
                strong_stop,
                request,
            },
        )
        .unwrap() else {
            panic!("partial-owned Delete did not inspect Root")
        };
        let StateProgress::Next(force_full) =
            advance_test(&port, &inventory, &command, inspect_root).unwrap()
        else {
            panic!("partial-owned Delete did not form a mixed plan")
        };
        let ColdDeleteStepState::DeleteForceFull {
            plan: AtomicDeleteBeginPlan::Normal { volumes, .. },
            ..
        } = force_full
        else {
            panic!("converged owned Root selected the disposable branch")
        };
        assert!(matches!(
            &volumes[0],
            AtomicVolumeDispositionInput::OwnedRelease { release }
                if release == &root_release
        ));
        assert_eq!(volumes[1], persistent);
    }

    fn test_lineage_identity() -> AttachmentLineageIdentity {
        AttachmentLineageIdentity {
            volume_id: id("volume.00.root"),
            attachment_id: id("attachment.0"),
            attachment_epoch: fence_epoch(10),
            acquire_origin: AcquireOrigin::Normal {
                transition_id: random(600),
            },
            node_id: id("node.a"),
            placement_epoch: epoch(1),
        }
    }

    #[test]
    fn proven_absent_lineage_uses_exact_authority_head_but_missing_materialized_path_fails() {
        let directory = tempfile::tempdir().unwrap();
        let physical_root = fs::canonicalize(directory.path()).unwrap();
        let identity = test_lineage_identity();
        let remote = remote_head(8);
        let base = InstalledOwnedLineage {
            volume_id: identity.volume_id.clone(),
            disk_id: id("disk.root"),
            disk_role: DiskRole::Root,
            attachment_id: identity.attachment_id.clone(),
            attachment_epoch: identity.attachment_epoch,
            acquire_origin: identity.acquire_origin.clone(),
            authority_receipt_digest: Some(digest(197)),
            authority_head_at_install: remote.clone(),
            storage: InstalledLineageStorage::ProvenAbsent,
        };

        assert_eq!(
            inspect_installed_lineage_durability(&base, &identity, &remote).unwrap(),
            (generation(8), WireU64::new(0).unwrap())
        );

        let missing = InstalledOwnedLineage {
            storage: InstalledLineageStorage::Materialized(
                HostPath::new(physical_root.join("missing-lineage").display().to_string()).unwrap(),
            ),
            ..base
        };
        assert!(inspect_installed_lineage_durability(&missing, &identity, &remote).is_err());
    }

    fn create_test_lineage(root: PathBuf, identity: &AttachmentLineageIdentity) -> PathBuf {
        // macOS exposes its temporary directory through `/var`, which is a
        // symlink to `/private/var`. Production traversal correctly refuses
        // symlink components, so fixtures use the resolved physical parent.
        let root = fs::canonicalize(root).unwrap();
        let lineage = root.join("lineage");
        fs::create_dir_all(lineage.join(cats_api::blockd::PENDING_PACK_DIR)).unwrap();
        fs::write(
            lineage.join("identity.json"),
            serde_json::to_vec(identity).unwrap(),
        )
        .unwrap();
        lineage
    }

    fn write_test_pack(
        lineage: &Path,
        identity: &AttachmentLineageIdentity,
        base_generation: i64,
        txn: &str,
    ) -> PathBuf {
        let header = cats_blockd::format::PackHeader {
            txn: txn.to_owned(),
            volume_id: identity.volume_id.to_string(),
            base_generation,
            lease_epoch: None,
            attachment_id: Some(identity.attachment_id.to_string()),
            attachment_epoch: Some(i64::try_from(identity.attachment_epoch.get()).unwrap()),
            acquire_origin: Some(identity.acquire_origin.clone()),
            entries: Vec::new(),
        };
        let path = lineage
            .join(cats_api::blockd::PENDING_PACK_DIR)
            .join(format!(
                "{base_generation:020}-{txn}{}",
                cats_api::blockd::PACK_FILE_SUFFIX
            ));
        fs::write(&path, cats_blockd::format::encode_pack(&header, &[])).unwrap();
        path
    }

    #[test]
    fn read_only_lineage_join_never_removes_covered_pack() {
        let directory = tempfile::tempdir().unwrap();
        let identity = test_lineage_identity();
        let lineage = create_test_lineage(directory.path().to_path_buf(), &identity);
        let covered = write_test_pack(&lineage, &identity, 7, "covered");
        let remote = remote_head(8);

        let (local, pending) =
            inspect_lineage_durability_read_only(&lineage, &identity, &remote).unwrap();
        assert_eq!(local, generation(8));
        assert_eq!(pending, WireU64::new(0).unwrap());
        assert!(
            covered.exists(),
            "observation-only join mutated the lineage"
        );

        let (local, pending) = inspect_lineage_durability(&lineage, &identity, &remote).unwrap();
        assert_eq!(local, generation(8));
        assert_eq!(pending, WireU64::new(0).unwrap());
        assert!(
            !covered.exists(),
            "terminal join did not clean covered residue"
        );
    }

    #[test]
    fn local_lineage_join_closes_exact_relaxed_tail_and_rejects_temp_read_only() {
        let directory = tempfile::tempdir().unwrap();
        let identity = test_lineage_identity();
        let lineage = create_test_lineage(directory.path().to_path_buf(), &identity);
        write_test_pack(&lineage, &identity, 8, "retained");
        let remote = remote_head(8);

        let (local, pending) =
            inspect_lineage_durability_read_only(&lineage, &identity, &remote).unwrap();
        assert_eq!(local, generation(9));
        assert_eq!(pending, WireU64::new(1).unwrap());

        let temp = lineage
            .join(cats_api::blockd::PENDING_PACK_DIR)
            .join(".tmp-torn");
        fs::write(&temp, b"unacknowledged").unwrap();
        assert!(inspect_lineage_durability_read_only(&lineage, &identity, &remote).is_err());
        assert!(temp.exists());
        let (local, pending) = inspect_lineage_durability(&lineage, &identity, &remote).unwrap();
        assert_eq!(local, generation(9));
        assert_eq!(pending, WireU64::new(1).unwrap());
        assert!(!temp.exists());
    }

    #[test]
    fn descriptor_cleanup_marker_recovers_response_loss_without_path_guessing() {
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("state");
        fs::create_dir(&state_path).unwrap();
        let state = StateDirectory::unanchored(state_path);
        let identity = test_lineage_identity();
        let lineage = create_test_lineage(directory.path().to_path_buf(), &identity);
        fs::create_dir(lineage.join("cache")).unwrap();
        fs::write(lineage.join("cache").join("page"), b"cache").unwrap();
        let target = local_cleanup_target(&lineage, identity).unwrap();
        let command = command(true);
        let marker = LocalCleanupMarker::new(
            &command,
            LocalCleanupPhase::DeleteRoot,
            digest(111),
            vec![target],
        )
        .unwrap();
        publish_cleanup_marker(&state, &command, &marker).unwrap();

        remove_cleanup_target(&marker.targets[0]).unwrap();
        assert!(!lineage.exists());
        let mut replay = load_cleanup_marker(&state, &command, LocalCleanupPhase::DeleteRoot)
            .unwrap()
            .unwrap();
        assert!(
            !replay.completed,
            "simulated crash unexpectedly completed marker"
        );
        remove_cleanup_target(&replay.targets[0]).unwrap();
        verify_cleanup_target_absent(&replay.targets[0]).unwrap();
        replay.mark_completed().unwrap();
        publish_cleanup_marker(&state, &command, &replay).unwrap();
        assert!(
            load_cleanup_marker(&state, &command, LocalCleanupPhase::DeleteRoot)
                .unwrap()
                .unwrap()
                .completed
        );
    }

    #[test]
    fn descriptor_cleanup_refuses_symlink_before_touching_external_target() {
        let directory = tempfile::tempdir().unwrap();
        let identity = test_lineage_identity();
        let lineage = create_test_lineage(directory.path().to_path_buf(), &identity);
        let external = directory.path().join("external");
        fs::write(&external, b"must-survive").unwrap();
        symlink(&external, lineage.join("aaa-link")).unwrap();
        let target = local_cleanup_target(&lineage, identity).unwrap();

        assert!(remove_cleanup_target(&target).is_err());
        assert_eq!(fs::read(&external).unwrap(), b"must-survive");
        assert!(lineage.join("identity.json").exists());
    }
}
