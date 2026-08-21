//! Installed atomic Suspend and Warm command handlers.
//!
//! The durable lifecycle journal owns the orchestration edge.  Every method on
//! [`SuspendWarmPlatformPort`] is an inspect-or-apply operation: it first
//! performs a fresh exact inspection, submits at most one physical effect when
//! the postcondition is absent, and never treats an ambiguous provider return
//! as success.  The same journaled step is therefore safe after response loss
//! or an Agent crash.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{Read as _, Seek as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::path::{Component, Path};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use cats_api::blockd::{BlockdControlCommand, BlockdControlResponse};
use cats_api::runtime_inventory::ObservedArtifactClassification;
use cats_api::runtime_lifecycle::{
    lifecycle_terminal_result_digest, validate_lifecycle_successor, CommandFailedResult,
    CommandFailureReason, EffectiveRuntimeReady as WireEffectiveRuntimeReady,
    ExecutionAbsenceProof, InterventionReason, InterventionTarget, LifecycleCommand,
    LifecycleCommandEnvelope, LifecycleCommandResponse, LifecyclePredecessor,
    LifecycleTerminalResult, NeedsInterventionResult, NodeResult, RetainedEvidence,
    RuntimeNetworkConfig, StartSource, SuspendAdmissionPolicy, SuspendDeclineReason,
    SuspendDeclinedResult, SuspendedResult, VolumeTerminalReceipt, WarmResult,
};
use cats_api::runtime_reconciliation::{
    AcquireOrigin, HostPath, Id, RandomId128, RemoteHead, Sha256Digest, UnixMillis,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::admission::{
    CloseLifecycleAdmission, EffectiveRuntimeReady as AdmissionRuntimeReady,
    IdleLifecycleCloseOutcome, LifecycleCloseOutcome, LifecycleGuardCounts,
    LifecycleRouteAdmissionCell,
};
use crate::ch::GUEST_VSOCK_PORT;
use crate::ch::{pause_exact_vmm_until, snapshot_exact_vmm_until, ExactVmEffectOutcome};
use crate::guest_client::GuestClient;

use super::super::executor::{
    LifecycleEffectAuthority, LifecycleEffectProgress, PlannedLifecycleEffect,
};
use super::super::journal::{ExactBytes, ExecutionStep, StartupPhysicalInventory};
use super::common::InstalledLifecycleContext;
use super::inventory::{
    inspect_exact_runtime, scan_startup_inventory, InstalledPhysicalVmmState,
    InstalledRuntimePhysicalJoin, InstalledRuntimePhysicalOutcome,
};
use super::start::{
    installed_runtime_manifest_digest, load_installed_runtime_manifest,
    load_installed_runtime_progress_manifest, InstalledRuntimeManifest,
    InstalledRuntimeProcessIdentity, InstalledRuntimeVolumeManifest,
};
use super::{artifact_id, InstalledPhysicalInspectionConfig};

const STEP_SUSPEND_ADMISSION: &str = "installed_suspend_admission";
const STEP_SUSPEND_GUARDS: &str = "installed_suspend_guards";
const STEP_SUSPEND_DISCOVER: &str = "installed_suspend_discover";
const STEP_SUSPEND_QUIESCE: &str = "installed_suspend_quiesce";
const STEP_SUSPEND_PAUSE: &str = "installed_suspend_pause";
const STEP_SUSPEND_FAILURE_STOP: &str = "installed_suspend_failure_stop";

const STEP_WARM_ADMISSION: &str = "installed_warm_admission";
const STEP_WARM_GUARDS: &str = "installed_warm_guards";
const STEP_WARM_DISCOVER: &str = "installed_warm_discover";
const STEP_WARM_QUIESCE: &str = "installed_warm_quiesce";
const STEP_WARM_DRAIN: &str = "installed_warm_drain";
const STEP_WARM_PAUSE: &str = "installed_warm_pause";
const STEP_WARM_SNAPSHOT: &str = "installed_warm_snapshot";
const STEP_WARM_STOP: &str = "installed_warm_stop";
const STEP_WARM_FAILURE_STOP: &str = "installed_warm_failure_stop";

const STEP_VERSION: u64 = 1;
const GUARD_POLL_INTERVAL: Duration = Duration::from_millis(10);
const STEP_PAYLOAD_MAX_BYTES: usize = 4 * 1024 * 1024;
const STOP_FENCE_DOMAIN: &[u8] = b"cats.atomic-lifecycle.suspend-warm-stop-fence.v1";
const BUSY_RECEIPT_DOMAIN: &[u8] = b"cats.atomic-lifecycle.suspend-busy.v1";
const WARM_READY_RECEIPT_DOMAIN: &[u8] = b"cats.atomic-lifecycle.warm-ready.v1";
const WARM_SNAPSHOT_RECEIPT_DOMAIN: &[u8] = b"cats.atomic-lifecycle.warm-snapshot-receipt.v1";
const PAUSE_RECEIPT_DOMAIN: &[u8] = b"cats.atomic-lifecycle.exact-pause-receipt.v1";
const WARM_SNAPSHOT_NAMESPACE: &str = "atomic-warm-snapshots-v1";
const WARM_SNAPSHOT_CONTENT_SUFFIX: &str = ".snapshot";
const WARM_SNAPSHOT_INTENT_SUFFIX: &str = ".warm-intent.json";
const WARM_SNAPSHOT_MANIFEST_SUFFIX: &str = ".warm.json";
const WARM_SNAPSHOT_TEMP_SUFFIX: &str = ".warm.tmp";
const WARM_TERMINAL_MANIFEST_SUFFIX: &str = ".warm-terminal.json";
const WARM_TERMINAL_TEMP_SUFFIX: &str = ".warm-terminal.tmp";
const WARM_SNAPSHOT_MANIFEST_MAX_BYTES: usize = 4 * 1024 * 1024;
const WARM_SNAPSHOT_MAX_FILES: usize = 4_096;
const BLOCKD_CONTROL_MAX_LINE_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const PLATFORM_POLL_INTERVAL: Duration = Duration::from_millis(20);
const WARM_SNAPSHOT_KEY_DOMAIN: &[u8] = b"cats.atomic-lifecycle.warm-snapshot-key.v1";
const WARM_SNAPSHOT_MANIFEST_DOMAIN: &[u8] = b"cats.atomic-lifecycle.warm-snapshot-manifest.v1";
const WARM_SNAPSHOT_INTENT_DOMAIN: &[u8] = b"cats.atomic-lifecycle.warm-snapshot-intent.v1";
const WARM_SNAPSHOT_PLAN_DOMAIN: &[u8] = b"cats.atomic-lifecycle.warm-snapshot-plan.v1";
const WARM_TERMINAL_MANIFEST_DOMAIN: &[u8] = b"cats.atomic-lifecycle.warm-terminal-manifest.v1";
const WARM_CLEANUP_AUTHORITY_DOMAIN: &[u8] = b"cats.atomic-lifecycle.warm-cleanup-authority.v1";
const WARM_CLEANUP_REMOVE_DOMAIN: &[u8] = b"cats.atomic-lifecycle.warm-cleanup-remove.v1";
const WARM_CLEANUP_TRANSFER_DOMAIN: &[u8] = b"cats.atomic-lifecycle.warm-cleanup-transfer.v1";
const WARM_CLEANUP_RETAIN_FAILED_START_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.warm-cleanup-retain-failed-start.v1";
const RETAINED_WARM_RESTART_SOURCE_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.retained-warm-restart-source.v1";
const WARM_SNAPSHOT_TREE_DOMAIN: &[u8] = b"cats.atomic-lifecycle.warm-snapshot-tree.v1";
const WARM_MEMORY_FILE_DOMAIN: &[u8] = b"cats.atomic-lifecycle.warm-memory-file.v1";
const WARM_RECOVERY_PREDECESSOR_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.warm-recovery-predecessor.v1";
const FAILED_PREDECESSOR_PHYSICAL_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.suspend-warm-failed-predecessor-physical.v1";

/// Fresh physical identity of the exact runtime named by the command's
/// immediate predecessor.
///
/// The production implementation derives this from the descriptor-retained
/// installed runtime manifest and a fresh VMM/blockd/frontend inspection.  A
/// manifest on disk by itself is not this evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstalledRuntimeEvidence {
    pub runtime_incarnation: RandomId128,
    pub runtime_config_digest: Sha256Digest,
    pub physical_identity_digest: Sha256Digest,
    pub vmm_state: InstalledVmmState,
    pub volume_receipts: Vec<VolumeTerminalReceipt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InstalledVmmState {
    Executing,
    Paused,
    Absent,
}

/// Guest work-fence plus syncfs evidence for the exact installed runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuestQuiesceEvidence {
    pub runtime_physical_identity_digest: Sha256Digest,
    pub source_epoch_digest: Sha256Digest,
    pub lease_sequence: u64,
    pub quiesce_receipt_digest: Sha256Digest,
}

/// Fresh exact VMM-paused evidence and post-pause local durability facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PausedRuntimeEvidence {
    pub pause_operation_id: Id,
    pub pause_request_fingerprint: Sha256Digest,
    pub runtime_physical_identity_digest: Sha256Digest,
    pub write_fence_receipt_digest: Sha256Digest,
    pub pause_receipt_digest: Sha256Digest,
    pub local_durability_receipts: Vec<VolumeTerminalReceipt>,
}

/// Durable and freshly re-opened Host-local Warm snapshot evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WarmSnapshotEvidence {
    pub snapshot_operation_id: Id,
    pub snapshot_request_fingerprint: Sha256Digest,
    pub runtime_physical_identity_digest: Sha256Digest,
    pub write_fence_receipt_digest: Sha256Digest,
    pub pause_receipt_digest: Sha256Digest,
    pub snapshot_intent_digest: Sha256Digest,
    pub snapshot_manifest_digest: Sha256Digest,
    pub snapshot_receipt_digest: Sha256Digest,
}

/// The second, post-Stop publication that turns a durable snapshot payload
/// into an adoptable Warm terminal artifact.  A pre-Stop snapshot manifest is
/// intentionally insufficient: this evidence also binds the exact execution
/// absence returned by the shared strong-Stop barrier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalizedWarmSnapshotEvidence {
    pub terminal_manifest_digest: Sha256Digest,
    pub warm_receipt_digest: Sha256Digest,
}

/// Exact write barrier consumed by a Warm drain/snapshot. Running sources
/// obtain a fresh Guest work fence; a Suspended predecessor reuses only its
/// exact verified pause receipt and never tries to wake the Guest to quiesce
/// it again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RuntimeWriteFenceEvidence {
    Guest {
        quiesce: GuestQuiesceEvidence,
    },
    InheritedSuspended {
        runtime_physical_identity_digest: Sha256Digest,
        pause_receipt_digest: Sha256Digest,
    },
}

/// Freshly reopened Host-local snapshot used only for an exact retry of a
/// prior Warm NeedsIntervention. No runtime is restarted to obtain this
/// evidence; `runtime.vmm_state` must be `Absent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveredWarmEvidence {
    pub runtime: InstalledRuntimeEvidence,
    pub write_fence: RuntimeWriteFenceEvidence,
    pub paused: PausedRuntimeEvidence,
    pub snapshot: WarmSnapshotEvidence,
    pub drained_volumes: Vec<VolumeTerminalReceipt>,
    pub predecessor: WarmRecoveryPredecessorEvidence,
}

/// Exact failed Warm terminal and fresh retained-snapshot join. This carrier
/// is journaled before the retry republishes a terminal Warm bundle, so a
/// crash cannot detach the reopened artifacts from the NeedsIntervention
/// response which authorized their convergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WarmRecoveryPredecessorEvidence {
    predecessor_terminal_result_digest: Sha256Digest,
    execution_absence: ExecutionAbsenceProof,
    retained_evidence: RetainedEvidence,
    carrier_digest: Sha256Digest,
}

/// A platform attempt whose exact postcondition is the only success oracle.
///
/// `Ambiguous` deliberately contains no provider text or caller-provided
/// evidence.  Before its deadline the command leaves the same step durable and
/// retries discovery.  At the frozen deadline the handler selects the command
/// contract's typed strong-Stop result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SuspendWarmPlatformAttempt<T> {
    Exact(T),
    DefiniteFailure(CommandFailureReason),
    DataSafetyBlocked {
        reason: InterventionReason,
        retained_volume_receipts: Vec<VolumeTerminalReceipt>,
    },
    Ambiguous,
}

/// Durable authorization for consuming the exact terminal Warm bundle named
/// by a same-Node predecessor.  The predecessor terminal-result digest closes
/// this carrier to the lifecycle CAS chain; the separate manifest and receipt
/// digests close it to the two-phase Host artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmSnapshotCleanupRequest {
    pub predecessor_operation_id: Id,
    pub predecessor_request_fingerprint: Sha256Digest,
    pub predecessor_terminal_result_digest: Sha256Digest,
    pub terminal_manifest_digest: Sha256Digest,
    pub warm_receipt_digest: Sha256Digest,
    pub source_runtime_incarnation: RandomId128,
    pub volume_receipts: Vec<VolumeTerminalReceipt>,
}

impl WarmSnapshotCleanupRequest {
    /// Freeze cleanup authority from an already validated exact Warm response.
    pub fn from_warm_predecessor(predecessor: &LifecycleCommandResponse) -> Result<Self> {
        let NodeResult::Warm(warm) = &predecessor.result else {
            anyhow::bail!("Warm snapshot cleanup predecessor is not Warm");
        };
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(predecessor.clone()),
        };
        Ok(Self {
            predecessor_operation_id: predecessor.operation_id.clone(),
            predecessor_request_fingerprint: predecessor.request_fingerprint.clone(),
            predecessor_terminal_result_digest: lifecycle_terminal_result_digest(&terminal)
                .context("digest Warm cleanup predecessor")?,
            terminal_manifest_digest: warm.warm_snapshot_manifest_digest.clone(),
            warm_receipt_digest: warm.warm_snapshot_receipt_digest.clone(),
            source_runtime_incarnation: warm.source_runtime_incarnation.clone(),
            volume_receipts: warm.volume_receipts.clone(),
        })
    }
}

/// Exact descriptor identities inspected before a Warm restore or destructive
/// Cold/Delete cleanup. The caller must persist this value in its lifecycle
/// journal before restoring from or unlinking the named bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmSnapshotCleanupAuthority {
    version: u64,
    cleanup_operation_id: Id,
    cleanup_request_fingerprint: Sha256Digest,
    workspace_id: Id,
    cat_id: Id,
    node_id: Id,
    placement_identity: cats_api::runtime_lifecycle::PlacementIdentity,
    runtime_config_id: Id,
    runtime_config_digest: Sha256Digest,
    request: WarmSnapshotCleanupRequest,
    terminal_operation_id: Id,
    terminal_request_fingerprint: Sha256Digest,
    prepared_operation_id: Id,
    prepared_request_fingerprint: Sha256Digest,
    mode: WarmSnapshotCleanupMode,
    snapshot_directory: cats_api::runtime_reconciliation::HostPath,
    /// Complete immutable launch/network/device attribution consumed when the
    /// snapshot was created. Same-Node Warm Start must derive its restore
    /// plan from this exact manifest; it may not allocate replacement
    /// CID/TAP/frontend identities which disagree with the CH snapshot.
    installed_runtime: Option<Box<InstalledRuntimeManifest>>,
    memory_file: WarmMemoryFileProof,
    memory_parent_identity: WarmCleanupObjectIdentity,
    namespace_identity: WarmCleanupObjectIdentity,
    terminal_manifest_identity: WarmCleanupObjectIdentity,
    intent_manifest_identity: WarmCleanupObjectIdentity,
    prepared_manifest_identity: WarmCleanupObjectIdentity,
    content_directory_identity: WarmCleanupObjectIdentity,
    /// Present only after a failed Warm Start durably revoked the original
    /// terminal manifest. The original descriptor authority remains intact;
    /// this binding moves mutation scope to one exact immediate successor:
    /// either SameNodeRetry or destructive Stop/Cold/Delete cleanup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retained_retry: Option<Box<RetainedWarmRetryBinding>>,
    authority_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedWarmRetryBinding {
    failed_start_operation_id: Id,
    failed_start_request_fingerprint: Sha256Digest,
    failed_start_terminal_result_digest: Sha256Digest,
    failed_start_retained_manifest_digest: Sha256Digest,
    inherited_predecessor_physical_digest: Sha256Digest,
    source_revocation_receipt_digest: Sha256Digest,
    source_carrier_digest: Sha256Digest,
}

/// Complete non-executable Warm restart source sealed into a failed Start's
/// TerminalRetained manifest. It preserves the already-inspected descriptors;
/// consumers may rebind it only through the exact immediate StartFailed edge,
/// either to retry the restore or to remove the retained bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedWarmRestartSourceCarrier {
    version: u64,
    failed_start_operation_id: Id,
    failed_start_request_fingerprint: Sha256Digest,
    inherited_predecessor_physical_digest: Sha256Digest,
    revocation_receipt_digest: Sha256Digest,
    source_authority: Box<WarmSnapshotCleanupAuthority>,
    carrier_digest: Sha256Digest,
}

impl RetainedWarmRestartSourceCarrier {
    pub(crate) fn digest(&self) -> &Sha256Digest {
        &self.carrier_digest
    }
}

impl WarmSnapshotCleanupAuthority {
    pub fn snapshot_directory(&self) -> &cats_api::runtime_reconciliation::HostPath {
        &self.snapshot_directory
    }

    pub fn memory_file(&self) -> &WarmMemoryFileProof {
        &self.memory_file
    }

    pub fn installed_runtime(&self) -> Result<&InstalledRuntimeManifest> {
        self.installed_runtime
            .as_deref()
            .context("Warm cleanup authority lacks its exact installed runtime")
    }

    pub fn mode(&self) -> WarmSnapshotCleanupMode {
        self.mode
    }

    pub fn source_runtime_incarnation(&self) -> &RandomId128 {
        &self.request.source_runtime_incarnation
    }

    pub fn terminal_manifest_digest(&self) -> &Sha256Digest {
        &self.request.terminal_manifest_digest
    }
}

/// Cleanup policy frozen before a Warm restart or destructive transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarmSnapshotCleanupMode {
    /// Same-Node Warm Start transfers the exact backing inode to the newly
    /// journaled runtime. Cleanup revokes only the old restart authority.
    TransferToRuntime,
    /// Cold/Stop/Delete have no future local restore and remove the exact backing.
    Remove,
}

/// Final journal evidence needed to consume a Warm bundle under its frozen
/// cleanup mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum WarmSnapshotCleanupCompletion {
    TransferToRuntime {
        runtime_incarnation: RandomId128,
        runtime_progress_manifest_digest: Sha256Digest,
    },
    /// A failed same-Node Warm Start must revoke the old terminal restart
    /// authority without deleting the exact prepared bundle or external RAM.
    /// The digest is the pre-Stop carrier sealed in that Start's journal.
    RetainForFailedStart {
        inherited_predecessor_physical_digest: Sha256Digest,
    },
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarmSnapshotCleanupAttempt<T> {
    Exact(T),
    Blocked,
}

/// One immutable snapshot input set threaded through create, reopen, verify,
/// and terminal publication. Grouping these references prevents individual
/// phases from accidentally accepting different runtime or lineage evidence.
#[derive(Clone, Copy)]
pub(crate) struct WarmSnapshotInputs<'a> {
    command: &'a LifecycleCommandEnvelope,
    predecessor: &'a LifecycleCommandResponse,
    runtime: &'a InstalledRuntimeEvidence,
    write_fence: &'a RuntimeWriteFenceEvidence,
    paused: &'a PausedRuntimeEvidence,
    drained_volumes: &'a [VolumeTerminalReceipt],
}

/// Narrow production platform boundary for Suspend/Warm.
///
/// Each call is synchronous and bounded by `deadline`.  It must first inspect
/// the exact postcondition identified by all supplied evidence.  If absent it
/// may submit that one effect once, but after any provider error/timeout it
/// must inspect again and return `Exact` only from the fresh postcondition.
/// Implementations never read Desired/Observation and never infer a target
/// from an unscoped process name or path prefix.
pub(crate) trait SuspendWarmPlatformPort: Send + Sync + 'static {
    /// Freshly join one exact Suspended/Warm predecessor to its current Owned
    /// Volume rows. This read-only carrier is shared with Start so a rejected
    /// sequence-zero renewal can retain predecessor attribution and a resume
    /// plan can reuse the exact installed identities without duplicating this
    /// scanner or guessing from Host paths.
    fn inspect_same_node_owned_predecessor(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        deadline: Instant,
    ) -> Result<SameNodeOwnedPredecessorPhysical>;

    fn inspect_rebound_warm_retry_source(
        &self,
        command: &LifecycleCommandEnvelope,
        authority: &WarmSnapshotCleanupAuthority,
        deadline: Instant,
    ) -> Result<SameNodeOwnedPredecessorPhysical>;

    fn inspect_runtime(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<InstalledRuntimeEvidence>>;

    fn quiesce_guest(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        runtime: &InstalledRuntimeEvidence,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<GuestQuiesceEvidence>>;

    fn pause_vmm(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        runtime: &InstalledRuntimeEvidence,
        quiesce: &GuestQuiesceEvidence,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<PausedRuntimeEvidence>>;

    fn drain_volumes_to_remote(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        runtime: &InstalledRuntimeEvidence,
        write_fence: &RuntimeWriteFenceEvidence,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<Vec<VolumeTerminalReceipt>>>;

    fn create_warm_snapshot(
        &self,
        inputs: WarmSnapshotInputs<'_>,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<WarmSnapshotEvidence>>;

    /// Reopen and hash an already-published Warm snapshot, then freshly prove
    /// that the exact source VMM is still Paused or is already Absent. This
    /// method is read-only: it must never submit another snapshot or restart
    /// an absent runtime. It closes the crash window between publishing the
    /// snapshot and applying the journaled strong-Stop successor step.
    fn verify_warm_snapshot(
        &self,
        inputs: WarmSnapshotInputs<'_>,
        expected_snapshot: &WarmSnapshotEvidence,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<WarmSnapshotEvidence>>;

    /// Publish or reopen the command-scoped terminal Warm manifest after the
    /// shared strong-Stop barrier has freshly proved execution absence.  This
    /// is a second immutable publication; it never rewrites the pre-Stop
    /// snapshot manifest and never treats that artifact alone as Warm.
    fn finalize_warm_snapshot(
        &self,
        inputs: WarmSnapshotInputs<'_>,
        snapshot: &WarmSnapshotEvidence,
        execution_absence: &ExecutionAbsenceProof,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<FinalizedWarmSnapshotEvidence>>;

    fn inspect_warm_recovery(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<RecoveredWarmEvidence>>;

    fn prepare_warm_snapshot_cleanup(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &WarmSnapshotCleanupRequest,
        deadline: Instant,
    ) -> Result<WarmSnapshotCleanupAttempt<WarmSnapshotCleanupAuthority>>;

    fn inspect_or_remove_warm_snapshot(
        &self,
        command: &LifecycleCommandEnvelope,
        authority: &WarmSnapshotCleanupAuthority,
        completion: &WarmSnapshotCleanupCompletion,
        deadline: Instant,
    ) -> Result<WarmSnapshotCleanupAttempt<Sha256Digest>>;
}

/// Opaque production Suspend/Warm platform composition.
///
/// The public wrapper lets the separate `cats-noded` crate assemble the
/// installed lifecycle adapter without making the effect port or its internal
/// evidence DTOs part of the Node Agent's public API.
#[derive(Clone)]
pub struct InstalledSuspendWarmPlatform {
    inner: Arc<dyn SuspendWarmPlatformPort>,
    probe_timeout: Duration,
}

impl InstalledSuspendWarmPlatform {
    /// Compose the real installed Suspend/Warm effects from the same physical
    /// coordinates retained by startup inventory and strong Stop.
    pub fn for_production(mut physical: InstalledPhysicalInspectionConfig) -> Result<Self> {
        physical.include_provider_process_binaries();
        anyhow::ensure!(
            !physical.inventory_timeout.is_zero() && !physical.physical_probe_timeout.is_zero(),
            "Suspend/Warm physical deadlines must be non-zero"
        );
        physical
            .state_directory
            .try_clone_directory()
            .context("open descriptor-retained StateDirectory for Suspend/Warm")?;
        let probe_timeout = physical.physical_probe_timeout;
        Ok(Self::new(
            Arc::new(ProductionSuspendWarmPlatform { physical }),
            probe_timeout,
        ))
    }

    /// Inspect and close the predecessor terminal manifest, immutable payload,
    /// and exact descriptor identities. The caller must journal the returned
    /// authority before restore or cleanup.
    pub fn prepare_warm_snapshot_cleanup(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &WarmSnapshotCleanupRequest,
    ) -> Result<WarmSnapshotCleanupAttempt<WarmSnapshotCleanupAuthority>> {
        let deadline = Instant::now()
            .checked_add(self.probe_timeout)
            .context("Warm snapshot inspection deadline overflow")?;
        self.inner
            .prepare_warm_snapshot_cleanup(command, request, deadline)
    }

    /// Consume one journal-authorized terminal Warm bundle during same-Node
    /// Warm Start, Cold, Stop, or Delete finalization. Start retains and
    /// freshly revalidates the exact memory inode for its journaled VMM;
    /// Cold/Stop/Delete remove that inode descriptor-relatively. Both modes
    /// durably revoke all old snapshot authority before returning their
    /// distinct receipt digest.
    pub fn inspect_or_remove_warm_snapshot(
        &self,
        command: &LifecycleCommandEnvelope,
        authority: &WarmSnapshotCleanupAuthority,
        completion: &WarmSnapshotCleanupCompletion,
    ) -> Result<WarmSnapshotCleanupAttempt<Sha256Digest>> {
        let deadline = Instant::now()
            .checked_add(self.probe_timeout)
            .context("Warm snapshot cleanup deadline overflow")?;
        self.inner
            .inspect_or_remove_warm_snapshot(command, authority, completion, deadline)
    }

    /// Return the exact read-only physical carrier for a same-Node
    /// Suspend/Warm successor. Start uses it to resume/restore; Cold/Delete
    /// and generic Stop freeze it before their strong Stop. The bounded
    /// inspection carries no mutation authority for the successor.
    pub(crate) fn inspect_same_node_owned_predecessor(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
    ) -> Result<SameNodeOwnedPredecessorPhysical> {
        let deadline = Instant::now()
            .checked_add(self.probe_timeout)
            .context("same-Node predecessor inspection deadline overflow")?;
        self.inner
            .inspect_same_node_owned_predecessor(command, predecessor, deadline)
    }

    /// Freshly reopen the descriptor identities carried across a failed Warm
    /// Start. The terminal manifest must remain absent while intent, prepared
    /// payload, full snapshot tree, and external RAM all remain exact.
    pub(crate) fn inspect_rebound_warm_retry_source(
        &self,
        command: &LifecycleCommandEnvelope,
        authority: &WarmSnapshotCleanupAuthority,
    ) -> Result<SameNodeOwnedPredecessorPhysical> {
        let deadline = Instant::now()
            .checked_add(self.probe_timeout)
            .context("retained Warm retry inspection deadline overflow")?;
        self.inner
            .inspect_rebound_warm_retry_source(command, authority, deadline)
    }

    pub(crate) fn new(inner: Arc<dyn SuspendWarmPlatformPort>, probe_timeout: Duration) -> Self {
        Self {
            inner,
            probe_timeout,
        }
    }

    pub(crate) fn as_port(&self) -> &Arc<dyn SuspendWarmPlatformPort> {
        &self.inner
    }
}

#[derive(Clone)]
struct ProductionSuspendWarmPlatform {
    physical: InstalledPhysicalInspectionConfig,
}

/// Immutable effect plan published before any snapshot directory or Cloud
/// Hypervisor snapshot side effect. It names only bounded, already-installed
/// coordinates and does not claim that any snapshot byte exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WarmSnapshotPlan {
    installed_runtime_manifest_digest: Sha256Digest,
    vmm_process: InstalledRuntimeProcessIdentity,
    vmm_api_socket_path: cats_api::runtime_reconciliation::HostPath,
    memory_file_path: cats_api::runtime_reconciliation::HostPath,
    content_directory_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WarmSnapshotIntentBody {
    version: u64,
    binding: StepBinding,
    workspace_id: Id,
    cat_id: Id,
    node_id: Id,
    placement_identity: cats_api::runtime_lifecycle::PlacementIdentity,
    runtime_config_id: Id,
    runtime_config_digest: Sha256Digest,
    source_runtime_incarnation: RandomId128,
    runtime_physical_identity_digest: Sha256Digest,
    write_fence_receipt_digest: Sha256Digest,
    pause_receipt_digest: Sha256Digest,
    drained_volumes: Vec<VolumeTerminalReceipt>,
    plan: WarmSnapshotPlan,
    plan_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WarmSnapshotIntent {
    body: WarmSnapshotIntentBody,
    intent_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WarmSnapshotTreeProof {
    digest: Sha256Digest,
    regular_file_count: u32,
    total_file_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmMemoryFileProof {
    pub path: cats_api::runtime_reconciliation::HostPath,
    pub device: u64,
    pub inode: u64,
    pub size_bytes: u64,
    pub digest: Sha256Digest,
}

/// Fresh, closed physical attribution for a same-Node Owned predecessor.
///
/// Start consumes this value only after a sequence-zero renewal was
/// definitely rejected or while sealing its provider plan.  It is not a
/// grant and cannot authorize a mutation: the full current `RemoteHead` and
/// owner binding still come from one fresh authority snapshot, while the
/// source-specific carrier below proves which exact Host artifact retained
/// that attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SameNodeOwnedPredecessorPhysical {
    pub(crate) physical_manifest_digest: Sha256Digest,
    pub(crate) runtime_incarnation: Option<RandomId128>,
    pub(crate) volumes: Vec<SameNodeOwnedPredecessorVolume>,
    pub(crate) source: SameNodeOwnedPredecessorSource,
}

impl SameNodeOwnedPredecessorPhysical {
    /// Return the complete immutable runtime attribution carried by every
    /// supported predecessor shape. Callers may flatten it into their own
    /// journaled plan but must not rediscover paths after a strong Stop.
    pub(crate) fn installed_runtime(&self) -> Result<&InstalledRuntimeManifest> {
        match &self.source {
            SameNodeOwnedPredecessorSource::RuntimeReady {
                installed_runtime, ..
            }
            | SameNodeOwnedPredecessorSource::SuspendDeclined {
                installed_runtime, ..
            }
            | SameNodeOwnedPredecessorSource::Suspended {
                installed_runtime, ..
            }
            | SameNodeOwnedPredecessorSource::Failed {
                installed_runtime, ..
            } => Ok(installed_runtime),
            SameNodeOwnedPredecessorSource::Warm { cleanup_authority } => {
                cleanup_authority.installed_runtime()
            }
            SameNodeOwnedPredecessorSource::RetainedWarm { cleanup_authority } => {
                cleanup_authority.installed_runtime()
            }
        }
    }

    /// Descriptor-retained removal/transfer authority exists only for a
    /// successful Warm predecessor. Generic Stop must persist the returned
    /// Remove authority and consume it before publishing Killed.
    pub(crate) fn warm_cleanup_authority(&self) -> Option<&WarmSnapshotCleanupAuthority> {
        match &self.source {
            SameNodeOwnedPredecessorSource::Warm { cleanup_authority }
            | SameNodeOwnedPredecessorSource::RetainedWarm { cleanup_authority } => {
                Some(cleanup_authority)
            }
            SameNodeOwnedPredecessorSource::RuntimeReady { .. }
            | SameNodeOwnedPredecessorSource::SuspendDeclined { .. }
            | SameNodeOwnedPredecessorSource::Suspended { .. }
            | SameNodeOwnedPredecessorSource::Failed { .. } => None,
        }
    }

    /// Fresh complete predecessor receipts in immutable runtime-config order.
    /// Callers use this projection only after validating the full carrier;
    /// the receipts alone are never predecessor authority.
    pub(crate) fn volume_receipts(&self) -> &[VolumeTerminalReceipt] {
        match &self.source {
            SameNodeOwnedPredecessorSource::RuntimeReady {
                volume_receipts, ..
            }
            | SameNodeOwnedPredecessorSource::SuspendDeclined {
                volume_receipts, ..
            }
            | SameNodeOwnedPredecessorSource::Suspended {
                volume_receipts, ..
            }
            | SameNodeOwnedPredecessorSource::Failed {
                volume_receipts, ..
            } => volume_receipts,
            SameNodeOwnedPredecessorSource::Warm { cleanup_authority }
            | SameNodeOwnedPredecessorSource::RetainedWarm { cleanup_authority } => {
                &cleanup_authority.request.volume_receipts
            }
        }
    }
}

/// Revalidate a carrier after it has been serialized into a successor journal.
/// This is intentionally pure: once StrongStop has started, re-inspecting the
/// predecessor VMM/bundle would either be impossible or would mistake the
/// successor's own effects for predecessor drift.
pub(crate) fn validate_same_node_owned_predecessor_physical(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    physical: &SameNodeOwnedPredecessorPhysical,
) -> Result<()> {
    validate_same_node_owned_start_source(command, predecessor)?;
    let installed = physical.installed_runtime()?;
    anyhow::ensure!(
        physical.physical_manifest_digest.as_bytes() != &[0; 32]
            && physical.runtime_incarnation.as_ref() == Some(&installed.runtime_incarnation)
            && installed.node_id == command.node_id
            && installed.cat_id == command.cat_id
            && installed.placement_identity == command.placement_identity
            && installed.runtime_config_id == command.runtime_config.config_id
            && installed.runtime_config_digest == command.runtime_config.config_digest
            && installed.manifest_digest == installed_runtime_manifest_digest(installed)?,
        "same-Node predecessor carrier changed its installed runtime identity"
    );
    match (&predecessor.result, &physical.source) {
        (
            NodeResult::RuntimeReady(ready),
            SameNodeOwnedPredecessorSource::RuntimeReady {
                installed_runtime: _,
                physical_identity_digest,
                volume_receipts,
            },
        ) => {
            anyhow::ensure!(
                physical_identity_digest.as_bytes() != &[0; 32]
                    && physical.physical_manifest_digest == installed.manifest_digest
                    && installed.source_lifecycle_operation_id == predecessor.operation_id
                    && installed.request_fingerprint == predecessor.request_fingerprint
                    && installed.runtime_incarnation == ready.runtime_incarnation
                    && installed.runtime_config_digest == ready.runtime_config_digest
                    && installed.execution_receipt_digest == ready.execution_receipt_digest
                    && installed.guest_ready_receipt_digest == ready.guest_ready_receipt_digest,
                "RuntimeReady carrier changed its exact executing runtime"
            );
            validate_prior_attachment_subset(&ready.volume_receipts, volume_receipts)?;
            validate_same_node_owned_carrier_volumes(
                command,
                installed,
                &physical.volumes,
                volume_receipts,
                false,
            )
        }
        (
            NodeResult::SuspendDeclined(declined),
            SameNodeOwnedPredecessorSource::SuspendDeclined {
                installed_runtime: _,
                physical_identity_digest,
                effective_runtime_ready,
                volume_receipts,
            },
        ) => {
            anyhow::ensure!(
                physical_identity_digest.as_bytes() != &[0; 32]
                    && physical.physical_manifest_digest == installed.manifest_digest
                    && effective_runtime_ready == &declined.effective_runtime_ready
                    && installed.source_lifecycle_operation_id
                        == effective_runtime_ready.source_lifecycle_operation_id
                    && installed.runtime_incarnation == effective_runtime_ready.runtime_incarnation
                    && installed.runtime_config_digest
                        == effective_runtime_ready.runtime_config_digest
                    && installed.execution_receipt_digest
                        == effective_runtime_ready.runtime_ready_receipt_digest,
                "SuspendDeclined carrier changed its exact effective runtime"
            );
            validate_same_node_owned_carrier_volumes(
                command,
                installed,
                &physical.volumes,
                volume_receipts,
                false,
            )
        }
        (
            NodeResult::Suspended(suspended),
            SameNodeOwnedPredecessorSource::Suspended {
                installed_runtime: _,
                physical_identity_digest,
                pause_receipt_digest,
                volume_receipts,
            },
        ) => {
            anyhow::ensure!(
                physical_identity_digest.as_bytes() != &[0; 32]
                    && physical.physical_manifest_digest == installed.manifest_digest
                    && pause_receipt_digest == &suspended.pause_receipt_digest
                    && installed.runtime_incarnation == suspended.runtime_incarnation
                    && installed.runtime_config_digest == suspended.runtime_config_digest,
                "Suspended carrier changed its exact paused runtime"
            );
            validate_prior_attachment_subset(
                &suspended.local_durability_receipts,
                volume_receipts,
            )?;
            validate_same_node_owned_carrier_volumes(
                command,
                installed,
                &physical.volumes,
                volume_receipts,
                false,
            )
        }
        (NodeResult::Warm(warm), SameNodeOwnedPredecessorSource::Warm { cleanup_authority }) => {
            validate_warm_cleanup_request(command, &cleanup_authority.request)?;
            let expected_mode = match command.command {
                LifecycleCommand::Start(_) => WarmSnapshotCleanupMode::TransferToRuntime,
                LifecycleCommand::Cold(_)
                | LifecycleCommand::Stop(_)
                | LifecycleCommand::Delete(_) => WarmSnapshotCleanupMode::Remove,
                _ => anyhow::bail!("command cannot consume a Warm predecessor carrier"),
            };
            anyhow::ensure!(
                cleanup_authority.authority_digest
                    == warm_cleanup_authority_digest(cleanup_authority)?
                    && cleanup_authority.mode == expected_mode
                    && cleanup_authority.retained_retry.is_none()
                    && cleanup_authority.cleanup_operation_id == command.operation_id
                    && cleanup_authority.cleanup_request_fingerprint == command.request_fingerprint
                    && cleanup_authority.request.source_runtime_incarnation
                        == warm.source_runtime_incarnation
                    && cleanup_authority.request.volume_receipts == warm.volume_receipts
                    && cleanup_authority.request.terminal_manifest_digest
                        == warm.warm_snapshot_manifest_digest
                    && cleanup_authority.request.warm_receipt_digest
                        == warm.warm_snapshot_receipt_digest
                    && physical.physical_manifest_digest
                        == cleanup_authority.request.terminal_manifest_digest,
                "Warm carrier changed its terminal bundle or cleanup authority"
            );
            validate_same_node_owned_carrier_volumes(
                command,
                installed,
                &physical.volumes,
                &cleanup_authority.request.volume_receipts,
                true,
            )
        }
        (
            NodeResult::StartFailed(failed),
            SameNodeOwnedPredecessorSource::RetainedWarm { cleanup_authority },
        ) => {
            validate_warm_cleanup_authority_scope(command, cleanup_authority)?;
            let retry = cleanup_authority
                .retained_retry
                .as_deref()
                .context("retained Warm carrier lost its StartFailed retry binding")?;
            let terminal = LifecycleTerminalResult::NodeResult {
                response: Box::new(predecessor.clone()),
            };
            let terminal_result_digest = lifecycle_terminal_result_digest(&terminal)
                .context("digest retained Warm StartFailed predecessor")?;
            anyhow::ensure!(
                retry.failed_start_operation_id == predecessor.operation_id
                    && retry.failed_start_request_fingerprint == predecessor.request_fingerprint
                    && retry.failed_start_terminal_result_digest == terminal_result_digest
                    && retry.failed_start_retained_manifest_digest
                        == failed.retained_evidence.artifact_manifest_digest
                    && physical.physical_manifest_digest
                        == failed.retained_evidence.artifact_manifest_digest
                    && cleanup_authority.mode == WarmSnapshotCleanupMode::TransferToRuntime
                    && execution_absence_proof_is_nonzero(&failed.not_running),
                "retained Warm carrier changed its immediate failed Start evidence"
            );
            validate_same_node_owned_carrier_volumes(
                command,
                installed,
                &physical.volumes,
                &cleanup_authority.request.volume_receipts,
                true,
            )
        }
        (
            NodeResult::SuspendFailed(failed) | NodeResult::WarmFailed(failed),
            SameNodeOwnedPredecessorSource::Failed {
                installed_runtime: _,
                execution_absence,
                retained_evidence,
                predecessor_terminal_result_digest,
                volume_receipts,
            },
        ) => {
            let terminal = LifecycleTerminalResult::NodeResult {
                response: Box::new(predecessor.clone()),
            };
            let terminal_result_digest = lifecycle_terminal_result_digest(&terminal)
                .context("digest persisted failed Suspend/Warm predecessor")?;
            anyhow::ensure!(
                execution_absence == &failed.not_running
                    && retained_evidence == &failed.retained_evidence
                    && predecessor_terminal_result_digest == &terminal_result_digest
                    && physical.physical_manifest_digest
                        == failed_predecessor_physical_digest(
                            predecessor,
                            &terminal_result_digest,
                            failed,
                            installed,
                            &physical.volumes,
                            volume_receipts,
                        )?,
                "failed Suspend/Warm carrier changed its terminal or retained evidence"
            );
            validate_same_node_owned_carrier_volumes(
                command,
                installed,
                &physical.volumes,
                volume_receipts,
                false,
            )
        }
        _ => anyhow::bail!("same-Node predecessor carrier source changed its terminal kind"),
    }
}

fn validate_same_node_owned_carrier_volumes(
    command: &LifecycleCommandEnvelope,
    installed: &InstalledRuntimeManifest,
    volumes: &[SameNodeOwnedPredecessorVolume],
    receipts: &[VolumeTerminalReceipt],
    require_remote: bool,
) -> Result<()> {
    validate_volume_receipts(command, receipts, require_remote)?;
    anyhow::ensure!(
        installed.volumes.len() == command.runtime_config.volumes.len()
            && volumes.len() == installed.volumes.len()
            && receipts.len() == volumes.len()
            && volumes
                .windows(2)
                .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "same-Node predecessor carrier Volume set is incomplete or reordered"
    );
    for (((configured, manifest), volume), receipt) in command
        .runtime_config
        .volumes
        .iter()
        .zip(&installed.volumes)
        .zip(volumes)
        .zip(receipts)
    {
        let grant_digest = manifest
            .authority_receipt_digest
            .as_ref()
            .context("same-Node predecessor installed Volume lost its StartGrant digest")?;
        anyhow::ensure!(
            manifest.volume_id == configured.volume_id
                && manifest.disk_id == configured.disk_id
                && manifest.disk_role == configured.disk_role
                && volume.volume_id == configured.volume_id
                && volume.disk_id == configured.disk_id
                && volume.disk_role == configured.disk_role
                && volume.attachment_id == manifest.attachment_id
                && volume.attachment_epoch == manifest.attachment_epoch
                && volume.acquire_origin == manifest.acquire_origin
                && volume.immutable_start_grant_receipt_digest == *grant_digest
                && volume.local_lineage_data_directory.as_ref()
                    == Some(&manifest.local_lineage_data_directory)
                && remote_head_is_unchanged_or_advanced(
                    &manifest.current_authority_head,
                    &volume.authoritative_head,
                )
                && receipt.volume_id == volume.volume_id
                && receipt.disk_id == volume.disk_id
                && receipt.disk_role == volume.disk_role
                && receipt.attachment_id == volume.attachment_id
                && receipt.attachment_epoch == volume.attachment_epoch
                && receipt.authority_receipt_digest.as_ref() == Some(grant_digest)
                && receipt.remote_durable_generation <= volume.authoritative_head.generation
                && volume.authoritative_head.generation <= receipt.local_durable_generation,
            "same-Node predecessor carrier changed Volume config, lineage, grant, or head"
        );
    }
    Ok(())
}

/// One exact predecessor-owned attachment in immutable runtime-config order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SameNodeOwnedPredecessorVolume {
    pub(crate) volume_id: Id,
    pub(crate) disk_id: Id,
    pub(crate) disk_role: cats_api::runtime_lifecycle::DiskRole,
    pub(crate) attachment_id: Id,
    pub(crate) attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    pub(crate) acquire_origin: AcquireOrigin,
    pub(crate) authoritative_head: RemoteHead,
    pub(crate) immutable_start_grant_receipt_digest: Sha256Digest,
    pub(crate) local_lineage_data_directory: Option<HostPath>,
}

/// Source-specific, read-only proof retained with the flat authority
/// projection.  Suspended carries the complete descriptor-scanned runtime
/// identity needed to resume rather than create a conflicting VMM. Warm
/// carries the already descriptor-verified transfer authority, including the
/// external file-backed RAM inode and immutable snapshot tree identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum SameNodeOwnedPredecessorSource {
    RuntimeReady {
        installed_runtime: Box<InstalledRuntimeManifest>,
        physical_identity_digest: Sha256Digest,
        volume_receipts: Vec<VolumeTerminalReceipt>,
    },
    SuspendDeclined {
        installed_runtime: Box<InstalledRuntimeManifest>,
        physical_identity_digest: Sha256Digest,
        effective_runtime_ready: WireEffectiveRuntimeReady,
        volume_receipts: Vec<VolumeTerminalReceipt>,
    },
    Suspended {
        installed_runtime: Box<InstalledRuntimeManifest>,
        physical_identity_digest: Sha256Digest,
        pause_receipt_digest: Sha256Digest,
        volume_receipts: Vec<VolumeTerminalReceipt>,
    },
    Warm {
        cleanup_authority: Box<WarmSnapshotCleanupAuthority>,
    },
    /// A prior failed Warm Start removed the executable terminal manifest but
    /// retained one exact prepared bundle and rebound it through the immediate
    /// StartFailed terminal to the current SameNodeRetry operation.
    RetainedWarm {
        cleanup_authority: Box<WarmSnapshotCleanupAuthority>,
    },
    /// SuspendFailed/WarmFailed are legal direct typed retries but their wire
    /// result deliberately carries no Volume projection. The carrier binds
    /// the exact not-running result to the original installed manifest and a
    /// fresh descriptor-verified Owned lineage; it never treats aggregate
    /// RetainedEvidence counts as storage authority.
    Failed {
        installed_runtime: Box<InstalledRuntimeManifest>,
        execution_absence: ExecutionAbsenceProof,
        retained_evidence: RetainedEvidence,
        predecessor_terminal_result_digest: Sha256Digest,
        volume_receipts: Vec<VolumeTerminalReceipt>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WarmSnapshotManifestBody {
    version: u64,
    binding: StepBinding,
    workspace_id: Id,
    cat_id: Id,
    node_id: Id,
    placement_identity: cats_api::runtime_lifecycle::PlacementIdentity,
    runtime_config_id: Id,
    runtime_config_digest: Sha256Digest,
    runtime: InstalledRuntimeEvidence,
    write_fence: RuntimeWriteFenceEvidence,
    paused: PausedRuntimeEvidence,
    drained_volumes: Vec<VolumeTerminalReceipt>,
    snapshot_intent_digest: Sha256Digest,
    installed_runtime_manifest_digest: Sha256Digest,
    content_directory_name: String,
    snapshot_tree: WarmSnapshotTreeProof,
    memory_file: WarmMemoryFileProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WarmSnapshotManifest {
    body: WarmSnapshotManifestBody,
    evidence: WarmSnapshotEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WarmTerminalManifestBody {
    version: u64,
    binding: StepBinding,
    workspace_id: Id,
    cat_id: Id,
    node_id: Id,
    placement_identity: cats_api::runtime_lifecycle::PlacementIdentity,
    runtime_config_id: Id,
    runtime_config_digest: Sha256Digest,
    source_runtime_incarnation: RandomId128,
    snapshot_intent_digest: Sha256Digest,
    prepared_snapshot: WarmSnapshotEvidence,
    drained_volumes: Vec<VolumeTerminalReceipt>,
    execution_absence: ExecutionAbsenceProof,
    warm_receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WarmTerminalManifest {
    body: WarmTerminalManifestBody,
    terminal_manifest_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstalledWarmIntentContentObservation {
    Absent,
    Present { evidence_digest: Sha256Digest },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstalledWarmSnapshotIntentArtifact {
    pub(crate) source_operation_id: Id,
    pub(crate) source_request_fingerprint: Sha256Digest,
    pub(crate) workspace_id: Id,
    pub(crate) cat_id: Id,
    pub(crate) node_id: Id,
    pub(crate) placement_identity: cats_api::runtime_lifecycle::PlacementIdentity,
    pub(crate) runtime_config_id: Id,
    pub(crate) runtime_config_digest: Sha256Digest,
    pub(crate) source_runtime_incarnation: RandomId128,
    pub(crate) intent_manifest_digest: Sha256Digest,
    pub(crate) snapshot_plan_digest: Sha256Digest,
    pub(crate) retained_volume_receipts: Vec<VolumeTerminalReceipt>,
    pub(crate) content_observation: InstalledWarmIntentContentObservation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstalledPreparedWarmSnapshotArtifact {
    pub(crate) source_operation_id: Id,
    pub(crate) source_request_fingerprint: Sha256Digest,
    pub(crate) workspace_id: Id,
    pub(crate) cat_id: Id,
    pub(crate) node_id: Id,
    pub(crate) placement_identity: cats_api::runtime_lifecycle::PlacementIdentity,
    pub(crate) runtime_config_id: Id,
    pub(crate) runtime_config_digest: Sha256Digest,
    pub(crate) source_runtime_incarnation: RandomId128,
    pub(crate) intent_manifest_digest: Sha256Digest,
    pub(crate) prepared_manifest_digest: Sha256Digest,
    pub(crate) snapshot_receipt_digest: Sha256Digest,
    pub(crate) retained_volume_receipts: Vec<VolumeTerminalReceipt>,
    pub(crate) snapshot_tree_digest: Sha256Digest,
    pub(crate) memory_file_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstalledWarmSnapshotArtifact {
    pub(crate) source_operation_id: Id,
    pub(crate) source_request_fingerprint: Sha256Digest,
    pub(crate) prepared_operation_id: Id,
    pub(crate) prepared_request_fingerprint: Sha256Digest,
    pub(crate) workspace_id: Id,
    pub(crate) cat_id: Id,
    pub(crate) node_id: Id,
    pub(crate) placement_identity: cats_api::runtime_lifecycle::PlacementIdentity,
    pub(crate) runtime_config_id: Id,
    pub(crate) runtime_config_digest: Sha256Digest,
    pub(crate) source_runtime_incarnation: RandomId128,
    pub(crate) terminal_manifest_digest: Sha256Digest,
    pub(crate) warm_receipt_digest: Sha256Digest,
    pub(crate) intent_manifest_digest: Sha256Digest,
    pub(crate) prepared_manifest_digest: Sha256Digest,
    pub(crate) snapshot_receipt_digest: Sha256Digest,
    pub(crate) execution_absence: ExecutionAbsenceProof,
    pub(crate) retained_volume_receipts: Vec<VolumeTerminalReceipt>,
    pub(crate) snapshot_tree_digest: Sha256Digest,
    pub(crate) memory_file_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstalledWarmSnapshotInventoryEntry {
    Terminal(Box<InstalledWarmSnapshotArtifact>),
    RetainedPrepared(Box<InstalledPreparedWarmSnapshotArtifact>),
    RetainedIntent(Box<InstalledWarmSnapshotIntentArtifact>),
    Quarantined {
        artifact_id: Id,
        evidence_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WarmCleanupObjectIdentity {
    device: u64,
    inode: u64,
}

impl SuspendWarmPlatformPort for ProductionSuspendWarmPlatform {
    fn inspect_same_node_owned_predecessor(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        deadline: Instant,
    ) -> Result<SameNodeOwnedPredecessorPhysical> {
        validate_same_node_owned_start_source(command, predecessor)?;
        match &predecessor.result {
            NodeResult::RuntimeReady(ready) => {
                let join =
                    match inspect_exact_runtime(&self.physical, command, predecessor, deadline)
                        .context("inspect exact RuntimeReady predecessor runtime")?
                    {
                        InstalledRuntimePhysicalOutcome::Exact(join)
                            if join.vmm_state == InstalledPhysicalVmmState::Executing =>
                        {
                            join
                        }
                        InstalledRuntimePhysicalOutcome::Exact(_)
                        | InstalledRuntimePhysicalOutcome::Absent(_)
                        | InstalledRuntimePhysicalOutcome::Unavailable
                        | InstalledRuntimePhysicalOutcome::Conflict => {
                            anyhow::bail!(
                                "same-Node RuntimeReady predecessor is not one exact executing runtime"
                            )
                        }
                    };
                anyhow::ensure!(
                    join.manifest.source_lifecycle_operation_id == predecessor.operation_id
                        && join.manifest.request_fingerprint == predecessor.request_fingerprint
                        && join.manifest.runtime_incarnation == ready.runtime_incarnation
                        && join.manifest.runtime_config_digest == ready.runtime_config_digest
                        && join.manifest.execution_receipt_digest == ready.execution_receipt_digest
                        && join.manifest.guest_ready_receipt_digest
                            == ready.guest_ready_receipt_digest
                        && join.manifest.manifest_digest.as_bytes() != &[0; 32],
                    "RuntimeReady predecessor changed its installed runtime identity"
                );
                validate_prior_attachment_subset(&ready.volume_receipts, &join.volume_receipts)?;
                let volumes = join_same_node_owned_predecessor_volumes(
                    &self.physical,
                    command,
                    &join.manifest,
                    &join.volume_receipts,
                    deadline,
                )?;
                Ok(SameNodeOwnedPredecessorPhysical {
                    physical_manifest_digest: join.manifest.manifest_digest.clone(),
                    runtime_incarnation: Some(join.manifest.runtime_incarnation.clone()),
                    volumes,
                    source: SameNodeOwnedPredecessorSource::RuntimeReady {
                        installed_runtime: Box::new(join.manifest),
                        physical_identity_digest: join.physical_identity_digest,
                        volume_receipts: join.volume_receipts,
                    },
                })
            }
            NodeResult::SuspendDeclined(declined) => {
                let join =
                    match inspect_exact_runtime(&self.physical, command, predecessor, deadline)
                        .context("inspect exact SuspendDeclined predecessor runtime")?
                    {
                        InstalledRuntimePhysicalOutcome::Exact(join)
                            if join.vmm_state == InstalledPhysicalVmmState::Executing =>
                        {
                            join
                        }
                        InstalledRuntimePhysicalOutcome::Exact(_)
                        | InstalledRuntimePhysicalOutcome::Absent(_)
                        | InstalledRuntimePhysicalOutcome::Unavailable
                        | InstalledRuntimePhysicalOutcome::Conflict => {
                            anyhow::bail!(
                                "same-Node SuspendDeclined predecessor is not one exact executing runtime"
                            )
                        }
                    };
                anyhow::ensure!(
                    join.manifest.source_lifecycle_operation_id
                            == declined
                                .effective_runtime_ready
                                .source_lifecycle_operation_id
                        && join.manifest.runtime_incarnation
                            == declined.effective_runtime_ready.runtime_incarnation
                        && join.manifest.runtime_config_digest
                            == declined.effective_runtime_ready.runtime_config_digest
                        && join.manifest.execution_receipt_digest
                            == declined
                                .effective_runtime_ready
                                .runtime_ready_receipt_digest
                        && join.manifest.manifest_digest.as_bytes() != &[0; 32],
                    "SuspendDeclined predecessor changed its effective RuntimeReady identity"
                );
                let volumes = join_same_node_owned_predecessor_volumes(
                    &self.physical,
                    command,
                    &join.manifest,
                    &join.volume_receipts,
                    deadline,
                )?;
                Ok(SameNodeOwnedPredecessorPhysical {
                    physical_manifest_digest: join.manifest.manifest_digest.clone(),
                    runtime_incarnation: Some(join.manifest.runtime_incarnation.clone()),
                    volumes,
                    source: SameNodeOwnedPredecessorSource::SuspendDeclined {
                        installed_runtime: Box::new(join.manifest),
                        physical_identity_digest: join.physical_identity_digest,
                        effective_runtime_ready: declined.effective_runtime_ready.clone(),
                        volume_receipts: join.volume_receipts,
                    },
                })
            }
            NodeResult::Suspended(suspended) => {
                let join =
                    match inspect_exact_runtime(&self.physical, command, predecessor, deadline)
                        .context("inspect exact Suspended predecessor runtime")?
                    {
                        InstalledRuntimePhysicalOutcome::Exact(join)
                            if join.vmm_state == InstalledPhysicalVmmState::Paused =>
                        {
                            join
                        }
                        InstalledRuntimePhysicalOutcome::Exact(_)
                        | InstalledRuntimePhysicalOutcome::Absent(_)
                        | InstalledRuntimePhysicalOutcome::Unavailable
                        | InstalledRuntimePhysicalOutcome::Conflict => {
                            anyhow::bail!(
                                "same-Node Suspended predecessor is not one exact paused runtime"
                            )
                        }
                    };
                anyhow::ensure!(
                    join.manifest.runtime_incarnation == suspended.runtime_incarnation
                        && join.manifest.runtime_config_digest == suspended.runtime_config_digest
                        && join.manifest.manifest_digest.as_bytes() != &[0; 32]
                        && join.volume_receipts.len() == suspended.local_durability_receipts.len(),
                    "Suspended predecessor manifest changed its terminal identity"
                );
                validate_prior_attachment_subset(
                    &suspended.local_durability_receipts,
                    &join.volume_receipts,
                )?;
                let volumes = join_same_node_owned_predecessor_volumes(
                    &self.physical,
                    command,
                    &join.manifest,
                    &join.volume_receipts,
                    deadline,
                )?;
                Ok(SameNodeOwnedPredecessorPhysical {
                    physical_manifest_digest: join.manifest.manifest_digest.clone(),
                    runtime_incarnation: Some(join.manifest.runtime_incarnation.clone()),
                    volumes,
                    source: SameNodeOwnedPredecessorSource::Suspended {
                        installed_runtime: Box::new(join.manifest),
                        physical_identity_digest: join.physical_identity_digest,
                        pause_receipt_digest: suspended.pause_receipt_digest.clone(),
                        volume_receipts: join.volume_receipts,
                    },
                })
            }
            NodeResult::Warm(warm) => {
                let request = WarmSnapshotCleanupRequest::from_warm_predecessor(predecessor)?;
                let authority = match inspect_warm_cleanup_authority(
                    &self.physical,
                    command,
                    &request,
                    deadline,
                )? {
                    WarmSnapshotCleanupAttempt::Exact(authority) => authority,
                    WarmSnapshotCleanupAttempt::Blocked => {
                        anyhow::bail!("same-Node Warm predecessor bundle is not exact")
                    }
                };
                anyhow::ensure!(
                    authority.mode
                        == match command.command {
                            LifecycleCommand::Start(_) => {
                                WarmSnapshotCleanupMode::TransferToRuntime
                            }
                            LifecycleCommand::Cold(_) | LifecycleCommand::Delete(_) => {
                                WarmSnapshotCleanupMode::Remove
                            }
                            LifecycleCommand::Stop(_) => WarmSnapshotCleanupMode::Remove,
                            _ => anyhow::bail!(
                                "same-Node Warm predecessor has an unsupported successor"
                            ),
                        }
                        && authority.request.source_runtime_incarnation
                            == warm.source_runtime_incarnation
                        && authority.request.volume_receipts == warm.volume_receipts
                        && authority.request.terminal_manifest_digest
                            == warm.warm_snapshot_manifest_digest
                        && authority.request.warm_receipt_digest
                            == warm.warm_snapshot_receipt_digest,
                    "Warm predecessor transfer authority changed its terminal result"
                );
                let volumes = join_same_node_owned_predecessor_volumes(
                    &self.physical,
                    command,
                    authority.installed_runtime()?,
                    &warm.volume_receipts,
                    deadline,
                )?;
                Ok(SameNodeOwnedPredecessorPhysical {
                    physical_manifest_digest: authority.request.terminal_manifest_digest.clone(),
                    runtime_incarnation: Some(warm.source_runtime_incarnation.clone()),
                    volumes,
                    source: SameNodeOwnedPredecessorSource::Warm {
                        cleanup_authority: Box::new(authority),
                    },
                })
            }
            NodeResult::SuspendFailed(failed) | NodeResult::WarmFailed(failed) => {
                validate_failed_predecessor_retained_projection(
                    &self.physical,
                    command,
                    failed,
                    deadline,
                )?;
                let installed = load_installed_runtime_manifest(
                    &self.physical.state_directory,
                    &command.cat_id,
                )
                .context("load failed Suspend/Warm predecessor installed runtime")?
                .context("failed Suspend/Warm predecessor lost its installed runtime manifest")?;
                anyhow::ensure!(
                    installed.node_id == command.node_id
                        && installed.cat_id == command.cat_id
                        && installed.placement_identity == command.placement_identity
                        && installed.runtime_config_id == command.runtime_config.config_id
                        && installed.runtime_config_digest == command.runtime_config.config_digest
                        && installed.manifest_digest.as_bytes() != &[0; 32]
                        && failed.retained_evidence.artifact_manifest_digest.as_bytes() != &[0; 32],
                    "failed Suspend/Warm predecessor changed its retained runtime target"
                );
                let (volumes, volume_receipts) = join_failed_same_node_owned_predecessor_volumes(
                    &self.physical,
                    command,
                    &installed,
                    deadline,
                )?;
                let terminal = LifecycleTerminalResult::NodeResult {
                    response: Box::new(predecessor.clone()),
                };
                let terminal_result_digest = lifecycle_terminal_result_digest(&terminal)
                    .context("digest failed Suspend/Warm predecessor")?;
                let physical_manifest_digest = failed_predecessor_physical_digest(
                    predecessor,
                    &terminal_result_digest,
                    failed,
                    &installed,
                    &volumes,
                    &volume_receipts,
                )?;
                Ok(SameNodeOwnedPredecessorPhysical {
                    physical_manifest_digest,
                    runtime_incarnation: Some(installed.runtime_incarnation.clone()),
                    volumes,
                    source: SameNodeOwnedPredecessorSource::Failed {
                        installed_runtime: Box::new(installed),
                        execution_absence: failed.not_running.clone(),
                        retained_evidence: failed.retained_evidence.clone(),
                        predecessor_terminal_result_digest: terminal_result_digest,
                        volume_receipts,
                    },
                })
            }
            _ => anyhow::bail!(
                "same-Node Owned predecessor is not RuntimeReady, SuspendDeclined, Suspended, Warm, SuspendFailed, or WarmFailed"
            ),
        }
    }

    fn inspect_rebound_warm_retry_source(
        &self,
        command: &LifecycleCommandEnvelope,
        authority: &WarmSnapshotCleanupAuthority,
        deadline: Instant,
    ) -> Result<SameNodeOwnedPredecessorPhysical> {
        inspect_rebound_warm_retry_source_physical(&self.physical, command, authority, deadline)
    }

    fn inspect_runtime(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<InstalledRuntimeEvidence>> {
        Ok(
            match inspect_exact_runtime_bounded(&self.physical, command, predecessor, deadline)? {
                InstalledRuntimePhysicalOutcome::Exact(join) => {
                    SuspendWarmPlatformAttempt::Exact(runtime_evidence_from_join(&join))
                }
                InstalledRuntimePhysicalOutcome::Absent(_) => {
                    SuspendWarmPlatformAttempt::DefiniteFailure(CommandFailureReason::VmmFailed)
                }
                InstalledRuntimePhysicalOutcome::Unavailable => {
                    SuspendWarmPlatformAttempt::Ambiguous
                }
                InstalledRuntimePhysicalOutcome::Conflict => {
                    SuspendWarmPlatformAttempt::DataSafetyBlocked {
                        reason: InterventionReason::ForeignOrAmbiguousResidue,
                        retained_volume_receipts: Vec::new(),
                    }
                }
            },
        )
    }

    fn quiesce_guest(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        runtime: &InstalledRuntimeEvidence,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<GuestQuiesceEvidence>> {
        let before = match exact_join_for_effect(
            &self.physical,
            command,
            predecessor,
            runtime,
            deadline,
            InstalledPhysicalVmmState::Executing,
        )? {
            JoinForEffect::Exact(join) => join,
            JoinForEffect::DefiniteFailure(reason) => {
                return Ok(SuspendWarmPlatformAttempt::DefiniteFailure(reason))
            }
            JoinForEffect::DataSafetyBlocked {
                reason,
                retained_volume_receipts,
            } => {
                return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason,
                    retained_volume_receipts,
                })
            }
            JoinForEffect::Ambiguous => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
        };
        let remaining =
            match remaining_platform_timeout(deadline, self.physical.physical_probe_timeout) {
                Ok(remaining) => remaining,
                Err(_) => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
            };
        let mut guest = match GuestClient::connect_hybrid_vsock_bounded_exact_peer(
            Path::new(before.manifest.vmm.vsock_socket_path.as_str()),
            GUEST_VSOCK_PORT,
            remaining,
            before.manifest.vmm.process.pid,
        ) {
            Ok(guest) => guest,
            Err(_) => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
        };
        let mut status = match guest.work_status_before(None, 0, deadline) {
            Ok(status) => status,
            Err(_) => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
        };
        if !status.leases.is_empty() {
            if Instant::now() >= deadline {
                return Ok(SuspendWarmPlatformAttempt::DefiniteFailure(
                    CommandFailureReason::GuestNotReady,
                ));
            }
            let wait_ms = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100))
                .as_millis()
                .max(1) as u64;
            status = match guest.work_status_before(Some(status.lease_sequence), wait_ms, deadline)
            {
                Ok(status) => status,
                Err(_) => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
            };
            if !status.leases.is_empty() {
                return Ok(if Instant::now() >= deadline {
                    SuspendWarmPlatformAttempt::DefiniteFailure(CommandFailureReason::GuestNotReady)
                } else {
                    SuspendWarmPlatformAttempt::Ambiguous
                });
            }
        }
        let source_epoch = RandomId128::new(status.source_epoch.clone())
            .context("Guest work source epoch is not canonical")?;
        if !status.quiescing {
            match guest.prepare_suspend_before(status.lease_sequence, deadline) {
                Ok((prepared_source, prepared_sequence))
                    if prepared_source == status.source_epoch
                        && prepared_sequence == status.lease_sequence => {}
                Ok(_) => {
                    return Ok(SuspendWarmPlatformAttempt::DefiniteFailure(
                        CommandFailureReason::StoredEvidenceConflict,
                    ))
                }
                Err(_) => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
            }
        }
        if guest.syncfs_before(deadline).is_err() {
            return Ok(SuspendWarmPlatformAttempt::Ambiguous);
        }
        let remaining =
            match remaining_platform_timeout(deadline, self.physical.physical_probe_timeout) {
                Ok(remaining) => remaining,
                Err(_) => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
            };
        let mut verify = match GuestClient::connect_hybrid_vsock_bounded_exact_peer(
            Path::new(before.manifest.vmm.vsock_socket_path.as_str()),
            GUEST_VSOCK_PORT,
            remaining,
            before.manifest.vmm.process.pid,
        ) {
            Ok(guest) => guest,
            Err(_) => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
        };
        let after_status = match verify.work_status_before(None, 0, deadline) {
            Ok(status) => status,
            Err(_) => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
        };
        if !after_status.quiescing
            || !after_status.leases.is_empty()
            || after_status.source_epoch != status.source_epoch
            || after_status.lease_sequence != status.lease_sequence
        {
            return Ok(SuspendWarmPlatformAttempt::DefiniteFailure(
                CommandFailureReason::GuestNotReady,
            ));
        }
        match exact_join_for_effect(
            &self.physical,
            command,
            predecessor,
            runtime,
            deadline,
            InstalledPhysicalVmmState::Executing,
        )? {
            JoinForEffect::Exact(_) => {}
            JoinForEffect::DefiniteFailure(reason) => {
                return Ok(SuspendWarmPlatformAttempt::DefiniteFailure(reason))
            }
            JoinForEffect::DataSafetyBlocked {
                reason,
                retained_volume_receipts,
            } => {
                return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason,
                    retained_volume_receipts,
                })
            }
            JoinForEffect::Ambiguous => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
        }
        let source_epoch_digest = digest_parts(
            b"cats.atomic-lifecycle.guest-source-epoch.v1",
            &[source_epoch.as_str().as_bytes()],
        );
        Ok(SuspendWarmPlatformAttempt::Exact(GuestQuiesceEvidence {
            runtime_physical_identity_digest: runtime.physical_identity_digest.clone(),
            source_epoch_digest: source_epoch_digest.clone(),
            lease_sequence: status.lease_sequence,
            quiesce_receipt_digest: guest_quiesce_receipt_digest(
                &runtime.physical_identity_digest,
                &source_epoch_digest,
                status.lease_sequence,
            ),
        }))
    }

    fn pause_vmm(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        runtime: &InstalledRuntimeEvidence,
        quiesce: &GuestQuiesceEvidence,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<PausedRuntimeEvidence>> {
        validate_quiesce_evidence(runtime, quiesce)?;
        let before =
            match inspect_exact_runtime_bounded(&self.physical, command, predecessor, deadline)? {
                InstalledRuntimePhysicalOutcome::Exact(join)
                    if matches!(
                        join.vmm_state,
                        InstalledPhysicalVmmState::Executing | InstalledPhysicalVmmState::Paused
                    ) && join_advances_runtime(runtime, &join).is_ok() =>
                {
                    join
                }
                InstalledRuntimePhysicalOutcome::Exact(join) => {
                    return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                        reason: InterventionReason::ForeignOrAmbiguousResidue,
                        retained_volume_receipts: join.volume_receipts,
                    })
                }
                InstalledRuntimePhysicalOutcome::Absent(_) => {
                    return Ok(SuspendWarmPlatformAttempt::DefiniteFailure(
                        CommandFailureReason::VmmFailed,
                    ))
                }
                InstalledRuntimePhysicalOutcome::Unavailable => {
                    return Ok(SuspendWarmPlatformAttempt::Ambiguous)
                }
                InstalledRuntimePhysicalOutcome::Conflict => {
                    return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                        reason: InterventionReason::ForeignOrAmbiguousResidue,
                        retained_volume_receipts: runtime.volume_receipts.clone(),
                    })
                }
            };
        let effect = pause_exact_vmm_until(
            Path::new(before.manifest.vmm.api_socket_path.as_str()),
            before.manifest.vmm.process.pid,
            deadline,
        )?;
        match effect {
            ExactVmEffectOutcome::Exact => {}
            ExactVmEffectOutcome::DefiniteFailure => {
                return Ok(SuspendWarmPlatformAttempt::DefiniteFailure(
                    CommandFailureReason::VmmFailed,
                ))
            }
            ExactVmEffectOutcome::Ambiguous => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
        }
        let after =
            match inspect_exact_runtime_bounded(&self.physical, command, predecessor, deadline)? {
                InstalledRuntimePhysicalOutcome::Exact(join)
                    if join.vmm_state == InstalledPhysicalVmmState::Paused
                        && join_advances_runtime(runtime, &join).is_ok() =>
                {
                    join
                }
                InstalledRuntimePhysicalOutcome::Exact(join) => {
                    return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                        reason: InterventionReason::ForeignOrAmbiguousResidue,
                        retained_volume_receipts: join.volume_receipts,
                    })
                }
                InstalledRuntimePhysicalOutcome::Absent(_) => {
                    return Ok(SuspendWarmPlatformAttempt::DefiniteFailure(
                        CommandFailureReason::VmmFailed,
                    ))
                }
                InstalledRuntimePhysicalOutcome::Unavailable => {
                    return Ok(SuspendWarmPlatformAttempt::Ambiguous)
                }
                InstalledRuntimePhysicalOutcome::Conflict => {
                    return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                        reason: InterventionReason::ForeignOrAmbiguousResidue,
                        retained_volume_receipts: runtime.volume_receipts.clone(),
                    })
                }
            };
        let write_fence = RuntimeWriteFenceEvidence::Guest {
            quiesce: quiesce.clone(),
        };
        let binding = StepBinding::new(command);
        let receipt =
            pause_receipt_digest(&binding, runtime, &write_fence, &after.volume_receipts)?;
        Ok(SuspendWarmPlatformAttempt::Exact(PausedRuntimeEvidence {
            pause_operation_id: binding.operation_id,
            pause_request_fingerprint: binding.request_fingerprint,
            runtime_physical_identity_digest: runtime.physical_identity_digest.clone(),
            write_fence_receipt_digest: quiesce.quiesce_receipt_digest.clone(),
            pause_receipt_digest: receipt,
            local_durability_receipts: after.volume_receipts,
        }))
    }

    fn drain_volumes_to_remote(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        runtime: &InstalledRuntimeEvidence,
        write_fence: &RuntimeWriteFenceEvidence,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<Vec<VolumeTerminalReceipt>>> {
        validate_write_fence(runtime, write_fence)?;
        let expected_state = match write_fence {
            RuntimeWriteFenceEvidence::Guest { .. } => InstalledPhysicalVmmState::Executing,
            RuntimeWriteFenceEvidence::InheritedSuspended { .. } => {
                InstalledPhysicalVmmState::Paused
            }
        };
        let before = match exact_join_for_effect(
            &self.physical,
            command,
            predecessor,
            runtime,
            deadline,
            expected_state,
        )? {
            JoinForEffect::Exact(join) => join,
            JoinForEffect::DefiniteFailure(reason) => {
                return Ok(SuspendWarmPlatformAttempt::DefiniteFailure(reason))
            }
            JoinForEffect::DataSafetyBlocked {
                reason,
                retained_volume_receipts,
            } => {
                return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason,
                    retained_volume_receipts,
                })
            }
            JoinForEffect::Ambiguous => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
        };
        for volume in &before.manifest.volumes {
            if send_exact_blockd_drain(volume, deadline).is_err() {
                break;
            }
        }
        match inspect_exact_runtime_bounded(&self.physical, command, predecessor, deadline)? {
            InstalledRuntimePhysicalOutcome::Exact(join)
                if join.vmm_state == expected_state
                    && join_advances_runtime(runtime, &join).is_ok()
                    && receipts_are_remote(&join.volume_receipts) =>
            {
                Ok(SuspendWarmPlatformAttempt::Exact(join.volume_receipts))
            }
            InstalledRuntimePhysicalOutcome::Exact(join)
                if join_advances_runtime(runtime, &join).is_ok() =>
            {
                if Instant::now() < deadline {
                    Ok(SuspendWarmPlatformAttempt::Ambiguous)
                } else {
                    Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                        reason: not_remote_reason(&join.volume_receipts),
                        retained_volume_receipts: join.volume_receipts,
                    })
                }
            }
            InstalledRuntimePhysicalOutcome::Exact(join) => {
                Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason: InterventionReason::AuthorityAmbiguous,
                    retained_volume_receipts: join.volume_receipts,
                })
            }
            InstalledRuntimePhysicalOutcome::Absent(_) => Ok(
                SuspendWarmPlatformAttempt::DefiniteFailure(CommandFailureReason::VmmFailed),
            ),
            InstalledRuntimePhysicalOutcome::Unavailable if Instant::now() < deadline => {
                Ok(SuspendWarmPlatformAttempt::Ambiguous)
            }
            InstalledRuntimePhysicalOutcome::Unavailable
            | InstalledRuntimePhysicalOutcome::Conflict => {
                Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason: InterventionReason::AuthorityAmbiguous,
                    retained_volume_receipts: before.volume_receipts,
                })
            }
        }
    }

    fn create_warm_snapshot(
        &self,
        inputs: WarmSnapshotInputs<'_>,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<WarmSnapshotEvidence>> {
        let WarmSnapshotInputs {
            command,
            predecessor,
            runtime,
            write_fence,
            paused,
            drained_volumes,
        } = inputs;
        let pause_binding = expected_pause_binding(command, predecessor, paused)?;
        validate_paused_evidence(command, &pause_binding, runtime, write_fence, paused, true)?;
        let join = match exact_join_for_effect(
            &self.physical,
            command,
            predecessor,
            runtime,
            deadline,
            InstalledPhysicalVmmState::Paused,
        )? {
            JoinForEffect::Exact(join) => join,
            JoinForEffect::DefiniteFailure(reason) => {
                return Ok(SuspendWarmPlatformAttempt::DefiniteFailure(reason))
            }
            JoinForEffect::DataSafetyBlocked {
                reason,
                retained_volume_receipts,
            } => {
                return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason,
                    retained_volume_receipts,
                })
            }
            JoinForEffect::Ambiguous => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
        };
        if validate_same_attachments(drained_volumes, &join.volume_receipts).is_err()
            || !receipts_are_remote(&join.volume_receipts)
        {
            return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                reason: InterventionReason::AuthorityAmbiguous,
                retained_volume_receipts: join.volume_receipts,
            });
        }
        match create_or_reopen_warm_snapshot(&self.physical, inputs, &join.manifest, deadline)? {
            SnapshotPublishAttempt::Exact(evidence) => {
                Ok(SuspendWarmPlatformAttempt::Exact(*evidence))
            }
            SnapshotPublishAttempt::DefiniteFailure => Ok(
                SuspendWarmPlatformAttempt::DefiniteFailure(CommandFailureReason::SnapshotInvalid),
            ),
            SnapshotPublishAttempt::Ambiguous => Ok(SuspendWarmPlatformAttempt::Ambiguous),
        }
    }

    fn verify_warm_snapshot(
        &self,
        inputs: WarmSnapshotInputs<'_>,
        expected_snapshot: &WarmSnapshotEvidence,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<WarmSnapshotEvidence>> {
        let WarmSnapshotInputs {
            command,
            predecessor,
            runtime: _,
            write_fence: _,
            paused: _,
            drained_volumes,
        } = inputs;
        let source_binding = expected_snapshot_binding(command, predecessor, expected_snapshot)?;
        let join = inspect_exact_runtime_bounded(&self.physical, command, predecessor, deadline)?;
        match &join {
            InstalledRuntimePhysicalOutcome::Exact(current)
                if current.vmm_state == InstalledPhysicalVmmState::Paused
                    && validate_same_attachments(drained_volumes, &current.volume_receipts)
                        .is_ok()
                    && receipts_are_remote(&current.volume_receipts) => {}
            InstalledRuntimePhysicalOutcome::Absent(_) => {
                if validate_absent_snapshot_authority(&self.physical, command, drained_volumes)
                    .is_err()
                {
                    return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                        reason: InterventionReason::AuthorityAmbiguous,
                        retained_volume_receipts: drained_volumes.to_vec(),
                    });
                }
            }
            InstalledRuntimePhysicalOutcome::Unavailable => {
                return Ok(SuspendWarmPlatformAttempt::Ambiguous)
            }
            InstalledRuntimePhysicalOutcome::Exact(current) => {
                return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason: InterventionReason::AuthorityAmbiguous,
                    retained_volume_receipts: current.volume_receipts.clone(),
                })
            }
            InstalledRuntimePhysicalOutcome::Conflict => {
                return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason: InterventionReason::ForeignOrAmbiguousResidue,
                    retained_volume_receipts: drained_volumes.to_vec(),
                })
            }
        }
        match reopen_warm_snapshot(
            &self.physical,
            &source_binding,
            inputs,
            expected_snapshot,
            deadline,
        )? {
            SnapshotReopenAttempt::Exact(manifest) => {
                Ok(SuspendWarmPlatformAttempt::Exact(manifest.evidence))
            }
            SnapshotReopenAttempt::Absent | SnapshotReopenAttempt::Invalid => Ok(
                SuspendWarmPlatformAttempt::DefiniteFailure(CommandFailureReason::SnapshotInvalid),
            ),
            SnapshotReopenAttempt::Unavailable => Ok(SuspendWarmPlatformAttempt::Ambiguous),
        }
    }

    fn finalize_warm_snapshot(
        &self,
        inputs: WarmSnapshotInputs<'_>,
        snapshot: &WarmSnapshotEvidence,
        execution_absence: &ExecutionAbsenceProof,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<FinalizedWarmSnapshotEvidence>> {
        let WarmSnapshotInputs {
            command,
            predecessor,
            runtime,
            write_fence,
            paused,
            drained_volumes,
        } = inputs;
        let source_binding = expected_snapshot_binding(command, predecessor, snapshot)?;
        validate_snapshot_evidence(
            &source_binding,
            runtime,
            write_fence,
            paused,
            drained_volumes,
            snapshot,
        )?;
        match reopen_warm_snapshot(&self.physical, &source_binding, inputs, snapshot, deadline)? {
            SnapshotReopenAttempt::Exact(_) => {}
            SnapshotReopenAttempt::Absent | SnapshotReopenAttempt::Invalid => {
                return Ok(SuspendWarmPlatformAttempt::DefiniteFailure(
                    CommandFailureReason::SnapshotInvalid,
                ))
            }
            SnapshotReopenAttempt::Unavailable => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
        }
        match finalize_or_reopen_warm_terminal(
            &self.physical,
            command,
            runtime,
            snapshot,
            drained_volumes,
            execution_absence,
            deadline,
        )? {
            TerminalPublishAttempt::Exact(evidence) => {
                Ok(SuspendWarmPlatformAttempt::Exact(evidence))
            }
            TerminalPublishAttempt::Invalid => Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                reason: InterventionReason::ForeignOrAmbiguousResidue,
                retained_volume_receipts: drained_volumes.to_vec(),
            }),
            TerminalPublishAttempt::Unavailable => Ok(SuspendWarmPlatformAttempt::Ambiguous),
        }
    }

    fn inspect_warm_recovery(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        deadline: Instant,
    ) -> Result<SuspendWarmPlatformAttempt<RecoveredWarmEvidence>> {
        let NodeResult::NeedsIntervention(intervention) = &predecessor.result else {
            return Ok(SuspendWarmPlatformAttempt::DefiniteFailure(
                CommandFailureReason::StoredEvidenceConflict,
            ));
        };
        if intervention.attempted_target != InterventionTarget::Warm {
            return Ok(SuspendWarmPlatformAttempt::DefiniteFailure(
                CommandFailureReason::StoredEvidenceConflict,
            ));
        }
        let binding = StepBinding::from_response(predecessor);
        let stored = match read_warm_snapshot_manifest(&self.physical, &binding, deadline)? {
            SnapshotManifestRead::Exact(manifest) => manifest,
            SnapshotManifestRead::Absent | SnapshotManifestRead::Invalid => {
                return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason: intervention.reason,
                    retained_volume_receipts: intervention.retained_volume_receipts.clone(),
                })
            }
            SnapshotManifestRead::Unavailable => return Ok(SuspendWarmPlatformAttempt::Ambiguous),
        };
        if !snapshot_manifest_matches_command(&stored.body, command, &binding) {
            return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                reason: InterventionReason::ForeignOrAmbiguousResidue,
                retained_volume_receipts: intervention.retained_volume_receipts.clone(),
            });
        }
        match inspect_exact_runtime_bounded(&self.physical, command, predecessor, deadline)? {
            InstalledRuntimePhysicalOutcome::Absent(_) => {}
            InstalledRuntimePhysicalOutcome::Unavailable => {
                return Ok(SuspendWarmPlatformAttempt::Ambiguous)
            }
            InstalledRuntimePhysicalOutcome::Exact(join) => {
                return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason: InterventionReason::ForeignOrAmbiguousResidue,
                    retained_volume_receipts: join.volume_receipts,
                })
            }
            InstalledRuntimePhysicalOutcome::Conflict => {
                return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason: InterventionReason::ForeignOrAmbiguousResidue,
                    retained_volume_receipts: intervention.retained_volume_receipts.clone(),
                })
            }
        }
        if validate_absent_snapshot_authority(&self.physical, command, &stored.body.drained_volumes)
            .is_err()
        {
            return Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                reason: InterventionReason::AuthorityAmbiguous,
                retained_volume_receipts: stored.body.drained_volumes.clone(),
            });
        }
        let mut absent_runtime = stored.body.runtime.clone();
        absent_runtime.vmm_state = InstalledVmmState::Absent;
        absent_runtime.volume_receipts = stored.body.drained_volumes.clone();
        match reopen_warm_snapshot(
            &self.physical,
            &binding,
            WarmSnapshotInputs {
                command,
                predecessor,
                runtime: &absent_runtime,
                write_fence: &stored.body.write_fence,
                paused: &stored.body.paused,
                drained_volumes: &stored.body.drained_volumes,
            },
            &stored.evidence,
            deadline,
        )? {
            SnapshotReopenAttempt::Exact(reopened) => {
                let predecessor_evidence = warm_recovery_predecessor_evidence(
                    command,
                    predecessor,
                    &absent_runtime,
                    &reopened.body.write_fence,
                    &reopened.body.paused,
                    &reopened.evidence,
                    &reopened.body.drained_volumes,
                )?;
                Ok(SuspendWarmPlatformAttempt::Exact(RecoveredWarmEvidence {
                    runtime: absent_runtime,
                    write_fence: reopened.body.write_fence,
                    paused: reopened.body.paused,
                    snapshot: reopened.evidence,
                    drained_volumes: reopened.body.drained_volumes,
                    predecessor: predecessor_evidence,
                }))
            }
            SnapshotReopenAttempt::Absent | SnapshotReopenAttempt::Invalid => {
                Ok(SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason: intervention.reason,
                    retained_volume_receipts: intervention.retained_volume_receipts.clone(),
                })
            }
            SnapshotReopenAttempt::Unavailable => Ok(SuspendWarmPlatformAttempt::Ambiguous),
        }
    }

    fn inspect_or_remove_warm_snapshot(
        &self,
        command: &LifecycleCommandEnvelope,
        authority: &WarmSnapshotCleanupAuthority,
        completion: &WarmSnapshotCleanupCompletion,
        deadline: Instant,
    ) -> Result<WarmSnapshotCleanupAttempt<Sha256Digest>> {
        inspect_or_remove_terminal_warm_bundle(
            &self.physical,
            command,
            authority,
            completion,
            deadline,
        )
    }

    fn prepare_warm_snapshot_cleanup(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &WarmSnapshotCleanupRequest,
        deadline: Instant,
    ) -> Result<WarmSnapshotCleanupAttempt<WarmSnapshotCleanupAuthority>> {
        inspect_warm_cleanup_authority(&self.physical, command, request, deadline)
    }
}

fn validate_same_node_owned_start_source(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
) -> Result<()> {
    let terminal = LifecycleTerminalResult::NodeResult {
        response: Box::new(predecessor.clone()),
    };
    let predecessor_kind = predecessor.result.kind();
    let failed_start_retry = matches!(
        (&command.command, predecessor_kind),
        (
            LifecycleCommand::Start(spec),
            cats_api::runtime_lifecycle::TerminalResultKind::StartFailed
                | cats_api::runtime_lifecycle::TerminalResultKind::SuspendFailed
                | cats_api::runtime_lifecycle::TerminalResultKind::WarmFailed,
        ) if spec.source == StartSource::SameNodeRetry
    );
    if !failed_start_retry {
        validate_lifecycle_successor(Some(&terminal), command)
            .context("validate same-Node Owned predecessor")?;
    }
    // A failed Start retry deliberately cannot be admitted from this
    // response-only physical scanner. The journal and Start handler have
    // already applied the operation-aware shared validator using the exact
    // canonical predecessor command retained in the atomic record. The code
    // below only joins that admitted identity to fresh local physical state.
    let expected_kind = match (&command.command, predecessor_kind) {
        (
            LifecycleCommand::Start(spec),
            cats_api::runtime_lifecycle::TerminalResultKind::Suspended,
        ) if spec.source == StartSource::SameNodeSuspended => {
            cats_api::runtime_lifecycle::TerminalResultKind::Suspended
        }
        (LifecycleCommand::Start(spec), cats_api::runtime_lifecycle::TerminalResultKind::Warm)
            if spec.source == StartSource::SameNodeWarm =>
        {
            cats_api::runtime_lifecycle::TerminalResultKind::Warm
        }
        (
            LifecycleCommand::Start(spec),
            kind @ (cats_api::runtime_lifecycle::TerminalResultKind::StartFailed
            | cats_api::runtime_lifecycle::TerminalResultKind::SuspendFailed
            | cats_api::runtime_lifecycle::TerminalResultKind::WarmFailed),
        ) if spec.source == StartSource::SameNodeRetry => kind,
        (
            LifecycleCommand::Stop(_),
            cats_api::runtime_lifecycle::TerminalResultKind::RuntimeReady,
        ) => cats_api::runtime_lifecycle::TerminalResultKind::RuntimeReady,
        (
            LifecycleCommand::Cold(_) | LifecycleCommand::Stop(_) | LifecycleCommand::Delete(_),
            kind @ (cats_api::runtime_lifecycle::TerminalResultKind::SuspendDeclined
            | cats_api::runtime_lifecycle::TerminalResultKind::Suspended
            | cats_api::runtime_lifecycle::TerminalResultKind::Warm
            | cats_api::runtime_lifecycle::TerminalResultKind::SuspendFailed
            | cats_api::runtime_lifecycle::TerminalResultKind::WarmFailed),
        ) => kind,
        _ => anyhow::bail!(
            "command is not an exact supported same-Node Suspend/Warm predecessor consumer"
        ),
    };
    let LifecyclePredecessor::SameNode {
        operation_id,
        terminal_result_kind,
        terminal_result_digest: declared_terminal_result_digest,
        node_id,
        placement_identity,
    } = &command.predecessor
    else {
        anyhow::bail!("same-Node predecessor inspection lacks SameNode authority")
    };
    let actual_terminal_digest = lifecycle_terminal_result_digest(&terminal)
        .context("digest same-Node predecessor terminal result")?;
    anyhow::ensure!(
        predecessor.operation_id == *operation_id
            && predecessor.request_fingerprint.as_bytes() != &[0; 32]
            && predecessor.workspace_id == command.workspace_id
            && predecessor.cat_id == command.cat_id
            && predecessor.node_id == *node_id
            && predecessor.node_id == command.node_id
            && predecessor.placement_identity == *placement_identity
            && predecessor.placement_identity == command.placement_identity
            && predecessor.result.kind() == expected_kind
            && *terminal_result_kind == expected_kind
            && actual_terminal_digest == *declared_terminal_result_digest,
        "same-Node predecessor response changed its exact command binding"
    );
    Ok(())
}

#[derive(Serialize)]
struct WarmRecoveryPredecessorPreimage<'a> {
    version: u64,
    retry_operation_id: &'a Id,
    retry_request_fingerprint: &'a Sha256Digest,
    predecessor_operation_id: &'a Id,
    predecessor_request_fingerprint: &'a Sha256Digest,
    predecessor_terminal_result_digest: &'a Sha256Digest,
    intervention: &'a NeedsInterventionResult,
    runtime: &'a InstalledRuntimeEvidence,
    write_fence: &'a RuntimeWriteFenceEvidence,
    paused: &'a PausedRuntimeEvidence,
    snapshot: &'a WarmSnapshotEvidence,
    drained_volumes: &'a [VolumeTerminalReceipt],
}

fn warm_recovery_predecessor_evidence(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    runtime: &InstalledRuntimeEvidence,
    write_fence: &RuntimeWriteFenceEvidence,
    paused: &PausedRuntimeEvidence,
    snapshot: &WarmSnapshotEvidence,
    drained_volumes: &[VolumeTerminalReceipt],
) -> Result<WarmRecoveryPredecessorEvidence> {
    anyhow::ensure!(
        matches!(command.command, LifecycleCommand::Warm(_)),
        "Warm recovery carrier cannot authorize another command"
    );
    validate_predecessor_response(command, predecessor)?;
    let NodeResult::NeedsIntervention(intervention) = &predecessor.result else {
        anyhow::bail!("Warm recovery carrier requires NeedsIntervention")
    };
    anyhow::ensure!(
        intervention.attempted_target == InterventionTarget::Warm
            && intervention.reason != InterventionReason::ForeignOrAmbiguousResidue
            && intervention
                .retained_evidence
                .artifact_manifest_digest
                .as_bytes()
                != &[0; 32]
            && execution_absence_proof_is_nonzero(&intervention.not_running),
        "Warm recovery predecessor lacks exact retained Warm authority"
    );
    validate_retained_volume_receipts(command, &intervention.retained_volume_receipts)?;
    validate_volume_receipts(command, drained_volumes, true)?;
    validate_prior_attachment_subset(&intervention.retained_volume_receipts, drained_volumes)?;
    let terminal = LifecycleTerminalResult::NodeResult {
        response: Box::new(predecessor.clone()),
    };
    let terminal_result_digest = lifecycle_terminal_result_digest(&terminal)
        .context("digest Warm recovery NeedsIntervention predecessor")?;
    let LifecyclePredecessor::SameNode {
        operation_id,
        terminal_result_kind,
        terminal_result_digest: declared_terminal_result_digest,
        node_id,
        placement_identity,
    } = &command.predecessor
    else {
        anyhow::bail!("Warm recovery carrier lacks same-Node predecessor authority")
    };
    anyhow::ensure!(
        *operation_id == predecessor.operation_id
            && *terminal_result_kind
                == cats_api::runtime_lifecycle::TerminalResultKind::NeedsIntervention
            && *declared_terminal_result_digest == terminal_result_digest
            && *node_id == predecessor.node_id
            && *placement_identity == predecessor.placement_identity,
        "Warm recovery carrier changed its predecessor terminal binding"
    );
    let canonical = serde_json::to_vec(&WarmRecoveryPredecessorPreimage {
        version: STEP_VERSION,
        retry_operation_id: &command.operation_id,
        retry_request_fingerprint: &command.request_fingerprint,
        predecessor_operation_id: &predecessor.operation_id,
        predecessor_request_fingerprint: &predecessor.request_fingerprint,
        predecessor_terminal_result_digest: &terminal_result_digest,
        intervention,
        runtime,
        write_fence,
        paused,
        snapshot,
        drained_volumes,
    })
    .context("encode Warm recovery predecessor carrier")?;
    Ok(WarmRecoveryPredecessorEvidence {
        predecessor_terminal_result_digest: terminal_result_digest,
        execution_absence: intervention.not_running.clone(),
        retained_evidence: intervention.retained_evidence.clone(),
        carrier_digest: digest_parts(WARM_RECOVERY_PREDECESSOR_DOMAIN, &[&canonical]),
    })
}

fn execution_absence_proof_is_nonzero(proof: &ExecutionAbsenceProof) -> bool {
    proof.stop_fence_receipt_digest.as_bytes() != &[0; 32]
        && proof.admission_closed_receipt_digest.as_bytes() != &[0; 32]
        && proof.dedicated_scope_absence_receipt_digest.as_bytes() != &[0; 32]
        && proof.frontend_absence_receipt_digest.as_bytes() != &[0; 32]
        && proof.restart_source_absence_receipt_digest.as_bytes() != &[0; 32]
}

fn validate_failed_predecessor_retained_projection(
    physical: &InstalledPhysicalInspectionConfig,
    command: &LifecycleCommandEnvelope,
    failed: &CommandFailedResult,
    deadline: Instant,
) -> Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    anyhow::ensure!(
        !remaining.is_zero(),
        "failed predecessor retained projection deadline elapsed"
    );
    let mut bounded = physical.clone();
    bounded.inventory_timeout = bounded.inventory_timeout.min(remaining);
    let (projection, _) = scan_startup_inventory(&bounded)
        .context("scan failed Suspend/Warm retained physical projection")?;
    let StartupPhysicalInventory::Complete {
        cats,
        unattributed_artifacts,
        ..
    } = projection
    else {
        anyhow::bail!("failed Suspend/Warm retained physical scan is incomplete")
    };
    anyhow::ensure!(
        Instant::now() < deadline
            && unattributed_artifacts.is_empty()
            && cats.windows(2).all(|pair| pair[0].cat_id < pair[1].cat_id),
        "failed Suspend/Warm retained physical scan is expired or ambiguous"
    );
    let matching = cats
        .iter()
        .filter(|cat| cat.cat_id == command.cat_id)
        .collect::<Vec<_>>();
    let [cat] = matching.as_slice() else {
        anyhow::bail!("failed Suspend/Warm predecessor lacks one exact Cat projection")
    };
    let mut adoptable = 0_u16;
    let mut gc_candidate = 0_u16;
    let mut retained = 0_u16;
    let mut quarantined = 0_u16;
    for artifact in &cat.observed_artifact_classifications {
        let count = match artifact {
            ObservedArtifactClassification::AdoptableCatState { .. } => &mut adoptable,
            ObservedArtifactClassification::CatOwnedGcCandidate { .. } => &mut gc_candidate,
            ObservedArtifactClassification::RetainedAuthorityOrData { .. } => &mut retained,
            ObservedArtifactClassification::QuarantinedForeignOrAmbiguous { .. } => {
                &mut quarantined
            }
        };
        *count = count
            .checked_add(1)
            .context("failed predecessor artifact count overflows")?;
    }
    anyhow::ensure!(
        cat.observed_placement == command.placement_identity
            && cat.observed_command_journal.is_none()
            && cat.observed_runtime_incarnation.is_none()
            && cat.observed_artifact_manifest_digest
                == failed.retained_evidence.artifact_manifest_digest
            && adoptable == failed.retained_evidence.adoptable_count
            && gc_candidate == failed.retained_evidence.gc_candidate_count
            && retained == failed.retained_evidence.retained_authority_or_data_count
            && quarantined == failed.retained_evidence.quarantined_count,
        "failed Suspend/Warm retained projection changed since its terminal strong Stop"
    );
    Ok(())
}

#[derive(Serialize)]
struct FailedPredecessorPhysicalPreimage<'a> {
    version: u64,
    predecessor_operation_id: &'a Id,
    predecessor_request_fingerprint: &'a Sha256Digest,
    predecessor_terminal_result_kind: cats_api::runtime_lifecycle::TerminalResultKind,
    predecessor_terminal_result_digest: &'a Sha256Digest,
    workspace_id: &'a Id,
    cat_id: &'a Id,
    node_id: &'a Id,
    placement_identity: &'a cats_api::runtime_lifecycle::PlacementIdentity,
    runtime_config_id: &'a Id,
    runtime_config_digest: &'a Sha256Digest,
    failed: &'a CommandFailedResult,
    installed_runtime_manifest_digest: &'a Sha256Digest,
    runtime_incarnation: &'a RandomId128,
    volumes: &'a [SameNodeOwnedPredecessorVolume],
    volume_receipts: &'a [VolumeTerminalReceipt],
}

pub(crate) fn failed_predecessor_physical_digest(
    predecessor: &LifecycleCommandResponse,
    terminal_result_digest: &Sha256Digest,
    failed: &CommandFailedResult,
    installed: &InstalledRuntimeManifest,
    volumes: &[SameNodeOwnedPredecessorVolume],
    volume_receipts: &[VolumeTerminalReceipt],
) -> Result<Sha256Digest> {
    anyhow::ensure!(
        terminal_result_digest.as_bytes() != &[0; 32]
            && failed.retained_evidence.artifact_manifest_digest.as_bytes() != &[0; 32]
            && failed.not_running.stop_fence_receipt_digest.as_bytes() != &[0; 32]
            && failed
                .not_running
                .admission_closed_receipt_digest
                .as_bytes()
                != &[0; 32]
            && failed
                .not_running
                .dedicated_scope_absence_receipt_digest
                .as_bytes()
                != &[0; 32]
            && failed
                .not_running
                .frontend_absence_receipt_digest
                .as_bytes()
                != &[0; 32]
            && failed
                .not_running
                .restart_source_absence_receipt_digest
                .as_bytes()
                != &[0; 32]
            && installed.manifest_digest.as_bytes() != &[0; 32]
            && volumes
                .windows(2)
                .all(|pair| pair[0].volume_id < pair[1].volume_id)
            && volume_receipts.len() == volumes.len()
            && volume_receipts
                .windows(2)
                .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "failed Suspend/Warm predecessor lacks closed retained or absence evidence"
    );
    let canonical = serde_json::to_vec(&FailedPredecessorPhysicalPreimage {
        version: STEP_VERSION,
        predecessor_operation_id: &predecessor.operation_id,
        predecessor_request_fingerprint: &predecessor.request_fingerprint,
        predecessor_terminal_result_kind: predecessor.result.kind(),
        predecessor_terminal_result_digest: terminal_result_digest,
        workspace_id: &predecessor.workspace_id,
        cat_id: &predecessor.cat_id,
        node_id: &predecessor.node_id,
        placement_identity: &predecessor.placement_identity,
        runtime_config_id: &installed.runtime_config_id,
        runtime_config_digest: &installed.runtime_config_digest,
        failed,
        installed_runtime_manifest_digest: &installed.manifest_digest,
        runtime_incarnation: &installed.runtime_incarnation,
        volumes,
        volume_receipts,
    })
    .context("encode failed Suspend/Warm predecessor physical carrier")?;
    Ok(digest_parts(
        FAILED_PREDECESSOR_PHYSICAL_DOMAIN,
        &[&canonical],
    ))
}

fn join_failed_same_node_owned_predecessor_volumes(
    physical: &InstalledPhysicalInspectionConfig,
    command: &LifecycleCommandEnvelope,
    installed: &InstalledRuntimeManifest,
    deadline: Instant,
) -> Result<(
    Vec<SameNodeOwnedPredecessorVolume>,
    Vec<VolumeTerminalReceipt>,
)> {
    use cats_storage::authority::{
        validate_volume_owner_binding, validate_volume_record, AttachmentLineageIdentity,
    };

    anyhow::ensure!(
        Instant::now() < deadline,
        "failed predecessor authority deadline elapsed"
    );
    anyhow::ensure!(
        installed.node_id == command.node_id
            && installed.cat_id == command.cat_id
            && installed.placement_identity == command.placement_identity
            && installed.runtime_config_id == command.runtime_config.config_id
            && installed.runtime_config_digest == command.runtime_config.config_digest
            && installed.manifest_digest.as_bytes() != &[0; 32]
            && installed.volumes.len() == command.runtime_config.volumes.len(),
        "failed predecessor installed manifest has another immutable target"
    );
    let candidates = command
        .runtime_config
        .volumes
        .iter()
        .map(|volume| volume.volume_id.clone())
        .collect::<BTreeSet<_>>();
    let snapshot = physical
        .volume_inventory_authority
        .load_node_volume_inventory(&physical.node_id, &candidates)
        .context("load failed predecessor Volume authority snapshot")?;
    anyhow::ensure!(
        snapshot.node_id == physical.node_id && Instant::now() < deadline,
        "failed predecessor authority snapshot has another Node or expired deadline"
    );
    let mut records = BTreeMap::new();
    for record in snapshot.records {
        validate_volume_record(&record.volume).context("validate failed predecessor Volume row")?;
        if let Some(binding) = &record.binding {
            validate_volume_owner_binding(binding, &record.volume)
                .context("validate failed predecessor owner binding")?;
        }
        anyhow::ensure!(
            records
                .insert(record.volume.volume_id.clone(), record)
                .is_none(),
            "failed predecessor authority repeats a Volume row"
        );
    }

    let mut volumes = Vec::with_capacity(command.runtime_config.volumes.len());
    let mut receipts = Vec::with_capacity(command.runtime_config.volumes.len());
    for (configured, manifest) in command
        .runtime_config
        .volumes
        .iter()
        .zip(&installed.volumes)
    {
        let record = records
            .get(&configured.volume_id)
            .context("failed predecessor authority omitted a configured Volume")?;
        let binding = record
            .binding
            .as_ref()
            .context("failed predecessor Volume is no longer Owned")?;
        let grant_digest = manifest
            .authority_receipt_digest
            .as_ref()
            .context("failed predecessor lacks its immutable StartGrant digest")?;
        anyhow::ensure!(
            manifest.volume_id == configured.volume_id
                && manifest.disk_id == configured.disk_id
                && manifest.disk_role == configured.disk_role
                && record.volume.volume_id == configured.volume_id
                && record.volume.size_bytes == configured.size_bytes
                && record.volume.durability == configured.durability
                && binding.owner_node_id == command.node_id
                && binding.attachment_id == manifest.attachment_id
                && binding.attachment_epoch == manifest.attachment_epoch
                && super::authority_acquire_origin(&record.volume)? == manifest.acquire_origin
                && remote_head_is_unchanged_or_advanced(
                    &manifest.current_authority_head,
                    &record.volume.head,
                ),
            "failed predecessor Volume changed config, owner, epoch, grant lineage, or head"
        );
        let identity = AttachmentLineageIdentity {
            volume_id: configured.volume_id.clone(),
            attachment_id: binding.attachment_id.clone(),
            attachment_epoch: binding.attachment_epoch,
            acquire_origin: manifest.acquire_origin.clone(),
            node_id: command.node_id.clone(),
            placement_epoch: command.placement_identity.placement_epoch,
        };
        let (local, _) = super::cold_delete::inspect_lineage_durability_read_only(
            Path::new(manifest.local_lineage_data_directory.as_str()),
            &identity,
            &record.volume.head,
        )
        .context("inspect failed predecessor retained local lineage")?;
        anyhow::ensure!(
            local >= record.volume.head.generation && Instant::now() < deadline,
            "failed predecessor local lineage is behind authority or inspection expired"
        );
        volumes.push(SameNodeOwnedPredecessorVolume {
            volume_id: configured.volume_id.clone(),
            disk_id: configured.disk_id.clone(),
            disk_role: configured.disk_role,
            attachment_id: manifest.attachment_id.clone(),
            attachment_epoch: manifest.attachment_epoch,
            acquire_origin: manifest.acquire_origin.clone(),
            authoritative_head: record.volume.head.clone(),
            immutable_start_grant_receipt_digest: grant_digest.clone(),
            local_lineage_data_directory: Some(manifest.local_lineage_data_directory.clone()),
        });
        receipts.push(VolumeTerminalReceipt {
            volume_id: configured.volume_id.clone(),
            disk_id: configured.disk_id.clone(),
            disk_role: configured.disk_role,
            attachment_id: manifest.attachment_id.clone(),
            attachment_epoch: manifest.attachment_epoch,
            local_durable_generation: local,
            remote_durable_generation: record.volume.head.generation,
            authority_receipt_digest: Some(grant_digest.clone()),
        });
    }
    anyhow::ensure!(
        volumes.len() == command.runtime_config.volumes.len()
            && receipts.len() == volumes.len()
            && volumes
                .windows(2)
                .all(|pair| pair[0].volume_id < pair[1].volume_id)
            && receipts
                .windows(2)
                .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "failed predecessor Volume carrier is incomplete or not in strict config order"
    );
    Ok((volumes, receipts))
}

fn join_same_node_owned_predecessor_volumes(
    physical: &InstalledPhysicalInspectionConfig,
    command: &LifecycleCommandEnvelope,
    installed: &InstalledRuntimeManifest,
    fresh_receipts: &[VolumeTerminalReceipt],
    deadline: Instant,
) -> Result<Vec<SameNodeOwnedPredecessorVolume>> {
    use cats_storage::authority::{validate_volume_owner_binding, validate_volume_record};

    anyhow::ensure!(
        Instant::now() < deadline,
        "same-Node predecessor authority deadline elapsed"
    );
    anyhow::ensure!(
        installed.node_id == command.node_id
            && installed.cat_id == command.cat_id
            && installed.placement_identity == command.placement_identity
            && installed.runtime_config_id == command.runtime_config.config_id
            && installed.runtime_config_digest == command.runtime_config.config_digest
            && installed.manifest_digest.as_bytes() != &[0; 32]
            && installed.volumes.len() == command.runtime_config.volumes.len()
            && fresh_receipts.len() == command.runtime_config.volumes.len(),
        "same-Node predecessor installed manifest has another immutable target"
    );
    let candidates = command
        .runtime_config
        .volumes
        .iter()
        .map(|volume| volume.volume_id.clone())
        .collect::<BTreeSet<_>>();
    let snapshot = physical
        .volume_inventory_authority
        .load_node_volume_inventory(&physical.node_id, &candidates)
        .context("load same-Node predecessor Volume authority snapshot")?;
    anyhow::ensure!(
        snapshot.node_id == physical.node_id && Instant::now() < deadline,
        "same-Node predecessor authority snapshot has another Node or expired deadline"
    );
    let mut records = BTreeMap::new();
    for record in snapshot.records {
        validate_volume_record(&record.volume)
            .context("validate same-Node predecessor Volume row")?;
        if let Some(binding) = &record.binding {
            validate_volume_owner_binding(binding, &record.volume)
                .context("validate same-Node predecessor owner binding")?;
        }
        anyhow::ensure!(
            records
                .insert(record.volume.volume_id.clone(), record)
                .is_none(),
            "same-Node predecessor authority repeats a Volume row"
        );
    }

    let mut volumes = Vec::with_capacity(command.runtime_config.volumes.len());
    for ((configured, manifest), receipt) in command
        .runtime_config
        .volumes
        .iter()
        .zip(&installed.volumes)
        .zip(fresh_receipts)
    {
        let record = records
            .get(&configured.volume_id)
            .context("same-Node predecessor authority omitted a configured Volume")?;
        let binding = record
            .binding
            .as_ref()
            .context("same-Node predecessor Volume is no longer Owned")?;
        let grant_digest = manifest
            .authority_receipt_digest
            .as_ref()
            .context("same-Node predecessor lacks its immutable StartGrant digest")?;
        anyhow::ensure!(
            manifest.volume_id == configured.volume_id
                && manifest.disk_id == configured.disk_id
                && manifest.disk_role == configured.disk_role
                && receipt.volume_id == configured.volume_id
                && receipt.disk_id == configured.disk_id
                && receipt.disk_role == configured.disk_role
                && receipt.attachment_id == manifest.attachment_id
                && receipt.attachment_epoch == manifest.attachment_epoch
                && receipt.authority_receipt_digest.as_ref() == Some(grant_digest)
                && record.volume.volume_id == configured.volume_id
                && record.volume.size_bytes == configured.size_bytes
                && record.volume.durability == configured.durability
                && binding.owner_node_id == command.node_id
                && binding.attachment_id == manifest.attachment_id
                && binding.attachment_epoch == manifest.attachment_epoch
                && super::authority_acquire_origin(&record.volume)? == manifest.acquire_origin
                && remote_head_is_unchanged_or_advanced(
                    &manifest.current_authority_head,
                    &record.volume.head,
                )
                && receipt.remote_durable_generation <= record.volume.head.generation
                && record.volume.head.generation <= receipt.local_durable_generation,
            "same-Node predecessor Volume changed owner, epoch, grant, head, or local lineage"
        );
        volumes.push(SameNodeOwnedPredecessorVolume {
            volume_id: configured.volume_id.clone(),
            disk_id: configured.disk_id.clone(),
            disk_role: configured.disk_role,
            attachment_id: manifest.attachment_id.clone(),
            attachment_epoch: manifest.attachment_epoch,
            acquire_origin: manifest.acquire_origin.clone(),
            authoritative_head: record.volume.head.clone(),
            immutable_start_grant_receipt_digest: grant_digest.clone(),
            local_lineage_data_directory: Some(manifest.local_lineage_data_directory.clone()),
        });
    }
    anyhow::ensure!(
        volumes
            .windows(2)
            .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "same-Node predecessor Volume carrier is not in strict config order"
    );
    Ok(volumes)
}

fn remote_head_is_unchanged_or_advanced(before: &RemoteHead, after: &RemoteHead) -> bool {
    after.generation > before.generation
        || (after.generation == before.generation
            && after.root_hash == before.root_hash
            && after.root_object_id == before.root_object_id)
}

enum JoinForEffect {
    Exact(Box<InstalledRuntimePhysicalJoin>),
    DefiniteFailure(CommandFailureReason),
    DataSafetyBlocked {
        reason: InterventionReason,
        retained_volume_receipts: Vec<VolumeTerminalReceipt>,
    },
    Ambiguous,
}

fn runtime_evidence_from_join(join: &InstalledRuntimePhysicalJoin) -> InstalledRuntimeEvidence {
    InstalledRuntimeEvidence {
        runtime_incarnation: join.manifest.runtime_incarnation.clone(),
        runtime_config_digest: join.manifest.runtime_config_digest.clone(),
        physical_identity_digest: join.physical_identity_digest.clone(),
        vmm_state: match join.vmm_state {
            InstalledPhysicalVmmState::Executing => InstalledVmmState::Executing,
            InstalledPhysicalVmmState::Paused => InstalledVmmState::Paused,
        },
        volume_receipts: join.volume_receipts.clone(),
    }
}

fn join_advances_runtime(
    runtime: &InstalledRuntimeEvidence,
    join: &InstalledRuntimePhysicalJoin,
) -> Result<()> {
    anyhow::ensure!(
        join.manifest.runtime_incarnation == runtime.runtime_incarnation
            && join.manifest.runtime_config_digest == runtime.runtime_config_digest,
        "fresh installed join names another runtime"
    );
    validate_attachment_lineage_advancement(&runtime.volume_receipts, &join.volume_receipts)
}

/// Preserve the inventory join's real errors while turning a provider/read
/// error observed only once the caller's frozen deadline has elapsed into the
/// platform's explicit unavailable state. Lifecycle orchestration can then
/// select its typed failure/NeedsIntervention result instead of retrying the
/// journal step forever. This is never a success fallback.
fn inspect_exact_runtime_bounded(
    physical: &InstalledPhysicalInspectionConfig,
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    deadline: Instant,
) -> Result<InstalledRuntimePhysicalOutcome> {
    match inspect_exact_runtime(physical, command, predecessor, deadline) {
        Ok(outcome) => Ok(outcome),
        Err(_) if Instant::now() >= deadline => Ok(InstalledRuntimePhysicalOutcome::Unavailable),
        Err(error) => Err(error),
    }
}

fn exact_join_for_effect(
    physical: &InstalledPhysicalInspectionConfig,
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    runtime: &InstalledRuntimeEvidence,
    deadline: Instant,
    expected_state: InstalledPhysicalVmmState,
) -> Result<JoinForEffect> {
    Ok(
        match inspect_exact_runtime_bounded(physical, command, predecessor, deadline)? {
            InstalledRuntimePhysicalOutcome::Exact(join)
                if join.vmm_state == expected_state
                    && join_advances_runtime(runtime, &join).is_ok() =>
            {
                JoinForEffect::Exact(Box::new(join))
            }
            InstalledRuntimePhysicalOutcome::Exact(join) => JoinForEffect::DataSafetyBlocked {
                reason: InterventionReason::ForeignOrAmbiguousResidue,
                retained_volume_receipts: join.volume_receipts,
            },
            InstalledRuntimePhysicalOutcome::Absent(_) => {
                JoinForEffect::DefiniteFailure(CommandFailureReason::VmmFailed)
            }
            InstalledRuntimePhysicalOutcome::Unavailable => JoinForEffect::Ambiguous,
            InstalledRuntimePhysicalOutcome::Conflict => JoinForEffect::DataSafetyBlocked {
                reason: InterventionReason::ForeignOrAmbiguousResidue,
                retained_volume_receipts: runtime.volume_receipts.clone(),
            },
        },
    )
}

fn remaining_platform_timeout(deadline: Instant, maximum: Duration) -> Result<Duration> {
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(maximum);
    anyhow::ensure!(!remaining.is_zero(), "physical effect deadline elapsed");
    Ok(remaining)
}

fn receipts_are_remote(receipts: &[VolumeTerminalReceipt]) -> bool {
    receipts.iter().all(|receipt| {
        receipt.remote_durable_generation == receipt.local_durable_generation
            && receipt.authority_receipt_digest.is_some()
    })
}

fn not_remote_reason(receipts: &[VolumeTerminalReceipt]) -> InterventionReason {
    if receipts.iter().any(|receipt| {
        receipt.disk_role == cats_api::runtime_lifecycle::DiskRole::Persistent
            && receipt.remote_durable_generation < receipt.local_durable_generation
    }) {
        InterventionReason::PersistentDiskNotRemoteDurable
    } else {
        InterventionReason::RetainedLocalTail
    }
}

fn send_exact_blockd_drain(
    volume: &InstalledRuntimeVolumeManifest,
    deadline: Instant,
) -> Result<()> {
    let mut stream = connect_unix_until(
        Path::new(volume.blockd_control_socket_path.as_str()),
        deadline,
    )
    .context("connect exact blockd control socket")?;
    ensure_control_peer_pid(&stream, volume.blockd.pid)
        .context("blockd control peer differs from installed process")?;
    set_unix_stream_timeouts_until(&stream, deadline)?;
    stream
        .write_all(BlockdControlCommand::Drain.as_wire().as_bytes())
        .context("write blockd drain command")?;
    stream
        .write_all(b"\n")
        .context("terminate blockd drain command")?;
    stream.flush().context("flush blockd drain command")?;
    let response = read_blockd_response_until(&mut stream, deadline)?;
    ensure_control_peer_pid(&stream, volume.blockd.pid)
        .context("blockd control peer changed during drain")?;
    let response = std::str::from_utf8(&response).context("blockd drain response is not UTF-8")?;
    match BlockdControlResponse::parse_wire(response).context("parse blockd drain response")? {
        BlockdControlResponse::Ok(_) => Ok(()),
        BlockdControlResponse::Error(message) => {
            anyhow::bail!("blockd drain rejected: {message}")
        }
    }
}

fn read_blockd_response_until(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    while response.len() <= BLOCKD_CONTROL_MAX_LINE_BYTES {
        set_unix_stream_timeouts_until(stream, deadline)?;
        let mut byte = [0_u8; 1];
        let count = stream
            .read(&mut byte)
            .context("read blockd drain response")?;
        anyhow::ensure!(count == 1, "blockd drain response ended before LF");
        response.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    anyhow::ensure!(
        !response.is_empty()
            && response.len() <= BLOCKD_CONTROL_MAX_LINE_BYTES
            && response.ends_with(b"\n"),
        "blockd drain response is missing or oversized"
    );
    Ok(response)
}

fn set_unix_stream_timeouts_until(stream: &UnixStream, deadline: Instant) -> Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    anyhow::ensure!(!remaining.is_zero(), "Unix control deadline elapsed");
    stream
        .set_read_timeout(Some(remaining))
        .context("set Unix control read deadline")?;
    stream
        .set_write_timeout(Some(remaining))
        .context("set Unix control write deadline")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn connect_unix_until(path: &Path, deadline: Instant) -> Result<UnixStream> {
    use std::os::fd::IntoRawFd as _;

    let bytes = path.as_os_str().as_bytes();
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() < 108 && !bytes.contains(&0),
        "Unix control path is outside the canonical sockaddr domain"
    );
    // SAFETY: socket returns a fresh descriptor and retains no Rust memory.
    let descriptor = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error()).context("create Unix control socket");
    }
    // SAFETY: the fresh descriptor has unique ownership here.
    let owned = unsafe { File::from_raw_fd(descriptor) };
    // SAFETY: zero is a valid initialization for sockaddr_un; the family and
    // NUL-terminated path are filled before the kernel reads it.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(bytes.iter().copied()) {
        *target = source as libc::c_char;
    }
    let address_length =
        (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    // SAFETY: the descriptor and sockaddr remain live for the call.
    let connected = unsafe {
        libc::connect(
            owned.as_raw_fd(),
            std::ptr::addr_of!(address).cast(),
            address_length,
        )
    };
    if connected != 0 {
        let error = std::io::Error::last_os_error();
        anyhow::ensure!(
            error.raw_os_error() == Some(libc::EINPROGRESS),
            "Unix control connect failed: {error}"
        );
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            anyhow::ensure!(
                !remaining.is_zero(),
                "Unix control connect deadline elapsed"
            );
            let timeout = i32::try_from(PLATFORM_POLL_INTERVAL.min(remaining).as_millis().max(1))
                .unwrap_or(1);
            let mut poll = libc::pollfd {
                fd: owned.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: poll names one initialized pollfd for this call.
            let result = unsafe { libc::poll(std::ptr::addr_of_mut!(poll), 1, timeout) };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error).context("poll Unix control connect");
            }
            if result == 0 {
                continue;
            }
            let mut socket_error = 0_i32;
            let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
            // SAFETY: both output pointers name writable initialized values.
            let result = unsafe {
                libc::getsockopt(
                    owned.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    std::ptr::addr_of_mut!(socket_error).cast(),
                    std::ptr::addr_of_mut!(length),
                )
            };
            anyhow::ensure!(
                result == 0 && socket_error == 0,
                "Unix control connect completed with error {socket_error}"
            );
            break;
        }
    }
    // SAFETY: ownership transfers from `owned` into exactly one UnixStream.
    let stream = unsafe { UnixStream::from_raw_fd(owned.into_raw_fd()) };
    stream
        .set_nonblocking(false)
        .context("restore blocking Unix control socket")?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    anyhow::ensure!(!remaining.is_zero(), "Unix control deadline elapsed");
    stream.set_read_timeout(Some(remaining))?;
    stream.set_write_timeout(Some(remaining))?;
    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
fn connect_unix_until(_path: &Path, _deadline: Instant) -> Result<UnixStream> {
    anyhow::bail!("exact installed Unix control sockets require Linux")
}

#[cfg(target_os = "linux")]
fn ensure_control_peer_pid(stream: &UnixStream, expected_pid: u32) -> Result<()> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: both output pointers name initialized writable objects and the
    // stream retains its descriptor throughout the call.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            std::ptr::addr_of_mut!(length),
        )
    };
    anyhow::ensure!(
        result == 0
            && length as usize == std::mem::size_of::<libc::ucred>()
            && credentials.pid > 0
            && u32::try_from(credentials.pid).ok() == Some(expected_pid),
        "Unix control peer PID differs from expectation"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_control_peer_pid(_stream: &UnixStream, _expected_pid: u32) -> Result<()> {
    anyhow::bail!("exact installed Unix peer credentials require Linux")
}

fn validate_absent_snapshot_authority(
    physical: &InstalledPhysicalInspectionConfig,
    command: &LifecycleCommandEnvelope,
    receipts: &[VolumeTerminalReceipt],
) -> Result<()> {
    use cats_storage::authority::{validate_volume_owner_binding, validate_volume_record};

    validate_volume_receipts(command, receipts, true)?;
    let candidates = receipts
        .iter()
        .map(|receipt| receipt.volume_id.clone())
        .collect::<BTreeSet<_>>();
    let snapshot = physical
        .volume_inventory_authority
        .load_node_volume_inventory(&physical.node_id, &candidates)
        .context("load absent Warm snapshot Volume authority")?;
    anyhow::ensure!(
        snapshot.node_id == physical.node_id,
        "absent Warm authority snapshot belongs to another Node"
    );
    let mut rows = BTreeMap::new();
    for record in snapshot.records {
        validate_volume_record(&record.volume).context("validate absent Warm authority row")?;
        if let Some(binding) = &record.binding {
            validate_volume_owner_binding(binding, &record.volume)
                .context("validate absent Warm owner binding")?;
        }
        anyhow::ensure!(
            rows.insert(record.volume.volume_id.clone(), record)
                .is_none(),
            "absent Warm authority repeats a Volume row"
        );
    }
    for receipt in receipts {
        let record = rows
            .get(&receipt.volume_id)
            .context("absent Warm authority omitted a retained Volume")?;
        let binding = record
            .binding
            .as_ref()
            .context("absent Warm Volume is no longer Owned")?;
        anyhow::ensure!(
            binding.owner_node_id == physical.node_id
                && binding.attachment_id == receipt.attachment_id
                && binding.attachment_epoch == receipt.attachment_epoch
                && record.volume.head.generation == receipt.remote_durable_generation,
            "absent Warm Volume authority changed from the durable snapshot"
        );
    }
    Ok(())
}

enum SnapshotPublishAttempt {
    Exact(Box<WarmSnapshotEvidence>),
    DefiniteFailure,
    Ambiguous,
}

enum SnapshotIntentPublishAttempt {
    Exact(Box<WarmSnapshotIntent>),
    Invalid,
    Unavailable,
}

enum SnapshotIntentRead {
    Exact(Box<WarmSnapshotIntent>),
    Absent,
    Invalid,
    Unavailable,
}

enum SnapshotReopenAttempt {
    Exact(Box<WarmSnapshotManifest>),
    Absent,
    Invalid,
    Unavailable,
}

enum SnapshotManifestRead {
    Exact(Box<WarmSnapshotManifest>),
    Absent,
    Invalid,
    Unavailable,
}

enum TerminalPublishAttempt {
    Exact(FinalizedWarmSnapshotEvidence),
    Invalid,
    Unavailable,
}

enum TerminalManifestRead {
    Exact(Box<WarmTerminalManifest>),
    Absent,
    Invalid,
    Unavailable,
}

fn inspect_warm_cleanup_authority(
    physical: &InstalledPhysicalInspectionConfig,
    command: &LifecycleCommandEnvelope,
    request: &WarmSnapshotCleanupRequest,
    deadline: Instant,
) -> Result<WarmSnapshotCleanupAttempt<WarmSnapshotCleanupAuthority>> {
    if validate_warm_cleanup_request(command, request).is_err() {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    let terminal_binding = StepBinding {
        version: STEP_VERSION,
        operation_id: request.predecessor_operation_id.clone(),
        request_fingerprint: request.predecessor_request_fingerprint.clone(),
    };
    let terminal = match read_warm_terminal_manifest(physical, &terminal_binding, deadline)? {
        TerminalManifestRead::Exact(manifest) => manifest,
        TerminalManifestRead::Unavailable => anyhow::bail!("Warm terminal read deadline elapsed"),
        TerminalManifestRead::Absent | TerminalManifestRead::Invalid => {
            return Ok(WarmSnapshotCleanupAttempt::Blocked)
        }
    };
    if !warm_terminal_matches_cleanup(command, request, &terminal) {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    let prepared_binding = StepBinding {
        version: STEP_VERSION,
        operation_id: terminal
            .body
            .prepared_snapshot
            .snapshot_operation_id
            .clone(),
        request_fingerprint: terminal
            .body
            .prepared_snapshot
            .snapshot_request_fingerprint
            .clone(),
    };
    let prepared = match read_warm_snapshot_manifest(physical, &prepared_binding, deadline)? {
        SnapshotManifestRead::Exact(manifest) => manifest,
        SnapshotManifestRead::Unavailable => anyhow::bail!("Warm payload read deadline elapsed"),
        SnapshotManifestRead::Absent | SnapshotManifestRead::Invalid => {
            return Ok(WarmSnapshotCleanupAttempt::Blocked)
        }
    };
    if prepared.evidence != terminal.body.prepared_snapshot
        || prepared.body.workspace_id != command.workspace_id
        || prepared.body.cat_id != command.cat_id
        || prepared.body.node_id != command.node_id
        || prepared.body.placement_identity != command.placement_identity
        || prepared.body.runtime_config_id != command.runtime_config.config_id
        || prepared.body.runtime_config_digest != command.runtime_config.config_digest
        || prepared.body.runtime.runtime_incarnation != request.source_runtime_incarnation
        || prepared.body.drained_volumes != request.volume_receipts
    {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    let installed_runtime = match verify_snapshot_payload_and_runtime(physical, &prepared, deadline)
    {
        Ok(installed) => installed,
        Err(error) if Instant::now() >= deadline => {
            return Err(error).context("Warm payload verification deadline elapsed")
        }
        Err(_) => return Ok(WarmSnapshotCleanupAttempt::Blocked),
    };

    let Some(namespace) = open_warm_snapshot_namespace(&physical.state_directory, false)? else {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    };
    let namespace_identity = directory_identity(&namespace)?;
    let terminal_name = warm_component_name(&terminal_binding, WARM_TERMINAL_MANIFEST_SUFFIX)?;
    let intent_name = warm_component_name(&prepared_binding, WARM_SNAPSHOT_INTENT_SUFFIX)?;
    let prepared_name = warm_component_name(&prepared_binding, WARM_SNAPSHOT_MANIFEST_SUFFIX)?;
    let content_name = CString::new(prepared.body.content_directory_name.clone())
        .context("Warm cleanup content name contains NUL")?;
    let Some(terminal_file) = openat_file_optional(
        &namespace,
        &terminal_name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?
    else {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    };
    let Some(prepared_file) = openat_file_optional(
        &namespace,
        &prepared_name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?
    else {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    };
    let Some(intent_file) = openat_file_optional(
        &namespace,
        &intent_name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?
    else {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    };
    if !matches!(
        read_warm_terminal_file(terminal_file.try_clone()?)?,
        TerminalManifestRead::Exact(ref exact) if exact == &terminal
    ) || !matches!(
        read_warm_snapshot_file(prepared_file.try_clone()?)?,
        SnapshotManifestRead::Exact(ref exact) if exact == &prepared
    ) || !matches!(
        read_warm_snapshot_intent_file(intent_file.try_clone()?)?,
        SnapshotIntentRead::Exact(ref exact)
            if exact.intent_digest == prepared.body.snapshot_intent_digest
                && intent_closes_prepared(exact, &prepared)
    ) {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    let Some(content) = openat_directory_optional(&namespace, &content_name)? else {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    };
    for (binding, suffix) in [
        (&prepared_binding, WARM_SNAPSHOT_TEMP_SUFFIX),
        (&terminal_binding, WARM_TERMINAL_TEMP_SUFFIX),
    ] {
        let name = warm_component_name(binding, suffix)?;
        if fstatat_nofollow(&namespace, &name)?.is_some() {
            return Ok(WarmSnapshotCleanupAttempt::Blocked);
        }
    }
    let terminal_identity = regular_single_link_identity(&terminal_file)?;
    let intent_identity = regular_single_link_identity(&intent_file)?;
    let prepared_identity = regular_single_link_identity(&prepared_file)?;
    let content_identity = directory_identity(&content)?;
    if terminal_identity.device != namespace_identity.device
        || intent_identity.device != namespace_identity.device
        || prepared_identity.device != namespace_identity.device
        || content_identity.device != namespace_identity.device
    {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    let snapshot_directory = cats_api::runtime_reconciliation::HostPath::new(
        physical
            .state_directory
            .path()
            .join(WARM_SNAPSHOT_NAMESPACE)
            .join(&prepared.body.content_directory_name)
            .to_str()
            .context("Warm snapshot directory is not UTF-8")?,
    )
    .context("Warm snapshot directory is not a canonical HostPath")?;
    let Some((memory_parent, memory_name)) = open_state_descendant_parent(
        &physical.state_directory,
        Path::new(prepared.body.memory_file.path.as_str()),
    )?
    else {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    };
    let Some(memory_file) = openat_file_optional(
        &memory_parent,
        &memory_name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?
    else {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    };
    let memory_parent_identity = directory_identity(&memory_parent)?;
    let exact_memory = memory_file_proof_from_open_file(
        memory_file,
        prepared.body.memory_file.path.clone(),
        prepared.body.memory_file.size_bytes,
        deadline,
        false,
    )?;
    if exact_memory != prepared.body.memory_file {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    let mode = match command.command {
        LifecycleCommand::Start(_) => WarmSnapshotCleanupMode::TransferToRuntime,
        LifecycleCommand::Cold(_) | LifecycleCommand::Stop(_) | LifecycleCommand::Delete(_) => {
            WarmSnapshotCleanupMode::Remove
        }
        _ => return Ok(WarmSnapshotCleanupAttempt::Blocked),
    };
    let mut authority = WarmSnapshotCleanupAuthority {
        version: STEP_VERSION,
        cleanup_operation_id: command.operation_id.clone(),
        cleanup_request_fingerprint: command.request_fingerprint.clone(),
        workspace_id: command.workspace_id.clone(),
        cat_id: command.cat_id.clone(),
        node_id: command.node_id.clone(),
        placement_identity: command.placement_identity.clone(),
        runtime_config_id: command.runtime_config.config_id.clone(),
        runtime_config_digest: command.runtime_config.config_digest.clone(),
        request: request.clone(),
        terminal_operation_id: terminal_binding.operation_id,
        terminal_request_fingerprint: terminal_binding.request_fingerprint,
        prepared_operation_id: prepared_binding.operation_id,
        prepared_request_fingerprint: prepared_binding.request_fingerprint,
        mode,
        snapshot_directory,
        installed_runtime: Some(Box::new(installed_runtime)),
        memory_file: prepared.body.memory_file,
        memory_parent_identity,
        namespace_identity,
        terminal_manifest_identity: terminal_identity,
        intent_manifest_identity: intent_identity,
        prepared_manifest_identity: prepared_identity,
        content_directory_identity: content_identity,
        retained_retry: None,
        authority_digest: Sha256Digest::from_bytes([0; 32]),
    };
    authority.authority_digest = warm_cleanup_authority_digest(&authority)?;
    Ok(WarmSnapshotCleanupAttempt::Exact(authority))
}

fn validate_warm_cleanup_request(
    command: &LifecycleCommandEnvelope,
    request: &WarmSnapshotCleanupRequest,
) -> Result<()> {
    anyhow::ensure!(
        matches!(
            &command.command,
            LifecycleCommand::Start(_)
                | LifecycleCommand::Cold(_)
                | LifecycleCommand::Stop(_)
                | LifecycleCommand::Delete(_)
        ),
        "only Warm Start, Cold, Stop, or Delete may consume a Warm bundle"
    );
    let LifecyclePredecessor::SameNode {
        operation_id,
        terminal_result_kind,
        terminal_result_digest,
        node_id,
        placement_identity,
    } = &command.predecessor
    else {
        anyhow::bail!("Warm cleanup lacks a same-Node predecessor");
    };
    anyhow::ensure!(
        *terminal_result_kind == cats_api::runtime_lifecycle::TerminalResultKind::Warm
            && operation_id == &request.predecessor_operation_id
            && terminal_result_digest == &request.predecessor_terminal_result_digest
            && node_id == &command.node_id
            && placement_identity == &command.placement_identity,
        "Warm cleanup request is not the command's exact predecessor"
    );
    validate_volume_receipts(command, &request.volume_receipts, true)
}

fn warm_terminal_matches_cleanup(
    command: &LifecycleCommandEnvelope,
    request: &WarmSnapshotCleanupRequest,
    manifest: &WarmTerminalManifest,
) -> bool {
    let body = &manifest.body;
    manifest.terminal_manifest_digest == request.terminal_manifest_digest
        && body.binding.operation_id == request.predecessor_operation_id
        && body.binding.request_fingerprint == request.predecessor_request_fingerprint
        && body.workspace_id == command.workspace_id
        && body.cat_id == command.cat_id
        && body.node_id == command.node_id
        && body.placement_identity == command.placement_identity
        && body.runtime_config_id == command.runtime_config.config_id
        && body.runtime_config_digest == command.runtime_config.config_digest
        && body.source_runtime_incarnation == request.source_runtime_incarnation
        && body.drained_volumes == request.volume_receipts
        && body.warm_receipt_digest == request.warm_receipt_digest
}

fn warm_cleanup_authority_digest(authority: &WarmSnapshotCleanupAuthority) -> Result<Sha256Digest> {
    let mut preimage = authority.clone();
    preimage.authority_digest = Sha256Digest::from_bytes([0; 32]);
    let bytes = serde_json::to_vec(&preimage).context("encode Warm cleanup authority")?;
    Ok(digest_parts(WARM_CLEANUP_AUTHORITY_DOMAIN, &[&bytes]))
}

fn validate_warm_cleanup_authority_scope(
    command: &LifecycleCommandEnvelope,
    authority: &WarmSnapshotCleanupAuthority,
) -> Result<()> {
    let expected_mode = match command.command {
        LifecycleCommand::Start(_) => WarmSnapshotCleanupMode::TransferToRuntime,
        LifecycleCommand::Cold(_) | LifecycleCommand::Stop(_) | LifecycleCommand::Delete(_) => {
            WarmSnapshotCleanupMode::Remove
        }
        _ => anyhow::bail!("command cannot consume a Warm bundle"),
    };
    match authority.retained_retry.as_deref() {
        None => validate_warm_cleanup_request(command, &authority.request)?,
        Some(binding) => {
            let exact_consumer = match &command.command {
                LifecycleCommand::Start(spec) => {
                    spec.source == StartSource::SameNodeRetry
                        && expected_mode == WarmSnapshotCleanupMode::TransferToRuntime
                }
                LifecycleCommand::Stop(_)
                | LifecycleCommand::Cold(_)
                | LifecycleCommand::Delete(_) => expected_mode == WarmSnapshotCleanupMode::Remove,
                _ => false,
            };
            let LifecyclePredecessor::SameNode {
                operation_id,
                terminal_result_kind,
                terminal_result_digest,
                node_id,
                placement_identity,
            } = &command.predecessor
            else {
                anyhow::bail!("retained Warm successor lacks same-Node predecessor authority")
            };
            anyhow::ensure!(
                exact_consumer
                    && *terminal_result_kind
                        == cats_api::runtime_lifecycle::TerminalResultKind::StartFailed
                    && operation_id == &binding.failed_start_operation_id
                    && terminal_result_digest == &binding.failed_start_terminal_result_digest
                    && node_id == &command.node_id
                    && placement_identity == &command.placement_identity
                    && binding.failed_start_request_fingerprint.as_bytes() != &[0; 32]
                    && binding.failed_start_retained_manifest_digest.as_bytes() != &[0; 32]
                    && binding.inherited_predecessor_physical_digest.as_bytes() != &[0; 32]
                    && binding.source_revocation_receipt_digest.as_bytes() != &[0; 32]
                    && binding.source_carrier_digest.as_bytes() != &[0; 32],
                "retained Warm cleanup authority changed its immediate successor chain"
            );
            validate_volume_receipts(command, &authority.request.volume_receipts, true)?;
        }
    }
    let installed_runtime_is_exact =
        authority
            .installed_runtime
            .as_deref()
            .is_some_and(|installed| {
                installed_runtime_manifest_digest(installed)
                    .is_ok_and(|digest| digest == installed.manifest_digest)
                    && installed.node_id == command.node_id
                    && installed.cat_id == command.cat_id
                    && installed.placement_identity == command.placement_identity
                    && installed.runtime_config_id == command.runtime_config.config_id
                    && installed.runtime_config_digest == command.runtime_config.config_digest
                    && installed.runtime_incarnation == authority.request.source_runtime_incarnation
                    && installed.vmm.memory_file_path == authority.memory_file.path
                    && installed.volumes.len() == authority.request.volume_receipts.len()
            });
    anyhow::ensure!(
        authority.version == STEP_VERSION
            && authority.cleanup_operation_id == command.operation_id
            && authority.cleanup_request_fingerprint == command.request_fingerprint
            && authority.workspace_id == command.workspace_id
            && authority.cat_id == command.cat_id
            && authority.node_id == command.node_id
            && authority.placement_identity == command.placement_identity
            && authority.runtime_config_id == command.runtime_config.config_id
            && authority.runtime_config_digest == command.runtime_config.config_digest
            && authority.terminal_operation_id == authority.request.predecessor_operation_id
            && authority.terminal_request_fingerprint
                == authority.request.predecessor_request_fingerprint
            && authority.request.terminal_manifest_digest.as_bytes() != &[0; 32]
            && authority.request.warm_receipt_digest.as_bytes() != &[0; 32]
            && authority.mode == expected_mode
            && installed_runtime_is_exact
            && authority.memory_file.device > 0
            && authority.memory_file.inode > 0
            && authority.memory_file.size_bytes > 0
            && authority.memory_file.digest.as_bytes() != &[0; 32]
            && authority.memory_parent_identity.device > 0
            && authority.memory_parent_identity.inode > 0
            && authority.namespace_identity.device > 0
            && authority.namespace_identity.inode > 0
            && authority.terminal_manifest_identity.device == authority.namespace_identity.device
            && authority.terminal_manifest_identity.inode > 0
            && authority.intent_manifest_identity.device == authority.namespace_identity.device
            && authority.intent_manifest_identity.inode > 0
            && authority.prepared_manifest_identity.device == authority.namespace_identity.device
            && authority.prepared_manifest_identity.inode > 0
            && authority.content_directory_identity.device == authority.namespace_identity.device
            && authority.content_directory_identity.inode > 0
            && authority.authority_digest == warm_cleanup_authority_digest(authority)?,
        "Warm cleanup authority changed after journal acceptance"
    );
    Ok(())
}

fn validate_warm_cleanup_authority(
    physical: &InstalledPhysicalInspectionConfig,
    command: &LifecycleCommandEnvelope,
    authority: &WarmSnapshotCleanupAuthority,
) -> Result<()> {
    validate_warm_cleanup_authority_scope(command, authority)?;
    let expected_snapshot_directory = physical
        .state_directory
        .path()
        .join(WARM_SNAPSHOT_NAMESPACE)
        .join(format!(
            "{}{WARM_SNAPSHOT_CONTENT_SUFFIX}",
            warm_snapshot_key(&StepBinding {
                version: STEP_VERSION,
                operation_id: authority.prepared_operation_id.clone(),
                request_fingerprint: authority.prepared_request_fingerprint.clone(),
            })
        ));
    let expected_mode = match command.command {
        LifecycleCommand::Start(_) => WarmSnapshotCleanupMode::TransferToRuntime,
        LifecycleCommand::Cold(_) | LifecycleCommand::Stop(_) | LifecycleCommand::Delete(_) => {
            WarmSnapshotCleanupMode::Remove
        }
        _ => anyhow::bail!("command cannot consume a Warm bundle"),
    };
    let memory_path = Path::new(authority.memory_file.path.as_str());
    let memory_relative = memory_path
        .strip_prefix(physical.state_directory.path())
        .context("Warm memory backing is outside the StateDirectory")?;
    let memory_is_external_to_snapshot_bundle =
        !memory_relative.starts_with(WARM_SNAPSHOT_NAMESPACE);
    let installed_runtime_is_exact =
        authority
            .installed_runtime
            .as_deref()
            .is_some_and(|installed| {
                installed_runtime_manifest_digest(installed)
                    .is_ok_and(|digest| digest == installed.manifest_digest)
                    && installed.node_id == command.node_id
                    && installed.cat_id == command.cat_id
                    && installed.placement_identity == command.placement_identity
                    && installed.runtime_config_id == command.runtime_config.config_id
                    && installed.runtime_config_digest == command.runtime_config.config_digest
                    && installed.runtime_incarnation == authority.request.source_runtime_incarnation
                    && installed.vmm.memory_file_path == authority.memory_file.path
                    && installed.volumes.len() == authority.request.volume_receipts.len()
            });
    anyhow::ensure!(
        authority.version == STEP_VERSION
            && authority.cleanup_operation_id == command.operation_id
            && authority.cleanup_request_fingerprint == command.request_fingerprint
            && authority.workspace_id == command.workspace_id
            && authority.cat_id == command.cat_id
            && authority.node_id == command.node_id
            && authority.placement_identity == command.placement_identity
            && authority.runtime_config_id == command.runtime_config.config_id
            && authority.runtime_config_digest == command.runtime_config.config_digest
            && authority.terminal_operation_id == authority.request.predecessor_operation_id
            && authority.terminal_request_fingerprint
                == authority.request.predecessor_request_fingerprint
            && authority.mode == expected_mode
            && Path::new(authority.snapshot_directory.as_str()) == expected_snapshot_directory
            && installed_runtime_is_exact
            && memory_is_external_to_snapshot_bundle
            && authority.memory_file.device > 0
            && authority.memory_file.inode > 0
            && authority.memory_file.size_bytes > 0
            && authority.memory_file.digest.as_bytes() != &[0; 32]
            && authority.memory_parent_identity.device > 0
            && authority.memory_parent_identity.inode > 0
            && authority.namespace_identity.device > 0
            && authority.namespace_identity.inode > 0
            && authority.terminal_manifest_identity.device == authority.namespace_identity.device
            && authority.terminal_manifest_identity.inode > 0
            && authority.intent_manifest_identity.device == authority.namespace_identity.device
            && authority.intent_manifest_identity.inode > 0
            && authority.prepared_manifest_identity.device == authority.namespace_identity.device
            && authority.prepared_manifest_identity.inode > 0
            && authority.content_directory_identity.device == authority.namespace_identity.device
            && authority.content_directory_identity.inode > 0
            && authority.authority_digest == warm_cleanup_authority_digest(authority)?,
        "Warm cleanup authority changed after journal acceptance"
    );
    Ok(())
}

fn inspect_rebound_warm_retry_source_physical(
    physical: &InstalledPhysicalInspectionConfig,
    command: &LifecycleCommandEnvelope,
    authority: &WarmSnapshotCleanupAuthority,
    deadline: Instant,
) -> Result<SameNodeOwnedPredecessorPhysical> {
    anyhow::ensure!(
        Instant::now() < deadline,
        "retained Warm retry inspection deadline elapsed"
    );
    validate_warm_cleanup_authority(physical, command, authority)?;
    let retry = authority
        .retained_retry
        .as_deref()
        .context("Warm retry authority lacks its retained StartFailed chain")?;
    let Some(namespace) = open_warm_snapshot_namespace(&physical.state_directory, false)? else {
        anyhow::bail!("retained Warm retry namespace is absent")
    };
    anyhow::ensure!(
        directory_identity(&namespace)? == authority.namespace_identity,
        "retained Warm retry namespace identity changed"
    );
    let terminal_binding = StepBinding {
        version: STEP_VERSION,
        operation_id: authority.terminal_operation_id.clone(),
        request_fingerprint: authority.terminal_request_fingerprint.clone(),
    };
    let prepared_binding = StepBinding {
        version: STEP_VERSION,
        operation_id: authority.prepared_operation_id.clone(),
        request_fingerprint: authority.prepared_request_fingerprint.clone(),
    };
    for (binding, suffix) in [
        (&prepared_binding, WARM_SNAPSHOT_TEMP_SUFFIX),
        (&terminal_binding, WARM_TERMINAL_TEMP_SUFFIX),
    ] {
        let name = warm_component_name(binding, suffix)?;
        anyhow::ensure!(
            fstatat_nofollow(&namespace, &name)?.is_none(),
            "retained Warm retry has an ambiguous temporary artifact"
        );
    }
    let terminal_name = warm_component_name(&terminal_binding, WARM_TERMINAL_MANIFEST_SUFFIX)?;
    let prepared_name = warm_component_name(&prepared_binding, WARM_SNAPSHOT_MANIFEST_SUFFIX)?;
    let intent_name = warm_component_name(&prepared_binding, WARM_SNAPSHOT_INTENT_SUFFIX)?;
    let content_name = warm_component_name(&prepared_binding, WARM_SNAPSHOT_CONTENT_SUFFIX)?;
    anyhow::ensure!(
        inspect_exact_warm_file(
            &namespace,
            &terminal_name,
            &authority.terminal_manifest_identity,
        )? == ExactWarmObjectPresence::Absent
            && inspect_exact_warm_file(
                &namespace,
                &prepared_name,
                &authority.prepared_manifest_identity,
            )? == ExactWarmObjectPresence::Exact
            && inspect_exact_warm_file(
                &namespace,
                &intent_name,
                &authority.intent_manifest_identity,
            )? == ExactWarmObjectPresence::Exact
            && inspect_exact_warm_directory(
                &namespace,
                &content_name,
                &authority.content_directory_identity,
            )? == ExactWarmObjectPresence::Exact,
        "retained Warm retry source is executable, incomplete, or replaced"
    );
    let prepared_file = openat_file(
        &namespace,
        &prepared_name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    )?;
    let prepared = match read_warm_snapshot_file(prepared_file)? {
        SnapshotManifestRead::Exact(manifest) => manifest,
        SnapshotManifestRead::Absent
        | SnapshotManifestRead::Invalid
        | SnapshotManifestRead::Unavailable => {
            anyhow::bail!("retained Warm prepared manifest is not exact")
        }
    };
    let intent_file = openat_file(
        &namespace,
        &intent_name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    )?;
    let intent = match read_warm_snapshot_intent_file(intent_file)? {
        SnapshotIntentRead::Exact(intent) => intent,
        SnapshotIntentRead::Absent
        | SnapshotIntentRead::Invalid
        | SnapshotIntentRead::Unavailable => {
            anyhow::bail!("retained Warm intent manifest is not exact")
        }
    };
    let installed = verify_snapshot_payload_and_runtime(physical, &prepared, deadline)
        .context("verify retained Warm snapshot tree and installed runtime")?;
    let expected_installed = authority.installed_runtime()?;
    anyhow::ensure!(
        intent_closes_prepared(&intent, &prepared)
            && prepared.body.binding == prepared_binding
            && prepared.body.workspace_id == command.workspace_id
            && prepared.body.cat_id == command.cat_id
            && prepared.body.node_id == command.node_id
            && prepared.body.placement_identity == command.placement_identity
            && prepared.body.runtime_config_id == command.runtime_config.config_id
            && prepared.body.runtime_config_digest == command.runtime_config.config_digest
            && prepared.body.runtime.runtime_incarnation
                == authority.request.source_runtime_incarnation
            && prepared.body.drained_volumes == authority.request.volume_receipts
            && prepared.body.memory_file == authority.memory_file
            && prepared.body.content_directory_name.as_bytes() == content_name.to_bytes()
            && &installed == expected_installed,
        "retained Warm retry payload, RAM, or immutable runtime changed"
    );
    let volumes = join_same_node_owned_predecessor_volumes(
        physical,
        command,
        expected_installed,
        &authority.request.volume_receipts,
        deadline,
    )?;
    Ok(SameNodeOwnedPredecessorPhysical {
        physical_manifest_digest: retry.failed_start_retained_manifest_digest.clone(),
        runtime_incarnation: Some(authority.request.source_runtime_incarnation.clone()),
        volumes,
        source: SameNodeOwnedPredecessorSource::RetainedWarm {
            cleanup_authority: Box::new(authority.clone()),
        },
    })
}

fn inspect_or_remove_terminal_warm_bundle(
    physical: &InstalledPhysicalInspectionConfig,
    command: &LifecycleCommandEnvelope,
    authority: &WarmSnapshotCleanupAuthority,
    completion: &WarmSnapshotCleanupCompletion,
    deadline: Instant,
) -> Result<WarmSnapshotCleanupAttempt<Sha256Digest>> {
    anyhow::ensure!(
        Instant::now() < deadline,
        "Warm snapshot cleanup deadline elapsed"
    );
    if validate_warm_cleanup_authority(physical, command, authority).is_err() {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    let completion = match (authority.mode, completion) {
        (
            WarmSnapshotCleanupMode::TransferToRuntime,
            WarmSnapshotCleanupCompletion::TransferToRuntime {
                runtime_incarnation,
                runtime_progress_manifest_digest,
            },
        ) => {
            if !validate_warm_memory_transfer(
                physical,
                command,
                authority,
                runtime_incarnation,
                runtime_progress_manifest_digest,
                deadline,
            )? {
                return Ok(WarmSnapshotCleanupAttempt::Blocked);
            }
            ValidatedWarmCleanupCompletion::TransferToRuntime {
                runtime_incarnation,
                runtime_progress_manifest_digest,
            }
        }
        (
            WarmSnapshotCleanupMode::TransferToRuntime,
            WarmSnapshotCleanupCompletion::RetainForFailedStart {
                inherited_predecessor_physical_digest,
            },
        ) if inherited_predecessor_physical_digest.as_bytes() != &[0; 32] => {
            ValidatedWarmCleanupCompletion::RetainForFailedStart {
                inherited_predecessor_physical_digest,
            }
        }
        (WarmSnapshotCleanupMode::Remove, WarmSnapshotCleanupCompletion::Remove) => {
            ValidatedWarmCleanupCompletion::Remove
        }
        _ => return Ok(WarmSnapshotCleanupAttempt::Blocked),
    };
    let Some(namespace) = open_warm_snapshot_namespace(&physical.state_directory, false)? else {
        physical
            .state_directory
            .try_clone_directory()
            .context("reopen StateDirectory for absent Warm namespace")?
            .sync_all()
            .context("fsync absent Warm namespace parent")?;
        return finish_warm_memory_cleanup(physical, command, authority, completion, deadline);
    };
    if directory_identity(&namespace)? != authority.namespace_identity {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    let terminal_binding = StepBinding {
        version: STEP_VERSION,
        operation_id: authority.terminal_operation_id.clone(),
        request_fingerprint: authority.terminal_request_fingerprint.clone(),
    };
    let prepared_binding = StepBinding {
        version: STEP_VERSION,
        operation_id: authority.prepared_operation_id.clone(),
        request_fingerprint: authority.prepared_request_fingerprint.clone(),
    };
    for (binding, suffix) in [
        (&prepared_binding, WARM_SNAPSHOT_TEMP_SUFFIX),
        (&terminal_binding, WARM_TERMINAL_TEMP_SUFFIX),
    ] {
        anyhow::ensure!(
            Instant::now() < deadline,
            "Warm snapshot cleanup deadline elapsed"
        );
        let name = warm_component_name(binding, suffix)?;
        if fstatat_nofollow(&namespace, &name)?.is_some() {
            return Ok(WarmSnapshotCleanupAttempt::Blocked);
        }
    }
    let terminal_name = warm_component_name(&terminal_binding, WARM_TERMINAL_MANIFEST_SUFFIX)?;
    let prepared_name = warm_component_name(&prepared_binding, WARM_SNAPSHOT_MANIFEST_SUFFIX)?;
    let content_name = warm_component_name(&prepared_binding, WARM_SNAPSHOT_CONTENT_SUFFIX)?;
    let intent_name = warm_component_name(&prepared_binding, WARM_SNAPSHOT_INTENT_SUFFIX)?;
    let terminal_presence = inspect_exact_warm_file(
        &namespace,
        &terminal_name,
        &authority.terminal_manifest_identity,
    )?;
    let prepared_presence = inspect_exact_warm_file(
        &namespace,
        &prepared_name,
        &authority.prepared_manifest_identity,
    )?;
    let intent_presence = inspect_exact_warm_file(
        &namespace,
        &intent_name,
        &authority.intent_manifest_identity,
    )?;
    let content_presence = inspect_exact_warm_directory(
        &namespace,
        &content_name,
        &authority.content_directory_identity,
    )?;
    if [
        terminal_presence,
        prepared_presence,
        intent_presence,
        content_presence,
    ]
    .contains(&ExactWarmObjectPresence::Conflict)
        || (terminal_presence == ExactWarmObjectPresence::Exact
            && [prepared_presence, intent_presence, content_presence]
                .iter()
                .any(|presence| *presence != ExactWarmObjectPresence::Exact))
        || (matches!(
            completion,
            ValidatedWarmCleanupCompletion::RetainForFailedStart { .. }
        ) && [prepared_presence, intent_presence, content_presence]
            .iter()
            .any(|presence| *presence != ExactWarmObjectPresence::Exact))
    {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    if matches!(
        completion,
        ValidatedWarmCleanupCompletion::RetainForFailedStart { .. }
    ) && inspect_warm_memory_file(physical, authority, true, deadline)?
        != ExactWarmObjectPresence::Exact
    {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    let memory_removal = if matches!(completion, ValidatedWarmCleanupCompletion::Remove) {
        match prepare_exact_warm_memory_removal(physical, authority, deadline)? {
            WarmMemoryRemovalPreparation::Exact(handle) => Some(handle),
            WarmMemoryRemovalPreparation::Absent
                if terminal_presence == ExactWarmObjectPresence::Absent =>
            {
                None
            }
            WarmMemoryRemovalPreparation::Absent | WarmMemoryRemovalPreparation::Conflict => {
                return Ok(WarmSnapshotCleanupAttempt::Blocked);
            }
        }
    } else {
        None
    };
    // Revoke the executable restart source first.  A crash after this unlink
    // can only leave command-owned retained material; it can never leave a
    // terminal Warm manifest pointing at a partially removed payload.
    if !remove_exact_warm_file(
        &namespace,
        &terminal_name,
        &authority.terminal_manifest_identity,
        deadline,
    )? {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    namespace
        .sync_all()
        .context("fsync Warm terminal authority revocation")?;
    if fstatat_nofollow(&namespace, &terminal_name)?.is_some() {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    if let ValidatedWarmCleanupCompletion::RetainForFailedStart {
        inherited_predecessor_physical_digest,
    } = completion
    {
        // This failed Start owns only revocation of the old executable Warm
        // terminal. Intent, prepared claim, payload, and RAM remain exact and
        // non-executable so a typed retry can inspect the retained bundle.
        return Ok(WarmSnapshotCleanupAttempt::Exact(
            warm_cleanup_retain_failed_start_digest(
                authority,
                inherited_predecessor_physical_digest,
            ),
        ));
    }

    // Destructive Cold/Delete cleanup owns the external file-backed RAM only
    // after the terminal manifest is durably absent. Same-Node Start keeps the
    // exact inode live and merely retires the old restart authority.
    if let Some(memory_removal) = memory_removal {
        if !remove_prepared_warm_memory_file(memory_removal, deadline)? {
            return Ok(WarmSnapshotCleanupAttempt::Blocked);
        }
    }

    // Revoke the non-executable prepared claim before mutating its payload so
    // every cleanup crash projects either RetainedPrepared (before this
    // unlink) or RetainedIntent (after it), never a prepared manifest over a
    // partially removed tree.
    if !remove_exact_warm_file(
        &namespace,
        &prepared_name,
        &authority.prepared_manifest_identity,
        deadline,
    )? {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    namespace
        .sync_all()
        .context("fsync Warm prepared claim revocation")?;
    if fstatat_nofollow(&namespace, &prepared_name)?.is_some() {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }

    if !remove_exact_warm_directory(
        &namespace,
        &content_name,
        &authority.content_directory_identity,
        deadline,
    )? {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    if !remove_exact_warm_file(
        &namespace,
        &intent_name,
        &authority.intent_manifest_identity,
        deadline,
    )? {
        return Ok(WarmSnapshotCleanupAttempt::Blocked);
    }
    namespace
        .sync_all()
        .context("fsync terminal Warm bundle removal")?;
    for name in [&terminal_name, &content_name, &prepared_name, &intent_name] {
        anyhow::ensure!(
            Instant::now() < deadline,
            "Warm snapshot cleanup deadline elapsed"
        );
        if fstatat_nofollow(&namespace, name)?.is_some() {
            return Ok(WarmSnapshotCleanupAttempt::Blocked);
        }
    }
    finish_warm_memory_cleanup(physical, command, authority, completion, deadline)
}

#[derive(Clone, Copy)]
enum ValidatedWarmCleanupCompletion<'a> {
    TransferToRuntime {
        runtime_incarnation: &'a RandomId128,
        runtime_progress_manifest_digest: &'a Sha256Digest,
    },
    RetainForFailedStart {
        inherited_predecessor_physical_digest: &'a Sha256Digest,
    },
    Remove,
}

fn finish_warm_memory_cleanup(
    physical: &InstalledPhysicalInspectionConfig,
    command: &LifecycleCommandEnvelope,
    authority: &WarmSnapshotCleanupAuthority,
    completion: ValidatedWarmCleanupCompletion<'_>,
    deadline: Instant,
) -> Result<WarmSnapshotCleanupAttempt<Sha256Digest>> {
    match completion {
        ValidatedWarmCleanupCompletion::RetainForFailedStart { .. } => {
            Ok(WarmSnapshotCleanupAttempt::Blocked)
        }
        ValidatedWarmCleanupCompletion::Remove => {
            if !remove_exact_warm_memory_file(physical, authority, deadline)?
                || inspect_warm_memory_file(physical, authority, true, deadline)?
                    != ExactWarmObjectPresence::Absent
            {
                return Ok(WarmSnapshotCleanupAttempt::Blocked);
            }
            Ok(WarmSnapshotCleanupAttempt::Exact(
                warm_cleanup_remove_digest(authority),
            ))
        }
        ValidatedWarmCleanupCompletion::TransferToRuntime {
            runtime_incarnation,
            runtime_progress_manifest_digest,
        } => {
            if !validate_warm_memory_transfer(
                physical,
                command,
                authority,
                runtime_incarnation,
                runtime_progress_manifest_digest,
                deadline,
            )? {
                return Ok(WarmSnapshotCleanupAttempt::Blocked);
            }
            Ok(WarmSnapshotCleanupAttempt::Exact(
                warm_cleanup_transfer_digest(
                    authority,
                    runtime_incarnation,
                    runtime_progress_manifest_digest,
                ),
            ))
        }
    }
}

fn warm_cleanup_remove_digest(authority: &WarmSnapshotCleanupAuthority) -> Sha256Digest {
    digest_parts(
        WARM_CLEANUP_REMOVE_DOMAIN,
        &[
            authority.authority_digest.as_bytes(),
            authority.request.terminal_manifest_digest.as_bytes(),
            authority.request.warm_receipt_digest.as_bytes(),
            authority.memory_file.digest.as_bytes(),
        ],
    )
}

fn warm_cleanup_transfer_digest(
    authority: &WarmSnapshotCleanupAuthority,
    runtime_incarnation: &RandomId128,
    runtime_progress_manifest_digest: &Sha256Digest,
) -> Sha256Digest {
    digest_parts(
        WARM_CLEANUP_TRANSFER_DOMAIN,
        &[
            authority.authority_digest.as_bytes(),
            authority.request.terminal_manifest_digest.as_bytes(),
            authority.request.warm_receipt_digest.as_bytes(),
            authority.memory_file.digest.as_bytes(),
            runtime_incarnation.as_str().as_bytes(),
            runtime_progress_manifest_digest.as_bytes(),
        ],
    )
}

fn warm_cleanup_retain_failed_start_digest(
    authority: &WarmSnapshotCleanupAuthority,
    inherited_predecessor_physical_digest: &Sha256Digest,
) -> Sha256Digest {
    digest_parts(
        WARM_CLEANUP_RETAIN_FAILED_START_DOMAIN,
        &[
            authority.authority_digest.as_bytes(),
            authority.request.terminal_manifest_digest.as_bytes(),
            authority.request.warm_receipt_digest.as_bytes(),
            authority.memory_file.digest.as_bytes(),
            inherited_predecessor_physical_digest.as_bytes(),
        ],
    )
}

fn retained_warm_restart_source_carrier_digest(
    carrier: &RetainedWarmRestartSourceCarrier,
) -> Result<Sha256Digest> {
    let mut preimage = carrier.clone();
    preimage.carrier_digest = Sha256Digest::from_bytes([0; 32]);
    let canonical =
        serde_json::to_vec(&preimage).context("encode retained Warm restart-source carrier")?;
    Ok(digest_parts(
        RETAINED_WARM_RESTART_SOURCE_DOMAIN,
        &[&canonical],
    ))
}

/// Seal the exact non-executable bundle left by RetainForFailedStart into the
/// current Start's TerminalRetained manifest. The returned carrier contains no
/// discovery authority; every path and inode came from the pre-effect Warm
/// cleanup authority already journaled by this command.
pub(crate) fn seal_retained_warm_restart_source(
    failed_start_command: &LifecycleCommandEnvelope,
    source_authority: &WarmSnapshotCleanupAuthority,
    inherited_predecessor_physical_digest: Sha256Digest,
    revocation_receipt_digest: Sha256Digest,
) -> Result<RetainedWarmRestartSourceCarrier> {
    validate_warm_cleanup_authority_scope(failed_start_command, source_authority)?;
    anyhow::ensure!(
        matches!(failed_start_command.command, LifecycleCommand::Start(_))
            && source_authority.mode == WarmSnapshotCleanupMode::TransferToRuntime
            && inherited_predecessor_physical_digest.as_bytes() != &[0; 32]
            && revocation_receipt_digest
                == warm_cleanup_retain_failed_start_digest(
                    source_authority,
                    &inherited_predecessor_physical_digest,
                ),
        "failed Start retained Warm carrier lacks its exact revocation receipt"
    );
    let mut carrier = RetainedWarmRestartSourceCarrier {
        version: STEP_VERSION,
        failed_start_operation_id: failed_start_command.operation_id.clone(),
        failed_start_request_fingerprint: failed_start_command.request_fingerprint.clone(),
        inherited_predecessor_physical_digest,
        revocation_receipt_digest,
        source_authority: Box::new(source_authority.clone()),
        carrier_digest: Sha256Digest::from_bytes([0; 32]),
    };
    carrier.carrier_digest = retained_warm_restart_source_carrier_digest(&carrier)?;
    validate_retained_warm_restart_source_for_failed_start(failed_start_command, &carrier)?;
    Ok(carrier)
}

/// Pure validation used when reopening a TerminalRetained manifest. Physical
/// freshness is deliberately separate and occurs only through
/// `inspect_rebound_warm_retry_source` before a new restore plan is journaled.
pub(crate) fn validate_retained_warm_restart_source(
    carrier: &RetainedWarmRestartSourceCarrier,
) -> Result<()> {
    let authority = carrier.source_authority.as_ref();
    let installed = authority.installed_runtime()?;
    anyhow::ensure!(
        carrier.version == STEP_VERSION
            && carrier.failed_start_operation_id == authority.cleanup_operation_id
            && carrier.failed_start_request_fingerprint == authority.cleanup_request_fingerprint
            && carrier.inherited_predecessor_physical_digest.as_bytes() != &[0; 32]
            && carrier.revocation_receipt_digest
                == warm_cleanup_retain_failed_start_digest(
                    authority,
                    &carrier.inherited_predecessor_physical_digest,
                )
            && authority.mode == WarmSnapshotCleanupMode::TransferToRuntime
            && authority.authority_digest == warm_cleanup_authority_digest(authority)?
            && installed_runtime_manifest_digest(installed)? == installed.manifest_digest
            && installed.runtime_incarnation == authority.request.source_runtime_incarnation
            && installed.runtime_config_id == authority.runtime_config_id
            && installed.runtime_config_digest == authority.runtime_config_digest
            && installed.vmm.memory_file_path == authority.memory_file.path
            && authority.request.terminal_manifest_digest.as_bytes() != &[0; 32]
            && authority.request.warm_receipt_digest.as_bytes() != &[0; 32]
            && authority.memory_file.device > 0
            && authority.memory_file.inode > 0
            && authority.memory_file.size_bytes > 0
            && authority.memory_file.digest.as_bytes() != &[0; 32]
            && carrier.carrier_digest == retained_warm_restart_source_carrier_digest(carrier)?,
        "retained Warm restart-source carrier changed after terminal publication"
    );
    Ok(())
}

pub(crate) fn validate_retained_warm_restart_source_for_failed_start(
    failed_start_command: &LifecycleCommandEnvelope,
    carrier: &RetainedWarmRestartSourceCarrier,
) -> Result<()> {
    validate_retained_warm_restart_source(carrier)?;
    validate_warm_cleanup_authority_scope(failed_start_command, &carrier.source_authority)?;
    anyhow::ensure!(
        matches!(failed_start_command.command, LifecycleCommand::Start(_))
            && carrier.failed_start_operation_id == failed_start_command.operation_id
            && carrier.failed_start_request_fingerprint == failed_start_command.request_fingerprint,
        "retained Warm restart source belongs to another failed Start"
    );
    Ok(())
}

pub(crate) fn validate_retained_warm_restart_source_for_source(
    failed_start_command: &LifecycleCommandEnvelope,
    carrier: &RetainedWarmRestartSourceCarrier,
    source_authority: &WarmSnapshotCleanupAuthority,
    source_physical_manifest_digest: &Sha256Digest,
) -> Result<()> {
    validate_retained_warm_restart_source_for_failed_start(failed_start_command, carrier)?;
    anyhow::ensure!(
        carrier.source_authority.as_ref() == source_authority
            && &carrier.inherited_predecessor_physical_digest == source_physical_manifest_digest,
        "retained Warm carrier differs from its journaled failed-Start source"
    );
    Ok(())
}

fn retained_warm_failed_start_binding(
    current_command: &LifecycleCommandEnvelope,
    failed_predecessor: &LifecycleCommandResponse,
    failed_start_retained_manifest_digest: &Sha256Digest,
    carrier: &RetainedWarmRestartSourceCarrier,
) -> Result<RetainedWarmRetryBinding> {
    validate_retained_warm_restart_source(carrier)?;
    let NodeResult::StartFailed(failed) = &failed_predecessor.result else {
        anyhow::bail!("retained Warm successor predecessor is not StartFailed")
    };
    let terminal = LifecycleTerminalResult::NodeResult {
        response: Box::new(failed_predecessor.clone()),
    };
    let terminal_result_digest = lifecycle_terminal_result_digest(&terminal)
        .context("digest retained Warm StartFailed predecessor")?;
    anyhow::ensure!(
        failed_predecessor.operation_id == carrier.failed_start_operation_id
            && failed_predecessor.request_fingerprint == carrier.failed_start_request_fingerprint
            && failed_predecessor.workspace_id == current_command.workspace_id
            && failed_predecessor.cat_id == current_command.cat_id
            && failed_predecessor.node_id == current_command.node_id
            && failed_predecessor.placement_identity == current_command.placement_identity
            && failed_start_retained_manifest_digest
                == &failed.retained_evidence.artifact_manifest_digest
            && failed_start_retained_manifest_digest.as_bytes() != &[0; 32]
            && execution_absence_proof_is_nonzero(&failed.not_running),
        "retained Warm successor changed its failed Start terminal chain"
    );
    Ok(RetainedWarmRetryBinding {
        failed_start_operation_id: failed_predecessor.operation_id.clone(),
        failed_start_request_fingerprint: failed_predecessor.request_fingerprint.clone(),
        failed_start_terminal_result_digest: terminal_result_digest,
        failed_start_retained_manifest_digest: failed_start_retained_manifest_digest.clone(),
        inherited_predecessor_physical_digest: carrier
            .inherited_predecessor_physical_digest
            .clone(),
        source_revocation_receipt_digest: carrier.revocation_receipt_digest.clone(),
        source_carrier_digest: carrier.carrier_digest.clone(),
    })
}

/// Rebind one TerminalRetained Warm source through its exact immediate
/// StartFailed response to a new SameNodeRetry Start. This is pure: it changes
/// only mutation scope and carries the original descriptor identities forward.
pub(crate) fn rebind_retained_warm_for_retry(
    current_command: &LifecycleCommandEnvelope,
    failed_predecessor: &LifecycleCommandResponse,
    carrier: &RetainedWarmRestartSourceCarrier,
) -> Result<WarmSnapshotCleanupAuthority> {
    validate_same_node_owned_start_source(current_command, failed_predecessor)?;
    let NodeResult::StartFailed(failed) = &failed_predecessor.result else {
        anyhow::bail!("retained Warm retry predecessor is not StartFailed")
    };
    let binding = retained_warm_failed_start_binding(
        current_command,
        failed_predecessor,
        &failed.retained_evidence.artifact_manifest_digest,
        carrier,
    )?;
    let mut rebound = (*carrier.source_authority).clone();
    rebound.cleanup_operation_id = current_command.operation_id.clone();
    rebound.cleanup_request_fingerprint = current_command.request_fingerprint.clone();
    rebound.retained_retry = Some(Box::new(binding));
    rebound.authority_digest = warm_cleanup_authority_digest(&rebound)?;
    validate_warm_cleanup_authority_scope(current_command, &rebound)?;
    Ok(rebound)
}

/// Purely rebind a failed Warm Start's non-executable retained bundle to the
/// exact immediate Stop/Cold/Delete successor. The caller must obtain the
/// digest and optional carrier from one already-validated TerminalRetained
/// manifest; accepting `Option` here makes loss of a Warm carrier fail closed.
pub(crate) fn rebind_retained_warm_for_removal(
    current_command: &LifecycleCommandEnvelope,
    failed_predecessor: &LifecycleCommandResponse,
    failed_start_retained_manifest_digest: &Sha256Digest,
    carrier: Option<&RetainedWarmRestartSourceCarrier>,
) -> Result<WarmSnapshotCleanupAuthority> {
    let carrier = carrier.context("failed Start retained manifest lacks its Warm carrier")?;
    let terminal = LifecycleTerminalResult::NodeResult {
        response: Box::new(failed_predecessor.clone()),
    };
    validate_lifecycle_successor(Some(&terminal), current_command)
        .context("validate retained Warm removal successor")?;
    anyhow::ensure!(
        matches!(
            current_command.command,
            LifecycleCommand::Stop(_) | LifecycleCommand::Cold(_) | LifecycleCommand::Delete(_)
        ),
        "retained Warm removal requires Stop, Cold, or Delete"
    );
    let binding = retained_warm_failed_start_binding(
        current_command,
        failed_predecessor,
        failed_start_retained_manifest_digest,
        carrier,
    )?;
    let mut rebound = (*carrier.source_authority).clone();
    rebound.cleanup_operation_id = current_command.operation_id.clone();
    rebound.cleanup_request_fingerprint = current_command.request_fingerprint.clone();
    rebound.mode = WarmSnapshotCleanupMode::Remove;
    rebound.retained_retry = Some(Box::new(binding));
    rebound.authority_digest = warm_cleanup_authority_digest(&rebound)?;
    validate_warm_cleanup_authority_scope(current_command, &rebound)?;
    Ok(rebound)
}

/// Pure replay validation for a journaled retained-Warm removal authority.
/// Equality with a freshly derived authority joins every descriptor and both
/// the original Warm and immediate StartFailed chains without path discovery.
pub(crate) fn validate_retained_warm_removal_authority(
    current_command: &LifecycleCommandEnvelope,
    failed_predecessor: &LifecycleCommandResponse,
    failed_start_retained_manifest_digest: &Sha256Digest,
    carrier: Option<&RetainedWarmRestartSourceCarrier>,
    authority: &WarmSnapshotCleanupAuthority,
) -> Result<()> {
    let expected = rebind_retained_warm_for_removal(
        current_command,
        failed_predecessor,
        failed_start_retained_manifest_digest,
        carrier,
    )?;
    anyhow::ensure!(
        authority == &expected,
        "journaled retained Warm removal authority changed"
    );
    Ok(())
}

/// Build a structurally exact retained-Warm carrier for sibling lifecycle
/// tests without exposing its production fields. This grants no physical
/// authority: descriptor values are synthetic and this function is absent
/// from non-test builds.
#[cfg(test)]
pub(crate) fn retained_warm_restart_source_carrier_for_test(
    successor_command: &LifecycleCommandEnvelope,
    failed_predecessor: &LifecycleCommandResponse,
    installed_runtime: InstalledRuntimeManifest,
) -> Result<RetainedWarmRestartSourceCarrier> {
    anyhow::ensure!(
        matches!(failed_predecessor.result, NodeResult::StartFailed(_))
            && failed_predecessor.workspace_id == successor_command.workspace_id
            && failed_predecessor.cat_id == successor_command.cat_id
            && failed_predecessor.node_id == successor_command.node_id
            && failed_predecessor.placement_identity == successor_command.placement_identity
            && installed_runtime_manifest_digest(&installed_runtime)?
                == installed_runtime.manifest_digest
            && installed_runtime.node_id == successor_command.node_id
            && installed_runtime.cat_id == successor_command.cat_id
            && installed_runtime.placement_identity == successor_command.placement_identity
            && installed_runtime.runtime_config_id == successor_command.runtime_config.config_id
            && installed_runtime.runtime_config_digest
                == successor_command.runtime_config.config_digest,
        "retained Warm test fixture changed its failed Start or installed runtime"
    );
    let fixture_digest = |label: &[u8]| {
        digest_parts(
            b"cats.test.retained-warm-removal-fixture.v1",
            &[
                label,
                failed_predecessor.operation_id.as_str().as_bytes(),
                failed_predecessor.request_fingerprint.as_bytes(),
            ],
        )
    };
    let volume_receipts = installed_runtime
        .volumes
        .iter()
        .map(|volume| {
            Ok(VolumeTerminalReceipt {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                disk_role: volume.disk_role,
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch: volume.attachment_epoch,
                local_durable_generation: volume.current_authority_head.generation,
                remote_durable_generation: volume.current_authority_head.generation,
                authority_receipt_digest: Some(
                    volume
                        .authority_receipt_digest
                        .clone()
                        .context("retained Warm test fixture lacks its StartGrant digest")?,
                ),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let source_runtime_incarnation = installed_runtime.runtime_incarnation.clone();
    let memory_file_path = installed_runtime.vmm.memory_file_path.clone();
    let source_operation_id = Id::new("test_retained_warm_source_operation")
        .context("construct retained Warm fixture source operation")?;
    let prepared_operation_id = Id::new("test_retained_warm_prepared_operation")
        .context("construct retained Warm fixture prepared operation")?;
    let mut source_authority = WarmSnapshotCleanupAuthority {
        version: STEP_VERSION,
        cleanup_operation_id: failed_predecessor.operation_id.clone(),
        cleanup_request_fingerprint: failed_predecessor.request_fingerprint.clone(),
        workspace_id: successor_command.workspace_id.clone(),
        cat_id: successor_command.cat_id.clone(),
        node_id: successor_command.node_id.clone(),
        placement_identity: successor_command.placement_identity.clone(),
        runtime_config_id: successor_command.runtime_config.config_id.clone(),
        runtime_config_digest: successor_command.runtime_config.config_digest.clone(),
        request: WarmSnapshotCleanupRequest {
            predecessor_operation_id: source_operation_id.clone(),
            predecessor_request_fingerprint: fixture_digest(b"source-request"),
            predecessor_terminal_result_digest: fixture_digest(b"source-terminal"),
            terminal_manifest_digest: fixture_digest(b"warm-terminal-manifest"),
            warm_receipt_digest: fixture_digest(b"warm-receipt"),
            source_runtime_incarnation,
            volume_receipts,
        },
        terminal_operation_id: source_operation_id,
        terminal_request_fingerprint: fixture_digest(b"source-request"),
        prepared_operation_id,
        prepared_request_fingerprint: fixture_digest(b"prepared-request"),
        mode: WarmSnapshotCleanupMode::TransferToRuntime,
        snapshot_directory: HostPath::new("/var/lib/cats/test-retained-warm.snapshot")
            .context("construct retained Warm fixture snapshot path")?,
        installed_runtime: Some(Box::new(installed_runtime)),
        memory_file: WarmMemoryFileProof {
            path: memory_file_path,
            device: 2,
            inode: 3,
            size_bytes: 1,
            digest: fixture_digest(b"memory"),
        },
        memory_parent_identity: WarmCleanupObjectIdentity {
            device: 2,
            inode: 2,
        },
        namespace_identity: WarmCleanupObjectIdentity {
            device: 1,
            inode: 1,
        },
        terminal_manifest_identity: WarmCleanupObjectIdentity {
            device: 1,
            inode: 2,
        },
        intent_manifest_identity: WarmCleanupObjectIdentity {
            device: 1,
            inode: 3,
        },
        prepared_manifest_identity: WarmCleanupObjectIdentity {
            device: 1,
            inode: 4,
        },
        content_directory_identity: WarmCleanupObjectIdentity {
            device: 1,
            inode: 5,
        },
        retained_retry: None,
        authority_digest: Sha256Digest::from_bytes([0; 32]),
    };
    source_authority.authority_digest = warm_cleanup_authority_digest(&source_authority)?;
    let inherited_predecessor_physical_digest = source_authority
        .installed_runtime()?
        .manifest_digest
        .clone();
    let revocation_receipt_digest = warm_cleanup_retain_failed_start_digest(
        &source_authority,
        &inherited_predecessor_physical_digest,
    );
    let mut carrier = RetainedWarmRestartSourceCarrier {
        version: STEP_VERSION,
        failed_start_operation_id: failed_predecessor.operation_id.clone(),
        failed_start_request_fingerprint: failed_predecessor.request_fingerprint.clone(),
        inherited_predecessor_physical_digest,
        revocation_receipt_digest,
        source_authority: Box::new(source_authority),
        carrier_digest: Sha256Digest::from_bytes([0; 32]),
    };
    carrier.carrier_digest = retained_warm_restart_source_carrier_digest(&carrier)?;
    validate_retained_warm_restart_source(&carrier)?;
    Ok(carrier)
}

/// Complete pure retained-Warm chain for sibling Stop/Cold/Delete tests.
/// The installed runtime and descriptor identities are synthetic; production
/// code cannot call this constructor.
#[cfg(test)]
pub(crate) fn retained_warm_restart_source_chain_for_test(
    successor_command: &LifecycleCommandEnvelope,
    failed_predecessor: &LifecycleCommandResponse,
) -> Result<(
    InstalledRuntimeManifest,
    RetainedWarmRestartSourceCarrier,
    WarmSnapshotCleanupAuthority,
)> {
    let runtime_incarnation = RandomId128::new("77".repeat(16))
        .context("construct retained Warm fixture runtime incarnation")?;
    let memory_file_path = HostPath::new("/var/lib/cats/test-retained-warm-memory")
        .context("construct retained Warm fixture memory path")?;
    let installed_runtime = tests::cleanup_installed_runtime(
        successor_command,
        &runtime_incarnation,
        &memory_file_path,
    );
    let carrier = retained_warm_restart_source_carrier_for_test(
        successor_command,
        failed_predecessor,
        installed_runtime.clone(),
    )?;
    let NodeResult::StartFailed(failed) = &failed_predecessor.result else {
        anyhow::bail!("retained Warm fixture predecessor is not StartFailed")
    };
    let authority = rebind_retained_warm_for_removal(
        successor_command,
        failed_predecessor,
        &failed.retained_evidence.artifact_manifest_digest,
        Some(&carrier),
    )?;
    validate_retained_warm_removal_authority(
        successor_command,
        failed_predecessor,
        &failed.retained_evidence.artifact_manifest_digest,
        Some(&carrier),
        &authority,
    )?;
    Ok((installed_runtime, carrier, authority))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactWarmObjectPresence {
    Absent,
    Exact,
    Conflict,
}

fn inspect_exact_warm_file(
    directory: &File,
    name: &CStr,
    expected: &WarmCleanupObjectIdentity,
) -> Result<ExactWarmObjectPresence> {
    let Some(before) = fstatat_nofollow(directory, name)? else {
        return Ok(ExactWarmObjectPresence::Absent);
    };
    if before.st_mode & libc::S_IFMT != libc::S_IFREG
        || before.st_nlink != 1
        || stat_identity(&before)? != *expected
    {
        return Ok(ExactWarmObjectPresence::Conflict);
    }
    let Some(file) = openat_file_optional(
        directory,
        name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )?
    else {
        return Ok(ExactWarmObjectPresence::Conflict);
    };
    let metadata = file.metadata().context("inspect exact Warm file")?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
    {
        return Ok(ExactWarmObjectPresence::Conflict);
    }
    let Some(after) = fstatat_nofollow(directory, name)? else {
        return Ok(ExactWarmObjectPresence::Conflict);
    };
    Ok(
        if after.st_mode & libc::S_IFMT == libc::S_IFREG
            && after.st_nlink == 1
            && stat_identity(&after)? == *expected
        {
            ExactWarmObjectPresence::Exact
        } else {
            ExactWarmObjectPresence::Conflict
        },
    )
}

fn inspect_exact_warm_directory(
    parent: &File,
    name: &CStr,
    expected: &WarmCleanupObjectIdentity,
) -> Result<ExactWarmObjectPresence> {
    let Some(before) = fstatat_nofollow(parent, name)? else {
        return Ok(ExactWarmObjectPresence::Absent);
    };
    if before.st_mode & libc::S_IFMT != libc::S_IFDIR || stat_identity(&before)? != *expected {
        return Ok(ExactWarmObjectPresence::Conflict);
    }
    let Some(directory) = openat_directory_optional(parent, name)? else {
        return Ok(ExactWarmObjectPresence::Conflict);
    };
    if directory_identity(&directory)? != *expected {
        return Ok(ExactWarmObjectPresence::Conflict);
    }
    let Some(after) = fstatat_nofollow(parent, name)? else {
        return Ok(ExactWarmObjectPresence::Conflict);
    };
    Ok(
        if after.st_mode & libc::S_IFMT == libc::S_IFDIR && stat_identity(&after)? == *expected {
            ExactWarmObjectPresence::Exact
        } else {
            ExactWarmObjectPresence::Conflict
        },
    )
}

fn inspect_warm_memory_file(
    physical: &InstalledPhysicalInspectionConfig,
    authority: &WarmSnapshotCleanupAuthority,
    verify_content_digest: bool,
    deadline: Instant,
) -> Result<ExactWarmObjectPresence> {
    anyhow::ensure!(Instant::now() < deadline, "Warm memory deadline elapsed");
    let Some((parent, name)) = open_state_descendant_parent(
        &physical.state_directory,
        Path::new(authority.memory_file.path.as_str()),
    )?
    else {
        return Ok(ExactWarmObjectPresence::Absent);
    };
    if directory_identity(&parent)? != authority.memory_parent_identity {
        return Ok(ExactWarmObjectPresence::Conflict);
    }
    let Some(before) = fstatat_nofollow(&parent, &name)? else {
        return Ok(ExactWarmObjectPresence::Absent);
    };
    if before.st_mode & libc::S_IFMT != libc::S_IFREG
        || before.st_nlink != 1
        || stat_identity(&before)?
            != (WarmCleanupObjectIdentity {
                device: authority.memory_file.device,
                inode: authority.memory_file.inode,
            })
        || u64::try_from(before.st_size).ok() != Some(authority.memory_file.size_bytes)
    {
        return Ok(ExactWarmObjectPresence::Conflict);
    }
    let Some(file) = openat_file_optional(
        &parent,
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?
    else {
        return Ok(ExactWarmObjectPresence::Conflict);
    };
    if verify_content_digest {
        let proof = memory_file_proof_from_open_file(
            file,
            authority.memory_file.path.clone(),
            authority.memory_file.size_bytes,
            deadline,
            false,
        )?;
        if proof != authority.memory_file {
            return Ok(ExactWarmObjectPresence::Conflict);
        }
    } else {
        let metadata = file.metadata().context("inspect transferred Warm memory")?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.dev() != authority.memory_file.device
            || metadata.ino() != authority.memory_file.inode
            || metadata.len() != authority.memory_file.size_bytes
        {
            return Ok(ExactWarmObjectPresence::Conflict);
        }
    }
    let Some(after) = fstatat_nofollow(&parent, &name)? else {
        return Ok(ExactWarmObjectPresence::Conflict);
    };
    Ok(
        if after.st_mode & libc::S_IFMT == libc::S_IFREG
            && after.st_nlink == 1
            && stat_identity(&after)?
                == (WarmCleanupObjectIdentity {
                    device: authority.memory_file.device,
                    inode: authority.memory_file.inode,
                })
            && u64::try_from(after.st_size).ok() == Some(authority.memory_file.size_bytes)
        {
            ExactWarmObjectPresence::Exact
        } else {
            ExactWarmObjectPresence::Conflict
        },
    )
}

struct PreparedWarmMemoryRemoval {
    parent: File,
    name: CString,
    file: File,
    parent_identity: WarmCleanupObjectIdentity,
    file_identity: WarmCleanupObjectIdentity,
    size_bytes: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

enum WarmMemoryRemovalPreparation {
    Absent,
    Exact(PreparedWarmMemoryRemoval),
    Conflict,
}

fn prepare_exact_warm_memory_removal(
    physical: &InstalledPhysicalInspectionConfig,
    authority: &WarmSnapshotCleanupAuthority,
    deadline: Instant,
) -> Result<WarmMemoryRemovalPreparation> {
    anyhow::ensure!(Instant::now() < deadline, "Warm memory deadline elapsed");
    let Some((parent, name)) = open_state_descendant_parent(
        &physical.state_directory,
        Path::new(authority.memory_file.path.as_str()),
    )?
    else {
        return Ok(WarmMemoryRemovalPreparation::Absent);
    };
    let parent_identity = directory_identity(&parent)?;
    if parent_identity != authority.memory_parent_identity {
        return Ok(WarmMemoryRemovalPreparation::Conflict);
    }
    let Some(before) = fstatat_nofollow(&parent, &name)? else {
        return Ok(WarmMemoryRemovalPreparation::Absent);
    };
    let file_identity = WarmCleanupObjectIdentity {
        device: authority.memory_file.device,
        inode: authority.memory_file.inode,
    };
    if before.st_mode & libc::S_IFMT != libc::S_IFREG
        || before.st_nlink != 1
        || stat_identity(&before)? != file_identity
        || u64::try_from(before.st_size).ok() != Some(authority.memory_file.size_bytes)
    {
        return Ok(WarmMemoryRemovalPreparation::Conflict);
    }
    let Some(file) = openat_file_optional(
        &parent,
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?
    else {
        return Ok(WarmMemoryRemovalPreparation::Conflict);
    };
    let proof = memory_file_proof_from_open_file(
        file.try_clone().context("retain Warm memory descriptor")?,
        authority.memory_file.path.clone(),
        authority.memory_file.size_bytes,
        deadline,
        false,
    )?;
    if proof != authority.memory_file {
        return Ok(WarmMemoryRemovalPreparation::Conflict);
    }
    let metadata = file
        .metadata()
        .context("retain verified Warm memory metadata")?;
    let Some(after) = fstatat_nofollow(&parent, &name)? else {
        return Ok(WarmMemoryRemovalPreparation::Conflict);
    };
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.dev() != file_identity.device
        || metadata.ino() != file_identity.inode
        || metadata.len() != authority.memory_file.size_bytes
        || after.st_mode & libc::S_IFMT != libc::S_IFREG
        || after.st_nlink != 1
        || stat_identity(&after)? != file_identity
        || u64::try_from(after.st_size).ok() != Some(authority.memory_file.size_bytes)
    {
        return Ok(WarmMemoryRemovalPreparation::Conflict);
    }
    Ok(WarmMemoryRemovalPreparation::Exact(
        PreparedWarmMemoryRemoval {
            parent,
            name,
            file,
            parent_identity,
            file_identity,
            size_bytes: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        },
    ))
}

fn remove_prepared_warm_memory_file(
    prepared: PreparedWarmMemoryRemoval,
    deadline: Instant,
) -> Result<bool> {
    anyhow::ensure!(Instant::now() < deadline, "Warm memory deadline elapsed");
    if directory_identity(&prepared.parent)? != prepared.parent_identity {
        return Ok(false);
    }
    let retained = prepared
        .file
        .metadata()
        .context("reinspect retained Warm memory descriptor")?;
    if !retained.file_type().is_file()
        || retained.nlink() != 1
        || retained.dev() != prepared.file_identity.device
        || retained.ino() != prepared.file_identity.inode
        || retained.len() != prepared.size_bytes
        || retained.mtime() != prepared.modified_seconds
        || retained.mtime_nsec() != prepared.modified_nanoseconds
    {
        return Ok(false);
    }
    let Some(current) = fstatat_nofollow(&prepared.parent, &prepared.name)? else {
        return Ok(false);
    };
    if current.st_mode & libc::S_IFMT != libc::S_IFREG
        || current.st_nlink != 1
        || stat_identity(&current)? != prepared.file_identity
        || u64::try_from(current.st_size).ok() != Some(prepared.size_bytes)
    {
        return Ok(false);
    }
    let current_file = openat_file(
        &prepared.parent,
        &prepared.name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    )?;
    let current_metadata = current_file
        .metadata()
        .context("reopen exact Warm memory before unlink")?;
    if !current_metadata.file_type().is_file()
        || current_metadata.nlink() != 1
        || current_metadata.dev() != prepared.file_identity.device
        || current_metadata.ino() != prepared.file_identity.inode
        || current_metadata.len() != prepared.size_bytes
        || current_metadata.mtime() != prepared.modified_seconds
        || current_metadata.mtime_nsec() != prepared.modified_nanoseconds
    {
        return Ok(false);
    }
    anyhow::ensure!(Instant::now() < deadline, "Warm memory deadline elapsed");
    let Some(current) = fstatat_nofollow(&prepared.parent, &prepared.name)? else {
        return Ok(false);
    };
    if stat_identity(&current)? != prepared.file_identity {
        return Ok(false);
    }
    unlinkat_component(&prepared.parent, &prepared.name, 0)?;
    prepared
        .parent
        .sync_all()
        .context("fsync removed Warm memory backing parent")?;
    Ok(fstatat_nofollow(&prepared.parent, &prepared.name)?.is_none())
}

fn remove_exact_warm_memory_file(
    physical: &InstalledPhysicalInspectionConfig,
    authority: &WarmSnapshotCleanupAuthority,
    deadline: Instant,
) -> Result<bool> {
    match inspect_warm_memory_file(physical, authority, true, deadline)? {
        ExactWarmObjectPresence::Absent => return Ok(true),
        ExactWarmObjectPresence::Conflict => return Ok(false),
        ExactWarmObjectPresence::Exact => {}
    }
    let Some((parent, name)) = open_state_descendant_parent(
        &physical.state_directory,
        Path::new(authority.memory_file.path.as_str()),
    )?
    else {
        return Ok(false);
    };
    if directory_identity(&parent)? != authority.memory_parent_identity
        || !remove_exact_warm_file(
            &parent,
            &name,
            &WarmCleanupObjectIdentity {
                device: authority.memory_file.device,
                inode: authority.memory_file.inode,
            },
            deadline,
        )?
    {
        return Ok(false);
    }
    parent
        .sync_all()
        .context("fsync removed Warm memory backing parent")?;
    Ok(fstatat_nofollow(&parent, &name)?.is_none())
}

fn validate_warm_memory_transfer(
    physical: &InstalledPhysicalInspectionConfig,
    command: &LifecycleCommandEnvelope,
    authority: &WarmSnapshotCleanupAuthority,
    runtime_incarnation: &RandomId128,
    runtime_progress_manifest_digest: &Sha256Digest,
    deadline: Instant,
) -> Result<bool> {
    if !matches!(command.command, LifecycleCommand::Start(_))
        || runtime_incarnation == &authority.request.source_runtime_incarnation
    {
        return Ok(false);
    }
    let Some(progress) =
        load_installed_runtime_progress_manifest(&physical.state_directory, command)?
    else {
        return Ok(false);
    };
    let Some(vmm) = progress.vmm.as_ref() else {
        return Ok(false);
    };
    if progress.manifest_digest != *runtime_progress_manifest_digest
        || progress.runtime_incarnation != *runtime_incarnation
        || vmm.memory_file_path != authority.memory_file.path
        || vmm.launch_identity.runtime_incarnation != *runtime_incarnation
        || vmm.launch_identity.memory_file_path != authority.memory_file.path
        || vmm.launch_identity.memory_bytes != authority.memory_file.size_bytes
        || vmm.launch_identity.memory_bytes != command.runtime_config.memory_bytes
    {
        return Ok(false);
    }
    Ok(
        inspect_warm_memory_file(physical, authority, false, deadline)?
            == ExactWarmObjectPresence::Exact,
    )
}

fn finalize_or_reopen_warm_terminal(
    physical: &InstalledPhysicalInspectionConfig,
    command: &LifecycleCommandEnvelope,
    runtime: &InstalledRuntimeEvidence,
    snapshot: &WarmSnapshotEvidence,
    drained_volumes: &[VolumeTerminalReceipt],
    execution_absence: &ExecutionAbsenceProof,
    deadline: Instant,
) -> Result<TerminalPublishAttempt> {
    if Instant::now() >= deadline {
        return Ok(TerminalPublishAttempt::Unavailable);
    }
    let binding = StepBinding::new(command);
    let warm_receipt_digest = warm_ready_receipt_digest_for_binding(
        &binding,
        snapshot,
        execution_absence,
        drained_volumes,
    )?;
    let body = WarmTerminalManifestBody {
        version: STEP_VERSION,
        binding: binding.clone(),
        workspace_id: command.workspace_id.clone(),
        cat_id: command.cat_id.clone(),
        node_id: command.node_id.clone(),
        placement_identity: command.placement_identity.clone(),
        runtime_config_id: command.runtime_config.config_id.clone(),
        runtime_config_digest: command.runtime_config.config_digest.clone(),
        source_runtime_incarnation: runtime.runtime_incarnation.clone(),
        snapshot_intent_digest: snapshot.snapshot_intent_digest.clone(),
        prepared_snapshot: snapshot.clone(),
        drained_volumes: drained_volumes.to_vec(),
        execution_absence: execution_absence.clone(),
        warm_receipt_digest: warm_receipt_digest.clone(),
    };
    let expected = WarmTerminalManifest {
        terminal_manifest_digest: warm_terminal_manifest_digest(&body)?,
        body,
    };
    match durable_read_warm_terminal_manifest(physical, &binding, deadline)? {
        TerminalManifestRead::Exact(found) => {
            return Ok(if *found == expected {
                TerminalPublishAttempt::Exact(finalized_warm_evidence(&found))
            } else {
                TerminalPublishAttempt::Invalid
            });
        }
        TerminalManifestRead::Invalid => return Ok(TerminalPublishAttempt::Invalid),
        TerminalManifestRead::Unavailable => return Ok(TerminalPublishAttempt::Unavailable),
        TerminalManifestRead::Absent => {}
    }

    let namespace = open_warm_snapshot_namespace(&physical.state_directory, true)?
        .context("Warm terminal namespace was not created")?;
    let key = warm_snapshot_key(&binding);
    let temp_name = CString::new(format!("{key}{WARM_TERMINAL_TEMP_SUFFIX}"))
        .context("Warm terminal temp name contains NUL")?;
    let target_name = CString::new(format!("{key}{WARM_TERMINAL_MANIFEST_SUFFIX}"))
        .context("Warm terminal target name contains NUL")?;
    if let Some(temp) = openat_file_optional(
        &namespace,
        &temp_name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )? {
        return match read_warm_terminal_file(temp.try_clone()?)? {
            TerminalManifestRead::Exact(found) if *found == expected => {
                temp.sync_all()
                    .context("fsync recovered Warm terminal temp")?;
                renameat(&namespace, &temp_name, &target_name)?;
                namespace
                    .sync_all()
                    .context("fsync recovered Warm terminal manifest")?;
                match durable_read_warm_terminal_manifest(physical, &binding, deadline)? {
                    TerminalManifestRead::Exact(reopened) if reopened == found => Ok(
                        TerminalPublishAttempt::Exact(finalized_warm_evidence(&reopened)),
                    ),
                    TerminalManifestRead::Unavailable => Ok(TerminalPublishAttempt::Unavailable),
                    TerminalManifestRead::Exact(_)
                    | TerminalManifestRead::Absent
                    | TerminalManifestRead::Invalid => Ok(TerminalPublishAttempt::Invalid),
                }
            }
            TerminalManifestRead::Unavailable => Ok(TerminalPublishAttempt::Unavailable),
            TerminalManifestRead::Exact(_)
            | TerminalManifestRead::Absent
            | TerminalManifestRead::Invalid => Ok(TerminalPublishAttempt::Invalid),
        };
    }
    publish_warm_terminal_manifest(&namespace, &binding, &expected)?;
    match durable_read_warm_terminal_manifest(physical, &binding, deadline)? {
        TerminalManifestRead::Exact(found) if *found == expected => Ok(
            TerminalPublishAttempt::Exact(finalized_warm_evidence(&found)),
        ),
        TerminalManifestRead::Unavailable => Ok(TerminalPublishAttempt::Unavailable),
        TerminalManifestRead::Exact(_)
        | TerminalManifestRead::Absent
        | TerminalManifestRead::Invalid => Ok(TerminalPublishAttempt::Invalid),
    }
}

fn finalized_warm_evidence(manifest: &WarmTerminalManifest) -> FinalizedWarmSnapshotEvidence {
    FinalizedWarmSnapshotEvidence {
        terminal_manifest_digest: manifest.terminal_manifest_digest.clone(),
        warm_receipt_digest: manifest.body.warm_receipt_digest.clone(),
    }
}

fn expected_warm_snapshot_intent(
    command: &LifecycleCommandEnvelope,
    binding: &StepBinding,
    runtime: &InstalledRuntimeEvidence,
    write_fence: &RuntimeWriteFenceEvidence,
    paused: &PausedRuntimeEvidence,
    drained_volumes: &[VolumeTerminalReceipt],
    installed: &InstalledRuntimeManifest,
) -> Result<WarmSnapshotIntent> {
    let plan = WarmSnapshotPlan {
        installed_runtime_manifest_digest: installed.manifest_digest.clone(),
        vmm_process: installed.vmm.process.clone(),
        vmm_api_socket_path: installed.vmm.api_socket_path.clone(),
        memory_file_path: installed.vmm.memory_file_path.clone(),
        content_directory_name: format!(
            "{}{WARM_SNAPSHOT_CONTENT_SUFFIX}",
            warm_snapshot_key(binding)
        ),
    };
    let plan_digest = warm_snapshot_plan_digest(&plan)?;
    let body = WarmSnapshotIntentBody {
        version: STEP_VERSION,
        binding: binding.clone(),
        workspace_id: command.workspace_id.clone(),
        cat_id: command.cat_id.clone(),
        node_id: command.node_id.clone(),
        placement_identity: command.placement_identity.clone(),
        runtime_config_id: command.runtime_config.config_id.clone(),
        runtime_config_digest: command.runtime_config.config_digest.clone(),
        source_runtime_incarnation: runtime.runtime_incarnation.clone(),
        runtime_physical_identity_digest: runtime.physical_identity_digest.clone(),
        write_fence_receipt_digest: write_fence_receipt_digest(write_fence).clone(),
        pause_receipt_digest: paused.pause_receipt_digest.clone(),
        drained_volumes: drained_volumes.to_vec(),
        plan,
        plan_digest,
    };
    let intent = WarmSnapshotIntent {
        intent_digest: warm_snapshot_intent_digest(&body)?,
        body,
    };
    validate_warm_snapshot_intent_internal(&intent)?;
    Ok(intent)
}

fn create_or_reopen_warm_snapshot_intent(
    state: &crate::state_directory::StateDirectory,
    expected: &WarmSnapshotIntent,
    deadline: Instant,
) -> Result<SnapshotIntentPublishAttempt> {
    if Instant::now() >= deadline {
        return Ok(SnapshotIntentPublishAttempt::Unavailable);
    }
    match read_warm_snapshot_intent_in(state, &expected.body.binding, deadline)? {
        SnapshotIntentRead::Exact(found) => {
            if *found != *expected {
                return Ok(SnapshotIntentPublishAttempt::Invalid);
            }
            return durable_reopen_warm_snapshot_intent(state, expected, deadline);
        }
        SnapshotIntentRead::Invalid => return Ok(SnapshotIntentPublishAttempt::Invalid),
        SnapshotIntentRead::Unavailable => return Ok(SnapshotIntentPublishAttempt::Unavailable),
        SnapshotIntentRead::Absent => {}
    }

    let namespace = open_warm_snapshot_namespace(state, true)?
        .context("Warm intent namespace was not created")?;
    // An effect without its closed intent is never adopted. In particular, do
    // not publish an intent after discovering a pre-existing content tree or
    // prepared/terminal claim: that would retroactively authorize an unknown
    // side effect.
    for suffix in [
        WARM_SNAPSHOT_CONTENT_SUFFIX,
        WARM_SNAPSHOT_MANIFEST_SUFFIX,
        WARM_SNAPSHOT_TEMP_SUFFIX,
        WARM_TERMINAL_MANIFEST_SUFFIX,
        WARM_TERMINAL_TEMP_SUFFIX,
    ] {
        let name = warm_component_name(&expected.body.binding, suffix)?;
        if fstatat_nofollow(&namespace, &name)?.is_some() {
            return Ok(SnapshotIntentPublishAttempt::Invalid);
        }
    }
    publish_warm_snapshot_intent(&namespace, expected)?;
    durable_reopen_warm_snapshot_intent(state, expected, deadline)
}

fn durable_reopen_warm_snapshot_intent(
    state: &crate::state_directory::StateDirectory,
    expected: &WarmSnapshotIntent,
    deadline: Instant,
) -> Result<SnapshotIntentPublishAttempt> {
    if Instant::now() >= deadline {
        return Ok(SnapshotIntentPublishAttempt::Unavailable);
    }
    let Some(namespace) = open_warm_snapshot_namespace(state, false)? else {
        return Ok(SnapshotIntentPublishAttempt::Invalid);
    };
    let name = warm_component_name(&expected.body.binding, WARM_SNAPSHOT_INTENT_SUFFIX)?;
    let Some(file) = openat_file_optional(
        &namespace,
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?
    else {
        return Ok(SnapshotIntentPublishAttempt::Invalid);
    };
    let identity = regular_single_link_identity(&file)?;
    let found = match read_warm_snapshot_intent_file(file.try_clone()?)? {
        SnapshotIntentRead::Exact(found) if *found == *expected => found,
        SnapshotIntentRead::Unavailable => return Ok(SnapshotIntentPublishAttempt::Unavailable),
        SnapshotIntentRead::Exact(_) | SnapshotIntentRead::Absent | SnapshotIntentRead::Invalid => {
            return Ok(SnapshotIntentPublishAttempt::Invalid)
        }
    };
    file.sync_all()
        .context("fsync exact replayed Warm snapshot intent")?;
    namespace
        .sync_all()
        .context("fsync exact replayed Warm intent namespace")?;
    let Some(current) = fstatat_nofollow(&namespace, &name)? else {
        return Ok(SnapshotIntentPublishAttempt::Invalid);
    };
    if stat_identity(&current)? != identity {
        return Ok(SnapshotIntentPublishAttempt::Invalid);
    }
    if Instant::now() >= deadline {
        return Ok(SnapshotIntentPublishAttempt::Unavailable);
    }
    Ok(SnapshotIntentPublishAttempt::Exact(found))
}

fn create_or_reopen_warm_snapshot(
    physical: &InstalledPhysicalInspectionConfig,
    inputs: WarmSnapshotInputs<'_>,
    installed: &InstalledRuntimeManifest,
    deadline: Instant,
) -> Result<SnapshotPublishAttempt> {
    let WarmSnapshotInputs {
        command,
        predecessor: _,
        runtime,
        write_fence,
        paused,
        drained_volumes,
    } = inputs;
    let binding = StepBinding::new(command);
    let expected_intent = expected_warm_snapshot_intent(
        command,
        &binding,
        runtime,
        write_fence,
        paused,
        drained_volumes,
        installed,
    )?;
    let intent = match create_or_reopen_warm_snapshot_intent(
        &physical.state_directory,
        &expected_intent,
        deadline,
    )? {
        SnapshotIntentPublishAttempt::Exact(intent) => intent,
        SnapshotIntentPublishAttempt::Invalid => {
            return Ok(SnapshotPublishAttempt::DefiniteFailure)
        }
        SnapshotIntentPublishAttempt::Unavailable => return Ok(SnapshotPublishAttempt::Ambiguous),
    };
    match durable_read_warm_snapshot_manifest(physical, &binding, deadline)? {
        SnapshotManifestRead::Exact(manifest) => {
            return Ok(
                match reopen_warm_snapshot(
                    physical,
                    &binding,
                    inputs,
                    &manifest.evidence,
                    deadline,
                )? {
                    SnapshotReopenAttempt::Exact(reopened) => {
                        SnapshotPublishAttempt::Exact(Box::new(reopened.evidence))
                    }
                    SnapshotReopenAttempt::Invalid | SnapshotReopenAttempt::Absent => {
                        SnapshotPublishAttempt::DefiniteFailure
                    }
                    SnapshotReopenAttempt::Unavailable => SnapshotPublishAttempt::Ambiguous,
                },
            );
        }
        SnapshotManifestRead::Invalid => return Ok(SnapshotPublishAttempt::DefiniteFailure),
        SnapshotManifestRead::Unavailable => return Ok(SnapshotPublishAttempt::Ambiguous),
        SnapshotManifestRead::Absent => {}
    }

    let namespace = open_warm_snapshot_namespace(&physical.state_directory, true)?
        .context("Warm snapshot namespace was not created")?;
    let key = warm_snapshot_key(&binding);
    let content_name = CString::new(intent.body.plan.content_directory_name.clone())
        .context("Warm snapshot content name contains NUL")?;
    let temp_name = CString::new(format!("{key}{WARM_SNAPSHOT_TEMP_SUFFIX}"))
        .context("Warm snapshot temp name contains NUL")?;
    if let Some(temp) = openat_file_optional(
        &namespace,
        &temp_name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )? {
        let candidate = read_warm_snapshot_file(temp.try_clone()?)?;
        if let SnapshotManifestRead::Exact(candidate) = candidate {
            if snapshot_manifest_inputs_match(&candidate, &binding, inputs, installed, &intent)
                && verify_snapshot_payload(physical, &candidate, deadline).is_ok()
            {
                let target = CString::new(format!("{key}{WARM_SNAPSHOT_MANIFEST_SUFFIX}"))
                    .context("Warm snapshot manifest name contains NUL")?;
                temp.sync_all()
                    .context("fsync recovered Warm snapshot manifest temp")?;
                renameat(&namespace, &temp_name, &target)?;
                namespace
                    .sync_all()
                    .context("fsync recovered Warm snapshot manifest namespace")?;
                return match durable_read_warm_snapshot_manifest(physical, &binding, deadline)? {
                    SnapshotManifestRead::Exact(reopened) if reopened == candidate => {
                        Ok(SnapshotPublishAttempt::Exact(Box::new(reopened.evidence)))
                    }
                    SnapshotManifestRead::Unavailable => Ok(SnapshotPublishAttempt::Ambiguous),
                    SnapshotManifestRead::Exact(_)
                    | SnapshotManifestRead::Absent
                    | SnapshotManifestRead::Invalid => Ok(SnapshotPublishAttempt::DefiniteFailure),
                };
            }
        }
        return Ok(SnapshotPublishAttempt::Ambiguous);
    }
    if openat_directory_optional(&namespace, &content_name)?.is_some() {
        return Ok(SnapshotPublishAttempt::Ambiguous);
    }
    mkdirat(&namespace, &content_name, 0o700).context("create Warm snapshot content directory")?;
    namespace
        .sync_all()
        .context("fsync Warm snapshot content directory creation")?;
    let content = openat_directory(&namespace, &content_name)?;
    let content_path = physical
        .state_directory
        .path()
        .join(WARM_SNAPSHOT_NAMESPACE)
        .join(OsStr::from_bytes(content_name.as_bytes()));
    ensure_path_matches_directory(&content_path, &content)?;

    // Cloud Hypervisor does not include file-backed RAM in its state files.
    // Sync the exact installed backing before asking CH to snapshot device/CPU
    // state, then hash it together with the finished bundle.
    let _ = memory_file_proof(physical, installed, command, deadline, true)?;
    match snapshot_exact_vmm_until(
        Path::new(intent.body.plan.vmm_api_socket_path.as_str()),
        intent.body.plan.vmm_process.pid,
        &content_path,
        deadline,
    )? {
        ExactVmEffectOutcome::Exact => {}
        ExactVmEffectOutcome::DefiniteFailure => {
            return Ok(SnapshotPublishAttempt::DefiniteFailure)
        }
        ExactVmEffectOutcome::Ambiguous => return Ok(SnapshotPublishAttempt::Ambiguous),
    }
    ensure_path_matches_directory(&content_path, &content)?;
    let snapshot_tree = snapshot_tree_proof(&content, command, deadline, true)?;
    let memory_file = memory_file_proof(physical, installed, command, deadline, true)?;
    let body = WarmSnapshotManifestBody {
        version: STEP_VERSION,
        binding: binding.clone(),
        workspace_id: command.workspace_id.clone(),
        cat_id: command.cat_id.clone(),
        node_id: command.node_id.clone(),
        placement_identity: command.placement_identity.clone(),
        runtime_config_id: command.runtime_config.config_id.clone(),
        runtime_config_digest: command.runtime_config.config_digest.clone(),
        runtime: runtime.clone(),
        write_fence: write_fence.clone(),
        paused: paused.clone(),
        drained_volumes: drained_volumes.to_vec(),
        snapshot_intent_digest: intent.intent_digest.clone(),
        installed_runtime_manifest_digest: installed.manifest_digest.clone(),
        content_directory_name: content_name
            .to_str()
            .context("Warm snapshot content name is not UTF-8")?
            .to_owned(),
        snapshot_tree,
        memory_file,
    };
    let manifest_digest = warm_snapshot_manifest_digest(&body)?;
    let evidence = WarmSnapshotEvidence {
        snapshot_operation_id: binding.operation_id.clone(),
        snapshot_request_fingerprint: binding.request_fingerprint.clone(),
        runtime_physical_identity_digest: runtime.physical_identity_digest.clone(),
        write_fence_receipt_digest: write_fence_receipt_digest(write_fence).clone(),
        pause_receipt_digest: paused.pause_receipt_digest.clone(),
        snapshot_intent_digest: intent.intent_digest.clone(),
        snapshot_manifest_digest: manifest_digest.clone(),
        snapshot_receipt_digest: warm_snapshot_receipt_digest(
            &binding,
            runtime,
            write_fence,
            paused,
            drained_volumes,
            &intent.intent_digest,
            &manifest_digest,
        )?,
    };
    let manifest = WarmSnapshotManifest { body, evidence };
    publish_warm_snapshot_manifest(&namespace, &binding, &manifest)?;
    match reopen_warm_snapshot(physical, &binding, inputs, &manifest.evidence, deadline)? {
        SnapshotReopenAttempt::Exact(reopened) => {
            Ok(SnapshotPublishAttempt::Exact(Box::new(reopened.evidence)))
        }
        SnapshotReopenAttempt::Invalid | SnapshotReopenAttempt::Absent => {
            Ok(SnapshotPublishAttempt::DefiniteFailure)
        }
        SnapshotReopenAttempt::Unavailable => Ok(SnapshotPublishAttempt::Ambiguous),
    }
}

fn reopen_warm_snapshot(
    physical: &InstalledPhysicalInspectionConfig,
    binding: &StepBinding,
    inputs: WarmSnapshotInputs<'_>,
    expected: &WarmSnapshotEvidence,
    deadline: Instant,
) -> Result<SnapshotReopenAttempt> {
    let command = inputs.command;
    let manifest = match durable_read_warm_snapshot_manifest(physical, binding, deadline)? {
        SnapshotManifestRead::Exact(manifest) => manifest,
        SnapshotManifestRead::Absent => return Ok(SnapshotReopenAttempt::Absent),
        SnapshotManifestRead::Invalid => return Ok(SnapshotReopenAttempt::Invalid),
        SnapshotManifestRead::Unavailable => return Ok(SnapshotReopenAttempt::Unavailable),
    };
    let Some(installed) =
        load_installed_runtime_manifest(&physical.state_directory, &command.cat_id)
            .context("reopen installed Runtime manifest for Warm snapshot")?
    else {
        return Ok(SnapshotReopenAttempt::Invalid);
    };
    let expected_intent = expected_warm_snapshot_intent(
        command,
        binding,
        inputs.runtime,
        inputs.write_fence,
        inputs.paused,
        inputs.drained_volumes,
        &installed,
    )?;
    let intent = match read_warm_snapshot_intent(physical, binding, deadline)? {
        SnapshotIntentRead::Exact(intent) if *intent == expected_intent => intent,
        SnapshotIntentRead::Unavailable => return Ok(SnapshotReopenAttempt::Unavailable),
        SnapshotIntentRead::Exact(_) | SnapshotIntentRead::Absent | SnapshotIntentRead::Invalid => {
            return Ok(SnapshotReopenAttempt::Invalid)
        }
    };
    if !snapshot_manifest_inputs_match(&manifest, binding, inputs, &installed, &intent)
        || &manifest.evidence != expected
    {
        return Ok(SnapshotReopenAttempt::Invalid);
    }
    match verify_snapshot_payload(physical, &manifest, deadline) {
        Ok(()) => Ok(SnapshotReopenAttempt::Exact(manifest)),
        Err(error) if Instant::now() >= deadline => {
            let _ = error;
            Ok(SnapshotReopenAttempt::Unavailable)
        }
        Err(_) => Ok(SnapshotReopenAttempt::Invalid),
    }
}

fn snapshot_manifest_inputs_match(
    manifest: &WarmSnapshotManifest,
    binding: &StepBinding,
    inputs: WarmSnapshotInputs<'_>,
    installed: &InstalledRuntimeManifest,
    intent: &WarmSnapshotIntent,
) -> bool {
    snapshot_manifest_matches_command(&manifest.body, inputs.command, binding)
        && manifest.body.runtime.runtime_incarnation == inputs.runtime.runtime_incarnation
        && manifest.body.runtime.runtime_config_digest == inputs.runtime.runtime_config_digest
        && manifest.body.runtime.physical_identity_digest == inputs.runtime.physical_identity_digest
        && manifest.body.write_fence == *inputs.write_fence
        && manifest.body.paused == *inputs.paused
        && manifest.body.drained_volumes == inputs.drained_volumes
        && manifest.body.snapshot_intent_digest == intent.intent_digest
        && manifest.evidence.snapshot_intent_digest == intent.intent_digest
        && manifest.body.installed_runtime_manifest_digest == installed.manifest_digest
}

fn snapshot_manifest_matches_command(
    body: &WarmSnapshotManifestBody,
    command: &LifecycleCommandEnvelope,
    binding: &StepBinding,
) -> bool {
    body.version == STEP_VERSION
        && &body.binding == binding
        && body.workspace_id == command.workspace_id
        && body.cat_id == command.cat_id
        && body.node_id == command.node_id
        && body.placement_identity == command.placement_identity
        && body.runtime_config_id == command.runtime_config.config_id
        && body.runtime_config_digest == command.runtime_config.config_digest
}

fn warm_snapshot_manifest_digest(body: &WarmSnapshotManifestBody) -> Result<Sha256Digest> {
    let canonical = serde_json::to_vec(body).context("encode Warm snapshot manifest body")?;
    Ok(digest_parts(WARM_SNAPSHOT_MANIFEST_DOMAIN, &[&canonical]))
}

fn warm_snapshot_plan_digest(plan: &WarmSnapshotPlan) -> Result<Sha256Digest> {
    let canonical = serde_json::to_vec(plan).context("encode Warm snapshot effect plan")?;
    Ok(digest_parts(WARM_SNAPSHOT_PLAN_DOMAIN, &[&canonical]))
}

fn warm_snapshot_intent_digest(body: &WarmSnapshotIntentBody) -> Result<Sha256Digest> {
    let canonical = serde_json::to_vec(body).context("encode Warm snapshot intent body")?;
    Ok(digest_parts(WARM_SNAPSHOT_INTENT_DOMAIN, &[&canonical]))
}

fn warm_terminal_manifest_digest(body: &WarmTerminalManifestBody) -> Result<Sha256Digest> {
    let canonical = serde_json::to_vec(body).context("encode Warm terminal manifest body")?;
    Ok(digest_parts(WARM_TERMINAL_MANIFEST_DOMAIN, &[&canonical]))
}

fn warm_snapshot_key(binding: &StepBinding) -> String {
    digest_parts(
        WARM_SNAPSHOT_KEY_DOMAIN,
        &[
            binding.operation_id.as_str().as_bytes(),
            binding.request_fingerprint.as_bytes(),
        ],
    )
    .as_str()
    .to_owned()
}

fn read_warm_snapshot_intent(
    physical: &InstalledPhysicalInspectionConfig,
    binding: &StepBinding,
    deadline: Instant,
) -> Result<SnapshotIntentRead> {
    read_warm_snapshot_intent_in(&physical.state_directory, binding, deadline)
}

fn read_warm_snapshot_intent_in(
    state: &crate::state_directory::StateDirectory,
    binding: &StepBinding,
    deadline: Instant,
) -> Result<SnapshotIntentRead> {
    if Instant::now() >= deadline {
        return Ok(SnapshotIntentRead::Unavailable);
    }
    let Some(namespace) = open_warm_snapshot_namespace(state, false)? else {
        return Ok(SnapshotIntentRead::Absent);
    };
    let name = warm_component_name(binding, WARM_SNAPSHOT_INTENT_SUFFIX)?;
    let Some(file) = openat_file_optional(
        &namespace,
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?
    else {
        return Ok(SnapshotIntentRead::Absent);
    };
    read_warm_snapshot_intent_file(file)
}

fn read_warm_snapshot_intent_file(file: File) -> Result<SnapshotIntentRead> {
    let metadata = file.metadata().context("inspect Warm intent file")?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > WARM_SNAPSHOT_MANIFEST_MAX_BYTES as u64
    {
        return Ok(SnapshotIntentRead::Invalid);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((WARM_SNAPSHOT_MANIFEST_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read Warm snapshot intent")?;
    if bytes.is_empty() || bytes.len() > WARM_SNAPSHOT_MANIFEST_MAX_BYTES {
        return Ok(SnapshotIntentRead::Invalid);
    }
    let intent: WarmSnapshotIntent = match serde_json::from_slice(&bytes) {
        Ok(intent) => intent,
        Err(_) => return Ok(SnapshotIntentRead::Invalid),
    };
    let canonical = serde_json::to_vec(&intent).context("re-encode Warm snapshot intent")?;
    if canonical != bytes || validate_warm_snapshot_intent_internal(&intent).is_err() {
        return Ok(SnapshotIntentRead::Invalid);
    }
    Ok(SnapshotIntentRead::Exact(Box::new(intent)))
}

fn read_warm_snapshot_manifest(
    physical: &InstalledPhysicalInspectionConfig,
    binding: &StepBinding,
    deadline: Instant,
) -> Result<SnapshotManifestRead> {
    if Instant::now() >= deadline {
        return Ok(SnapshotManifestRead::Unavailable);
    }
    let Some(namespace) = open_warm_snapshot_namespace(&physical.state_directory, false)? else {
        return Ok(SnapshotManifestRead::Absent);
    };
    let name = CString::new(format!(
        "{}{WARM_SNAPSHOT_MANIFEST_SUFFIX}",
        warm_snapshot_key(binding)
    ))
    .context("Warm snapshot manifest name contains NUL")?;
    let Some(file) = openat_file_optional(
        &namespace,
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?
    else {
        return Ok(SnapshotManifestRead::Absent);
    };
    read_warm_snapshot_file(file)
}

fn read_warm_terminal_manifest(
    physical: &InstalledPhysicalInspectionConfig,
    binding: &StepBinding,
    deadline: Instant,
) -> Result<TerminalManifestRead> {
    if Instant::now() >= deadline {
        return Ok(TerminalManifestRead::Unavailable);
    }
    let Some(namespace) = open_warm_snapshot_namespace(&physical.state_directory, false)? else {
        return Ok(TerminalManifestRead::Absent);
    };
    let name = CString::new(format!(
        "{}{WARM_TERMINAL_MANIFEST_SUFFIX}",
        warm_snapshot_key(binding)
    ))
    .context("Warm terminal manifest name contains NUL")?;
    let Some(file) = openat_file_optional(
        &namespace,
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?
    else {
        return Ok(TerminalManifestRead::Absent);
    };
    read_warm_terminal_file(file)
}

fn durable_read_warm_snapshot_manifest(
    physical: &InstalledPhysicalInspectionConfig,
    binding: &StepBinding,
    deadline: Instant,
) -> Result<SnapshotManifestRead> {
    if Instant::now() >= deadline {
        return Ok(SnapshotManifestRead::Unavailable);
    }
    let Some(namespace) = open_warm_snapshot_namespace(&physical.state_directory, false)? else {
        return Ok(SnapshotManifestRead::Absent);
    };
    let name = warm_component_name(binding, WARM_SNAPSHOT_MANIFEST_SUFFIX)?;
    let Some(file) = openat_file_optional(
        &namespace,
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?
    else {
        return Ok(SnapshotManifestRead::Absent);
    };
    let manifest = match read_warm_snapshot_file(file.try_clone()?)? {
        SnapshotManifestRead::Exact(manifest) => manifest,
        SnapshotManifestRead::Absent => return Ok(SnapshotManifestRead::Absent),
        SnapshotManifestRead::Invalid => return Ok(SnapshotManifestRead::Invalid),
        SnapshotManifestRead::Unavailable => return Ok(SnapshotManifestRead::Unavailable),
    };
    let identity = regular_single_link_identity(&file)?;
    file.sync_all()
        .context("fsync exact replayed Warm prepared manifest")?;
    namespace
        .sync_all()
        .context("fsync exact replayed Warm prepared namespace")?;
    let Some(current) = fstatat_nofollow(&namespace, &name)? else {
        return Ok(SnapshotManifestRead::Invalid);
    };
    if stat_identity(&current)? != identity {
        return Ok(SnapshotManifestRead::Invalid);
    }
    if Instant::now() >= deadline {
        return Ok(SnapshotManifestRead::Unavailable);
    }
    Ok(SnapshotManifestRead::Exact(manifest))
}

fn durable_read_warm_terminal_manifest(
    physical: &InstalledPhysicalInspectionConfig,
    binding: &StepBinding,
    deadline: Instant,
) -> Result<TerminalManifestRead> {
    if Instant::now() >= deadline {
        return Ok(TerminalManifestRead::Unavailable);
    }
    let Some(namespace) = open_warm_snapshot_namespace(&physical.state_directory, false)? else {
        return Ok(TerminalManifestRead::Absent);
    };
    let name = warm_component_name(binding, WARM_TERMINAL_MANIFEST_SUFFIX)?;
    let Some(file) = openat_file_optional(
        &namespace,
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?
    else {
        return Ok(TerminalManifestRead::Absent);
    };
    let manifest = match read_warm_terminal_file(file.try_clone()?)? {
        TerminalManifestRead::Exact(manifest) => manifest,
        TerminalManifestRead::Absent => return Ok(TerminalManifestRead::Absent),
        TerminalManifestRead::Invalid => return Ok(TerminalManifestRead::Invalid),
        TerminalManifestRead::Unavailable => return Ok(TerminalManifestRead::Unavailable),
    };
    let identity = regular_single_link_identity(&file)?;
    file.sync_all()
        .context("fsync exact replayed Warm terminal manifest")?;
    namespace
        .sync_all()
        .context("fsync exact replayed Warm terminal namespace")?;
    let Some(current) = fstatat_nofollow(&namespace, &name)? else {
        return Ok(TerminalManifestRead::Invalid);
    };
    if stat_identity(&current)? != identity {
        return Ok(TerminalManifestRead::Invalid);
    }
    if Instant::now() >= deadline {
        return Ok(TerminalManifestRead::Unavailable);
    }
    Ok(TerminalManifestRead::Exact(manifest))
}

fn read_warm_snapshot_file(file: File) -> Result<SnapshotManifestRead> {
    let metadata = file
        .metadata()
        .context("inspect Warm snapshot manifest file")?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > WARM_SNAPSHOT_MANIFEST_MAX_BYTES as u64
    {
        return Ok(SnapshotManifestRead::Invalid);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((WARM_SNAPSHOT_MANIFEST_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read Warm snapshot manifest")?;
    if bytes.is_empty() || bytes.len() > WARM_SNAPSHOT_MANIFEST_MAX_BYTES {
        return Ok(SnapshotManifestRead::Invalid);
    }
    let manifest: WarmSnapshotManifest = match serde_json::from_slice(&bytes) {
        Ok(manifest) => manifest,
        Err(_) => return Ok(SnapshotManifestRead::Invalid),
    };
    let canonical = serde_json::to_vec(&manifest).context("re-encode Warm snapshot manifest")?;
    if canonical != bytes || validate_warm_snapshot_manifest_internal(&manifest).is_err() {
        return Ok(SnapshotManifestRead::Invalid);
    }
    Ok(SnapshotManifestRead::Exact(Box::new(manifest)))
}

fn read_warm_terminal_file(file: File) -> Result<TerminalManifestRead> {
    let metadata = file
        .metadata()
        .context("inspect Warm terminal manifest file")?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > WARM_SNAPSHOT_MANIFEST_MAX_BYTES as u64
    {
        return Ok(TerminalManifestRead::Invalid);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((WARM_SNAPSHOT_MANIFEST_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read Warm terminal manifest")?;
    if bytes.is_empty() || bytes.len() > WARM_SNAPSHOT_MANIFEST_MAX_BYTES {
        return Ok(TerminalManifestRead::Invalid);
    }
    let manifest: WarmTerminalManifest = match serde_json::from_slice(&bytes) {
        Ok(manifest) => manifest,
        Err(_) => return Ok(TerminalManifestRead::Invalid),
    };
    let canonical = serde_json::to_vec(&manifest).context("re-encode Warm terminal manifest")?;
    if canonical != bytes || validate_warm_terminal_manifest_internal(&manifest).is_err() {
        return Ok(TerminalManifestRead::Invalid);
    }
    Ok(TerminalManifestRead::Exact(Box::new(manifest)))
}

fn validate_warm_snapshot_intent_internal(intent: &WarmSnapshotIntent) -> Result<()> {
    let body = &intent.body;
    anyhow::ensure!(
        body.version == STEP_VERSION
            && body.binding.version == STEP_VERSION
            && body.source_runtime_incarnation.as_str().len() == 32
            && body.plan.vmm_process.pid > 0
            && body.plan.content_directory_name
                == format!(
                    "{}{WARM_SNAPSHOT_CONTENT_SUFFIX}",
                    warm_snapshot_key(&body.binding)
                )
            && closed_remote_receipts(&body.drained_volumes),
        "Warm snapshot intent has an invalid closed shape"
    );
    anyhow::ensure!(
        body.plan_digest == warm_snapshot_plan_digest(&body.plan)?,
        "Warm snapshot plan digest changed"
    );
    anyhow::ensure!(
        intent.intent_digest == warm_snapshot_intent_digest(body)?,
        "Warm snapshot intent digest changed"
    );
    Ok(())
}

fn validate_warm_snapshot_manifest_internal(manifest: &WarmSnapshotManifest) -> Result<()> {
    let body = &manifest.body;
    anyhow::ensure!(
        body.version == STEP_VERSION
            && body.binding.operation_id == manifest.evidence.snapshot_operation_id
            && body.binding.request_fingerprint == manifest.evidence.snapshot_request_fingerprint
            && body.content_directory_name
                == format!(
                    "{}{WARM_SNAPSHOT_CONTENT_SUFFIX}",
                    warm_snapshot_key(&body.binding)
                )
            && body.snapshot_intent_digest == manifest.evidence.snapshot_intent_digest
            && body.snapshot_tree.regular_file_count > 0
            && body.memory_file.size_bytes > 0,
        "Warm snapshot manifest has an invalid closed shape"
    );
    let digest = warm_snapshot_manifest_digest(body)?;
    anyhow::ensure!(
        manifest.evidence.snapshot_manifest_digest == digest,
        "Warm snapshot manifest digest changed"
    );
    validate_snapshot_evidence(
        &body.binding,
        &body.runtime,
        &body.write_fence,
        &body.paused,
        &body.drained_volumes,
        &manifest.evidence,
    )
}

fn validate_warm_terminal_manifest_internal(manifest: &WarmTerminalManifest) -> Result<()> {
    let body = &manifest.body;
    anyhow::ensure!(
        body.version == STEP_VERSION
            && body.binding.version == STEP_VERSION
            && body.source_runtime_incarnation.as_str().len() == 32
            && body.snapshot_intent_digest == body.prepared_snapshot.snapshot_intent_digest
            && body.prepared_snapshot.snapshot_manifest_digest.as_bytes() != &[0; 32]
            && body
                .drained_volumes
                .windows(2)
                .all(|pair| pair[0].volume_id < pair[1].volume_id)
            && receipts_are_remote(&body.drained_volumes),
        "Warm terminal manifest has an invalid closed shape"
    );
    anyhow::ensure!(
        body.warm_receipt_digest
            == warm_ready_receipt_digest_for_binding(
                &body.binding,
                &body.prepared_snapshot,
                &body.execution_absence,
                &body.drained_volumes,
            )?,
        "Warm terminal receipt digest changed"
    );
    anyhow::ensure!(
        manifest.terminal_manifest_digest == warm_terminal_manifest_digest(body)?,
        "Warm terminal manifest digest changed"
    );
    Ok(())
}

fn publish_warm_snapshot_intent(namespace: &File, intent: &WarmSnapshotIntent) -> Result<()> {
    validate_warm_snapshot_intent_internal(intent)?;
    let bytes = serde_json::to_vec(intent).context("encode Warm snapshot intent")?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= WARM_SNAPSHOT_MANIFEST_MAX_BYTES,
        "Warm snapshot intent exceeds its closed byte bound"
    );
    let target_name = warm_component_name(&intent.body.binding, WARM_SNAPSHOT_INTENT_SUFFIX)?;
    // O_EXCL is the no-replace publication boundary. A crash during this small
    // write may leave an invalid intent file, but no snapshot/content effect
    // has happened yet and replay quarantines rather than repairing it.
    let mut target = openat_file(
        namespace,
        &target_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o600,
    )?;
    target
        .write_all(&bytes)
        .context("write no-replace Warm snapshot intent")?;
    target.sync_all().context("fsync Warm snapshot intent")?;
    namespace
        .sync_all()
        .context("fsync Warm snapshot intent namespace")
}

fn publish_warm_snapshot_manifest(
    namespace: &File,
    binding: &StepBinding,
    manifest: &WarmSnapshotManifest,
) -> Result<()> {
    validate_warm_snapshot_manifest_internal(manifest)?;
    let bytes = serde_json::to_vec(manifest).context("encode Warm snapshot manifest")?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= WARM_SNAPSHOT_MANIFEST_MAX_BYTES,
        "Warm snapshot manifest exceeds its closed byte bound"
    );
    let key = warm_snapshot_key(binding);
    let temp_name = CString::new(format!("{key}{WARM_SNAPSHOT_TEMP_SUFFIX}"))
        .context("Warm snapshot temp name contains NUL")?;
    let target_name = CString::new(format!("{key}{WARM_SNAPSHOT_MANIFEST_SUFFIX}"))
        .context("Warm snapshot target name contains NUL")?;
    let mut temp = openat_file(
        namespace,
        &temp_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o600,
    )?;
    temp.write_all(&bytes)
        .context("write Warm snapshot manifest temp")?;
    temp.sync_all()
        .context("fsync Warm snapshot manifest temp")?;
    renameat(namespace, &temp_name, &target_name)?;
    namespace
        .sync_all()
        .context("fsync Warm snapshot manifest namespace")
}

fn publish_warm_terminal_manifest(
    namespace: &File,
    binding: &StepBinding,
    manifest: &WarmTerminalManifest,
) -> Result<()> {
    validate_warm_terminal_manifest_internal(manifest)?;
    let bytes = serde_json::to_vec(manifest).context("encode Warm terminal manifest")?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= WARM_SNAPSHOT_MANIFEST_MAX_BYTES,
        "Warm terminal manifest exceeds its closed byte bound"
    );
    let key = warm_snapshot_key(binding);
    let temp_name = CString::new(format!("{key}{WARM_TERMINAL_TEMP_SUFFIX}"))
        .context("Warm terminal temp name contains NUL")?;
    let target_name = CString::new(format!("{key}{WARM_TERMINAL_MANIFEST_SUFFIX}"))
        .context("Warm terminal target name contains NUL")?;
    let mut temp = openat_file(
        namespace,
        &temp_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o600,
    )?;
    temp.write_all(&bytes)
        .context("write Warm terminal manifest temp")?;
    temp.sync_all()
        .context("fsync Warm terminal manifest temp")?;
    renameat(namespace, &temp_name, &target_name)?;
    namespace
        .sync_all()
        .context("fsync Warm terminal manifest namespace")
}

fn verify_snapshot_payload(
    physical: &InstalledPhysicalInspectionConfig,
    manifest: &WarmSnapshotManifest,
    deadline: Instant,
) -> Result<()> {
    verify_snapshot_payload_and_runtime(physical, manifest, deadline).map(|_| ())
}

fn verify_snapshot_payload_and_runtime(
    physical: &InstalledPhysicalInspectionConfig,
    manifest: &WarmSnapshotManifest,
    deadline: Instant,
) -> Result<InstalledRuntimeManifest> {
    let namespace = open_warm_snapshot_namespace(&physical.state_directory, false)?
        .context("Warm snapshot namespace disappeared")?;
    let content_name = CString::new(manifest.body.content_directory_name.clone())
        .context("Warm snapshot content name contains NUL")?;
    let content = openat_directory(&namespace, &content_name)
        .context("reopen Warm snapshot content directory")?;
    let actual_tree = snapshot_tree_proof_from_manifest(&content, &manifest.body, deadline, false)?;
    anyhow::ensure!(
        actual_tree == manifest.body.snapshot_tree,
        "Warm snapshot tree digest changed"
    );
    let installed =
        load_installed_runtime_manifest(&physical.state_directory, &manifest.body.cat_id)?
            .context("Warm snapshot installed Runtime manifest disappeared")?;
    anyhow::ensure!(
        installed.manifest_digest == manifest.body.installed_runtime_manifest_digest,
        "Warm snapshot installed Runtime manifest changed"
    );
    let actual_memory = memory_file_proof_from_state_path(
        &physical.state_directory,
        Path::new(manifest.body.memory_file.path.as_str()),
        manifest.body.memory_file.size_bytes,
        deadline,
        false,
    )?;
    anyhow::ensure!(
        actual_memory == manifest.body.memory_file,
        "Warm snapshot memory backing changed"
    );
    Ok(installed)
}

/// Enumerate the complete two-phase Warm namespace without consulting the
/// lifecycle journal. A terminal entry is emitted only after its terminal
/// manifest, referenced pre-Stop manifest, snapshot tree, and memory backing
/// all re-open exactly. Prepared-only bundles remain retained data; unknown,
/// partial, corrupt, or temporary entries are quarantined and never upgraded
/// to Warm by observation.
pub(crate) fn enumerate_installed_warm_snapshot_artifacts(
    physical: &InstalledPhysicalInspectionConfig,
    deadline: Instant,
) -> Result<Vec<InstalledWarmSnapshotInventoryEntry>> {
    let Some(namespace) = open_warm_snapshot_namespace(&physical.state_directory, false)? else {
        return Ok(Vec::new());
    };
    let names = warm_directory_entry_names(&namespace, deadline)?;
    let mut groups: BTreeMap<Vec<u8>, WarmArtifactGroup> = BTreeMap::new();
    let mut projected = Vec::new();
    for raw_name in names {
        let Some((key, component)) = split_warm_artifact_name(&raw_name) else {
            projected.push((
                raw_name.clone(),
                quarantined_warm_inventory_entry(&namespace, &raw_name)?,
            ));
            continue;
        };
        groups.entry(key).or_default().set(component, raw_name);
    }

    for (raw_key, group) in groups {
        anyhow::ensure!(
            Instant::now() < deadline,
            "Warm artifact inventory deadline elapsed"
        );
        let group_names = group.names();
        let quarantine = || quarantined_warm_inventory_entries(&namespace, &group_names);
        let Some(intent_name) = group.intent.as_ref() else {
            projected.push((raw_key, quarantine()?));
            continue;
        };
        let intent_name_c =
            CString::new(intent_name.clone()).context("Warm intent name contains NUL")?;
        let intent = match openat_file_optional(
            &namespace,
            &intent_name_c,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )? {
            Some(file) => match read_warm_snapshot_intent_file(file)? {
                SnapshotIntentRead::Exact(intent) => intent,
                SnapshotIntentRead::Absent
                | SnapshotIntentRead::Invalid
                | SnapshotIntentRead::Unavailable => {
                    projected.push((raw_key, quarantine()?));
                    continue;
                }
            },
            None => {
                projected.push((raw_key, quarantine()?));
                continue;
            }
        };
        let key = warm_snapshot_key(&intent.body.binding);
        if raw_key.as_slice() != key.as_bytes()
            || intent_name.as_slice() != format!("{key}{WARM_SNAPSHOT_INTENT_SUFFIX}").as_bytes()
        {
            projected.push((raw_key, quarantine()?));
            continue;
        }
        let content_observation = match intent_content_observation(&namespace, &group, &intent)? {
            Some(observation) => observation,
            None => {
                projected.push((raw_key, quarantine()?));
                continue;
            }
        };
        let intent_artifact = intent_warm_inventory_artifact(&intent, content_observation);

        let Some(prepared_name) = group.prepared.as_ref() else {
            // A terminal publication (or its temp) cannot precede a prepared
            // payload. Snapshot-temp/content residue is nevertheless exactly
            // command-owned by the durable intent and remains non-executable.
            if group.terminal.is_some() || group.terminal_temp.is_some() {
                projected.push((raw_key, quarantine()?));
            } else {
                projected.push((
                    raw_key,
                    InstalledWarmSnapshotInventoryEntry::RetainedIntent(Box::new(intent_artifact)),
                ));
            }
            continue;
        };
        if group.prepared_temp.is_some() {
            projected.push((raw_key, quarantine()?));
            continue;
        }
        let prepared_name_c =
            CString::new(prepared_name.clone()).context("Warm prepared name contains NUL")?;
        let prepared = match openat_file_optional(
            &namespace,
            &prepared_name_c,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )? {
            Some(file) => match read_warm_snapshot_file(file)? {
                SnapshotManifestRead::Exact(prepared) => prepared,
                SnapshotManifestRead::Absent
                | SnapshotManifestRead::Invalid
                | SnapshotManifestRead::Unavailable => {
                    projected.push((raw_key, quarantine()?));
                    continue;
                }
            },
            None => {
                projected.push((raw_key, quarantine()?));
                continue;
            }
        };
        if prepared_name.as_slice() != format!("{key}{WARM_SNAPSHOT_MANIFEST_SUFFIX}").as_bytes()
            || !intent_closes_prepared(&intent, &prepared)
        {
            projected.push((raw_key, quarantine()?));
            continue;
        }
        if let Err(error) = verify_snapshot_payload(physical, &prepared, deadline) {
            if Instant::now() >= deadline {
                return Err(error).context("Warm prepared artifact inventory deadline elapsed");
            }
            projected.push((raw_key, quarantine()?));
            continue;
        }
        let prepared_artifact = prepared_warm_inventory_artifact(&prepared);
        let Some(terminal_name) = group.terminal.as_ref() else {
            projected.push((
                raw_key,
                InstalledWarmSnapshotInventoryEntry::RetainedPrepared(Box::new(prepared_artifact)),
            ));
            continue;
        };
        if group.terminal_temp.is_some() {
            projected.push((raw_key, quarantine()?));
            continue;
        }
        let terminal_name_c =
            CString::new(terminal_name.clone()).context("Warm terminal name contains NUL")?;
        let terminal = match openat_file_optional(
            &namespace,
            &terminal_name_c,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )? {
            Some(file) => match read_warm_terminal_file(file)? {
                TerminalManifestRead::Exact(terminal) => terminal,
                TerminalManifestRead::Absent
                | TerminalManifestRead::Invalid
                | TerminalManifestRead::Unavailable => {
                    projected.push((raw_key, quarantine()?));
                    continue;
                }
            },
            None => {
                projected.push((raw_key, quarantine()?));
                continue;
            }
        };
        if terminal_name.as_slice() != format!("{key}{WARM_TERMINAL_MANIFEST_SUFFIX}").as_bytes()
            || !terminal_closes_prepared(&terminal, &prepared)
        {
            projected.push((raw_key, quarantine()?));
            continue;
        }
        projected.push((
            raw_key,
            InstalledWarmSnapshotInventoryEntry::Terminal(Box::new(
                InstalledWarmSnapshotArtifact {
                    source_operation_id: terminal.body.binding.operation_id.clone(),
                    source_request_fingerprint: terminal.body.binding.request_fingerprint.clone(),
                    prepared_operation_id: prepared.body.binding.operation_id.clone(),
                    prepared_request_fingerprint: prepared.body.binding.request_fingerprint.clone(),
                    workspace_id: terminal.body.workspace_id.clone(),
                    cat_id: terminal.body.cat_id.clone(),
                    node_id: terminal.body.node_id.clone(),
                    placement_identity: terminal.body.placement_identity.clone(),
                    runtime_config_id: terminal.body.runtime_config_id.clone(),
                    runtime_config_digest: terminal.body.runtime_config_digest.clone(),
                    source_runtime_incarnation: terminal.body.source_runtime_incarnation.clone(),
                    terminal_manifest_digest: terminal.terminal_manifest_digest.clone(),
                    warm_receipt_digest: terminal.body.warm_receipt_digest.clone(),
                    intent_manifest_digest: prepared_artifact.intent_manifest_digest.clone(),
                    prepared_manifest_digest: prepared_artifact.prepared_manifest_digest.clone(),
                    snapshot_receipt_digest: prepared_artifact.snapshot_receipt_digest.clone(),
                    execution_absence: terminal.body.execution_absence.clone(),
                    retained_volume_receipts: terminal.body.drained_volumes.clone(),
                    snapshot_tree_digest: prepared_artifact.snapshot_tree_digest.clone(),
                    memory_file_digest: prepared_artifact.memory_file_digest.clone(),
                },
            )),
        ));
    }
    projected.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(projected.into_iter().map(|(_, entry)| entry).collect())
}

#[derive(Default)]
struct WarmArtifactGroup {
    intent: Option<Vec<u8>>,
    content: Option<Vec<u8>>,
    prepared_temp: Option<Vec<u8>>,
    prepared: Option<Vec<u8>>,
    terminal_temp: Option<Vec<u8>>,
    terminal: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
enum WarmArtifactComponent {
    Intent,
    Content,
    PreparedTemp,
    Prepared,
    TerminalTemp,
    Terminal,
}

impl WarmArtifactGroup {
    fn set(&mut self, component: WarmArtifactComponent, name: Vec<u8>) {
        let slot = match component {
            WarmArtifactComponent::Intent => &mut self.intent,
            WarmArtifactComponent::Content => &mut self.content,
            WarmArtifactComponent::PreparedTemp => &mut self.prepared_temp,
            WarmArtifactComponent::Prepared => &mut self.prepared,
            WarmArtifactComponent::TerminalTemp => &mut self.terminal_temp,
            WarmArtifactComponent::Terminal => &mut self.terminal,
        };
        debug_assert!(slot.is_none(), "directory entry names are unique");
        *slot = Some(name);
    }

    fn names(&self) -> Vec<&[u8]> {
        let mut names = [
            self.intent.as_deref(),
            self.content.as_deref(),
            self.prepared_temp.as_deref(),
            self.prepared.as_deref(),
            self.terminal_temp.as_deref(),
            self.terminal.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        names.sort();
        names
    }
}

fn split_warm_artifact_name(raw_name: &[u8]) -> Option<(Vec<u8>, WarmArtifactComponent)> {
    for (suffix, component) in [
        (WARM_SNAPSHOT_INTENT_SUFFIX, WarmArtifactComponent::Intent),
        (WARM_SNAPSHOT_CONTENT_SUFFIX, WarmArtifactComponent::Content),
        (
            WARM_SNAPSHOT_TEMP_SUFFIX,
            WarmArtifactComponent::PreparedTemp,
        ),
        (
            WARM_SNAPSHOT_MANIFEST_SUFFIX,
            WarmArtifactComponent::Prepared,
        ),
        (
            WARM_TERMINAL_TEMP_SUFFIX,
            WarmArtifactComponent::TerminalTemp,
        ),
        (
            WARM_TERMINAL_MANIFEST_SUFFIX,
            WarmArtifactComponent::Terminal,
        ),
    ] {
        if raw_name.len() > suffix.len() && raw_name.ends_with(suffix.as_bytes()) {
            return Some((
                raw_name[..raw_name.len() - suffix.len()].to_vec(),
                component,
            ));
        }
    }
    None
}

fn intent_content_observation(
    namespace: &File,
    group: &WarmArtifactGroup,
    intent: &WarmSnapshotIntent,
) -> Result<Option<InstalledWarmIntentContentObservation>> {
    let Some(raw_name) = group.content.as_ref() else {
        return Ok(Some(InstalledWarmIntentContentObservation::Absent));
    };
    if raw_name.as_slice() != intent.body.plan.content_directory_name.as_bytes() {
        return Ok(None);
    }
    let name = CString::new(raw_name.clone()).context("Warm content name contains NUL")?;
    let Some(stat) = fstatat_nofollow(namespace, &name)? else {
        return Ok(None);
    };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Ok(None);
    }
    let content = openat_directory(namespace, &name)?;
    let namespace_identity = directory_identity(namespace)?;
    let content_identity = directory_identity(&content)?;
    if content_identity.device != namespace_identity.device || content_identity.inode == 0 {
        return Ok(None);
    }
    let metadata = content
        .metadata()
        .context("inspect retained Warm content")?;
    let mut evidence = Vec::new();
    evidence.extend_from_slice(intent.intent_digest.as_bytes());
    evidence.extend_from_slice(intent.body.plan_digest.as_bytes());
    evidence.extend_from_slice(&(raw_name.len() as u64).to_be_bytes());
    evidence.extend_from_slice(raw_name);
    evidence.extend_from_slice(&metadata.dev().to_be_bytes());
    evidence.extend_from_slice(&metadata.ino().to_be_bytes());
    evidence.extend_from_slice(&metadata.mode().to_be_bytes());
    evidence.extend_from_slice(&metadata.nlink().to_be_bytes());
    evidence.extend_from_slice(&metadata.len().to_be_bytes());
    evidence.extend_from_slice(&metadata.mtime().to_be_bytes());
    evidence.extend_from_slice(&metadata.mtime_nsec().to_be_bytes());
    Ok(Some(InstalledWarmIntentContentObservation::Present {
        evidence_digest: digest_parts(
            b"cats.atomic-lifecycle.warm-intent-content-observation.v1",
            &[&evidence],
        ),
    }))
}

fn intent_warm_inventory_artifact(
    intent: &WarmSnapshotIntent,
    content_observation: InstalledWarmIntentContentObservation,
) -> InstalledWarmSnapshotIntentArtifact {
    InstalledWarmSnapshotIntentArtifact {
        source_operation_id: intent.body.binding.operation_id.clone(),
        source_request_fingerprint: intent.body.binding.request_fingerprint.clone(),
        workspace_id: intent.body.workspace_id.clone(),
        cat_id: intent.body.cat_id.clone(),
        node_id: intent.body.node_id.clone(),
        placement_identity: intent.body.placement_identity.clone(),
        runtime_config_id: intent.body.runtime_config_id.clone(),
        runtime_config_digest: intent.body.runtime_config_digest.clone(),
        source_runtime_incarnation: intent.body.source_runtime_incarnation.clone(),
        intent_manifest_digest: intent.intent_digest.clone(),
        snapshot_plan_digest: intent.body.plan_digest.clone(),
        retained_volume_receipts: intent.body.drained_volumes.clone(),
        content_observation,
    }
}

fn prepared_warm_inventory_artifact(
    manifest: &WarmSnapshotManifest,
) -> InstalledPreparedWarmSnapshotArtifact {
    InstalledPreparedWarmSnapshotArtifact {
        source_operation_id: manifest.body.binding.operation_id.clone(),
        source_request_fingerprint: manifest.body.binding.request_fingerprint.clone(),
        workspace_id: manifest.body.workspace_id.clone(),
        cat_id: manifest.body.cat_id.clone(),
        node_id: manifest.body.node_id.clone(),
        placement_identity: manifest.body.placement_identity.clone(),
        runtime_config_id: manifest.body.runtime_config_id.clone(),
        runtime_config_digest: manifest.body.runtime_config_digest.clone(),
        source_runtime_incarnation: manifest.body.runtime.runtime_incarnation.clone(),
        intent_manifest_digest: manifest.body.snapshot_intent_digest.clone(),
        prepared_manifest_digest: manifest.evidence.snapshot_manifest_digest.clone(),
        snapshot_receipt_digest: manifest.evidence.snapshot_receipt_digest.clone(),
        retained_volume_receipts: manifest.body.drained_volumes.clone(),
        snapshot_tree_digest: manifest.body.snapshot_tree.digest.clone(),
        memory_file_digest: manifest.body.memory_file.digest.clone(),
    }
}

fn intent_closes_prepared(intent: &WarmSnapshotIntent, prepared: &WarmSnapshotManifest) -> bool {
    intent.body.binding == prepared.body.binding
        && intent.body.workspace_id == prepared.body.workspace_id
        && intent.body.cat_id == prepared.body.cat_id
        && intent.body.node_id == prepared.body.node_id
        && intent.body.placement_identity == prepared.body.placement_identity
        && intent.body.runtime_config_id == prepared.body.runtime_config_id
        && intent.body.runtime_config_digest == prepared.body.runtime_config_digest
        && intent.body.source_runtime_incarnation == prepared.body.runtime.runtime_incarnation
        && intent.body.runtime_physical_identity_digest
            == prepared.body.runtime.physical_identity_digest
        && intent.body.write_fence_receipt_digest
            == *write_fence_receipt_digest(&prepared.body.write_fence)
        && intent.body.pause_receipt_digest == prepared.body.paused.pause_receipt_digest
        && intent.body.drained_volumes == prepared.body.drained_volumes
        && intent.intent_digest == prepared.body.snapshot_intent_digest
        && intent.intent_digest == prepared.evidence.snapshot_intent_digest
        && intent.body.plan.installed_runtime_manifest_digest
            == prepared.body.installed_runtime_manifest_digest
        && intent.body.plan.content_directory_name == prepared.body.content_directory_name
        && intent.body.plan.memory_file_path == prepared.body.memory_file.path
}

fn terminal_closes_prepared(
    terminal: &WarmTerminalManifest,
    prepared: &WarmSnapshotManifest,
) -> bool {
    terminal.body.binding == prepared.body.binding
        && terminal.body.workspace_id == prepared.body.workspace_id
        && terminal.body.cat_id == prepared.body.cat_id
        && terminal.body.node_id == prepared.body.node_id
        && terminal.body.placement_identity == prepared.body.placement_identity
        && terminal.body.runtime_config_id == prepared.body.runtime_config_id
        && terminal.body.runtime_config_digest == prepared.body.runtime_config_digest
        && terminal.body.source_runtime_incarnation == prepared.body.runtime.runtime_incarnation
        && terminal.body.snapshot_intent_digest == prepared.body.snapshot_intent_digest
        && terminal.body.prepared_snapshot == prepared.evidence
        && terminal.body.drained_volumes == prepared.body.drained_volumes
        && closed_remote_receipts(&terminal.body.drained_volumes)
}

fn closed_remote_receipts(receipts: &[VolumeTerminalReceipt]) -> bool {
    receipts
        .windows(2)
        .all(|pair| pair[0].volume_id < pair[1].volume_id)
        && receipts_are_remote(receipts)
}

fn quarantined_warm_inventory_entry(
    namespace: &File,
    raw_name: &[u8],
) -> Result<InstalledWarmSnapshotInventoryEntry> {
    quarantined_warm_inventory_entries(namespace, &[raw_name])
}

fn quarantined_warm_inventory_entries(
    namespace: &File,
    raw_names: &[&[u8]],
) -> Result<InstalledWarmSnapshotInventoryEntry> {
    let mut evidence = Vec::new();
    for raw_name in raw_names {
        evidence.extend_from_slice(&(raw_name.len() as u64).to_be_bytes());
        evidence.extend_from_slice(raw_name);
        let name = CString::new(*raw_name).context("Warm residue name contains NUL")?;
        if let Some(stat) = fstatat_nofollow(namespace, &name)? {
            evidence.extend_from_slice(&i128::from(stat.st_dev).to_be_bytes());
            evidence.extend_from_slice(&i128::from(stat.st_ino).to_be_bytes());
            evidence.extend_from_slice(&u64::from(stat.st_mode).to_be_bytes());
            evidence.extend_from_slice(&i128::from(stat.st_size).to_be_bytes());
        }
    }
    Ok(InstalledWarmSnapshotInventoryEntry::Quarantined {
        artifact_id: artifact_id("warm-snapshot-residue", &evidence)?,
        evidence_digest: digest_parts(
            b"cats.atomic-lifecycle.warm-inventory-quarantine.v1",
            &[&evidence],
        ),
    })
}

fn snapshot_tree_proof(
    directory: &File,
    command: &LifecycleCommandEnvelope,
    deadline: Instant,
    sync: bool,
) -> Result<WarmSnapshotTreeProof> {
    let maximum_bytes = command
        .runtime_config
        .memory_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(1_u64 << 30))
        .context("Warm snapshot tree byte bound overflow")?;
    hash_directory_tree(directory, maximum_bytes, deadline, sync)
}

fn snapshot_tree_proof_from_manifest(
    directory: &File,
    body: &WarmSnapshotManifestBody,
    deadline: Instant,
    sync: bool,
) -> Result<WarmSnapshotTreeProof> {
    let maximum_bytes = body
        .memory_file
        .size_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(1_u64 << 30))
        .context("Warm snapshot verification byte bound overflow")?;
    hash_directory_tree(directory, maximum_bytes, deadline, sync)
}

fn memory_file_proof(
    physical: &InstalledPhysicalInspectionConfig,
    installed: &InstalledRuntimeManifest,
    command: &LifecycleCommandEnvelope,
    deadline: Instant,
    sync: bool,
) -> Result<WarmMemoryFileProof> {
    memory_file_proof_from_state_path(
        &physical.state_directory,
        Path::new(installed.vmm.memory_file_path.as_str()),
        command.runtime_config.memory_bytes,
        deadline,
        sync,
    )
}

fn memory_file_proof_from_state_path(
    state: &crate::state_directory::StateDirectory,
    path: &Path,
    expected_size: u64,
    deadline: Instant,
    sync: bool,
) -> Result<WarmMemoryFileProof> {
    let Some((parent, name)) = open_state_descendant_parent(state, path)? else {
        anyhow::bail!("Warm memory backing parent is absent")
    };
    let parent_identity = directory_identity(&parent)?;
    let Some(file) = openat_file_optional(
        &parent,
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?
    else {
        anyhow::bail!("Warm memory backing is absent")
    };
    let path = cats_api::runtime_reconciliation::HostPath::new(
        path.as_os_str()
            .to_str()
            .context("Warm memory path is not UTF-8")?,
    )
    .context("Warm memory path is not an absolute normalized HostPath")?;
    let proof = memory_file_proof_from_open_file(file, path, expected_size, deadline, sync)?;
    let Some(current) = fstatat_nofollow(&parent, &name)? else {
        anyhow::bail!("Warm memory backing disappeared after hashing")
    };
    anyhow::ensure!(
        directory_identity(&parent)? == parent_identity
            && current.st_mode & libc::S_IFMT == libc::S_IFREG
            && current.st_nlink == 1
            && stat_identity(&current)?
                == (WarmCleanupObjectIdentity {
                    device: proof.device,
                    inode: proof.inode,
                })
            && u64::try_from(current.st_size).ok() == Some(proof.size_bytes),
        "Warm memory backing path changed after hashing"
    );
    Ok(proof)
}

#[cfg(all(test, target_os = "linux"))]
fn memory_file_proof_from_path(
    path: &Path,
    expected_size: u64,
    deadline: Instant,
    sync: bool,
) -> Result<WarmMemoryFileProof> {
    let name = CString::new(path.as_os_str().as_bytes()).context("memory path contains NUL")?;
    // SAFETY: `name` is a valid NUL-terminated path and open retains no Rust
    // pointers. A successful descriptor transfers into File exactly once.
    let descriptor = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error()).context("open Warm memory backing");
    }
    // SAFETY: open returned one uniquely owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let path = cats_api::runtime_reconciliation::HostPath::new(
        path.as_os_str()
            .to_str()
            .context("Warm memory path is not UTF-8")?,
    )
    .context("Warm memory path is not an absolute normalized HostPath")?;
    memory_file_proof_from_open_file(file, path, expected_size, deadline, sync)
}

fn memory_file_proof_from_open_file(
    mut file: File,
    path: cats_api::runtime_reconciliation::HostPath,
    expected_size: u64,
    deadline: Instant,
    sync: bool,
) -> Result<WarmMemoryFileProof> {
    anyhow::ensure!(
        Instant::now() < deadline,
        "Warm memory proof deadline elapsed"
    );
    let before = file.metadata().context("inspect Warm memory backing")?;
    anyhow::ensure!(
        before.file_type().is_file()
            && before.nlink() == 1
            && before.len() == expected_size
            && before.ino() > 0,
        "Warm memory backing shape changed"
    );
    if sync {
        file.sync_all().context("fsync Warm memory backing")?;
    }
    let digest = hash_regular_file(&mut file, WARM_MEMORY_FILE_DOMAIN, expected_size, deadline)?;
    let after = file.metadata().context("reinspect Warm memory backing")?;
    anyhow::ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "Warm memory backing changed while hashing"
    );
    Ok(WarmMemoryFileProof {
        path,
        device: before.dev(),
        inode: before.ino(),
        size_bytes: before.len(),
        digest,
    })
}

fn hash_regular_file(
    file: &mut File,
    domain: &[u8],
    expected_size: u64,
    deadline: Instant,
) -> Result<Sha256Digest> {
    file.rewind().context("rewind file for Warm hash")?;
    let mut hash = Sha256::new();
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    hash.update(expected_size.to_be_bytes());
    let mut remaining = expected_size;
    let mut buffer = vec![0_u8; 1024 * 1024].into_boxed_slice();
    while remaining > 0 {
        anyhow::ensure!(Instant::now() < deadline, "Warm file hash deadline elapsed");
        let maximum = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded read size fits usize");
        let count = file
            .read(&mut buffer[..maximum])
            .context("read Warm snapshot file")?;
        anyhow::ensure!(count > 0, "Warm snapshot file ended before its exact size");
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut extra = [0_u8; 1];
    anyhow::ensure!(
        file.read(&mut extra).context("probe Warm file EOF")? == 0,
        "Warm snapshot file grew while hashing"
    );
    Ok(Sha256Digest::from_bytes(hash.finalize().into()))
}

fn hash_directory_tree(
    root: &File,
    maximum_bytes: u64,
    deadline: Instant,
    sync: bool,
) -> Result<WarmSnapshotTreeProof> {
    let mut entries = Vec::new();
    collect_tree_entries(root, Vec::new(), &mut entries, deadline)?;
    anyhow::ensure!(
        !entries.is_empty() && entries.len() <= WARM_SNAPSHOT_MAX_FILES,
        "Warm snapshot tree is empty or exceeds its file bound"
    );
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hash = Sha256::new();
    hash.update((WARM_SNAPSHOT_TREE_DOMAIN.len() as u64).to_be_bytes());
    hash.update(WARM_SNAPSHOT_TREE_DOMAIN);
    let mut regular_file_count = 0_u32;
    let mut total_file_bytes = 0_u64;
    for (relative, mut file, metadata) in entries {
        anyhow::ensure!(Instant::now() < deadline, "Warm tree hash deadline elapsed");
        hash.update((relative.len() as u64).to_be_bytes());
        hash.update(&relative);
        hash.update(metadata.mode().to_be_bytes());
        hash.update(metadata.len().to_be_bytes());
        if metadata.file_type().is_dir() {
            hash.update(b"directory");
            if sync {
                file.sync_all().context("fsync Warm snapshot directory")?;
            }
            continue;
        }
        anyhow::ensure!(
            metadata.file_type().is_file() && metadata.nlink() == 1,
            "Warm snapshot tree contains a non-regular or linked file"
        );
        regular_file_count = regular_file_count
            .checked_add(1)
            .context("Warm snapshot file count overflow")?;
        total_file_bytes = total_file_bytes
            .checked_add(metadata.len())
            .context("Warm snapshot byte count overflow")?;
        anyhow::ensure!(
            total_file_bytes <= maximum_bytes,
            "Warm snapshot tree exceeds its byte bound"
        );
        if sync {
            file.sync_all().context("fsync Warm snapshot file")?;
        }
        let file_digest = hash_regular_file(
            &mut file,
            b"cats.atomic-lifecycle.warm-tree-file.v1",
            metadata.len(),
            deadline,
        )?;
        hash.update(file_digest.as_bytes());
        let after = file.metadata().context("reinspect Warm snapshot file")?;
        anyhow::ensure!(
            metadata.dev() == after.dev()
                && metadata.ino() == after.ino()
                && metadata.len() == after.len()
                && metadata.mtime() == after.mtime()
                && metadata.mtime_nsec() == after.mtime_nsec(),
            "Warm snapshot file changed while hashing"
        );
    }
    if sync {
        root.sync_all()
            .context("fsync Warm snapshot content root")?;
    }
    anyhow::ensure!(
        regular_file_count > 0,
        "Warm snapshot contains no state file"
    );
    Ok(WarmSnapshotTreeProof {
        digest: Sha256Digest::from_bytes(hash.finalize().into()),
        regular_file_count,
        total_file_bytes,
    })
}

#[cfg(target_os = "linux")]
fn collect_tree_entries(
    directory: &File,
    prefix: Vec<u8>,
    entries: &mut Vec<(Vec<u8>, File, std::fs::Metadata)>,
    deadline: Instant,
) -> Result<()> {
    anyhow::ensure!(
        Instant::now() < deadline,
        "Warm tree enumeration deadline elapsed"
    );
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let mut names = std::fs::read_dir(&proc_path)
        .context("enumerate descriptor-retained Warm snapshot directory")?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    for name in names {
        anyhow::ensure!(
            entries.len() < WARM_SNAPSHOT_MAX_FILES,
            "Warm snapshot tree exceeds its entry bound"
        );
        let name_bytes = name.as_bytes();
        anyhow::ensure!(
            !name_bytes.is_empty()
                && name_bytes != b"."
                && name_bytes != b".."
                && !name_bytes.contains(&0),
            "Warm snapshot tree contains an invalid name"
        );
        let c_name = CString::new(name_bytes).context("Warm snapshot name contains NUL")?;
        let file = openat_file(
            directory,
            &c_name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0,
        )?;
        let metadata = file.metadata().context("inspect Warm snapshot entry")?;
        let mut relative = prefix.clone();
        if !relative.is_empty() {
            relative.push(b'/');
        }
        relative.extend_from_slice(name_bytes);
        if metadata.file_type().is_dir() {
            let child = file
                .try_clone()
                .context("retain Warm snapshot child directory")?;
            entries.push((relative.clone(), file, metadata));
            collect_tree_entries(&child, relative, entries, deadline)?;
        } else {
            entries.push((relative, file, metadata));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn collect_tree_entries(
    _directory: &File,
    _prefix: Vec<u8>,
    _entries: &mut Vec<(Vec<u8>, File, std::fs::Metadata)>,
    _deadline: Instant,
) -> Result<()> {
    anyhow::bail!("descriptor-retained Warm snapshot enumeration requires Linux")
}

fn open_warm_snapshot_namespace(
    state: &crate::state_directory::StateDirectory,
    create: bool,
) -> Result<Option<File>> {
    let root = state
        .try_clone_directory()
        .context("reopen descriptor-retained StateDirectory")?;
    let name = CString::new(WARM_SNAPSHOT_NAMESPACE).expect("fixed namespace has no NUL");
    match openat_directory(&root, &name) {
        Ok(directory) => Ok(Some(directory)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            if !create {
                return Ok(None);
            }
            mkdirat(&root, &name, 0o700).context("create Warm snapshot namespace")?;
            root.sync_all()
                .context("fsync Warm snapshot StateDirectory")?;
            Ok(Some(openat_directory(&root, &name)?))
        }
        Err(error) => Err(error),
    }
}

/// Open the exact parent of one StateDirectory-descendant path without ever
/// resolving a symlink. The returned basename is a single retained component
/// suitable for `openat`/`unlinkat` against the returned parent descriptor.
fn open_state_descendant_parent(
    state: &crate::state_directory::StateDirectory,
    absolute: &Path,
) -> Result<Option<(File, CString)>> {
    let relative = absolute
        .strip_prefix(state.path())
        .context("Warm memory backing is outside the StateDirectory")?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(component) if !component.as_bytes().is_empty() => Ok(component),
            _ => anyhow::bail!("Warm memory backing has a non-normal path component"),
        })
        .collect::<Result<Vec<_>>>()?;
    let (basename, parents) = components
        .split_last()
        .context("Warm memory backing path does not name a file")?;
    let mut parent = state
        .try_clone_directory()
        .context("reopen descriptor-retained StateDirectory for Warm memory")?;
    for component in parents {
        let component = CString::new(component.as_bytes())
            .context("Warm memory parent component contains NUL")?;
        let Some(next) = openat_directory_optional(&parent, &component)? else {
            return Ok(None);
        };
        parent = next;
    }
    let basename =
        CString::new(basename.as_bytes()).context("Warm memory backing basename contains NUL")?;
    Ok(Some((parent, basename)))
}

fn mkdirat(directory: &File, name: &CStr, mode: libc::mode_t) -> Result<()> {
    loop {
        // SAFETY: directory owns a live descriptor and name remains a valid
        // NUL-terminated relative component for the call.
        let result = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), mode) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("mkdirat Warm snapshot component");
        }
    }
}

fn openat_directory(directory: &File, name: &CStr) -> Result<File> {
    openat_file(
        directory,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )
}

fn openat_directory_optional(directory: &File, name: &CStr) -> Result<Option<File>> {
    openat_file_optional(
        directory,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
    )
}

fn openat_file(directory: &File, name: &CStr, flags: i32, mode: u32) -> Result<File> {
    loop {
        // SAFETY: directory owns a live descriptor and name is a retained
        // NUL-terminated relative component. A successful descriptor moves
        // into exactly one File.
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
        if descriptor >= 0 {
            // SAFETY: openat returned one uniquely owned descriptor.
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("openat Warm snapshot component");
        }
    }
}

fn openat_file_optional(directory: &File, name: &CStr, flags: i32) -> Result<Option<File>> {
    match openat_file(directory, name, flags, 0) {
        Ok(file) => Ok(Some(file)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn renameat(directory: &File, source: &CStr, target: &CStr) -> Result<()> {
    loop {
        // SAFETY: all descriptors/names remain live and renameat retains no
        // pointers after the call.
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
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("rename Warm snapshot manifest");
        }
    }
}

fn warm_component_name(binding: &StepBinding, suffix: &str) -> Result<CString> {
    CString::new(format!("{}{suffix}", warm_snapshot_key(binding)))
        .context("Warm artifact component contains NUL")
}

fn regular_single_link_identity(file: &File) -> Result<WarmCleanupObjectIdentity> {
    let metadata = file.metadata().context("inspect Warm regular artifact")?;
    anyhow::ensure!(
        metadata.file_type().is_file() && metadata.nlink() == 1,
        "Warm artifact is not a single-link regular file"
    );
    Ok(WarmCleanupObjectIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn directory_identity(directory: &File) -> Result<WarmCleanupObjectIdentity> {
    let metadata = directory
        .metadata()
        .context("inspect Warm directory artifact")?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "Warm artifact is not a directory"
    );
    Ok(WarmCleanupObjectIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn fstatat_nofollow(directory: &File, name: &CStr) -> Result<Option<libc::stat>> {
    loop {
        // SAFETY: `stat` is initialized by successful fstatat; the descriptor
        // and component remain live, and AT_SYMLINK_NOFOLLOW prevents a
        // corrupt Warm artifact from redirecting classification.
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: `stat` points to writable storage, `name` is a live
        // NUL-terminated component, and `directory` retains its descriptor
        // throughout this call.
        let result = unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                std::ptr::addr_of_mut!(stat),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Ok(Some(stat));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error).context("fstatat Warm artifact");
    }
}

fn stat_identity(stat: &libc::stat) -> Result<WarmCleanupObjectIdentity> {
    Ok(WarmCleanupObjectIdentity {
        device: warm_device_number(stat.st_dev)?,
        inode: stat.st_ino,
    })
}

#[cfg(target_os = "linux")]
fn warm_device_number(device: libc::dev_t) -> Result<u64> {
    Ok(device)
}

#[cfg(not(target_os = "linux"))]
fn warm_device_number(device: libc::dev_t) -> Result<u64> {
    u64::try_from(device).context("Warm artifact device is negative")
}

fn remove_exact_warm_file(
    directory: &File,
    name: &CStr,
    expected: &WarmCleanupObjectIdentity,
    deadline: Instant,
) -> Result<bool> {
    anyhow::ensure!(Instant::now() < deadline, "Warm cleanup deadline elapsed");
    let Some(before) = fstatat_nofollow(directory, name)? else {
        return Ok(true);
    };
    if before.st_mode & libc::S_IFMT != libc::S_IFREG || &stat_identity(&before)? != expected {
        return Ok(false);
    }
    let file = openat_file(
        directory,
        name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    )?;
    if regular_single_link_identity(&file)? != *expected {
        return Ok(false);
    }
    anyhow::ensure!(Instant::now() < deadline, "Warm cleanup deadline elapsed");
    let Some(current) = fstatat_nofollow(directory, name)? else {
        return Ok(false);
    };
    if stat_identity(&current)? != *expected {
        return Ok(false);
    }
    unlinkat_component(directory, name, 0)?;
    Ok(fstatat_nofollow(directory, name)?.is_none())
}

fn remove_exact_warm_directory(
    parent: &File,
    name: &CStr,
    expected: &WarmCleanupObjectIdentity,
    deadline: Instant,
) -> Result<bool> {
    anyhow::ensure!(Instant::now() < deadline, "Warm cleanup deadline elapsed");
    let Some(before) = fstatat_nofollow(parent, name)? else {
        return Ok(true);
    };
    if before.st_mode & libc::S_IFMT != libc::S_IFDIR || &stat_identity(&before)? != expected {
        return Ok(false);
    }
    let directory = openat_directory(parent, name)?;
    if directory_identity(&directory)? != *expected
        || !remove_warm_directory_contents(&directory, expected.device, deadline)?
    {
        return Ok(false);
    }
    anyhow::ensure!(Instant::now() < deadline, "Warm cleanup deadline elapsed");
    let Some(current) = fstatat_nofollow(parent, name)? else {
        return Ok(false);
    };
    if stat_identity(&current)? != *expected {
        return Ok(false);
    }
    unlinkat_component(parent, name, libc::AT_REMOVEDIR)?;
    parent
        .sync_all()
        .context("fsync Warm snapshot directory removal")?;
    Ok(fstatat_nofollow(parent, name)?.is_none())
}

fn remove_warm_directory_contents(
    directory: &File,
    root_device: u64,
    deadline: Instant,
) -> Result<bool> {
    for raw_name in warm_directory_entry_names(directory, deadline)? {
        anyhow::ensure!(Instant::now() < deadline, "Warm cleanup deadline elapsed");
        let name = CString::new(raw_name).context("Warm cleanup entry contains NUL")?;
        let Some(before) = fstatat_nofollow(directory, &name)? else {
            return Ok(false);
        };
        if stat_identity(&before)?.device != root_device {
            return Ok(false);
        }
        match before.st_mode & libc::S_IFMT {
            libc::S_IFREG => {
                let expected = stat_identity(&before)?;
                if !remove_exact_warm_file(directory, &name, &expected, deadline)? {
                    return Ok(false);
                }
            }
            libc::S_IFDIR => {
                let expected = stat_identity(&before)?;
                if !remove_exact_warm_directory(directory, &name, &expected, deadline)? {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }
    directory
        .sync_all()
        .context("fsync descriptor-safe Warm content cleanup")?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn warm_directory_entry_names(directory: &File, deadline: Instant) -> Result<Vec<Vec<u8>>> {
    anyhow::ensure!(
        Instant::now() < deadline,
        "Warm directory enumeration deadline elapsed"
    );
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let mut names = std::fs::read_dir(proc_path)
        .context("enumerate descriptor-retained Warm cleanup directory")?
        .map(|entry| entry.map(|entry| entry.file_name().as_bytes().to_vec()))
        .collect::<std::io::Result<Vec<_>>>()?;
    anyhow::ensure!(
        Instant::now() < deadline,
        "Warm directory enumeration deadline elapsed"
    );
    anyhow::ensure!(
        names.len() <= WARM_SNAPSHOT_MAX_FILES,
        "Warm cleanup directory exceeds its entry bound"
    );
    names.sort();
    anyhow::ensure!(
        names.iter().all(|name| !name.is_empty()
            && name.as_slice() != b"."
            && name.as_slice() != b".."
            && !name.contains(&0)),
        "Warm cleanup directory contains an invalid component"
    );
    Ok(names)
}

#[cfg(not(target_os = "linux"))]
fn warm_directory_entry_names(_directory: &File, _deadline: Instant) -> Result<Vec<Vec<u8>>> {
    anyhow::bail!("descriptor-retained Warm cleanup requires Linux")
}

fn unlinkat_component(directory: &File, name: &CStr, flags: i32) -> Result<()> {
    loop {
        // SAFETY: the descriptor/component remain live for the call and
        // unlinkat retains neither.
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("unlink exact Warm artifact");
        }
    }
}

fn ensure_path_matches_directory(path: &Path, retained: &File) -> Result<()> {
    let lexical = std::fs::symlink_metadata(path)
        .context("reopen lexical Warm snapshot directory without following links")?;
    let retained = retained
        .metadata()
        .context("inspect retained Warm snapshot directory")?;
    anyhow::ensure!(
        lexical.file_type().is_dir()
            && retained.file_type().is_dir()
            && lexical.dev() == retained.dev()
            && lexical.ino() == retained.ino(),
        "Warm snapshot lexical directory changed identity"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StepBinding {
    version: u64,
    operation_id: Id,
    request_fingerprint: Sha256Digest,
}

impl StepBinding {
    fn new(command: &LifecycleCommandEnvelope) -> Self {
        Self {
            version: STEP_VERSION,
            operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
        }
    }

    fn from_response(response: &LifecycleCommandResponse) -> Self {
        Self {
            version: STEP_VERSION,
            operation_id: response.operation_id.clone(),
            request_fingerprint: response.request_fingerprint.clone(),
        }
    }

    fn validate(&self, command: &LifecycleCommandEnvelope) -> Result<()> {
        anyhow::ensure!(
            self.version == STEP_VERSION
                && self.operation_id == command.operation_id
                && self.request_fingerprint == command.request_fingerprint,
            "Suspend/Warm durable step belongs to another command"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum SuspendWarmStepState {
    SuspendAdmission,
    SuspendGuards,
    SuspendDiscover,
    SuspendQuiesce {
        runtime: InstalledRuntimeEvidence,
    },
    SuspendPause {
        runtime: InstalledRuntimeEvidence,
        quiesce: GuestQuiesceEvidence,
    },
    SuspendFailureStop {
        reason: CommandFailureReason,
        retained_volume_receipts: Vec<VolumeTerminalReceipt>,
    },
    WarmAdmission,
    WarmGuards,
    WarmDiscover,
    WarmQuiesce {
        runtime: InstalledRuntimeEvidence,
    },
    WarmDrain {
        runtime: InstalledRuntimeEvidence,
        write_fence: RuntimeWriteFenceEvidence,
    },
    WarmPause {
        runtime: InstalledRuntimeEvidence,
        quiesce: GuestQuiesceEvidence,
        drained_volumes: Vec<VolumeTerminalReceipt>,
    },
    WarmSnapshot {
        runtime: InstalledRuntimeEvidence,
        write_fence: RuntimeWriteFenceEvidence,
        drained_volumes: Vec<VolumeTerminalReceipt>,
        paused: PausedRuntimeEvidence,
    },
    WarmStop {
        runtime: InstalledRuntimeEvidence,
        write_fence: RuntimeWriteFenceEvidence,
        paused: PausedRuntimeEvidence,
        drained_volumes: Vec<VolumeTerminalReceipt>,
        snapshot: Box<WarmSnapshotEvidence>,
        recovery_predecessor: Option<Box<WarmRecoveryPredecessorEvidence>>,
    },
    WarmFailureStop {
        outcome: WarmFailureOutcome,
        retained_volume_receipts: Vec<VolumeTerminalReceipt>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WarmFailureOutcome {
    Failed { reason: CommandFailureReason },
    NeedsIntervention { reason: InterventionReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SuspendWarmStepPayload {
    binding: StepBinding,
    state: SuspendWarmStepState,
}

pub(super) fn plan(
    _ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    inherited_stop_fence: bool,
) -> Result<PlannedLifecycleEffect> {
    let predecessor = predecessor.context("Suspend/Warm lacks its exact same-Node predecessor")?;
    validate_predecessor_response(command, predecessor)?;
    match command.command {
        LifecycleCommand::Suspend(_) => {
            anyhow::ensure!(
                !inherited_stop_fence,
                "Suspend cannot inherit a predecessor Stop fence"
            );
            validate_suspend_source(command, predecessor)?;
            planned_unfenced(command, SuspendWarmStepState::SuspendAdmission)
        }
        LifecycleCommand::Warm(_) => {
            validate_warm_source(command, predecessor)?;
            let step = encode_step(command, SuspendWarmStepState::WarmAdmission)?;
            if inherited_stop_fence {
                Ok(PlannedLifecycleEffect::inherit_stop_fence(step))
            } else {
                Ok(PlannedLifecycleEffect::install_stop_fence(
                    step,
                    stop_fence_payload(command)?,
                ))
            }
        }
        LifecycleCommand::Start(_)
        | LifecycleCommand::Cold(_)
        | LifecycleCommand::Stop(_)
        | LifecycleCommand::Delete(_) => {
            anyhow::bail!("Suspend/Warm handler received another lifecycle command")
        }
    }
}

pub(super) fn apply(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    step: &ExecutionStep,
    authority: LifecycleEffectAuthority<'_>,
) -> Result<LifecycleEffectProgress> {
    let predecessor = predecessor.context("Suspend/Warm lacks its exact same-Node predecessor")?;
    validate_predecessor_response(command, predecessor)?;
    let payload = decode_step(step, command)?;
    anyhow::ensure!(
        step.name.as_str() == step_name(&payload.state),
        "Suspend/Warm step name and recovery payload disagree"
    );
    match (&command.command, &payload.state) {
        (LifecycleCommand::Suspend(_), state) if is_suspend_state(state) => {
            apply_suspend(ctx, command, predecessor, state, authority)
        }
        (LifecycleCommand::Warm(_), state) if is_warm_state(state) => {
            apply_warm(ctx, command, predecessor, state, authority)
        }
        _ => anyhow::bail!("Suspend/Warm durable step is invalid for this command"),
    }
}

fn planned_unfenced(
    command: &LifecycleCommandEnvelope,
    state: SuspendWarmStepState,
) -> Result<PlannedLifecycleEffect> {
    Ok(PlannedLifecycleEffect::unfenced(encode_step(
        command, state,
    )?))
}

fn planned_inherit(
    command: &LifecycleCommandEnvelope,
    state: SuspendWarmStepState,
) -> Result<PlannedLifecycleEffect> {
    Ok(PlannedLifecycleEffect::inherit_stop_fence(encode_step(
        command, state,
    )?))
}

fn encode_step(
    command: &LifecycleCommandEnvelope,
    state: SuspendWarmStepState,
) -> Result<ExecutionStep> {
    let name = Id::new(step_name(&state)).context("Suspend/Warm step name is invalid")?;
    let bytes = serde_json::to_vec(&SuspendWarmStepPayload {
        binding: StepBinding::new(command),
        state,
    })
    .context("encode Suspend/Warm durable step")?;
    anyhow::ensure!(
        bytes.len() <= STEP_PAYLOAD_MAX_BYTES,
        "Suspend/Warm durable step exceeds its closed byte bound"
    );
    Ok(ExecutionStep {
        name,
        recovery_payload: ExactBytes::new(bytes),
    })
}

fn decode_step(
    step: &ExecutionStep,
    command: &LifecycleCommandEnvelope,
) -> Result<SuspendWarmStepPayload> {
    anyhow::ensure!(
        step.recovery_payload.as_slice().len() <= STEP_PAYLOAD_MAX_BYTES,
        "Suspend/Warm durable step exceeds its closed byte bound"
    );
    let payload: SuspendWarmStepPayload = serde_json::from_slice(step.recovery_payload.as_slice())
        .context("decode Suspend/Warm durable step")?;
    payload.binding.validate(command)?;
    Ok(payload)
}

fn step_name(state: &SuspendWarmStepState) -> &'static str {
    match state {
        SuspendWarmStepState::SuspendAdmission => STEP_SUSPEND_ADMISSION,
        SuspendWarmStepState::SuspendGuards => STEP_SUSPEND_GUARDS,
        SuspendWarmStepState::SuspendDiscover => STEP_SUSPEND_DISCOVER,
        SuspendWarmStepState::SuspendQuiesce { .. } => STEP_SUSPEND_QUIESCE,
        SuspendWarmStepState::SuspendPause { .. } => STEP_SUSPEND_PAUSE,
        SuspendWarmStepState::SuspendFailureStop { .. } => STEP_SUSPEND_FAILURE_STOP,
        SuspendWarmStepState::WarmAdmission => STEP_WARM_ADMISSION,
        SuspendWarmStepState::WarmGuards => STEP_WARM_GUARDS,
        SuspendWarmStepState::WarmDiscover => STEP_WARM_DISCOVER,
        SuspendWarmStepState::WarmQuiesce { .. } => STEP_WARM_QUIESCE,
        SuspendWarmStepState::WarmDrain { .. } => STEP_WARM_DRAIN,
        SuspendWarmStepState::WarmPause { .. } => STEP_WARM_PAUSE,
        SuspendWarmStepState::WarmSnapshot { .. } => STEP_WARM_SNAPSHOT,
        SuspendWarmStepState::WarmStop { .. } => STEP_WARM_STOP,
        SuspendWarmStepState::WarmFailureStop { .. } => STEP_WARM_FAILURE_STOP,
    }
}

fn is_suspend_state(state: &SuspendWarmStepState) -> bool {
    matches!(
        state,
        SuspendWarmStepState::SuspendAdmission
            | SuspendWarmStepState::SuspendGuards
            | SuspendWarmStepState::SuspendDiscover
            | SuspendWarmStepState::SuspendQuiesce { .. }
            | SuspendWarmStepState::SuspendPause { .. }
            | SuspendWarmStepState::SuspendFailureStop { .. }
    )
}

fn is_warm_state(state: &SuspendWarmStepState) -> bool {
    !is_suspend_state(state)
}

fn stop_fence_payload(command: &LifecycleCommandEnvelope) -> Result<ExactBytes> {
    let canonical = serde_json::to_vec(&StepBinding::new(command))
        .context("encode Suspend/Warm Stop fence binding")?;
    let mut bytes = Vec::with_capacity(STOP_FENCE_DOMAIN.len() + 1 + canonical.len());
    bytes.extend_from_slice(STOP_FENCE_DOMAIN);
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(ExactBytes::new(bytes))
}

#[derive(Debug, Clone)]
struct SourceRuntime {
    runtime_incarnation: Option<RandomId128>,
    admission_ready: Option<AdmissionRuntimeReady>,
    wire_effective_ready: Option<WireEffectiveRuntimeReady>,
    volume_receipts: Option<Vec<VolumeTerminalReceipt>>,
    predecessor_closed: bool,
}

fn apply_suspend(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    state: &SuspendWarmStepState,
    authority: LifecycleEffectAuthority<'_>,
) -> Result<LifecycleEffectProgress> {
    let LifecycleCommand::Suspend(spec) = &command.command else {
        unreachable!("caller checked Suspend command")
    };
    match state {
        SuspendWarmStepState::SuspendAdmission => {
            require_unfenced(&authority)?;
            let source = suspend_source(command, predecessor)?;
            let retained_volume_receipts = source.volume_receipts.clone().unwrap_or_default();
            let admission_ready = source
                .admission_ready
                .context("Suspend source lacks RuntimeReady admission")?;
            let wire_ready = source
                .wire_effective_ready
                .context("Suspend source lacks effective RuntimeReady wire evidence")?;
            let cell = lifecycle_cell(ctx, command)?;
            let close = CloseLifecycleAdmission::new(command.operation_id.clone(), admission_ready);
            match spec.admission_policy {
                SuspendAdmissionPolicy::RequireIdle => {
                    let outcome = match cell.try_close_lifecycle_if_idle(&close) {
                        Ok(outcome) => outcome,
                        Err(_) => {
                            return suspend_failure_plan(
                                command,
                                CommandFailureReason::StoredEvidenceConflict,
                                retained_volume_receipts.clone(),
                            )
                        }
                    };
                    match outcome {
                        IdleLifecycleCloseOutcome::Busy {
                            effective_runtime_ready,
                            platform_guards,
                            endpoint_guards,
                        } => {
                            anyhow::ensure!(
                                effective_runtime_ready.source_lifecycle_operation_id()
                                    == &wire_ready.source_lifecycle_operation_id
                                    && effective_runtime_ready.runtime_incarnation()
                                        == &wire_ready.runtime_incarnation,
                                "RequireIdle Busy proof changed the effective RuntimeReady source"
                            );
                            let counts = LifecycleGuardCounts {
                                platform_guards,
                                endpoint_guards,
                            };
                            anyhow::ensure!(
                                !counts.is_drained(),
                                "RequireIdle Busy proof contains no active guard"
                            );
                            let receipt = busy_receipt_digest(command, &wire_ready, &counts)?;
                            return Ok(LifecycleEffectProgress::Terminal(
                                NodeResult::SuspendDeclined(Box::new(SuspendDeclinedResult {
                                    reason: SuspendDeclineReason::Busy,
                                    admission_cell_never_closed_receipt_digest: receipt,
                                    effective_runtime_ready: wire_ready,
                                })),
                            ));
                        }
                        IdleLifecycleCloseOutcome::Closed { .. }
                        | IdleLifecycleCloseOutcome::Replay => {}
                    }
                }
                SuspendAdmissionPolicy::CloseAndDrain => {
                    let outcome = match cell.close_lifecycle(&close) {
                        Ok(outcome) => outcome,
                        Err(_) => {
                            return suspend_failure_plan(
                                command,
                                CommandFailureReason::StoredEvidenceConflict,
                                retained_volume_receipts.clone(),
                            )
                        }
                    };
                    match outcome {
                        LifecycleCloseOutcome::Closed { .. } | LifecycleCloseOutcome::Replay => {}
                    }
                }
            }
            Ok(LifecycleEffectProgress::Next(planned_unfenced(
                command,
                SuspendWarmStepState::SuspendGuards,
            )?))
        }
        SuspendWarmStepState::SuspendGuards => {
            require_unfenced(&authority)?;
            let deadline = deadline_instant(spec.grace_deadline_unix_ms)?;
            let cell = lifecycle_cell(ctx, command)?;
            let drained = match wait_for_guards(cell.as_ref(), deadline) {
                Ok(drained) => drained,
                Err(_) => {
                    return suspend_failure_plan(
                        command,
                        CommandFailureReason::StoredEvidenceConflict,
                        predecessor_retained_receipts(predecessor),
                    )
                }
            };
            if drained {
                return Ok(LifecycleEffectProgress::Next(planned_unfenced(
                    command,
                    SuspendWarmStepState::SuspendDiscover,
                )?));
            }
            suspend_failure_plan(
                command,
                CommandFailureReason::LocalCleanupFailed,
                predecessor_retained_receipts(predecessor),
            )
        }
        SuspendWarmStepState::SuspendDiscover => {
            require_unfenced(&authority)?;
            let deadline = deadline_instant(spec.grace_deadline_unix_ms)?;
            let attempt = ctx
                .suspend_warm_platform()
                .inspect_runtime(command, predecessor, deadline)
                .context("discover exact runtime before Suspend")?;
            match attempt {
                SuspendWarmPlatformAttempt::Exact(runtime) => {
                    validate_runtime_evidence(command, predecessor, &runtime)?;
                    anyhow::ensure!(
                        runtime.vmm_state == InstalledVmmState::Executing,
                        "Suspend source VMM is not freshly verified executing"
                    );
                    Ok(LifecycleEffectProgress::Next(planned_unfenced(
                        command,
                        SuspendWarmStepState::SuspendQuiesce { runtime },
                    )?))
                }
                SuspendWarmPlatformAttempt::DefiniteFailure(reason) => suspend_failure_plan(
                    command,
                    reason,
                    predecessor_retained_receipts(predecessor),
                ),
                SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    retained_volume_receipts,
                    ..
                } => {
                    let retained_volume_receipts = preserve_complete_predecessor_receipts(
                        command,
                        predecessor,
                        &retained_volume_receipts,
                    )?;
                    suspend_failure_plan(
                        command,
                        CommandFailureReason::StoredEvidenceConflict,
                        retained_volume_receipts,
                    )
                }
                SuspendWarmPlatformAttempt::Ambiguous if Instant::now() < deadline => {
                    anyhow::bail!("Suspend runtime discovery remains ambiguous")
                }
                SuspendWarmPlatformAttempt::Ambiguous => suspend_failure_plan(
                    command,
                    CommandFailureReason::StoredEvidenceConflict,
                    predecessor_retained_receipts(predecessor),
                ),
            }
        }
        SuspendWarmStepState::SuspendQuiesce { runtime } => {
            require_unfenced(&authority)?;
            validate_runtime_evidence(command, predecessor, runtime)?;
            let deadline = deadline_instant(spec.grace_deadline_unix_ms)?;
            let attempt = ctx
                .suspend_warm_platform()
                .quiesce_guest(command, predecessor, runtime, deadline)
                .context("quiesce exact Guest before Suspend")?;
            match attempt {
                SuspendWarmPlatformAttempt::Exact(quiesce) => {
                    validate_quiesce_evidence(runtime, &quiesce)?;
                    Ok(LifecycleEffectProgress::Next(planned_unfenced(
                        command,
                        SuspendWarmStepState::SuspendPause {
                            runtime: runtime.clone(),
                            quiesce,
                        },
                    )?))
                }
                SuspendWarmPlatformAttempt::DefiniteFailure(reason) => {
                    suspend_failure_plan(command, reason, runtime.volume_receipts.clone())
                }
                SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    retained_volume_receipts,
                    ..
                } => {
                    validate_retained_volume_receipts(command, &retained_volume_receipts)?;
                    let retained_volume_receipts = merge_attachment_receipts(
                        &runtime.volume_receipts,
                        &retained_volume_receipts,
                    )?;
                    suspend_failure_plan(
                        command,
                        CommandFailureReason::StoredEvidenceConflict,
                        retained_volume_receipts,
                    )
                }
                SuspendWarmPlatformAttempt::Ambiguous if Instant::now() < deadline => {
                    anyhow::bail!("Suspend Guest quiesce remains ambiguous")
                }
                SuspendWarmPlatformAttempt::Ambiguous => suspend_failure_plan(
                    command,
                    CommandFailureReason::GuestNotReady,
                    runtime.volume_receipts.clone(),
                ),
            }
        }
        SuspendWarmStepState::SuspendPause { runtime, quiesce } => {
            require_unfenced(&authority)?;
            validate_runtime_evidence(command, predecessor, runtime)?;
            validate_quiesce_evidence(runtime, quiesce)?;
            let deadline = deadline_instant(spec.grace_deadline_unix_ms)?;
            let attempt = ctx
                .suspend_warm_platform()
                .pause_vmm(command, predecessor, runtime, quiesce, deadline)
                .context("pause exact VMM for Suspend")?;
            match attempt {
                SuspendWarmPlatformAttempt::Exact(paused) => {
                    let write_fence = RuntimeWriteFenceEvidence::Guest {
                        quiesce: quiesce.clone(),
                    };
                    validate_paused_evidence(
                        command,
                        &StepBinding::new(command),
                        runtime,
                        &write_fence,
                        &paused,
                        false,
                    )?;
                    Ok(LifecycleEffectProgress::Terminal(NodeResult::Suspended(
                        Box::new(SuspendedResult {
                            runtime_incarnation: runtime.runtime_incarnation.clone(),
                            runtime_config_digest: command.runtime_config.config_digest.clone(),
                            pause_receipt_digest: paused.pause_receipt_digest,
                            local_durability_receipts: paused.local_durability_receipts,
                        }),
                    )))
                }
                SuspendWarmPlatformAttempt::DefiniteFailure(reason) => {
                    suspend_failure_plan(command, reason, runtime.volume_receipts.clone())
                }
                SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    retained_volume_receipts,
                    ..
                } => {
                    validate_retained_volume_receipts(command, &retained_volume_receipts)?;
                    let retained_volume_receipts = merge_attachment_receipts(
                        &runtime.volume_receipts,
                        &retained_volume_receipts,
                    )?;
                    suspend_failure_plan(
                        command,
                        CommandFailureReason::StoredEvidenceConflict,
                        retained_volume_receipts,
                    )
                }
                SuspendWarmPlatformAttempt::Ambiguous if Instant::now() < deadline => {
                    anyhow::bail!("Suspend VMM pause remains ambiguous")
                }
                SuspendWarmPlatformAttempt::Ambiguous => suspend_failure_plan(
                    command,
                    CommandFailureReason::VmmFailed,
                    runtime.volume_receipts.clone(),
                ),
            }
        }
        SuspendWarmStepState::SuspendFailureStop {
            reason,
            retained_volume_receipts,
        } => {
            if !retained_volume_receipts.is_empty() {
                validate_retained_volume_receipts(command, retained_volume_receipts)?;
            }
            let stopped = ctx
                .execute_strong_stop_with_retained_receipts(
                    command,
                    Some(predecessor),
                    authority,
                    retained_volume_receipts,
                )
                .context("strong Stop failed Suspend")?;
            validate_volume_receipts(command, &stopped.retained_volume_receipts, false)
                .context("failed Suspend lacks its complete retained Volume carrier")?;
            Ok(LifecycleEffectProgress::Terminal(
                NodeResult::SuspendFailed(Box::new(CommandFailedResult {
                    reason: *reason,
                    not_running: stopped.execution_absence,
                    retained_evidence: stopped.retained_evidence,
                    retained_volume_receipts: stopped.retained_volume_receipts,
                })),
            ))
        }
        _ => anyhow::bail!("invalid Suspend durable step"),
    }
}

fn apply_warm(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    state: &SuspendWarmStepState,
    authority: LifecycleEffectAuthority<'_>,
) -> Result<LifecycleEffectProgress> {
    let LifecycleCommand::Warm(spec) = &command.command else {
        unreachable!("caller checked Warm command")
    };
    require_current_fence(&authority)?;
    match state {
        SuspendWarmStepState::WarmAdmission => {
            let source = warm_source(command, predecessor)?;
            let cell = lifecycle_cell(ctx, command)?;
            if source.predecessor_closed {
                let outcome = match cell.adopt_closed_lifecycle_successor(
                    &command.operation_id,
                    &predecessor.operation_id,
                ) {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        return warm_failure_plan(
                            command,
                            WarmFailureOutcome::Failed {
                                reason: CommandFailureReason::StoredEvidenceConflict,
                            },
                            predecessor_retained_receipts(predecessor),
                        )
                    }
                };
                match outcome {
                    LifecycleCloseOutcome::Closed { .. } | LifecycleCloseOutcome::Replay => {}
                }
            } else {
                let ready = source
                    .admission_ready
                    .context("Running Warm source lacks RuntimeReady admission")?;
                let outcome = match cell.close_lifecycle(&CloseLifecycleAdmission::new(
                    command.operation_id.clone(),
                    ready,
                )) {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        return warm_failure_plan(
                            command,
                            WarmFailureOutcome::Failed {
                                reason: CommandFailureReason::StoredEvidenceConflict,
                            },
                            predecessor_retained_receipts(predecessor),
                        )
                    }
                };
                match outcome {
                    LifecycleCloseOutcome::Closed { .. } | LifecycleCloseOutcome::Replay => {}
                }
            }
            Ok(LifecycleEffectProgress::Next(planned_inherit(
                command,
                SuspendWarmStepState::WarmGuards,
            )?))
        }
        SuspendWarmStepState::WarmGuards => {
            let deadline = deadline_instant(spec.grace_deadline_unix_ms)?;
            let cell = lifecycle_cell(ctx, command)?;
            let drained = match wait_for_guards(cell.as_ref(), deadline) {
                Ok(drained) => drained,
                Err(_) => {
                    return warm_failure_plan(
                        command,
                        WarmFailureOutcome::Failed {
                            reason: CommandFailureReason::StoredEvidenceConflict,
                        },
                        predecessor_retained_receipts(predecessor),
                    )
                }
            };
            if drained {
                return Ok(LifecycleEffectProgress::Next(planned_inherit(
                    command,
                    SuspendWarmStepState::WarmDiscover,
                )?));
            }
            warm_failure_plan(
                command,
                WarmFailureOutcome::Failed {
                    reason: CommandFailureReason::LocalCleanupFailed,
                },
                predecessor_retained_receipts(predecessor),
            )
        }
        SuspendWarmStepState::WarmDiscover => {
            let deadline = deadline_instant(spec.convergence_deadline_unix_ms)?;
            if matches!(&predecessor.result, NodeResult::NeedsIntervention(_)) {
                return match ctx
                    .suspend_warm_platform()
                    .inspect_warm_recovery(command, predecessor, deadline)
                    .context("reopen exact retained Warm recovery evidence")?
                {
                    SuspendWarmPlatformAttempt::Exact(recovered) => {
                        validate_recovered_warm(command, predecessor, &recovered)?;
                        Ok(LifecycleEffectProgress::Next(planned_inherit(
                            command,
                            SuspendWarmStepState::WarmStop {
                                runtime: recovered.runtime,
                                write_fence: recovered.write_fence,
                                paused: recovered.paused,
                                drained_volumes: recovered.drained_volumes,
                                snapshot: Box::new(recovered.snapshot),
                                recovery_predecessor: Some(Box::new(recovered.predecessor)),
                            },
                        )?))
                    }
                    SuspendWarmPlatformAttempt::DefiniteFailure(_)
                    | SuspendWarmPlatformAttempt::DataSafetyBlocked { .. }
                    | SuspendWarmPlatformAttempt::Ambiguous => warm_failure_plan(
                        command,
                        WarmFailureOutcome::NeedsIntervention {
                            reason: intervention_reason(predecessor)?,
                        },
                        predecessor_retained_receipts(predecessor),
                    ),
                };
            }
            match ctx
                .suspend_warm_platform()
                .inspect_runtime(command, predecessor, deadline)
                .context("discover exact runtime before Warm")?
            {
                SuspendWarmPlatformAttempt::Exact(runtime) => {
                    validate_runtime_evidence(command, predecessor, &runtime)?;
                    match &predecessor.result {
                        NodeResult::RuntimeReady(_) | NodeResult::SuspendDeclined(_) => {
                            anyhow::ensure!(
                                runtime.vmm_state == InstalledVmmState::Executing,
                                "Running Warm source VMM is not freshly verified executing"
                            );
                            Ok(LifecycleEffectProgress::Next(planned_inherit(
                                command,
                                SuspendWarmStepState::WarmQuiesce { runtime },
                            )?))
                        }
                        NodeResult::Suspended(suspended) => {
                            anyhow::ensure!(
                                runtime.vmm_state == InstalledVmmState::Paused,
                                "Suspended Warm source VMM is not freshly verified paused"
                            );
                            let write_fence = RuntimeWriteFenceEvidence::InheritedSuspended {
                                runtime_physical_identity_digest: runtime
                                    .physical_identity_digest
                                    .clone(),
                                pause_receipt_digest: suspended.pause_receipt_digest.clone(),
                            };
                            validate_write_fence(&runtime, &write_fence)?;
                            Ok(LifecycleEffectProgress::Next(planned_inherit(
                                command,
                                SuspendWarmStepState::WarmDrain {
                                    runtime,
                                    write_fence,
                                },
                            )?))
                        }
                        _ => anyhow::bail!("Warm discovery reached another predecessor kind"),
                    }
                }
                SuspendWarmPlatformAttempt::DefiniteFailure(reason) => warm_failure_plan(
                    command,
                    WarmFailureOutcome::Failed { reason },
                    predecessor_retained_receipts(predecessor),
                ),
                SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason,
                    retained_volume_receipts,
                } => {
                    let retained_volume_receipts = preserve_complete_predecessor_receipts(
                        command,
                        predecessor,
                        &retained_volume_receipts,
                    )?;
                    warm_failure_plan(
                        command,
                        WarmFailureOutcome::NeedsIntervention { reason },
                        retained_volume_receipts,
                    )
                }
                SuspendWarmPlatformAttempt::Ambiguous if Instant::now() < deadline => {
                    anyhow::bail!("Warm runtime discovery remains ambiguous")
                }
                SuspendWarmPlatformAttempt::Ambiguous => warm_failure_plan(
                    command,
                    WarmFailureOutcome::NeedsIntervention {
                        reason: InterventionReason::ForeignOrAmbiguousResidue,
                    },
                    predecessor_retained_receipts(predecessor),
                ),
            }
        }
        SuspendWarmStepState::WarmQuiesce { runtime } => {
            validate_runtime_evidence(command, predecessor, runtime)?;
            let deadline = deadline_instant(spec.convergence_deadline_unix_ms)?;
            match ctx
                .suspend_warm_platform()
                .quiesce_guest(command, predecessor, runtime, deadline)
                .context("quiesce exact Guest before Warm")?
            {
                SuspendWarmPlatformAttempt::Exact(quiesce) => {
                    validate_quiesce_evidence(runtime, &quiesce)?;
                    Ok(LifecycleEffectProgress::Next(planned_inherit(
                        command,
                        SuspendWarmStepState::WarmDrain {
                            runtime: runtime.clone(),
                            write_fence: RuntimeWriteFenceEvidence::Guest { quiesce },
                        },
                    )?))
                }
                SuspendWarmPlatformAttempt::DefiniteFailure(reason) => warm_failure_plan(
                    command,
                    WarmFailureOutcome::Failed { reason },
                    runtime.volume_receipts.clone(),
                ),
                SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason,
                    retained_volume_receipts,
                } => {
                    validate_retained_volume_receipts(command, &retained_volume_receipts)?;
                    let retained_volume_receipts = merge_attachment_receipts(
                        &runtime.volume_receipts,
                        &retained_volume_receipts,
                    )?;
                    warm_failure_plan(
                        command,
                        WarmFailureOutcome::NeedsIntervention { reason },
                        retained_volume_receipts,
                    )
                }
                SuspendWarmPlatformAttempt::Ambiguous if Instant::now() < deadline => {
                    anyhow::bail!("Warm Guest quiesce remains ambiguous")
                }
                SuspendWarmPlatformAttempt::Ambiguous => warm_failure_plan(
                    command,
                    WarmFailureOutcome::Failed {
                        reason: CommandFailureReason::GuestNotReady,
                    },
                    runtime.volume_receipts.clone(),
                ),
            }
        }
        SuspendWarmStepState::WarmDrain {
            runtime,
            write_fence,
        } => {
            validate_runtime_evidence(command, predecessor, runtime)?;
            validate_write_fence(runtime, write_fence)?;
            let deadline = deadline_instant(spec.convergence_deadline_unix_ms)?;
            match ctx
                .suspend_warm_platform()
                .drain_volumes_to_remote(command, predecessor, runtime, write_fence, deadline)
                .context("drain every retained Volume before Warm")?
            {
                SuspendWarmPlatformAttempt::Exact(drained_volumes) => {
                    validate_volume_receipts(command, &drained_volumes, true)?;
                    validate_attachment_lineage_advancement(
                        &runtime.volume_receipts,
                        &drained_volumes,
                    )?;
                    match write_fence {
                        RuntimeWriteFenceEvidence::Guest { quiesce } => {
                            Ok(LifecycleEffectProgress::Next(planned_inherit(
                                command,
                                SuspendWarmStepState::WarmPause {
                                    runtime: runtime.clone(),
                                    quiesce: quiesce.clone(),
                                    drained_volumes,
                                },
                            )?))
                        }
                        RuntimeWriteFenceEvidence::InheritedSuspended {
                            pause_receipt_digest,
                            ..
                        } => {
                            let paused = PausedRuntimeEvidence {
                                pause_operation_id: predecessor.operation_id.clone(),
                                pause_request_fingerprint: predecessor.request_fingerprint.clone(),
                                runtime_physical_identity_digest: runtime
                                    .physical_identity_digest
                                    .clone(),
                                write_fence_receipt_digest: pause_receipt_digest.clone(),
                                pause_receipt_digest: pause_receipt_digest.clone(),
                                local_durability_receipts: drained_volumes.clone(),
                            };
                            validate_paused_evidence(
                                command,
                                &StepBinding::from_response(predecessor),
                                runtime,
                                write_fence,
                                &paused,
                                true,
                            )?;
                            Ok(LifecycleEffectProgress::Next(planned_inherit(
                                command,
                                SuspendWarmStepState::WarmSnapshot {
                                    runtime: runtime.clone(),
                                    write_fence: write_fence.clone(),
                                    drained_volumes,
                                    paused,
                                },
                            )?))
                        }
                    }
                }
                SuspendWarmPlatformAttempt::DefiniteFailure(reason) => warm_failure_plan(
                    command,
                    WarmFailureOutcome::Failed { reason },
                    runtime.volume_receipts.clone(),
                ),
                SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason,
                    retained_volume_receipts,
                } => {
                    validate_retained_volume_receipts(command, &retained_volume_receipts)?;
                    let retained_volume_receipts = merge_attachment_receipts(
                        &runtime.volume_receipts,
                        &retained_volume_receipts,
                    )?;
                    warm_failure_plan(
                        command,
                        WarmFailureOutcome::NeedsIntervention { reason },
                        retained_volume_receipts,
                    )
                }
                SuspendWarmPlatformAttempt::Ambiguous if Instant::now() < deadline => {
                    anyhow::bail!("Warm Volume convergence remains ambiguous")
                }
                SuspendWarmPlatformAttempt::Ambiguous => warm_failure_plan(
                    command,
                    WarmFailureOutcome::NeedsIntervention {
                        reason: InterventionReason::AuthorityAmbiguous,
                    },
                    runtime.volume_receipts.clone(),
                ),
            }
        }
        SuspendWarmStepState::WarmPause {
            runtime,
            quiesce,
            drained_volumes,
        } => {
            validate_runtime_evidence(command, predecessor, runtime)?;
            validate_quiesce_evidence(runtime, quiesce)?;
            validate_volume_receipts(command, drained_volumes, true)?;
            let deadline = deadline_instant(spec.convergence_deadline_unix_ms)?;
            match ctx
                .suspend_warm_platform()
                .pause_vmm(command, predecessor, runtime, quiesce, deadline)
                .context("pause exact VMM before Warm snapshot")?
            {
                SuspendWarmPlatformAttempt::Exact(paused) => {
                    let write_fence = RuntimeWriteFenceEvidence::Guest {
                        quiesce: quiesce.clone(),
                    };
                    validate_paused_evidence(
                        command,
                        &StepBinding::new(command),
                        runtime,
                        &write_fence,
                        &paused,
                        true,
                    )?;
                    validate_same_attachments(drained_volumes, &paused.local_durability_receipts)?;
                    Ok(LifecycleEffectProgress::Next(planned_inherit(
                        command,
                        SuspendWarmStepState::WarmSnapshot {
                            runtime: runtime.clone(),
                            write_fence,
                            drained_volumes: drained_volumes.clone(),
                            paused,
                        },
                    )?))
                }
                SuspendWarmPlatformAttempt::DefiniteFailure(reason) => warm_failure_plan(
                    command,
                    WarmFailureOutcome::Failed { reason },
                    drained_volumes.clone(),
                ),
                SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason,
                    retained_volume_receipts,
                } => {
                    validate_retained_volume_receipts(command, &retained_volume_receipts)?;
                    let retained_volume_receipts =
                        merge_attachment_receipts(drained_volumes, &retained_volume_receipts)?;
                    warm_failure_plan(
                        command,
                        WarmFailureOutcome::NeedsIntervention { reason },
                        retained_volume_receipts,
                    )
                }
                SuspendWarmPlatformAttempt::Ambiguous if Instant::now() < deadline => {
                    anyhow::bail!("Warm VMM pause remains ambiguous")
                }
                SuspendWarmPlatformAttempt::Ambiguous => warm_failure_plan(
                    command,
                    WarmFailureOutcome::Failed {
                        reason: CommandFailureReason::VmmFailed,
                    },
                    drained_volumes.clone(),
                ),
            }
        }
        SuspendWarmStepState::WarmSnapshot {
            runtime,
            write_fence,
            drained_volumes,
            paused,
        } => {
            validate_runtime_evidence(command, predecessor, runtime)?;
            validate_write_fence(runtime, write_fence)?;
            validate_volume_receipts(command, drained_volumes, true)?;
            validate_paused_evidence(
                command,
                &expected_pause_binding(command, predecessor, paused)?,
                runtime,
                write_fence,
                paused,
                true,
            )?;
            let deadline = deadline_instant(spec.convergence_deadline_unix_ms)?;
            match ctx
                .suspend_warm_platform()
                .create_warm_snapshot(
                    WarmSnapshotInputs {
                        command,
                        predecessor,
                        runtime,
                        write_fence,
                        paused,
                        drained_volumes,
                    },
                    deadline,
                )
                .context("create and verify exact Warm snapshot")?
            {
                SuspendWarmPlatformAttempt::Exact(snapshot) => {
                    validate_snapshot_evidence(
                        &StepBinding::new(command),
                        runtime,
                        write_fence,
                        paused,
                        drained_volumes,
                        &snapshot,
                    )?;
                    Ok(LifecycleEffectProgress::Next(planned_inherit(
                        command,
                        SuspendWarmStepState::WarmStop {
                            runtime: runtime.clone(),
                            write_fence: write_fence.clone(),
                            paused: paused.clone(),
                            drained_volumes: drained_volumes.clone(),
                            snapshot: Box::new(snapshot),
                            recovery_predecessor: None,
                        },
                    )?))
                }
                SuspendWarmPlatformAttempt::DefiniteFailure(reason) => warm_failure_plan(
                    command,
                    WarmFailureOutcome::Failed { reason },
                    drained_volumes.clone(),
                ),
                SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason,
                    retained_volume_receipts,
                } => {
                    validate_retained_volume_receipts(command, &retained_volume_receipts)?;
                    let retained_volume_receipts =
                        merge_attachment_receipts(drained_volumes, &retained_volume_receipts)?;
                    warm_failure_plan(
                        command,
                        WarmFailureOutcome::NeedsIntervention { reason },
                        retained_volume_receipts,
                    )
                }
                SuspendWarmPlatformAttempt::Ambiguous if Instant::now() < deadline => {
                    anyhow::bail!("Warm snapshot creation remains ambiguous")
                }
                SuspendWarmPlatformAttempt::Ambiguous => warm_failure_plan(
                    command,
                    WarmFailureOutcome::NeedsIntervention {
                        reason: InterventionReason::WarmSnapshotAmbiguous,
                    },
                    drained_volumes.clone(),
                ),
            }
        }
        SuspendWarmStepState::WarmStop {
            runtime,
            write_fence,
            paused,
            drained_volumes,
            snapshot,
            recovery_predecessor,
        } => {
            validate_runtime_evidence(command, predecessor, runtime)?;
            validate_warm_stop_recovery_predecessor(
                WarmSnapshotInputs {
                    command,
                    predecessor,
                    runtime,
                    write_fence,
                    paused,
                    drained_volumes,
                },
                snapshot,
                recovery_predecessor.as_deref(),
            )?;
            validate_write_fence_for_snapshot(runtime, write_fence)?;
            validate_volume_receipts(command, drained_volumes, true)?;
            validate_paused_evidence(
                command,
                &expected_pause_binding(command, predecessor, paused)?,
                runtime,
                write_fence,
                paused,
                true,
            )?;
            validate_snapshot_evidence(
                &expected_snapshot_binding(command, predecessor, snapshot)?,
                runtime,
                write_fence,
                paused,
                drained_volumes,
                snapshot,
            )?;
            let deadline = deadline_instant(spec.convergence_deadline_unix_ms)?;
            match ctx
                .suspend_warm_platform()
                .verify_warm_snapshot(
                    WarmSnapshotInputs {
                        command,
                        predecessor,
                        runtime,
                        write_fence,
                        paused,
                        drained_volumes,
                    },
                    snapshot,
                    deadline,
                )
                .context("reopen exact Warm snapshot before strong Stop")?
            {
                SuspendWarmPlatformAttempt::Exact(reopened) => {
                    validate_snapshot_evidence(
                        &expected_snapshot_binding(command, predecessor, &reopened)?,
                        runtime,
                        write_fence,
                        paused,
                        drained_volumes,
                        &reopened,
                    )?;
                    anyhow::ensure!(
                        &reopened == snapshot.as_ref(),
                        "reopened Warm snapshot differs from the journaled exact snapshot"
                    );
                }
                SuspendWarmPlatformAttempt::DefiniteFailure(reason) => {
                    return warm_failure_plan(
                        command,
                        WarmFailureOutcome::Failed { reason },
                        drained_volumes.clone(),
                    )
                }
                SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason,
                    retained_volume_receipts,
                } => {
                    validate_retained_volume_receipts(command, &retained_volume_receipts)?;
                    let retained_volume_receipts =
                        merge_attachment_receipts(drained_volumes, &retained_volume_receipts)?;
                    return warm_failure_plan(
                        command,
                        WarmFailureOutcome::NeedsIntervention { reason },
                        retained_volume_receipts,
                    );
                }
                SuspendWarmPlatformAttempt::Ambiguous if Instant::now() < deadline => {
                    anyhow::bail!("Warm snapshot verification remains ambiguous")
                }
                SuspendWarmPlatformAttempt::Ambiguous => {
                    return warm_failure_plan(
                        command,
                        WarmFailureOutcome::NeedsIntervention {
                            reason: InterventionReason::WarmSnapshotAmbiguous,
                        },
                        drained_volumes.clone(),
                    )
                }
            }
            // The shared barrier is intentionally last: Warm must make the
            // memory/device snapshot durable before it stops the VMM.
            let stopped = ctx
                .execute_strong_stop_with_retained_receipts(
                    command,
                    Some(predecessor),
                    authority,
                    drained_volumes,
                )
                .context("stop VMM/frontends after durable Warm snapshot")?;
            validate_retained_after_warm(drained_volumes, &stopped.retained_volume_receipts)?;
            let finalization_deadline = Instant::now()
                .checked_add(ctx.config().physical_probe_timeout)
                .context("Warm terminal publication deadline overflow")?;
            let finalized = match ctx
                .suspend_warm_platform()
                .finalize_warm_snapshot(
                    WarmSnapshotInputs {
                        command,
                        predecessor,
                        runtime,
                        write_fence,
                        paused,
                        drained_volumes,
                    },
                    snapshot,
                    &stopped.execution_absence,
                    finalization_deadline,
                )
                .context("publish post-Stop terminal Warm manifest")?
            {
                SuspendWarmPlatformAttempt::Exact(finalized) => finalized,
                SuspendWarmPlatformAttempt::DefiniteFailure(reason) => {
                    return warm_failure_plan(
                        command,
                        WarmFailureOutcome::Failed { reason },
                        drained_volumes.clone(),
                    )
                }
                SuspendWarmPlatformAttempt::DataSafetyBlocked {
                    reason,
                    retained_volume_receipts,
                } => {
                    validate_retained_volume_receipts(command, &retained_volume_receipts)?;
                    let retained_volume_receipts =
                        merge_attachment_receipts(drained_volumes, &retained_volume_receipts)?;
                    return warm_failure_plan(
                        command,
                        WarmFailureOutcome::NeedsIntervention { reason },
                        retained_volume_receipts,
                    );
                }
                SuspendWarmPlatformAttempt::Ambiguous => {
                    return warm_failure_plan(
                        command,
                        WarmFailureOutcome::NeedsIntervention {
                            reason: InterventionReason::WarmSnapshotAmbiguous,
                        },
                        drained_volumes.clone(),
                    )
                }
            };
            anyhow::ensure!(
                finalized.warm_receipt_digest
                    == warm_ready_receipt_digest(
                        command,
                        snapshot,
                        &stopped.execution_absence,
                        drained_volumes,
                    )?,
                "terminal Warm manifest changed its command receipt"
            );
            Ok(LifecycleEffectProgress::Terminal(NodeResult::Warm(
                Box::new(WarmResult {
                    runtime_config_digest: command.runtime_config.config_digest.clone(),
                    source_runtime_incarnation: runtime.runtime_incarnation.clone(),
                    warm_snapshot_receipt_digest: finalized.warm_receipt_digest,
                    warm_snapshot_manifest_digest: finalized.terminal_manifest_digest,
                    volume_receipts: drained_volumes.clone(),
                }),
            )))
        }
        SuspendWarmStepState::WarmFailureStop {
            outcome,
            retained_volume_receipts,
        } => {
            if !retained_volume_receipts.is_empty() {
                validate_retained_volume_receipts(command, retained_volume_receipts)?;
            }
            let stopped = ctx
                .execute_strong_stop_with_retained_receipts(
                    command,
                    Some(predecessor),
                    authority,
                    retained_volume_receipts,
                )
                .context("strong Stop failed Warm")?;
            match outcome {
                WarmFailureOutcome::Failed { reason } => {
                    validate_volume_receipts(command, &stopped.retained_volume_receipts, false)
                        .context("failed Warm lacks its complete retained Volume carrier")?;
                    Ok(LifecycleEffectProgress::Terminal(NodeResult::WarmFailed(
                        Box::new(CommandFailedResult {
                            reason: *reason,
                            not_running: stopped.execution_absence,
                            retained_evidence: stopped.retained_evidence,
                            retained_volume_receipts: stopped.retained_volume_receipts,
                        }),
                    )))
                }
                WarmFailureOutcome::NeedsIntervention { reason } => {
                    Ok(LifecycleEffectProgress::Terminal(
                        NodeResult::NeedsIntervention(Box::new(NeedsInterventionResult {
                            attempted_target: InterventionTarget::Warm,
                            reason: *reason,
                            not_running: stopped.execution_absence,
                            retained_evidence: stopped.retained_evidence,
                            retained_volume_receipts: stopped.retained_volume_receipts,
                        })),
                    ))
                }
            }
        }
        _ => anyhow::bail!("invalid Warm durable step"),
    }
}

fn suspend_failure_plan(
    command: &LifecycleCommandEnvelope,
    reason: CommandFailureReason,
    retained_volume_receipts: Vec<VolumeTerminalReceipt>,
) -> Result<LifecycleEffectProgress> {
    Ok(LifecycleEffectProgress::Next(
        PlannedLifecycleEffect::install_stop_fence(
            encode_step(
                command,
                SuspendWarmStepState::SuspendFailureStop {
                    reason,
                    retained_volume_receipts,
                },
            )?,
            stop_fence_payload(command)?,
        ),
    ))
}

fn warm_failure_plan(
    command: &LifecycleCommandEnvelope,
    outcome: WarmFailureOutcome,
    retained_volume_receipts: Vec<VolumeTerminalReceipt>,
) -> Result<LifecycleEffectProgress> {
    Ok(LifecycleEffectProgress::Next(planned_inherit(
        command,
        SuspendWarmStepState::WarmFailureStop {
            outcome,
            retained_volume_receipts,
        },
    )?))
}

fn validate_predecessor_response(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
) -> Result<()> {
    let terminal = LifecycleTerminalResult::NodeResult {
        response: Box::new(predecessor.clone()),
    };
    validate_lifecycle_successor(Some(&terminal), command)
        .context("validate exact same-Node Suspend/Warm predecessor")?;
    anyhow::ensure!(
        command.expected_predecessor_operation_id.as_ref() == Some(&predecessor.operation_id)
            && predecessor.workspace_id == command.workspace_id
            && predecessor.cat_id == command.cat_id
            && predecessor.node_id == command.node_id
            && predecessor.placement_identity == command.placement_identity,
        "Suspend/Warm predecessor response does not bind the command target"
    );
    Ok(())
}

fn validate_suspend_source(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
) -> Result<()> {
    match &predecessor.result {
        NodeResult::RuntimeReady(ready) => anyhow::ensure!(
            ready.runtime_config_digest == command.runtime_config.config_digest,
            "Suspend RuntimeReady predecessor has another runtime config"
        ),
        NodeResult::SuspendDeclined(declined) => anyhow::ensure!(
            declined.effective_runtime_ready.runtime_config_digest
                == command.runtime_config.config_digest,
            "SuspendDeclined predecessor has another effective runtime config"
        ),
        _ => anyhow::bail!("Suspend requires an effective RuntimeReady predecessor"),
    }
    Ok(())
}

fn validate_warm_source(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
) -> Result<()> {
    match &predecessor.result {
        NodeResult::RuntimeReady(ready) => anyhow::ensure!(
            ready.runtime_config_digest == command.runtime_config.config_digest,
            "Warm RuntimeReady predecessor has another runtime config"
        ),
        NodeResult::SuspendDeclined(declined) => anyhow::ensure!(
            declined.effective_runtime_ready.runtime_config_digest
                == command.runtime_config.config_digest,
            "Warm SuspendDeclined predecessor has another effective runtime config"
        ),
        NodeResult::Suspended(suspended) => anyhow::ensure!(
            suspended.runtime_config_digest == command.runtime_config.config_digest,
            "Warm Suspended predecessor has another runtime config"
        ),
        NodeResult::NeedsIntervention(intervention) => anyhow::ensure!(
            intervention.attempted_target == InterventionTarget::Warm
                && intervention.reason != InterventionReason::ForeignOrAmbiguousResidue,
            "Warm retry lacks exact retained Warm convergence authority"
        ),
        _ => anyhow::bail!("Warm predecessor is not a legal installed source"),
    }
    Ok(())
}

fn suspend_source(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
) -> Result<SourceRuntime> {
    validate_suspend_source(command, predecessor)?;
    let guest_ipv4 = guest_ipv4(command);
    Ok(match &predecessor.result {
        NodeResult::RuntimeReady(ready) => {
            let wire = WireEffectiveRuntimeReady {
                source_lifecycle_operation_id: predecessor.operation_id.clone(),
                runtime_incarnation: ready.runtime_incarnation.clone(),
                runtime_config_digest: ready.runtime_config_digest.clone(),
                runtime_ready_receipt_digest: ready.execution_receipt_digest.clone(),
            };
            SourceRuntime {
                runtime_incarnation: Some(ready.runtime_incarnation.clone()),
                admission_ready: Some(AdmissionRuntimeReady::new(
                    predecessor.operation_id.clone(),
                    ready.runtime_incarnation.clone(),
                    guest_ipv4,
                )),
                wire_effective_ready: Some(wire),
                volume_receipts: Some(ready.volume_receipts.clone()),
                predecessor_closed: false,
            }
        }
        NodeResult::SuspendDeclined(declined) => SourceRuntime {
            runtime_incarnation: Some(declined.effective_runtime_ready.runtime_incarnation.clone()),
            admission_ready: Some(AdmissionRuntimeReady::new(
                declined
                    .effective_runtime_ready
                    .source_lifecycle_operation_id
                    .clone(),
                declined.effective_runtime_ready.runtime_incarnation.clone(),
                guest_ipv4,
            )),
            wire_effective_ready: Some(declined.effective_runtime_ready.clone()),
            volume_receipts: None,
            predecessor_closed: false,
        },
        _ => unreachable!("Suspend source was validated"),
    })
}

fn warm_source(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
) -> Result<SourceRuntime> {
    validate_warm_source(command, predecessor)?;
    match &predecessor.result {
        NodeResult::RuntimeReady(_) | NodeResult::SuspendDeclined(_) => {
            suspend_source(command, predecessor)
        }
        NodeResult::Suspended(suspended) => Ok(SourceRuntime {
            runtime_incarnation: Some(suspended.runtime_incarnation.clone()),
            admission_ready: None,
            wire_effective_ready: None,
            volume_receipts: Some(suspended.local_durability_receipts.clone()),
            predecessor_closed: true,
        }),
        NodeResult::NeedsIntervention(intervention) => Ok(SourceRuntime {
            runtime_incarnation: None,
            admission_ready: None,
            wire_effective_ready: None,
            volume_receipts: Some(intervention.retained_volume_receipts.clone()),
            predecessor_closed: true,
        }),
        _ => unreachable!("Warm source was validated"),
    }
}

fn guest_ipv4(command: &LifecycleCommandEnvelope) -> cats_api::runtime_reconciliation::Ipv4Address {
    match &command.runtime_config.network_config {
        RuntimeNetworkConfig::IsolatedIpv4 { guest_ipv4, .. } => guest_ipv4.clone(),
    }
}

fn lifecycle_cell(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
) -> Result<std::sync::Arc<LifecycleRouteAdmissionCell>> {
    ctx.admission_registry()
        .lookup(&command.cat_id)
        .context("look up Suspend/Warm Host-global admission cell")?
        .context("Suspend/Warm same-Node Cat has no recovered admission cell")
}

fn require_unfenced(authority: &LifecycleEffectAuthority<'_>) -> Result<()> {
    anyhow::ensure!(
        authority.stop_fence().is_none(),
        "ordinary Suspend step unexpectedly holds a Stop fence"
    );
    Ok(())
}

fn require_current_fence(authority: &LifecycleEffectAuthority<'_>) -> Result<()> {
    authority
        .stop_fence()
        .context("Warm physical effect lacks its retained Stop fence")?
        .assert_current()
        .context("Warm Stop fence is no longer current")
}

fn deadline_instant(deadline_unix_ms: UnixMillis) -> Result<Instant> {
    let now_instant = Instant::now();
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Host clock precedes Unix epoch")?
        .as_millis();
    let target_unix_ms = u128::from(deadline_unix_ms.get());
    if target_unix_ms <= now_unix_ms {
        return Ok(now_instant);
    }
    let remaining_ms = u64::try_from(target_unix_ms - now_unix_ms)
        .context("Suspend/Warm deadline exceeds the monotonic clock range")?;
    now_instant
        .checked_add(Duration::from_millis(remaining_ms))
        .context("Suspend/Warm monotonic deadline overflow")
}

fn wait_for_guards(cell: &LifecycleRouteAdmissionCell, deadline: Instant) -> Result<bool> {
    loop {
        let counts = cell
            .active_guard_counts()
            .context("inspect Suspend/Warm lifecycle guards")?;
        if counts.is_drained() {
            return Ok(true);
        }
        let now = Instant::now();
        if now >= deadline {
            // `counts` is already the required fresh check at/past the frozen
            // absolute deadline. Never extend a grace window by one poll.
            return Ok(false);
        }
        thread::sleep(GUARD_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
}

#[derive(Serialize)]
struct BusyReceiptPreimage<'a> {
    binding: StepBinding,
    effective_runtime_ready: &'a WireEffectiveRuntimeReady,
    platform_guards: u32,
    endpoint_guards: &'a [(Id, u32)],
}

fn busy_receipt_digest(
    command: &LifecycleCommandEnvelope,
    effective_runtime_ready: &WireEffectiveRuntimeReady,
    counts: &LifecycleGuardCounts,
) -> Result<Sha256Digest> {
    // Serialization of this private closed struct is infallible for the wire
    // newtypes it contains. Hashing the exact guard snapshot binds Busy to the
    // same atomic read that declined close.
    let canonical = serde_json::to_vec(&BusyReceiptPreimage {
        binding: StepBinding::new(command),
        effective_runtime_ready,
        platform_guards: counts.platform_guards,
        endpoint_guards: &counts.endpoint_guards,
    })
    .context("encode atomic RequireIdle Busy receipt")?;
    Ok(digest_parts(BUSY_RECEIPT_DOMAIN, &[&canonical]))
}

fn validate_runtime_evidence(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    runtime: &InstalledRuntimeEvidence,
) -> Result<()> {
    anyhow::ensure!(
        runtime.runtime_config_digest == command.runtime_config.config_digest,
        "installed runtime evidence has another immutable config"
    );
    validate_volume_receipts(command, &runtime.volume_receipts, false)?;
    let source = match command.command {
        LifecycleCommand::Suspend(_) => suspend_source(command, predecessor)?,
        LifecycleCommand::Warm(_) => warm_source(command, predecessor)?,
        _ => anyhow::bail!("runtime evidence validation received another command"),
    };
    if let Some(expected) = source.runtime_incarnation {
        anyhow::ensure!(
            runtime.runtime_incarnation == expected,
            "installed runtime incarnation differs from its predecessor"
        );
    }
    if let Some(previous) = source.volume_receipts {
        validate_retained_volume_receipts(command, &previous)?;
        if matches!(&predecessor.result, NodeResult::RuntimeReady(_)) {
            validate_running_predecessor_subset(&previous, &runtime.volume_receipts)?;
        } else {
            validate_prior_attachment_subset(&previous, &runtime.volume_receipts)?;
        }
    }
    Ok(())
}

fn validate_quiesce_evidence(
    runtime: &InstalledRuntimeEvidence,
    quiesce: &GuestQuiesceEvidence,
) -> Result<()> {
    anyhow::ensure!(
        quiesce.runtime_physical_identity_digest == runtime.physical_identity_digest,
        "Guest quiesce evidence is not bound to the exact runtime work fence"
    );
    anyhow::ensure!(
        quiesce.quiesce_receipt_digest
            == guest_quiesce_receipt_digest(
                &runtime.physical_identity_digest,
                &quiesce.source_epoch_digest,
                quiesce.lease_sequence,
            ),
        "Guest quiesce receipt does not bind its source epoch and lease sequence"
    );
    Ok(())
}

fn validate_paused_evidence(
    command: &LifecycleCommandEnvelope,
    pause_binding: &StepBinding,
    runtime: &InstalledRuntimeEvidence,
    write_fence: &RuntimeWriteFenceEvidence,
    paused: &PausedRuntimeEvidence,
    require_remote: bool,
) -> Result<()> {
    anyhow::ensure!(
        paused.pause_operation_id == pause_binding.operation_id
            && paused.pause_request_fingerprint == pause_binding.request_fingerprint
            && paused.runtime_physical_identity_digest == runtime.physical_identity_digest
            && &paused.write_fence_receipt_digest == write_fence_receipt_digest(write_fence),
        "paused VMM evidence is not bound to the exact quiesced runtime"
    );
    validate_volume_receipts(command, &paused.local_durability_receipts, require_remote)?;
    match write_fence {
        RuntimeWriteFenceEvidence::Guest { .. } => anyhow::ensure!(
            paused.pause_receipt_digest
                == pause_receipt_digest(
                    pause_binding,
                    runtime,
                    write_fence,
                    &paused.local_durability_receipts,
                )?,
            "VMM pause receipt does not bind the exact Guest fence and local lineage"
        ),
        RuntimeWriteFenceEvidence::InheritedSuspended {
            pause_receipt_digest,
            ..
        } => anyhow::ensure!(
            &paused.pause_receipt_digest == pause_receipt_digest,
            "inherited Suspended pause receipt changed"
        ),
    }
    validate_attachment_lineage_advancement(
        &runtime.volume_receipts,
        &paused.local_durability_receipts,
    )
}

fn expected_pause_binding(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    paused: &PausedRuntimeEvidence,
) -> Result<StepBinding> {
    let current = StepBinding::new(command);
    if paused.pause_operation_id == current.operation_id
        && paused.pause_request_fingerprint == current.request_fingerprint
    {
        return Ok(current);
    }
    let prior = StepBinding::from_response(predecessor);
    let prior_is_retained_pause = matches!(&predecessor.result, NodeResult::Suspended(_))
        || matches!(&predecessor.result, NodeResult::NeedsIntervention(intervention)
            if intervention.attempted_target == InterventionTarget::Warm);
    anyhow::ensure!(
        prior_is_retained_pause
            && paused.pause_operation_id == prior.operation_id
            && paused.pause_request_fingerprint == prior.request_fingerprint,
        "VMM pause evidence belongs to neither this command nor its exact retained predecessor"
    );
    Ok(prior)
}

fn validate_volume_receipts(
    command: &LifecycleCommandEnvelope,
    receipts: &[VolumeTerminalReceipt],
    require_remote: bool,
) -> Result<()> {
    anyhow::ensure!(
        receipts.len() == command.runtime_config.volumes.len(),
        "Suspend/Warm receipt set is not the complete immutable Volume set"
    );
    for (configured, receipt) in command.runtime_config.volumes.iter().zip(receipts) {
        anyhow::ensure!(
            receipt.volume_id == configured.volume_id
                && receipt.disk_id == configured.disk_id
                && receipt.disk_role == configured.disk_role
                && receipt.remote_durable_generation <= receipt.local_durable_generation
                && (!require_remote
                    || receipt.remote_durable_generation == receipt.local_durable_generation)
                && receipt.authority_receipt_digest.is_some(),
            "Suspend/Warm Volume receipt is incomplete, reordered, or unsafe"
        );
    }
    Ok(())
}

fn validate_retained_volume_receipts(
    command: &LifecycleCommandEnvelope,
    receipts: &[VolumeTerminalReceipt],
) -> Result<()> {
    let mut configured_index = 0_usize;
    for receipt in receipts {
        while configured_index < command.runtime_config.volumes.len()
            && command.runtime_config.volumes[configured_index].volume_id < receipt.volume_id
        {
            configured_index += 1;
        }
        let configured = command
            .runtime_config
            .volumes
            .get(configured_index)
            .context("retained receipt names an unconfigured Volume")?;
        anyhow::ensure!(
            receipt.volume_id == configured.volume_id
                && receipt.disk_id == configured.disk_id
                && receipt.disk_role == configured.disk_role
                && receipt.remote_durable_generation <= receipt.local_durable_generation
                && receipt.authority_receipt_digest.is_some(),
            "retained Volume receipt is reordered, duplicated, or unsafe"
        );
        configured_index += 1;
    }
    Ok(())
}

fn validate_same_attachments(
    before: &[VolumeTerminalReceipt],
    after: &[VolumeTerminalReceipt],
) -> Result<()> {
    anyhow::ensure!(before.len() == after.len(), "Volume attachment set changed");
    for (before, after) in before.iter().zip(after) {
        anyhow::ensure!(
            before.volume_id == after.volume_id
                && before.disk_id == after.disk_id
                && before.disk_role == after.disk_role
                && before.attachment_id == after.attachment_id
                && before.attachment_epoch == after.attachment_epoch
                && before.authority_receipt_digest == after.authority_receipt_digest
                && before.local_durable_generation == after.local_durable_generation
                && before.remote_durable_generation <= after.remote_durable_generation,
            "Suspend/Warm changed attachment authority or local durable lineage"
        );
    }
    Ok(())
}

fn validate_attachment_lineage_advancement(
    before: &[VolumeTerminalReceipt],
    after: &[VolumeTerminalReceipt],
) -> Result<()> {
    anyhow::ensure!(before.len() == after.len(), "Volume attachment set changed");
    for (before, after) in before.iter().zip(after) {
        anyhow::ensure!(
            before.volume_id == after.volume_id
                && before.disk_id == after.disk_id
                && before.disk_role == after.disk_role
                && before.attachment_id == after.attachment_id
                && before.attachment_epoch == after.attachment_epoch
                && before.authority_receipt_digest == after.authority_receipt_digest
                && before.local_durable_generation <= after.local_durable_generation
                && before.remote_durable_generation <= after.remote_durable_generation,
            "Suspend pause changed attachment authority or regressed durable lineage"
        );
    }
    Ok(())
}

fn validate_attachment_subset(
    complete: &[VolumeTerminalReceipt],
    subset: &[VolumeTerminalReceipt],
) -> Result<()> {
    let mut complete_index = 0_usize;
    for retained in subset {
        while complete_index < complete.len()
            && complete[complete_index].volume_id < retained.volume_id
        {
            complete_index += 1;
        }
        let current = complete
            .get(complete_index)
            .context("retained receipt is outside the installed Volume set")?;
        anyhow::ensure!(
            current.volume_id == retained.volume_id
                && current.disk_id == retained.disk_id
                && current.disk_role == retained.disk_role
                && current.attachment_id == retained.attachment_id
                && current.attachment_epoch == retained.attachment_epoch
                && current.authority_receipt_digest == retained.authority_receipt_digest
                && current.local_durable_generation <= retained.local_durable_generation
                && current.remote_durable_generation <= retained.remote_durable_generation,
            "retained receipt changed installed attachment authority or lineage"
        );
        complete_index += 1;
    }
    Ok(())
}

/// Preserve every already-journaled attachment while incorporating any
/// fresher lineage returned by a partial physical failure inspection. A
/// partial provider view may refine known receipts, but it must never erase
/// the only retained evidence for an unaffected Volume.
fn merge_attachment_receipts(
    complete: &[VolumeTerminalReceipt],
    subset: &[VolumeTerminalReceipt],
) -> Result<Vec<VolumeTerminalReceipt>> {
    anyhow::ensure!(
        complete
            .windows(2)
            .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "complete retained Volume receipts are not strictly sorted"
    );
    validate_attachment_subset(complete, subset)?;
    let mut merged = complete.to_vec();
    for retained in subset {
        let index = merged
            .binary_search_by(|candidate| candidate.volume_id.cmp(&retained.volume_id))
            .map_err(|_| anyhow::anyhow!("validated retained receipt disappeared while merging"))?;
        merged[index] = retained.clone();
    }
    Ok(merged)
}

fn validate_prior_attachment_subset(
    prior: &[VolumeTerminalReceipt],
    current: &[VolumeTerminalReceipt],
) -> Result<()> {
    let mut current_index = 0_usize;
    for previous in prior {
        while current_index < current.len() && current[current_index].volume_id < previous.volume_id
        {
            current_index += 1;
        }
        let now = current
            .get(current_index)
            .context("prior receipt is outside the installed Volume set")?;
        anyhow::ensure!(
            now.volume_id == previous.volume_id
                && now.disk_id == previous.disk_id
                && now.disk_role == previous.disk_role
                && now.attachment_id == previous.attachment_id
                && now.attachment_epoch == previous.attachment_epoch
                && now.authority_receipt_digest == previous.authority_receipt_digest
                && now.local_durable_generation == previous.local_durable_generation
                && previous.remote_durable_generation <= now.remote_durable_generation,
            "installed attachment regressed or changed from retained predecessor evidence"
        );
        current_index += 1;
    }
    Ok(())
}

fn validate_running_predecessor_subset(
    prior: &[VolumeTerminalReceipt],
    current: &[VolumeTerminalReceipt],
) -> Result<()> {
    let mut current_index = 0_usize;
    for previous in prior {
        while current_index < current.len() && current[current_index].volume_id < previous.volume_id
        {
            current_index += 1;
        }
        let now = current
            .get(current_index)
            .context("RuntimeReady receipt is outside the installed Volume set")?;
        anyhow::ensure!(
            now.volume_id == previous.volume_id
                && now.disk_id == previous.disk_id
                && now.disk_role == previous.disk_role
                && now.attachment_id == previous.attachment_id
                && now.attachment_epoch == previous.attachment_epoch
                && now.authority_receipt_digest == previous.authority_receipt_digest
                && previous.local_durable_generation <= now.local_durable_generation
                && previous.remote_durable_generation <= now.remote_durable_generation,
            "Running attachment regressed or changed from RuntimeReady evidence"
        );
        current_index += 1;
    }
    Ok(())
}

fn validate_snapshot_evidence(
    snapshot_binding: &StepBinding,
    runtime: &InstalledRuntimeEvidence,
    write_fence: &RuntimeWriteFenceEvidence,
    paused: &PausedRuntimeEvidence,
    drained_volumes: &[VolumeTerminalReceipt],
    snapshot: &WarmSnapshotEvidence,
) -> Result<()> {
    anyhow::ensure!(
        snapshot.snapshot_operation_id == snapshot_binding.operation_id
            && snapshot.snapshot_request_fingerprint == snapshot_binding.request_fingerprint
            && snapshot.runtime_physical_identity_digest == runtime.physical_identity_digest
            && &snapshot.write_fence_receipt_digest == write_fence_receipt_digest(write_fence)
            && snapshot.pause_receipt_digest == paused.pause_receipt_digest
            && snapshot.snapshot_receipt_digest
                == warm_snapshot_receipt_digest(
                    snapshot_binding,
                    runtime,
                    write_fence,
                    paused,
                    drained_volumes,
                    &snapshot.snapshot_intent_digest,
                    &snapshot.snapshot_manifest_digest,
                )?,
        "Warm snapshot is not bound to the exact paused runtime"
    );
    Ok(())
}

fn expected_snapshot_binding(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    snapshot: &WarmSnapshotEvidence,
) -> Result<StepBinding> {
    let current = StepBinding::new(command);
    if snapshot.snapshot_operation_id == current.operation_id
        && snapshot.snapshot_request_fingerprint == current.request_fingerprint
    {
        return Ok(current);
    }
    let prior = StepBinding::from_response(predecessor);
    anyhow::ensure!(
        matches!(&predecessor.result, NodeResult::NeedsIntervention(intervention)
            if intervention.attempted_target == InterventionTarget::Warm)
            && snapshot.snapshot_operation_id == prior.operation_id
            && snapshot.snapshot_request_fingerprint == prior.request_fingerprint,
        "Warm snapshot belongs to neither this command nor its exact Warm retry predecessor"
    );
    Ok(prior)
}

fn validate_write_fence(
    runtime: &InstalledRuntimeEvidence,
    write_fence: &RuntimeWriteFenceEvidence,
) -> Result<()> {
    match write_fence {
        RuntimeWriteFenceEvidence::Guest { quiesce } => {
            anyhow::ensure!(
                runtime.vmm_state == InstalledVmmState::Executing,
                "Guest work fence is attached to a non-executing source"
            );
            validate_quiesce_evidence(runtime, quiesce)
        }
        RuntimeWriteFenceEvidence::InheritedSuspended {
            runtime_physical_identity_digest,
            ..
        } => {
            anyhow::ensure!(
                runtime.vmm_state == InstalledVmmState::Paused
                    && runtime_physical_identity_digest == &runtime.physical_identity_digest,
                "inherited Suspended fence is not bound to the exact paused runtime"
            );
            Ok(())
        }
    }
}

fn validate_write_fence_for_snapshot(
    runtime: &InstalledRuntimeEvidence,
    write_fence: &RuntimeWriteFenceEvidence,
) -> Result<()> {
    if runtime.vmm_state == InstalledVmmState::Absent {
        return match write_fence {
            RuntimeWriteFenceEvidence::Guest { quiesce } => {
                validate_quiesce_evidence(runtime, quiesce)
            }
            RuntimeWriteFenceEvidence::InheritedSuspended {
                runtime_physical_identity_digest,
                ..
            } => {
                anyhow::ensure!(
                    runtime_physical_identity_digest == &runtime.physical_identity_digest,
                    "inherited Suspended fence is not bound to the absent snapshot source"
                );
                Ok(())
            }
        };
    }
    validate_write_fence(runtime, write_fence)
}

fn write_fence_receipt_digest(write_fence: &RuntimeWriteFenceEvidence) -> &Sha256Digest {
    match write_fence {
        RuntimeWriteFenceEvidence::Guest { quiesce } => &quiesce.quiesce_receipt_digest,
        RuntimeWriteFenceEvidence::InheritedSuspended {
            pause_receipt_digest,
            ..
        } => pause_receipt_digest,
    }
}

fn validate_recovered_warm(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    recovered: &RecoveredWarmEvidence,
) -> Result<()> {
    anyhow::ensure!(
        matches!(&predecessor.result, NodeResult::NeedsIntervention(_))
            && recovered.runtime.runtime_config_digest == command.runtime_config.config_digest
            && recovered.runtime.vmm_state == InstalledVmmState::Absent,
        "Warm recovery is not an exact absent retained runtime"
    );
    validate_volume_receipts(command, &recovered.runtime.volume_receipts, true)?;
    validate_volume_receipts(command, &recovered.drained_volumes, true)?;
    validate_same_attachments(
        &recovered.runtime.volume_receipts,
        &recovered.drained_volumes,
    )?;
    if let NodeResult::NeedsIntervention(intervention) = &predecessor.result {
        validate_retained_volume_receipts(command, &intervention.retained_volume_receipts)?;
        validate_prior_attachment_subset(
            &intervention.retained_volume_receipts,
            &recovered.drained_volumes,
        )?;
    }
    validate_write_fence_for_snapshot(&recovered.runtime, &recovered.write_fence)?;
    // The snapshot adapter reopens and hashes the durable manifest; these
    // cross-links ensure it did not combine evidence from separate attempts.
    anyhow::ensure!(
        recovered.paused.runtime_physical_identity_digest
            == recovered.runtime.physical_identity_digest
            && &recovered.paused.write_fence_receipt_digest
                == write_fence_receipt_digest(&recovered.write_fence),
        "recovered Warm pause evidence is not internally exact"
    );
    validate_snapshot_evidence(
        &StepBinding::from_response(predecessor),
        &recovered.runtime,
        &recovered.write_fence,
        &recovered.paused,
        &recovered.drained_volumes,
        &recovered.snapshot,
    )?;
    let expected = warm_recovery_predecessor_evidence(
        command,
        predecessor,
        &recovered.runtime,
        &recovered.write_fence,
        &recovered.paused,
        &recovered.snapshot,
        &recovered.drained_volumes,
    )?;
    anyhow::ensure!(
        recovered.predecessor == expected,
        "recovered Warm artifacts changed their NeedsIntervention carrier"
    );
    Ok(())
}

fn validate_warm_stop_recovery_predecessor(
    inputs: WarmSnapshotInputs<'_>,
    snapshot: &WarmSnapshotEvidence,
    recovery_predecessor: Option<&WarmRecoveryPredecessorEvidence>,
) -> Result<()> {
    let WarmSnapshotInputs {
        command,
        predecessor,
        runtime,
        write_fence,
        paused,
        drained_volumes,
    } = inputs;
    match (&predecessor.result, recovery_predecessor) {
        (NodeResult::NeedsIntervention(intervention), Some(actual))
            if intervention.attempted_target == InterventionTarget::Warm =>
        {
            let expected = warm_recovery_predecessor_evidence(
                command,
                predecessor,
                runtime,
                write_fence,
                paused,
                snapshot,
                drained_volumes,
            )?;
            anyhow::ensure!(
                *actual == expected,
                "journaled Warm recovery carrier changed after fresh inspection"
            );
            Ok(())
        }
        (NodeResult::NeedsIntervention(_), None) => {
            anyhow::bail!("Warm retry lost its journaled NeedsIntervention carrier")
        }
        (NodeResult::NeedsIntervention(_), Some(_)) => {
            anyhow::bail!("Warm retry carrier names another intervention target")
        }
        (_, None) => Ok(()),
        (_, Some(_)) => anyhow::bail!(
            "ordinary Warm source cannot inherit a NeedsIntervention recovery carrier"
        ),
    }
}

fn intervention_reason(predecessor: &LifecycleCommandResponse) -> Result<InterventionReason> {
    match &predecessor.result {
        NodeResult::NeedsIntervention(intervention)
            if intervention.attempted_target == InterventionTarget::Warm =>
        {
            Ok(intervention.reason)
        }
        _ => anyhow::bail!("Warm recovery lacks its exact NeedsIntervention reason"),
    }
}

fn predecessor_retained_receipts(
    predecessor: &LifecycleCommandResponse,
) -> Vec<VolumeTerminalReceipt> {
    match &predecessor.result {
        NodeResult::RuntimeReady(ready) => ready.volume_receipts.clone(),
        NodeResult::Suspended(suspended) => suspended.local_durability_receipts.clone(),
        NodeResult::NeedsIntervention(intervention) => {
            intervention.retained_volume_receipts.clone()
        }
        _ => Vec::new(),
    }
}

fn preserve_complete_predecessor_receipts(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    observed_subset: &[VolumeTerminalReceipt],
) -> Result<Vec<VolumeTerminalReceipt>> {
    validate_retained_volume_receipts(command, observed_subset)?;
    let complete = predecessor_retained_receipts(predecessor);
    if complete.len() != command.runtime_config.volumes.len() {
        return Ok(observed_subset.to_vec());
    }
    validate_volume_receipts(command, &complete, false)?;
    merge_attachment_receipts(&complete, observed_subset)
}

fn validate_retained_after_warm(
    drained: &[VolumeTerminalReceipt],
    retained: &[VolumeTerminalReceipt],
) -> Result<()> {
    anyhow::ensure!(
        drained == retained,
        "post-snapshot strong Stop changed or omitted retained Volume evidence"
    );
    Ok(())
}

#[derive(Serialize)]
struct WarmReadyReceiptPreimage<'a> {
    binding: StepBinding,
    snapshot: &'a WarmSnapshotEvidence,
    execution_absence: &'a ExecutionAbsenceProof,
    volume_receipts: &'a [VolumeTerminalReceipt],
}

fn warm_ready_receipt_digest(
    command: &LifecycleCommandEnvelope,
    snapshot: &WarmSnapshotEvidence,
    execution_absence: &ExecutionAbsenceProof,
    volume_receipts: &[VolumeTerminalReceipt],
) -> Result<Sha256Digest> {
    warm_ready_receipt_digest_for_binding(
        &StepBinding::new(command),
        snapshot,
        execution_absence,
        volume_receipts,
    )
}

fn warm_ready_receipt_digest_for_binding(
    binding: &StepBinding,
    snapshot: &WarmSnapshotEvidence,
    execution_absence: &ExecutionAbsenceProof,
    volume_receipts: &[VolumeTerminalReceipt],
) -> Result<Sha256Digest> {
    let canonical = serde_json::to_vec(&WarmReadyReceiptPreimage {
        binding: binding.clone(),
        snapshot,
        execution_absence,
        volume_receipts,
    })
    .context("encode exact Warm terminal receipt")?;
    Ok(digest_parts(WARM_READY_RECEIPT_DOMAIN, &[&canonical]))
}

#[derive(Serialize)]
struct WarmSnapshotReceiptPreimage<'a> {
    binding: StepBinding,
    runtime_incarnation: &'a RandomId128,
    runtime_physical_identity_digest: &'a Sha256Digest,
    write_fence: &'a RuntimeWriteFenceEvidence,
    pause_receipt_digest: &'a Sha256Digest,
    drained_volumes: &'a [VolumeTerminalReceipt],
    snapshot_intent_digest: &'a Sha256Digest,
    snapshot_manifest_digest: &'a Sha256Digest,
}

#[derive(Serialize)]
struct PauseReceiptPreimage<'a> {
    binding: StepBinding,
    runtime_incarnation: &'a RandomId128,
    runtime_physical_identity_digest: &'a Sha256Digest,
    write_fence: &'a RuntimeWriteFenceEvidence,
    local_durability_receipts: &'a [VolumeTerminalReceipt],
}

fn pause_receipt_digest(
    pause_binding: &StepBinding,
    runtime: &InstalledRuntimeEvidence,
    write_fence: &RuntimeWriteFenceEvidence,
    local_durability_receipts: &[VolumeTerminalReceipt],
) -> Result<Sha256Digest> {
    let canonical = serde_json::to_vec(&PauseReceiptPreimage {
        binding: pause_binding.clone(),
        runtime_incarnation: &runtime.runtime_incarnation,
        runtime_physical_identity_digest: &runtime.physical_identity_digest,
        write_fence,
        local_durability_receipts,
    })
    .context("encode exact VMM pause receipt")?;
    Ok(digest_parts(PAUSE_RECEIPT_DOMAIN, &[&canonical]))
}

fn warm_snapshot_receipt_digest(
    snapshot_binding: &StepBinding,
    runtime: &InstalledRuntimeEvidence,
    write_fence: &RuntimeWriteFenceEvidence,
    paused: &PausedRuntimeEvidence,
    drained_volumes: &[VolumeTerminalReceipt],
    snapshot_intent_digest: &Sha256Digest,
    snapshot_manifest_digest: &Sha256Digest,
) -> Result<Sha256Digest> {
    let canonical = serde_json::to_vec(&WarmSnapshotReceiptPreimage {
        binding: snapshot_binding.clone(),
        runtime_incarnation: &runtime.runtime_incarnation,
        runtime_physical_identity_digest: &runtime.physical_identity_digest,
        write_fence,
        pause_receipt_digest: &paused.pause_receipt_digest,
        drained_volumes,
        snapshot_intent_digest,
        snapshot_manifest_digest,
    })
    .context("encode exact Warm snapshot receipt")?;
    Ok(digest_parts(WARM_SNAPSHOT_RECEIPT_DOMAIN, &[&canonical]))
}

fn guest_quiesce_receipt_digest(
    runtime_physical_identity_digest: &Sha256Digest,
    source_epoch_digest: &Sha256Digest,
    lease_sequence: u64,
) -> Sha256Digest {
    digest_parts(
        b"cats.atomic-lifecycle.guest-work-fence.v1",
        &[
            runtime_physical_identity_digest.as_bytes(),
            source_epoch_digest.as_bytes(),
            &lease_sequence.to_be_bytes(),
        ],
    )
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
    let mut hash = Sha256::new();
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    Sha256Digest::from_bytes(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::runtime_lifecycle::{
        ColdSpec, DiskRole, ImmutableRuntimeConfig, LifecyclePredecessor, PlacementIdentity,
        RuntimeVolumeConfig, RuntimeVolumeGuestBinding, StopSpec, SuspendSpec, TerminalResultKind,
        WarmSpec,
    };
    #[cfg(target_os = "linux")]
    use cats_api::runtime_lifecycle::{
        RuntimeReadyResult, RuntimeVolumeAuthorityInput, StartSpec, StartVolumeAuthority,
        WarmResult,
    };
    use cats_api::runtime_reconciliation::{
        AsciiText, IsolatedIpv4Kind, NetworkConfig, RuntimeLaunchArtifact, RuntimeLaunchIdentity,
        RuntimeNetworkIdentity, VmmBootProvenance,
    };
    use cats_api::runtime_reconciliation::{
        Durability, Epoch, FenceEpoch, Generation, Ipv4Address, MacAddress, WireU64,
    };
    #[cfg(target_os = "linux")]
    use cats_storage::authority::{
        AuthorityError, NodeVolumeInventorySnapshot, RuntimeVolumeInventoryAuthority,
    };

    use super::super::start::{
        InstalledRuntimeBlockFrontend, InstalledRuntimeNetworkManifest, InstalledRuntimeVmmManifest,
    };

    fn id(value: &str) -> Id {
        Id::new(value).expect("valid test ID")
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn random(byte: u8) -> RandomId128 {
        RandomId128::new(format!("{byte:02x}").repeat(16)).expect("valid test random ID")
    }

    fn runtime_config() -> ImmutableRuntimeConfig {
        ImmutableRuntimeConfig::new(
            id("config_suspend_warm"),
            digest(1),
            2,
            512 * 1024 * 1024,
            digest(2),
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id: id("network_suspend_warm"),
                guest_mac: MacAddress::new("02:00:00:00:00:12").expect("valid MAC"),
                guest_ipv4: Ipv4Address::new("10.0.0.2").expect("valid Guest IP"),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.1").expect("valid gateway IP"),
            },
            vec![RuntimeVolumeConfig {
                volume_id: id("volume_suspend_warm_root"),
                disk_id: id("disk_suspend_warm_root"),
                disk_role: DiskRole::Root,
                size_bytes: 1024 * 1024,
                durability: Durability::Relaxed,
                guest_device_serial: id("suspend_warm_root"),
                guest_device_slot: 0,
                guest_binding: RuntimeVolumeGuestBinding::RootBoot,
            }],
        )
        .expect("valid runtime config")
    }

    fn receipt(local: u64, remote: u64) -> VolumeTerminalReceipt {
        VolumeTerminalReceipt {
            volume_id: id("volume_suspend_warm_root"),
            disk_id: id("disk_suspend_warm_root"),
            disk_role: DiskRole::Root,
            attachment_id: id("attachment_suspend_warm_root"),
            attachment_epoch: FenceEpoch::new(3).expect("valid attachment epoch"),
            local_durable_generation: Generation::new(local).expect("valid local generation"),
            remote_durable_generation: Generation::new(remote).expect("valid remote generation"),
            authority_receipt_digest: Some(digest(16)),
        }
    }

    fn absence(byte: u8) -> ExecutionAbsenceProof {
        ExecutionAbsenceProof {
            stop_fence_receipt_digest: digest(byte),
            admission_closed_receipt_digest: digest(byte.wrapping_add(1)),
            dedicated_scope_absence_receipt_digest: digest(byte.wrapping_add(2)),
            frontend_absence_receipt_digest: digest(byte.wrapping_add(3)),
            restart_source_absence_receipt_digest: digest(byte.wrapping_add(4)),
        }
    }

    fn prepared_manifest(command: &LifecycleCommandEnvelope) -> WarmSnapshotManifest {
        let runtime = InstalledRuntimeEvidence {
            runtime_incarnation: random(30),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            physical_identity_digest: digest(31),
            vmm_state: InstalledVmmState::Executing,
            volume_receipts: vec![receipt(7, 7)],
        };
        let source_epoch_digest = digest(32);
        let quiesce = GuestQuiesceEvidence {
            runtime_physical_identity_digest: runtime.physical_identity_digest.clone(),
            source_epoch_digest: source_epoch_digest.clone(),
            lease_sequence: 4,
            quiesce_receipt_digest: guest_quiesce_receipt_digest(
                &runtime.physical_identity_digest,
                &source_epoch_digest,
                4,
            ),
        };
        let write_fence = RuntimeWriteFenceEvidence::Guest { quiesce };
        let binding = StepBinding::new(command);
        let paused = PausedRuntimeEvidence {
            pause_operation_id: binding.operation_id.clone(),
            pause_request_fingerprint: binding.request_fingerprint.clone(),
            runtime_physical_identity_digest: runtime.physical_identity_digest.clone(),
            write_fence_receipt_digest: write_fence_receipt_digest(&write_fence).clone(),
            pause_receipt_digest: pause_receipt_digest(
                &binding,
                &runtime,
                &write_fence,
                &runtime.volume_receipts,
            )
            .expect("encode fixture pause receipt"),
            local_durability_receipts: runtime.volume_receipts.clone(),
        };
        let snapshot_intent_digest = digest(36);
        let body = WarmSnapshotManifestBody {
            version: STEP_VERSION,
            binding: binding.clone(),
            workspace_id: command.workspace_id.clone(),
            cat_id: command.cat_id.clone(),
            node_id: command.node_id.clone(),
            placement_identity: command.placement_identity.clone(),
            runtime_config_id: command.runtime_config.config_id.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            runtime: runtime.clone(),
            write_fence: write_fence.clone(),
            paused: paused.clone(),
            drained_volumes: runtime.volume_receipts.clone(),
            snapshot_intent_digest: snapshot_intent_digest.clone(),
            installed_runtime_manifest_digest: digest(33),
            content_directory_name: format!(
                "{}{WARM_SNAPSHOT_CONTENT_SUFFIX}",
                warm_snapshot_key(&binding)
            ),
            snapshot_tree: WarmSnapshotTreeProof {
                digest: digest(34),
                regular_file_count: 1,
                total_file_bytes: 3,
            },
            memory_file: WarmMemoryFileProof {
                path: cats_api::runtime_reconciliation::HostPath::new(
                    "/var/lib/cats/test/warm-memory",
                )
                .expect("valid fixture memory path"),
                device: 1,
                inode: 2,
                size_bytes: 1,
                digest: digest(35),
            },
        };
        let snapshot_manifest_digest =
            warm_snapshot_manifest_digest(&body).expect("digest fixture prepared manifest");
        let evidence = WarmSnapshotEvidence {
            snapshot_operation_id: binding.operation_id.clone(),
            snapshot_request_fingerprint: binding.request_fingerprint.clone(),
            runtime_physical_identity_digest: runtime.physical_identity_digest.clone(),
            write_fence_receipt_digest: write_fence_receipt_digest(&write_fence).clone(),
            pause_receipt_digest: paused.pause_receipt_digest.clone(),
            snapshot_intent_digest: snapshot_intent_digest.clone(),
            snapshot_receipt_digest: warm_snapshot_receipt_digest(
                &binding,
                &runtime,
                &write_fence,
                &paused,
                &runtime.volume_receipts,
                &snapshot_intent_digest,
                &snapshot_manifest_digest,
            )
            .expect("digest fixture snapshot receipt"),
            snapshot_manifest_digest,
        };
        let manifest = WarmSnapshotManifest { body, evidence };
        validate_warm_snapshot_manifest_internal(&manifest)
            .expect("fixture prepared manifest is closed");
        manifest
    }

    fn snapshot_intent(command: &LifecycleCommandEnvelope) -> WarmSnapshotIntent {
        let prepared = prepared_manifest(command);
        let plan = WarmSnapshotPlan {
            installed_runtime_manifest_digest: prepared
                .body
                .installed_runtime_manifest_digest
                .clone(),
            vmm_process: InstalledRuntimeProcessIdentity {
                pid: 41,
                start_time_ticks: WireU64::new(42).expect("valid fixture start time"),
            },
            vmm_api_socket_path: cats_api::runtime_reconciliation::HostPath::new(
                "/var/lib/cats/test/ch.sock",
            )
            .expect("valid fixture API path"),
            memory_file_path: prepared.body.memory_file.path.clone(),
            content_directory_name: prepared.body.content_directory_name.clone(),
        };
        let plan_digest = warm_snapshot_plan_digest(&plan).expect("digest fixture snapshot plan");
        let body = WarmSnapshotIntentBody {
            version: STEP_VERSION,
            binding: prepared.body.binding.clone(),
            workspace_id: prepared.body.workspace_id.clone(),
            cat_id: prepared.body.cat_id.clone(),
            node_id: prepared.body.node_id.clone(),
            placement_identity: prepared.body.placement_identity.clone(),
            runtime_config_id: prepared.body.runtime_config_id.clone(),
            runtime_config_digest: prepared.body.runtime_config_digest.clone(),
            source_runtime_incarnation: prepared.body.runtime.runtime_incarnation.clone(),
            runtime_physical_identity_digest: prepared
                .body
                .runtime
                .physical_identity_digest
                .clone(),
            write_fence_receipt_digest: write_fence_receipt_digest(&prepared.body.write_fence)
                .clone(),
            pause_receipt_digest: prepared.body.paused.pause_receipt_digest.clone(),
            drained_volumes: prepared.body.drained_volumes.clone(),
            plan,
            plan_digest,
        };
        let intent = WarmSnapshotIntent {
            intent_digest: warm_snapshot_intent_digest(&body)
                .expect("digest fixture snapshot intent"),
            body,
        };
        validate_warm_snapshot_intent_internal(&intent).expect("fixture intent is closed");
        intent
    }

    #[cfg(target_os = "linux")]
    struct EmptyVolumeInventory;

    #[cfg(target_os = "linux")]
    impl RuntimeVolumeInventoryAuthority for EmptyVolumeInventory {
        fn load_node_volume_inventory(
            &self,
            node_id: &Id,
            _candidate_volume_ids: &BTreeSet<Id>,
        ) -> std::result::Result<NodeVolumeInventorySnapshot, AuthorityError> {
            Ok(NodeVolumeInventorySnapshot {
                node_id: node_id.clone(),
                read_at_unix_ms: UnixMillis::new(1).expect("valid inventory time"),
                records: Vec::new(),
            })
        }
    }

    #[cfg(target_os = "linux")]
    fn physical_for_warm_inventory(
        state: crate::state_directory::StateDirectory,
        node_id: Id,
    ) -> InstalledPhysicalInspectionConfig {
        InstalledPhysicalInspectionConfig {
            state_directory: state,
            node_id,
            volume_inventory_authority: Arc::new(EmptyVolumeInventory),
            systemctl_binary: PathBuf::from("/bin/false"),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            proc_root: PathBuf::from("/proc"),
            ip_binary: PathBuf::from("/bin/false"),
            network_class_root: PathBuf::from("/sys/class/net"),
            managed_socket_roots: Vec::new(),
            managed_process_binaries: BTreeSet::new(),
            kernel_nbd: None,
            inventory_timeout: Duration::from_secs(1),
            physical_probe_timeout: Duration::from_secs(1),
        }
    }

    fn test_launch_artifact(path: &str, byte: u8) -> RuntimeLaunchArtifact {
        RuntimeLaunchArtifact {
            path: HostPath::new(path).expect("valid launch artifact path"),
            length: WireU64::new(1).expect("valid launch artifact length"),
            content_sha256: digest(byte),
        }
    }

    pub(super) fn cleanup_installed_runtime(
        command: &LifecycleCommandEnvelope,
        runtime_incarnation: &RandomId128,
        memory_file_path: &HostPath,
    ) -> InstalledRuntimeManifest {
        let RuntimeNetworkConfig::IsolatedIpv4 {
            network_id,
            guest_mac,
            guest_ipv4,
            prefix_length,
            gateway_ipv4,
        } = &command.runtime_config.network_config;
        let network = RuntimeNetworkIdentity {
            network_config: NetworkConfig {
                kind: IsolatedIpv4Kind::IsolatedIpv4,
                network_id: network_id.clone(),
                guest_mac: guest_mac.clone(),
                guest_ipv4: guest_ipv4.clone(),
                prefix_length: *prefix_length,
                gateway_ipv4: gateway_ipv4.clone(),
            },
            tap_name: id("tap_warm_stop_cleanup"),
            ownership_token: random(91),
        };
        let api_socket_path =
            HostPath::new("/run/cats/test-warm-stop-api.sock").expect("valid API socket path");
        let vsock_socket_path =
            HostPath::new("/run/cats/test-warm-stop-vsock.sock").expect("valid vsock socket path");
        let launch = RuntimeLaunchIdentity {
            runtime_incarnation: runtime_incarnation.clone(),
            scope_id: id("cats_warm_stop_vmm"),
            launcher_executable: Box::new(test_launch_artifact("/usr/lib/cats/vmm-launcher", 92)),
            boot: Box::new(VmmBootProvenance {
                vmm_executable: test_launch_artifact("/usr/bin/cloud-hypervisor", 93),
                kernel: test_launch_artifact("/usr/lib/cats/vmlinux", 94),
                initramfs: None,
                kernel_cmdline: AsciiText::new("console=hvc0").expect("valid kernel command line"),
            }),
            process_identity_token: random(95),
            vcpus: command.runtime_config.vcpus,
            memory_bytes: command.runtime_config.memory_bytes,
            boot_image_digest: command.runtime_config.boot_image_digest.clone(),
            guest_config_digest: command.runtime_config.guest_runtime_profile_digest.clone(),
            api_socket_path: api_socket_path.clone(),
            vsock_socket_path: vsock_socket_path.clone(),
            guest_cid: 8,
            memory_file_path: memory_file_path.clone(),
            serial_log_path: HostPath::new("/var/log/cats/test-warm-stop-serial.log")
                .expect("valid serial log path"),
            vmm_log_path: HostPath::new("/var/log/cats/test-warm-stop.log")
                .expect("valid VMM log path"),
            network: Box::new(network.clone()),
            devices: Vec::new(),
        };
        let head = RemoteHead {
            generation: Generation::new(7).expect("valid generation"),
            root_hash: None,
            root_object_id: None,
        };
        let volumes = command
            .runtime_config
            .volumes
            .iter()
            .enumerate()
            .map(|(index, configured)| {
                let attachment_id = if index == 0 {
                    id("attachment_suspend_warm_root")
                } else {
                    Id::new(format!("test_retained_warm_attachment_{index}"))
                        .expect("valid fixture attachment ID")
                };
                let lineage_path = if index == 0 {
                    "/var/lib/cats/test-warm-stop-lineage".to_owned()
                } else {
                    format!("/var/lib/cats/test-retained-warm-lineage/{index}")
                };
                let blockd_path = if index == 0 {
                    "/run/cats/test-warm-stop-blockd.sock".to_owned()
                } else {
                    format!("/run/cats/test-retained-warm-blockd-{index}.sock")
                };
                let frontend_path = if index == 0 {
                    "/run/cats/test-warm-stop-vhost.sock".to_owned()
                } else {
                    format!("/run/cats/test-retained-warm-vhost-{index}.sock")
                };
                InstalledRuntimeVolumeManifest {
                    volume_id: configured.volume_id.clone(),
                    disk_id: configured.disk_id.clone(),
                    disk_role: configured.disk_role,
                    attachment_id,
                    attachment_epoch: FenceEpoch::new(3).expect("valid attachment epoch"),
                    acquire_origin: AcquireOrigin::Normal {
                        transition_id: random(99_u8.wrapping_add(index as u8)),
                    },
                    launch_head: head.clone(),
                    current_authority_head: head.clone(),
                    authority_receipt_digest: Some(digest(16_u8.wrapping_add(index as u8))),
                    local_lineage_data_directory: HostPath::new(lineage_path)
                        .expect("valid lineage path"),
                    blockd: InstalledRuntimeProcessIdentity {
                        pid: 101,
                        start_time_ticks: WireU64::new(2).expect("valid process start time"),
                    },
                    blockd_control_socket_path: HostPath::new(blockd_path)
                        .expect("valid blockd socket path"),
                    frontend: InstalledRuntimeBlockFrontend::VhostUserBlk {
                        socket_path: HostPath::new(frontend_path).expect("valid vhost socket path"),
                    },
                }
            })
            .collect();
        let mut manifest = InstalledRuntimeManifest {
            version: cats_api::runtime_reconciliation::ContractVersion::V1,
            node_id: command.node_id.clone(),
            cat_id: command.cat_id.clone(),
            placement_identity: command.placement_identity.clone(),
            source_lifecycle_operation_id: id("operation_ready"),
            request_fingerprint: digest(96),
            runtime_config_id: command.runtime_config.config_id.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            runtime_incarnation: runtime_incarnation.clone(),
            execution_receipt_digest: digest(97),
            guest_ready_receipt_digest: digest(98),
            retired_restart_source_absence_digest: None,
            vmm: InstalledRuntimeVmmManifest {
                process: InstalledRuntimeProcessIdentity {
                    pid: 100,
                    start_time_ticks: WireU64::new(1).expect("valid process start time"),
                },
                parent_slice_id: id("cats_warm_stop_parent"),
                systemd_unit_id: id("cats_warm_stop_vmm"),
                api_socket_path,
                vsock_socket_path,
                memory_file_path: memory_file_path.clone(),
                launch_identity: Box::new(launch),
            },
            network: InstalledRuntimeNetworkManifest {
                identity: Box::new(network),
            },
            volumes,
            manifest_digest: Sha256Digest::from_bytes([0; 32]),
        };
        manifest.manifest_digest = installed_runtime_manifest_digest(&manifest)
            .expect("digest exact cleanup installed runtime");
        manifest
    }

    #[cfg(target_os = "linux")]
    struct WarmStopCleanupFixture {
        _directory: tempfile::TempDir,
        physical: InstalledPhysicalInspectionConfig,
        command: LifecycleCommandEnvelope,
        authority: WarmSnapshotCleanupAuthority,
        namespace_path: PathBuf,
        terminal_path: PathBuf,
        memory_path: PathBuf,
    }

    #[cfg(target_os = "linux")]
    fn warm_stop_cleanup_fixture() -> WarmStopCleanupFixture {
        let directory = tempfile::tempdir().expect("create Warm Stop StateDirectory");
        let state =
            crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf());
        let placement = PlacementIdentity {
            node_id: id("node_suspend_warm"),
            placement_epoch: Epoch::new(1).expect("valid placement epoch"),
        };
        let attempted = LifecycleCommandEnvelope::new(
            id("operation_warm_for_stop"),
            id("workspace_suspend_warm"),
            id("cat_suspend_warm"),
            placement.node_id.clone(),
            placement.clone(),
            runtime_config(),
            Some(id("operation_ready")),
            LifecyclePredecessor::SameNode {
                operation_id: id("operation_ready"),
                terminal_result_kind: TerminalResultKind::RuntimeReady,
                terminal_result_digest: digest(101),
                node_id: placement.node_id.clone(),
                placement_identity: placement.clone(),
            },
            LifecycleCommand::Warm(WarmSpec {
                grace_deadline_unix_ms: UnixMillis::new(8_000_000_000_000).expect("valid deadline"),
                convergence_deadline_unix_ms: UnixMillis::new(8_000_000_001_000)
                    .expect("valid deadline"),
            }),
        )
        .expect("valid Warm command");
        let runtime_incarnation = random(102);
        let predecessor = LifecycleCommandResponse::new(
            &attempted,
            NodeResult::Warm(Box::new(WarmResult {
                runtime_config_digest: attempted.runtime_config.config_digest.clone(),
                source_runtime_incarnation: runtime_incarnation.clone(),
                warm_snapshot_receipt_digest: digest(103),
                warm_snapshot_manifest_digest: digest(104),
                volume_receipts: vec![receipt(7, 7)],
            })),
        )
        .expect("valid Warm predecessor response");
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(predecessor.clone()),
        };
        let command = LifecycleCommandEnvelope::new(
            id("operation_stop_warm"),
            predecessor.workspace_id.clone(),
            predecessor.cat_id.clone(),
            predecessor.node_id.clone(),
            predecessor.placement_identity.clone(),
            runtime_config(),
            Some(predecessor.operation_id.clone()),
            LifecyclePredecessor::SameNode {
                operation_id: predecessor.operation_id.clone(),
                terminal_result_kind: TerminalResultKind::Warm,
                terminal_result_digest: lifecycle_terminal_result_digest(&terminal)
                    .expect("digest Warm predecessor"),
                node_id: predecessor.node_id.clone(),
                placement_identity: predecessor.placement_identity.clone(),
            },
            LifecycleCommand::Stop(StopSpec {
                grace_deadline_unix_ms: UnixMillis::new(8_000_000_002_000).expect("valid deadline"),
            }),
        )
        .expect("valid Stop after Warm");
        let request = WarmSnapshotCleanupRequest::from_warm_predecessor(&predecessor)
            .expect("freeze Warm cleanup request");
        let prepared_binding = StepBinding {
            version: STEP_VERSION,
            operation_id: id("operation_warm_prepared"),
            request_fingerprint: digest(105),
        };
        let terminal_binding = StepBinding::from_response(&predecessor);
        let namespace_path = directory.path().join(WARM_SNAPSHOT_NAMESPACE);
        std::fs::create_dir(&namespace_path).expect("create Warm namespace");
        let terminal_name = warm_component_name(&terminal_binding, WARM_TERMINAL_MANIFEST_SUFFIX)
            .expect("valid terminal name");
        let intent_name = warm_component_name(&prepared_binding, WARM_SNAPSHOT_INTENT_SUFFIX)
            .expect("valid intent name");
        let prepared_name = warm_component_name(&prepared_binding, WARM_SNAPSHOT_MANIFEST_SUFFIX)
            .expect("valid prepared name");
        let content_name = warm_component_name(&prepared_binding, WARM_SNAPSHOT_CONTENT_SUFFIX)
            .expect("valid content name");
        let terminal_path = namespace_path.join(terminal_name.to_str().expect("UTF-8 name"));
        let intent_path = namespace_path.join(intent_name.to_str().expect("UTF-8 name"));
        let prepared_path = namespace_path.join(prepared_name.to_str().expect("UTF-8 name"));
        let content_path = namespace_path.join(content_name.to_str().expect("UTF-8 name"));
        std::fs::write(&terminal_path, b"terminal").expect("write terminal fixture");
        std::fs::write(&intent_path, b"intent").expect("write intent fixture");
        std::fs::write(&prepared_path, b"prepared").expect("write prepared fixture");
        std::fs::create_dir(&content_path).expect("create snapshot content fixture");
        std::fs::write(content_path.join("state"), b"snapshot-state")
            .expect("write snapshot content fixture");
        let memory_parent_path = directory.path().join("runtime-memory");
        std::fs::create_dir(&memory_parent_path).expect("create memory parent");
        let memory_path = memory_parent_path.join("memory.bin");
        std::fs::write(&memory_path, b"warm-stop-memory").expect("write Warm memory fixture");
        let memory_file = memory_file_proof_from_path(
            &memory_path,
            b"warm-stop-memory".len() as u64,
            Instant::now() + Duration::from_secs(2),
            true,
        )
        .expect("prove Warm memory fixture");
        let namespace = File::open(&namespace_path).expect("open Warm namespace");
        let memory_parent = File::open(&memory_parent_path).expect("open memory parent");
        let mut authority = WarmSnapshotCleanupAuthority {
            version: STEP_VERSION,
            cleanup_operation_id: command.operation_id.clone(),
            cleanup_request_fingerprint: command.request_fingerprint.clone(),
            workspace_id: command.workspace_id.clone(),
            cat_id: command.cat_id.clone(),
            node_id: command.node_id.clone(),
            placement_identity: command.placement_identity.clone(),
            runtime_config_id: command.runtime_config.config_id.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            request,
            terminal_operation_id: terminal_binding.operation_id,
            terminal_request_fingerprint: terminal_binding.request_fingerprint,
            prepared_operation_id: prepared_binding.operation_id,
            prepared_request_fingerprint: prepared_binding.request_fingerprint,
            mode: WarmSnapshotCleanupMode::Remove,
            snapshot_directory: HostPath::new(content_path.to_str().expect("UTF-8 content path"))
                .expect("valid content path"),
            installed_runtime: Some(Box::new(cleanup_installed_runtime(
                &command,
                &runtime_incarnation,
                &memory_file.path,
            ))),
            memory_file,
            memory_parent_identity: directory_identity(&memory_parent)
                .expect("inspect memory parent"),
            namespace_identity: directory_identity(&namespace).expect("inspect Warm namespace"),
            terminal_manifest_identity: regular_single_link_identity(
                &File::open(&terminal_path).expect("open terminal fixture"),
            )
            .expect("inspect terminal fixture"),
            intent_manifest_identity: regular_single_link_identity(
                &File::open(&intent_path).expect("open intent fixture"),
            )
            .expect("inspect intent fixture"),
            prepared_manifest_identity: regular_single_link_identity(
                &File::open(&prepared_path).expect("open prepared fixture"),
            )
            .expect("inspect prepared fixture"),
            content_directory_identity: directory_identity(
                &File::open(&content_path).expect("open content fixture"),
            )
            .expect("inspect content fixture"),
            retained_retry: None,
            authority_digest: Sha256Digest::from_bytes([0; 32]),
        };
        authority.authority_digest =
            warm_cleanup_authority_digest(&authority).expect("digest Stop cleanup authority");
        let physical = physical_for_warm_inventory(state, command.node_id.clone());
        validate_warm_cleanup_authority(&physical, &command, &authority)
            .expect("fixture is exact Stop cleanup authority");
        WarmStopCleanupFixture {
            _directory: directory,
            physical,
            command,
            authority,
            namespace_path,
            terminal_path,
            memory_path,
        }
    }

    fn terminal_manifest(
        command: &LifecycleCommandEnvelope,
        prepared: &WarmSnapshotManifest,
        execution_absence: ExecutionAbsenceProof,
    ) -> WarmTerminalManifest {
        let binding = StepBinding::new(command);
        let warm_receipt_digest = warm_ready_receipt_digest_for_binding(
            &binding,
            &prepared.evidence,
            &execution_absence,
            &prepared.body.drained_volumes,
        )
        .expect("digest fixture Warm receipt");
        let body = WarmTerminalManifestBody {
            version: STEP_VERSION,
            binding,
            workspace_id: command.workspace_id.clone(),
            cat_id: command.cat_id.clone(),
            node_id: command.node_id.clone(),
            placement_identity: command.placement_identity.clone(),
            runtime_config_id: command.runtime_config.config_id.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            source_runtime_incarnation: prepared.body.runtime.runtime_incarnation.clone(),
            snapshot_intent_digest: prepared.body.snapshot_intent_digest.clone(),
            prepared_snapshot: prepared.evidence.clone(),
            drained_volumes: prepared.body.drained_volumes.clone(),
            execution_absence,
            warm_receipt_digest,
        };
        let terminal_manifest_digest =
            warm_terminal_manifest_digest(&body).expect("digest fixture terminal manifest");
        let manifest = WarmTerminalManifest {
            body,
            terminal_manifest_digest,
        };
        validate_warm_terminal_manifest_internal(&manifest)
            .expect("fixture terminal manifest is closed");
        manifest
    }

    fn suspend_command() -> LifecycleCommandEnvelope {
        let placement = PlacementIdentity {
            node_id: id("node_suspend_warm"),
            placement_epoch: Epoch::new(1).expect("valid placement epoch"),
        };
        LifecycleCommandEnvelope::new(
            id("operation_suspend"),
            id("workspace_suspend_warm"),
            id("cat_suspend_warm"),
            placement.node_id.clone(),
            placement.clone(),
            runtime_config(),
            Some(id("operation_ready")),
            LifecyclePredecessor::SameNode {
                operation_id: id("operation_ready"),
                terminal_result_kind: TerminalResultKind::RuntimeReady,
                terminal_result_digest: digest(3),
                node_id: placement.node_id.clone(),
                placement_identity: placement,
            },
            LifecycleCommand::Suspend(SuspendSpec {
                admission_policy: SuspendAdmissionPolicy::CloseAndDrain,
                grace_deadline_unix_ms: UnixMillis::new(8_000_000_000_000).expect("valid deadline"),
            }),
        )
        .expect("valid Suspend command shape")
    }

    fn warm_needs_intervention_retry() -> (
        LifecycleCommandResponse,
        LifecycleCommandEnvelope,
        RecoveredWarmEvidence,
    ) {
        let placement = PlacementIdentity {
            node_id: id("node_suspend_warm"),
            placement_epoch: Epoch::new(1).expect("valid placement epoch"),
        };
        let attempted = LifecycleCommandEnvelope::new(
            id("operation_warm_attempt"),
            id("workspace_suspend_warm"),
            id("cat_suspend_warm"),
            placement.node_id.clone(),
            placement.clone(),
            runtime_config(),
            Some(id("operation_ready")),
            LifecyclePredecessor::SameNode {
                operation_id: id("operation_ready"),
                terminal_result_kind: TerminalResultKind::RuntimeReady,
                terminal_result_digest: digest(3),
                node_id: placement.node_id.clone(),
                placement_identity: placement.clone(),
            },
            LifecycleCommand::Warm(WarmSpec {
                grace_deadline_unix_ms: UnixMillis::new(8_000_000_000_000).expect("valid deadline"),
                convergence_deadline_unix_ms: UnixMillis::new(8_000_000_001_000)
                    .expect("valid deadline"),
            }),
        )
        .expect("valid first Warm command");
        let predecessor = LifecycleCommandResponse::new(
            &attempted,
            NodeResult::NeedsIntervention(Box::new(NeedsInterventionResult {
                attempted_target: InterventionTarget::Warm,
                reason: InterventionReason::WarmSnapshotAmbiguous,
                not_running: absence(50),
                retained_evidence: RetainedEvidence {
                    artifact_manifest_digest: digest(56),
                    adoptable_count: 0,
                    gc_candidate_count: 0,
                    retained_authority_or_data_count: 1,
                    quarantined_count: 0,
                },
                retained_volume_receipts: vec![receipt(7, 7)],
            })),
        )
        .expect("valid Warm NeedsIntervention response");
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(predecessor.clone()),
        };
        let retry = LifecycleCommandEnvelope::new(
            id("operation_warm_retry"),
            predecessor.workspace_id.clone(),
            predecessor.cat_id.clone(),
            predecessor.node_id.clone(),
            predecessor.placement_identity.clone(),
            runtime_config(),
            Some(predecessor.operation_id.clone()),
            LifecyclePredecessor::SameNode {
                operation_id: predecessor.operation_id.clone(),
                terminal_result_kind: TerminalResultKind::NeedsIntervention,
                terminal_result_digest: lifecycle_terminal_result_digest(&terminal)
                    .expect("digest Warm predecessor"),
                node_id: predecessor.node_id.clone(),
                placement_identity: predecessor.placement_identity.clone(),
            },
            LifecycleCommand::Warm(WarmSpec {
                grace_deadline_unix_ms: UnixMillis::new(8_000_000_002_000).expect("valid deadline"),
                convergence_deadline_unix_ms: UnixMillis::new(8_000_000_003_000)
                    .expect("valid deadline"),
            }),
        )
        .expect("valid Warm retry command");
        let prepared = prepared_manifest(&attempted);
        let mut runtime = prepared.body.runtime.clone();
        runtime.vmm_state = InstalledVmmState::Absent;
        runtime.volume_receipts = prepared.body.drained_volumes.clone();
        let predecessor_evidence = warm_recovery_predecessor_evidence(
            &retry,
            &predecessor,
            &runtime,
            &prepared.body.write_fence,
            &prepared.body.paused,
            &prepared.evidence,
            &prepared.body.drained_volumes,
        )
        .expect("close Warm recovery predecessor carrier");
        let recovered = RecoveredWarmEvidence {
            runtime,
            write_fence: prepared.body.write_fence,
            paused: prepared.body.paused,
            snapshot: prepared.evidence,
            drained_volumes: prepared.body.drained_volumes,
            predecessor: predecessor_evidence,
        };
        (predecessor, retry, recovered)
    }

    #[test]
    fn warm_recovery_carrier_binds_terminal_retention_absence_and_fresh_snapshot() {
        let (predecessor, retry, recovered) = warm_needs_intervention_retry();
        validate_recovered_warm(&retry, &predecessor, &recovered)
            .expect("exact Warm recovery carrier is accepted");

        let mut changed_retention = recovered.clone();
        changed_retention
            .predecessor
            .retained_evidence
            .retained_authority_or_data_count = 2;
        assert!(validate_recovered_warm(&retry, &predecessor, &changed_retention).is_err());

        let mut changed_snapshot = recovered.clone();
        changed_snapshot.snapshot.snapshot_manifest_digest = digest(99);
        assert!(validate_recovered_warm(&retry, &predecessor, &changed_snapshot).is_err());

        let mut missing_absence = predecessor.clone();
        let NodeResult::NeedsIntervention(intervention) = &mut missing_absence.result else {
            unreachable!("fixture is Warm NeedsIntervention")
        };
        intervention.not_running.frontend_absence_receipt_digest =
            Sha256Digest::from_bytes([0; 32]);
        assert!(warm_recovery_predecessor_evidence(
            &retry,
            &missing_absence,
            &recovered.runtime,
            &recovered.write_fence,
            &recovered.paused,
            &recovered.snapshot,
            &recovered.drained_volumes,
        )
        .is_err());
    }

    #[test]
    fn generic_owned_carrier_rejects_warm_intervention_for_cold() {
        let (predecessor, retry, _) = warm_needs_intervention_retry();
        let cold = LifecycleCommandEnvelope::new(
            id("operation_cold_after_warm_intervention"),
            retry.workspace_id.clone(),
            retry.cat_id.clone(),
            retry.node_id.clone(),
            retry.placement_identity.clone(),
            (*retry.runtime_config).clone(),
            Some(predecessor.operation_id.clone()),
            retry.predecessor.clone(),
            LifecycleCommand::Cold(ColdSpec {
                grace_deadline_unix_ms: UnixMillis::new(8_000_000_004_000).expect("valid deadline"),
                convergence_deadline_unix_ms: UnixMillis::new(8_000_000_005_000)
                    .expect("valid deadline"),
            }),
        )
        .expect("Cold command shape may name an exact predecessor");
        assert!(validate_same_node_owned_start_source(&cold, &predecessor).is_err());
    }

    #[test]
    fn suspend_allows_retained_local_tail_but_warm_requires_remote_equality() {
        let command = suspend_command();
        let tail = vec![receipt(7, 5)];
        validate_volume_receipts(&command, &tail, false)
            .expect("Suspended may retain a Relaxed local tail");
        assert!(validate_volume_receipts(&command, &tail, true).is_err());
        validate_volume_receipts(&command, &[receipt(7, 7)], true)
            .expect("Warm accepts exact R equals L");
    }

    #[test]
    fn owned_receipts_require_and_preserve_the_exact_start_grant_digest() {
        let command = suspend_command();
        let original = receipt(7, 5);
        let mut missing = original.clone();
        missing.authority_receipt_digest = None;
        assert!(validate_volume_receipts(&command, &[missing], false).is_err());

        let mut changed = receipt(7, 7);
        changed.authority_receipt_digest = Some(digest(17));
        assert!(validate_same_attachments(&[original], &[changed]).is_err());
    }

    #[test]
    fn inherited_suspended_fence_requires_the_exact_paused_runtime() {
        let runtime = InstalledRuntimeEvidence {
            runtime_incarnation: random(4),
            runtime_config_digest: runtime_config().config_digest,
            physical_identity_digest: digest(5),
            vmm_state: InstalledVmmState::Paused,
            volume_receipts: vec![receipt(7, 5)],
        };
        let fence = RuntimeWriteFenceEvidence::InheritedSuspended {
            runtime_physical_identity_digest: digest(5),
            pause_receipt_digest: digest(6),
        };
        validate_write_fence(&runtime, &fence).expect("exact paused source is reusable");
        let mut executing = runtime.clone();
        executing.vmm_state = InstalledVmmState::Executing;
        assert!(validate_write_fence(&executing, &fence).is_err());
        let wrong = RuntimeWriteFenceEvidence::InheritedSuspended {
            runtime_physical_identity_digest: digest(7),
            pause_receipt_digest: digest(6),
        };
        assert!(validate_write_fence(&runtime, &wrong).is_err());
    }

    #[test]
    fn never_used_guest_can_quiesce_at_lease_sequence_zero() {
        let runtime = InstalledRuntimeEvidence {
            runtime_incarnation: random(18),
            runtime_config_digest: runtime_config().config_digest,
            physical_identity_digest: digest(19),
            vmm_state: InstalledVmmState::Executing,
            volume_receipts: vec![receipt(0, 0)],
        };
        let source_epoch_digest = digest(20);
        let quiesce = GuestQuiesceEvidence {
            runtime_physical_identity_digest: runtime.physical_identity_digest.clone(),
            source_epoch_digest: source_epoch_digest.clone(),
            lease_sequence: 0,
            quiesce_receipt_digest: guest_quiesce_receipt_digest(
                &runtime.physical_identity_digest,
                &source_epoch_digest,
                0,
            ),
        };
        validate_quiesce_evidence(&runtime, &quiesce)
            .expect("the Guest's initial empty lease epoch is a valid work fence");
    }

    #[test]
    fn suspend_pause_accepts_syncfs_lineage_advancement() {
        let command = suspend_command();
        let runtime = InstalledRuntimeEvidence {
            runtime_incarnation: random(21),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            physical_identity_digest: digest(22),
            vmm_state: InstalledVmmState::Executing,
            volume_receipts: vec![receipt(5, 4)],
        };
        let source_epoch_digest = digest(23);
        let quiesce = GuestQuiesceEvidence {
            runtime_physical_identity_digest: runtime.physical_identity_digest.clone(),
            source_epoch_digest: source_epoch_digest.clone(),
            lease_sequence: 0,
            quiesce_receipt_digest: guest_quiesce_receipt_digest(
                &runtime.physical_identity_digest,
                &source_epoch_digest,
                0,
            ),
        };
        let fence = RuntimeWriteFenceEvidence::Guest { quiesce };
        let pause_binding = StepBinding::new(&command);
        let local_durability_receipts = vec![receipt(7, 5)];
        let paused = PausedRuntimeEvidence {
            pause_operation_id: pause_binding.operation_id.clone(),
            pause_request_fingerprint: pause_binding.request_fingerprint.clone(),
            runtime_physical_identity_digest: runtime.physical_identity_digest.clone(),
            write_fence_receipt_digest: write_fence_receipt_digest(&fence).clone(),
            pause_receipt_digest: pause_receipt_digest(
                &pause_binding,
                &runtime,
                &fence,
                &local_durability_receipts,
            )
            .expect("encode pause receipt"),
            local_durability_receipts,
        };
        validate_paused_evidence(&command, &pause_binding, &runtime, &fence, &paused, false)
            .expect("Guest syncfs may advance the local generation before VMM pause");
    }

    #[test]
    fn warm_snapshot_receipt_binds_manifest_fence_and_drained_lineage() {
        let command = suspend_command();
        let runtime = InstalledRuntimeEvidence {
            runtime_incarnation: random(9),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            physical_identity_digest: digest(10),
            vmm_state: InstalledVmmState::Executing,
            volume_receipts: vec![receipt(7, 7)],
        };
        let source_epoch_digest = digest(11);
        let quiesce = GuestQuiesceEvidence {
            runtime_physical_identity_digest: runtime.physical_identity_digest.clone(),
            source_epoch_digest: source_epoch_digest.clone(),
            lease_sequence: 12,
            quiesce_receipt_digest: guest_quiesce_receipt_digest(
                &runtime.physical_identity_digest,
                &source_epoch_digest,
                12,
            ),
        };
        let write_fence = RuntimeWriteFenceEvidence::Guest { quiesce };
        let pause_binding = StepBinding::new(&command);
        let paused = PausedRuntimeEvidence {
            pause_operation_id: pause_binding.operation_id.clone(),
            pause_request_fingerprint: pause_binding.request_fingerprint.clone(),
            runtime_physical_identity_digest: runtime.physical_identity_digest.clone(),
            write_fence_receipt_digest: write_fence_receipt_digest(&write_fence).clone(),
            pause_receipt_digest: pause_receipt_digest(
                &pause_binding,
                &runtime,
                &write_fence,
                &runtime.volume_receipts,
            )
            .expect("encode pause receipt"),
            local_durability_receipts: runtime.volume_receipts.clone(),
        };
        let manifest_digest = digest(14);
        let snapshot_intent_digest = digest(13);
        let snapshot_binding = StepBinding::new(&command);
        let snapshot = WarmSnapshotEvidence {
            snapshot_operation_id: snapshot_binding.operation_id.clone(),
            snapshot_request_fingerprint: snapshot_binding.request_fingerprint.clone(),
            runtime_physical_identity_digest: runtime.physical_identity_digest.clone(),
            write_fence_receipt_digest: write_fence_receipt_digest(&write_fence).clone(),
            pause_receipt_digest: paused.pause_receipt_digest.clone(),
            snapshot_intent_digest: snapshot_intent_digest.clone(),
            snapshot_manifest_digest: manifest_digest.clone(),
            snapshot_receipt_digest: warm_snapshot_receipt_digest(
                &snapshot_binding,
                &runtime,
                &write_fence,
                &paused,
                &runtime.volume_receipts,
                &snapshot_intent_digest,
                &manifest_digest,
            )
            .expect("encode snapshot receipt"),
        };
        validate_snapshot_evidence(
            &snapshot_binding,
            &runtime,
            &write_fence,
            &paused,
            &runtime.volume_receipts,
            &snapshot,
        )
        .expect("exact snapshot receipt is valid");

        let changed_manifest = WarmSnapshotEvidence {
            snapshot_manifest_digest: digest(15),
            ..snapshot.clone()
        };
        assert!(validate_snapshot_evidence(
            &snapshot_binding,
            &runtime,
            &write_fence,
            &paused,
            &runtime.volume_receipts,
            &changed_manifest,
        )
        .is_err());

        let changed_lineage = vec![receipt(8, 8)];
        assert!(validate_snapshot_evidence(
            &snapshot_binding,
            &runtime,
            &write_fence,
            &paused,
            &changed_lineage,
            &snapshot,
        )
        .is_err());
    }

    #[test]
    fn failure_step_durably_retains_fresh_volume_receipts() {
        let command = suspend_command();
        let retained = vec![receipt(9, 8)];
        let step = encode_step(
            &command,
            SuspendWarmStepState::SuspendFailureStop {
                reason: CommandFailureReason::VmmFailed,
                retained_volume_receipts: retained.clone(),
            },
        )
        .expect("encode failure step");
        let decoded = decode_step(&step, &command).expect("decode failure step");
        assert!(matches!(
            decoded.state,
            SuspendWarmStepState::SuspendFailureStop {
                reason: CommandFailureReason::VmmFailed,
                retained_volume_receipts,
            } if retained_volume_receipts == retained
        ));
    }

    #[test]
    fn partial_failure_evidence_refines_without_erasing_complete_receipts() {
        let mut first = receipt(7, 7);
        first.volume_id = id("a_volume");
        first.disk_id = id("a_disk");
        let mut second = receipt(8, 8);
        second.volume_id = id("b_volume");
        second.disk_id = id("b_disk");
        let complete = vec![first.clone(), second.clone()];
        let mut refined_second = second;
        refined_second.local_durable_generation =
            Generation::new(9).expect("valid refined local generation");
        refined_second.remote_durable_generation =
            Generation::new(9).expect("valid refined remote generation");

        let merged = merge_attachment_receipts(&complete, &[refined_second.clone()])
            .expect("merge exact retained subset");
        assert_eq!(merged, vec![first, refined_second]);
    }

    #[test]
    fn guest_quiesce_receipt_is_bound_to_runtime_epoch_and_sequence() {
        let runtime = InstalledRuntimeEvidence {
            runtime_incarnation: random(8),
            runtime_config_digest: runtime_config().config_digest,
            physical_identity_digest: digest(9),
            vmm_state: InstalledVmmState::Executing,
            volume_receipts: vec![receipt(4, 4)],
        };
        let source_epoch_digest = digest(10);
        let quiesce = GuestQuiesceEvidence {
            runtime_physical_identity_digest: runtime.physical_identity_digest.clone(),
            source_epoch_digest: source_epoch_digest.clone(),
            lease_sequence: 12,
            quiesce_receipt_digest: guest_quiesce_receipt_digest(
                &runtime.physical_identity_digest,
                &source_epoch_digest,
                12,
            ),
        };
        validate_quiesce_evidence(&runtime, &quiesce).expect("exact Guest fence");
        let mut wrong = quiesce;
        wrong.lease_sequence = 13;
        assert!(validate_quiesce_evidence(&runtime, &wrong).is_err());
    }

    #[test]
    fn terminal_warm_manifest_and_receipt_bind_the_exact_execution_absence() {
        let command = suspend_command();
        let prepared = prepared_manifest(&command);
        let first = terminal_manifest(&command, &prepared, absence(40));
        let second = terminal_manifest(&command, &prepared, absence(50));

        assert_ne!(
            first.body.warm_receipt_digest,
            second.body.warm_receipt_digest
        );
        assert_ne!(
            first.terminal_manifest_digest,
            second.terminal_manifest_digest
        );

        let mut self_claimed = first;
        self_claimed.body.execution_absence = absence(60);
        assert!(validate_warm_terminal_manifest_internal(&self_claimed).is_err());
    }

    #[test]
    fn prepared_manifest_cannot_be_parsed_as_a_terminal_warm_authority() {
        use std::io::Write as _;

        let prepared = prepared_manifest(&suspend_command());
        let bytes = serde_json::to_vec(&prepared).expect("encode prepared fixture");
        let mut file = tempfile::NamedTempFile::new().expect("create prepared manifest file");
        file.write_all(&bytes).expect("write prepared manifest");
        file.as_file().sync_all().expect("sync prepared manifest");

        assert!(matches!(
            read_warm_snapshot_file(
                File::open(file.path()).expect("reopen prepared manifest for calibration")
            )
            .expect("read prepared parser calibration"),
            SnapshotManifestRead::Exact(_)
        ));
        assert!(matches!(
            read_warm_terminal_file(
                File::open(file.path()).expect("reopen prepared manifest as terminal")
            )
            .expect("read terminal parser rejection"),
            TerminalManifestRead::Invalid
        ));
    }

    #[test]
    fn warm_intent_is_no_replace_and_durable_before_snapshot_side_effects() {
        let directory = tempfile::tempdir().expect("create Warm intent directory");
        let state =
            crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf());
        let intent = snapshot_intent(&suspend_command());
        let deadline = Instant::now() + Duration::from_secs(2);

        assert!(matches!(
            create_or_reopen_warm_snapshot_intent(&state, &intent, deadline)
                .expect("publish exact Warm intent"),
            SnapshotIntentPublishAttempt::Exact(ref found) if found.as_ref() == &intent
        ));
        let namespace = open_warm_snapshot_namespace(&state, false)
            .expect("open Warm namespace")
            .expect("Warm namespace exists");
        for suffix in [
            WARM_SNAPSHOT_CONTENT_SUFFIX,
            WARM_SNAPSHOT_TEMP_SUFFIX,
            WARM_SNAPSHOT_MANIFEST_SUFFIX,
            WARM_TERMINAL_TEMP_SUFFIX,
            WARM_TERMINAL_MANIFEST_SUFFIX,
        ] {
            let name = warm_component_name(&intent.body.binding, suffix)
                .expect("derive bounded Warm component");
            assert!(
                fstatat_nofollow(&namespace, &name)
                    .expect("inspect absent snapshot component")
                    .is_none(),
                "intent publication created a snapshot side effect for {suffix}"
            );
        }
        assert!(matches!(
            create_or_reopen_warm_snapshot_intent(&state, &intent, deadline)
                .expect("replay exact Warm intent"),
            SnapshotIntentPublishAttempt::Exact(ref found) if found.as_ref() == &intent
        ));
    }

    #[test]
    fn warm_intent_never_retroactively_authorizes_preexisting_snapshot_content() {
        let directory = tempfile::tempdir().expect("create Warm intent directory");
        let state =
            crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf());
        let intent = snapshot_intent(&suspend_command());
        let namespace = open_warm_snapshot_namespace(&state, true)
            .expect("create Warm namespace")
            .expect("Warm namespace exists");
        let content_name = warm_component_name(&intent.body.binding, WARM_SNAPSHOT_CONTENT_SUFFIX)
            .expect("derive Warm content name");
        mkdirat(&namespace, &content_name, 0o700).expect("create preexisting content");
        namespace.sync_all().expect("sync preexisting content name");

        assert!(matches!(
            create_or_reopen_warm_snapshot_intent(
                &state,
                &intent,
                Instant::now() + Duration::from_secs(2),
            )
            .expect("reject retroactive intent"),
            SnapshotIntentPublishAttempt::Invalid
        ));
        let intent_name = warm_component_name(&intent.body.binding, WARM_SNAPSHOT_INTENT_SUFFIX)
            .expect("derive Warm intent name");
        assert!(fstatat_nofollow(&namespace, &intent_name)
            .expect("inspect absent retroactive intent")
            .is_none());
        assert!(
            fstatat_nofollow(&namespace, &content_name)
                .expect("reinspect preserved content")
                .is_some(),
            "rejected intent touched preexisting retained data"
        );
    }

    #[test]
    fn torn_warm_intent_is_never_overwritten_or_allowed_to_snapshot() {
        let directory = tempfile::tempdir().expect("create Warm intent directory");
        let state =
            crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf());
        let intent = snapshot_intent(&suspend_command());
        let namespace = open_warm_snapshot_namespace(&state, true)
            .expect("create Warm namespace")
            .expect("Warm namespace exists");
        let intent_name = warm_component_name(&intent.body.binding, WARM_SNAPSHOT_INTENT_SUFFIX)
            .expect("derive Warm intent name");
        let mut file = openat_file(
            &namespace,
            &intent_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
        .expect("create torn intent");
        file.write_all(b"{").expect("write torn intent prefix");
        file.sync_all().expect("sync torn intent");
        namespace.sync_all().expect("sync torn intent name");

        assert!(matches!(
            create_or_reopen_warm_snapshot_intent(
                &state,
                &intent,
                Instant::now() + Duration::from_secs(2),
            )
            .expect("inspect torn intent"),
            SnapshotIntentPublishAttempt::Invalid
        ));
        let mut bytes = Vec::new();
        openat_file(
            &namespace,
            &intent_name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
        .expect("reopen torn intent")
        .read_to_end(&mut bytes)
        .expect("read torn intent");
        assert_eq!(bytes, b"{");
        let content_name = warm_component_name(&intent.body.binding, WARM_SNAPSHOT_CONTENT_SUFFIX)
            .expect("derive Warm content name");
        assert!(fstatat_nofollow(&namespace, &content_name)
            .expect("inspect absent snapshot content")
            .is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_inventory_keeps_intent_and_partial_content_non_executable() {
        let directory = tempfile::tempdir().expect("create Warm inventory directory");
        let state =
            crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf());
        let intent = snapshot_intent(&suspend_command());
        assert!(matches!(
            create_or_reopen_warm_snapshot_intent(
                &state,
                &intent,
                Instant::now() + Duration::from_secs(2),
            )
            .expect("publish inventory intent"),
            SnapshotIntentPublishAttempt::Exact(_)
        ));
        let physical = physical_for_warm_inventory(state.clone(), intent.body.node_id.clone());
        let intent_only = enumerate_installed_warm_snapshot_artifacts(
            &physical,
            Instant::now() + Duration::from_secs(2),
        )
        .expect("enumerate intent-only bundle");
        assert!(matches!(
            intent_only.as_slice(),
            [InstalledWarmSnapshotInventoryEntry::RetainedIntent(artifact)]
                if matches!(artifact.as_ref(), InstalledWarmSnapshotIntentArtifact {
                    content_observation: InstalledWarmIntentContentObservation::Absent,
                    ..
                })
        ));

        let namespace = open_warm_snapshot_namespace(&state, false)
            .expect("open Warm namespace")
            .expect("Warm namespace exists");
        let content_name = warm_component_name(&intent.body.binding, WARM_SNAPSHOT_CONTENT_SUFFIX)
            .expect("derive content name");
        mkdirat(&namespace, &content_name, 0o700).expect("create partial content directory");
        let content = openat_directory(&namespace, &content_name).expect("open partial content");
        let partial_name = CString::new("partial-state").expect("valid partial name");
        let mut partial = openat_file(
            &content,
            &partial_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
        .expect("create partial snapshot state");
        partial
            .write_all(b"partial")
            .expect("write partial snapshot state");
        partial.sync_all().expect("sync partial snapshot state");
        content.sync_all().expect("sync partial content directory");
        namespace.sync_all().expect("sync partial content name");

        let partial_content = enumerate_installed_warm_snapshot_artifacts(
            &physical,
            Instant::now() + Duration::from_secs(2),
        )
        .expect("enumerate intent plus partial content");
        assert!(matches!(
            partial_content.as_slice(),
            [InstalledWarmSnapshotInventoryEntry::RetainedIntent(artifact)]
                if matches!(artifact.as_ref(), InstalledWarmSnapshotIntentArtifact {
                    content_observation: InstalledWarmIntentContentObservation::Present { .. },
                    ..
                })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_inventory_quarantines_prepared_claim_without_its_intent() {
        let directory = tempfile::tempdir().expect("create Warm inventory directory");
        let state =
            crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf());
        let command = suspend_command();
        let prepared = prepared_manifest(&command);
        let namespace = open_warm_snapshot_namespace(&state, true)
            .expect("create Warm namespace")
            .expect("Warm namespace exists");
        publish_warm_snapshot_manifest(&namespace, &prepared.body.binding, &prepared)
            .expect("publish orphaned prepared claim");
        let physical = physical_for_warm_inventory(state, command.node_id.clone());

        let inventory = enumerate_installed_warm_snapshot_artifacts(
            &physical,
            Instant::now() + Duration::from_secs(2),
        )
        .expect("enumerate orphaned prepared claim");
        assert!(matches!(
            inventory.as_slice(),
            [InstalledWarmSnapshotInventoryEntry::Quarantined { .. }]
        ));
    }

    #[test]
    fn prepared_and_terminal_manifests_close_the_exact_intent_phase() {
        let command = suspend_command();
        let intent = snapshot_intent(&command);
        let mut prepared = prepared_manifest(&command);
        prepared.body.snapshot_intent_digest = intent.intent_digest.clone();
        prepared.evidence.snapshot_intent_digest = intent.intent_digest.clone();
        prepared.evidence.snapshot_manifest_digest =
            warm_snapshot_manifest_digest(&prepared.body).expect("redigest prepared body");
        prepared.evidence.snapshot_receipt_digest = warm_snapshot_receipt_digest(
            &prepared.body.binding,
            &prepared.body.runtime,
            &prepared.body.write_fence,
            &prepared.body.paused,
            &prepared.body.drained_volumes,
            &intent.intent_digest,
            &prepared.evidence.snapshot_manifest_digest,
        )
        .expect("redigest prepared receipt");
        validate_warm_snapshot_manifest_internal(&prepared)
            .expect("prepared fixture closes its exact intent digest");
        assert!(intent_closes_prepared(&intent, &prepared));

        let terminal = terminal_manifest(&command, &prepared, absence(90));
        assert!(terminal_closes_prepared(&terminal, &prepared));

        let mut wrong_intent = intent.clone();
        wrong_intent.intent_digest = digest(91);
        assert!(!intent_closes_prepared(&wrong_intent, &prepared));
        let mut wrong_terminal = terminal;
        wrong_terminal.body.snapshot_intent_digest = digest(92);
        assert!(!terminal_closes_prepared(&wrong_terminal, &prepared));
    }

    #[test]
    fn cleanup_authority_digest_rejects_descriptor_or_command_mutation() {
        let command = suspend_command();
        let binding = StepBinding::new(&command);
        let request = WarmSnapshotCleanupRequest {
            predecessor_operation_id: id("operation_warm"),
            predecessor_request_fingerprint: digest(70),
            predecessor_terminal_result_digest: digest(71),
            terminal_manifest_digest: digest(72),
            warm_receipt_digest: digest(73),
            source_runtime_incarnation: random(74),
            volume_receipts: vec![receipt(7, 7)],
        };
        let mut authority = WarmSnapshotCleanupAuthority {
            version: STEP_VERSION,
            cleanup_operation_id: command.operation_id.clone(),
            cleanup_request_fingerprint: command.request_fingerprint.clone(),
            workspace_id: command.workspace_id.clone(),
            cat_id: command.cat_id.clone(),
            node_id: command.node_id.clone(),
            placement_identity: command.placement_identity.clone(),
            runtime_config_id: command.runtime_config.config_id.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            request,
            terminal_operation_id: id("operation_warm"),
            terminal_request_fingerprint: digest(70),
            prepared_operation_id: binding.operation_id,
            prepared_request_fingerprint: binding.request_fingerprint,
            mode: WarmSnapshotCleanupMode::Remove,
            snapshot_directory: cats_api::runtime_reconciliation::HostPath::new(
                "/var/lib/cats/test/warm.snapshot",
            )
            .expect("valid fixture snapshot path"),
            installed_runtime: None,
            memory_file: WarmMemoryFileProof {
                path: cats_api::runtime_reconciliation::HostPath::new(
                    "/var/lib/cats/test/warm-memory",
                )
                .expect("valid fixture memory path"),
                device: 2,
                inode: 7,
                size_bytes: 4096,
                digest: digest(76),
            },
            memory_parent_identity: WarmCleanupObjectIdentity {
                device: 2,
                inode: 6,
            },
            namespace_identity: WarmCleanupObjectIdentity {
                device: 1,
                inode: 2,
            },
            terminal_manifest_identity: WarmCleanupObjectIdentity {
                device: 1,
                inode: 3,
            },
            intent_manifest_identity: WarmCleanupObjectIdentity {
                device: 1,
                inode: 6,
            },
            prepared_manifest_identity: WarmCleanupObjectIdentity {
                device: 1,
                inode: 4,
            },
            content_directory_identity: WarmCleanupObjectIdentity {
                device: 1,
                inode: 5,
            },
            retained_retry: None,
            authority_digest: Sha256Digest::from_bytes([0; 32]),
        };
        authority.authority_digest =
            warm_cleanup_authority_digest(&authority).expect("digest cleanup authority");

        let remove_digest = warm_cleanup_remove_digest(&authority);
        let transfer_digest = warm_cleanup_transfer_digest(&authority, &random(80), &digest(81));
        let retained_failed_start_digest =
            warm_cleanup_retain_failed_start_digest(&authority, &digest(82));
        assert_ne!(
            remove_digest, transfer_digest,
            "Remove absence must never authorize a Start memory transfer"
        );
        assert_ne!(
            transfer_digest,
            warm_cleanup_transfer_digest(&authority, &random(80), &digest(83)),
            "transfer proof binds the exact journaled Start progress"
        );
        assert_ne!(remove_digest, retained_failed_start_digest);
        assert_ne!(transfer_digest, retained_failed_start_digest);
        assert_ne!(
            retained_failed_start_digest,
            warm_cleanup_retain_failed_start_digest(&authority, &digest(84)),
            "failed-Start revocation binds the exact inherited predecessor carrier"
        );

        let mut changed_inode = authority.clone();
        changed_inode.content_directory_identity.inode += 1;
        assert_ne!(
            changed_inode.authority_digest,
            warm_cleanup_authority_digest(&changed_inode).expect("digest changed inode")
        );

        let mut changed_memory = authority.clone();
        changed_memory.memory_file.inode += 1;
        assert_ne!(
            changed_memory.authority_digest,
            warm_cleanup_authority_digest(&changed_memory).expect("digest changed memory inode")
        );

        let mut changed_mode = authority.clone();
        changed_mode.mode = WarmSnapshotCleanupMode::TransferToRuntime;
        assert_ne!(
            changed_mode.authority_digest,
            warm_cleanup_authority_digest(&changed_mode).expect("digest changed cleanup mode")
        );

        let mut changed_request = authority;
        changed_request.request.terminal_manifest_digest = digest(75);
        assert_ne!(
            changed_request.authority_digest,
            warm_cleanup_authority_digest(&changed_request).expect("digest changed request")
        );
    }

    #[test]
    fn retained_warm_start_failed_removal_rebind_is_exact_and_pure() {
        let seed = suspend_command();
        let failed_predecessor = LifecycleCommandResponse {
            version: cats_api::runtime_reconciliation::ContractVersion::V1,
            operation_id: id("operation_failed_warm_start_for_removal"),
            workspace_id: seed.workspace_id.clone(),
            cat_id: seed.cat_id.clone(),
            node_id: seed.node_id.clone(),
            placement_identity: seed.placement_identity.clone(),
            request_fingerprint: digest(120),
            result: NodeResult::StartFailed(Box::new(CommandFailedResult {
                reason: CommandFailureReason::InvalidLocalPrecondition,
                not_running: absence(121),
                retained_evidence: RetainedEvidence {
                    artifact_manifest_digest: digest(126),
                    adoptable_count: 0,
                    gc_candidate_count: 0,
                    retained_authority_or_data_count: 1,
                    quarantined_count: 0,
                },
                retained_volume_receipts: vec![receipt(7, 7)],
            })),
        };
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(failed_predecessor.clone()),
        };
        let command = LifecycleCommandEnvelope::new(
            id("operation_stop_failed_warm_start"),
            seed.workspace_id.clone(),
            seed.cat_id.clone(),
            seed.node_id.clone(),
            seed.placement_identity.clone(),
            (*seed.runtime_config).clone(),
            Some(failed_predecessor.operation_id.clone()),
            LifecyclePredecessor::SameNode {
                operation_id: failed_predecessor.operation_id.clone(),
                terminal_result_kind: TerminalResultKind::StartFailed,
                terminal_result_digest: lifecycle_terminal_result_digest(&terminal)
                    .expect("digest failed Start terminal"),
                node_id: failed_predecessor.node_id.clone(),
                placement_identity: failed_predecessor.placement_identity.clone(),
            },
            LifecycleCommand::Stop(StopSpec {
                grace_deadline_unix_ms: UnixMillis::new(8_000_000_006_000).expect("valid deadline"),
            }),
        )
        .expect("valid Stop after StartFailed");
        let (_installed, carrier, authority) =
            retained_warm_restart_source_chain_for_test(&command, &failed_predecessor)
                .expect("construct exact retained Warm removal chain");
        validate_retained_warm_removal_authority(
            &command,
            &failed_predecessor,
            &digest(126),
            Some(&carrier),
            &authority,
        )
        .expect("exact removal authority replays");
        assert_eq!(authority.mode(), WarmSnapshotCleanupMode::Remove);
        assert!(rebind_retained_warm_for_removal(
            &command,
            &failed_predecessor,
            &digest(126),
            None,
        )
        .is_err());
        assert!(rebind_retained_warm_for_removal(
            &command,
            &failed_predecessor,
            &digest(127),
            Some(&carrier),
        )
        .is_err());

        let mut changed_authority = authority;
        changed_authority.cleanup_request_fingerprint = digest(128);
        changed_authority.authority_digest = warm_cleanup_authority_digest(&changed_authority)
            .expect("redigest changed removal authority");
        assert!(validate_retained_warm_removal_authority(
            &command,
            &failed_predecessor,
            &digest(126),
            Some(&carrier),
            &changed_authority,
        )
        .is_err());

        let mut consumed_carrier = carrier;
        consumed_carrier.source_authority.mode = WarmSnapshotCleanupMode::Remove;
        consumed_carrier.source_authority.authority_digest =
            warm_cleanup_authority_digest(&consumed_carrier.source_authority)
                .expect("redigest consumed source authority");
        consumed_carrier.revocation_receipt_digest = warm_cleanup_retain_failed_start_digest(
            &consumed_carrier.source_authority,
            &consumed_carrier.inherited_predecessor_physical_digest,
        );
        consumed_carrier.carrier_digest =
            retained_warm_restart_source_carrier_digest(&consumed_carrier)
                .expect("redigest consumed carrier");
        assert!(rebind_retained_warm_for_removal(
            &command,
            &failed_predecessor,
            &digest(126),
            Some(&consumed_carrier),
        )
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_ready_stop_carrier_binds_full_manifest_and_fresh_receipts() {
        let seed = suspend_command();
        let runtime_incarnation = random(112);
        let predecessor = LifecycleCommandResponse {
            version: cats_api::runtime_reconciliation::ContractVersion::V1,
            operation_id: id("operation_ready"),
            workspace_id: seed.workspace_id.clone(),
            cat_id: seed.cat_id.clone(),
            node_id: seed.node_id.clone(),
            placement_identity: seed.placement_identity.clone(),
            request_fingerprint: digest(96),
            result: NodeResult::RuntimeReady(Box::new(RuntimeReadyResult {
                runtime_incarnation: runtime_incarnation.clone(),
                runtime_config_digest: seed.runtime_config.config_digest.clone(),
                execution_receipt_digest: digest(97),
                guest_ready_receipt_digest: digest(98),
                volume_receipts: vec![receipt(7, 7)],
            })),
        };
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(predecessor.clone()),
        };
        let command = LifecycleCommandEnvelope::new(
            id("operation_stop_runtime_ready"),
            predecessor.workspace_id.clone(),
            predecessor.cat_id.clone(),
            predecessor.node_id.clone(),
            predecessor.placement_identity.clone(),
            (*seed.runtime_config).clone(),
            Some(predecessor.operation_id.clone()),
            LifecyclePredecessor::SameNode {
                operation_id: predecessor.operation_id.clone(),
                terminal_result_kind: TerminalResultKind::RuntimeReady,
                terminal_result_digest: lifecycle_terminal_result_digest(&terminal)
                    .expect("digest RuntimeReady predecessor"),
                node_id: predecessor.node_id.clone(),
                placement_identity: predecessor.placement_identity.clone(),
            },
            LifecycleCommand::Stop(StopSpec {
                grace_deadline_unix_ms: UnixMillis::new(8_000_000_002_000).expect("valid deadline"),
            }),
        )
        .expect("valid Stop after RuntimeReady");
        let memory_file_path =
            HostPath::new("/var/lib/cats/test/runtime-ready-memory").expect("valid memory path");
        let installed =
            cleanup_installed_runtime(&command, &runtime_incarnation, &memory_file_path);
        let installed_volume = &installed.volumes[0];
        let carrier_volume = SameNodeOwnedPredecessorVolume {
            volume_id: installed_volume.volume_id.clone(),
            disk_id: installed_volume.disk_id.clone(),
            disk_role: installed_volume.disk_role,
            attachment_id: installed_volume.attachment_id.clone(),
            attachment_epoch: installed_volume.attachment_epoch,
            acquire_origin: installed_volume.acquire_origin.clone(),
            authoritative_head: installed_volume.current_authority_head.clone(),
            immutable_start_grant_receipt_digest: installed_volume
                .authority_receipt_digest
                .clone()
                .expect("installed StartGrant digest"),
            local_lineage_data_directory: Some(
                installed_volume.local_lineage_data_directory.clone(),
            ),
        };
        let mut carrier = SameNodeOwnedPredecessorPhysical {
            physical_manifest_digest: installed.manifest_digest.clone(),
            runtime_incarnation: Some(runtime_incarnation),
            volumes: vec![carrier_volume],
            source: SameNodeOwnedPredecessorSource::RuntimeReady {
                installed_runtime: Box::new(installed),
                physical_identity_digest: digest(113),
                volume_receipts: vec![receipt(7, 7)],
            },
        };
        validate_same_node_owned_predecessor_physical(&command, &predecessor, &carrier)
            .expect("exact RuntimeReady Stop carrier is accepted");
        assert_eq!(carrier.volume_receipts(), [receipt(7, 7)]);

        let SameNodeOwnedPredecessorSource::RuntimeReady {
            physical_identity_digest,
            ..
        } = &mut carrier.source
        else {
            unreachable!("fixture is RuntimeReady")
        };
        *physical_identity_digest = Sha256Digest::from_bytes([0; 32]);
        assert!(
            validate_same_node_owned_predecessor_physical(&command, &predecessor, &carrier)
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn warm_stop_cleanup_revokes_restart_source_and_replays_crash_but_rejects_stale_bundle() {
        let fixture = warm_stop_cleanup_fixture();
        // Simulate response loss/crash immediately after the executable
        // terminal manifest was durably revoked but before payload cleanup.
        std::fs::remove_file(&fixture.terminal_path)
            .expect("simulate terminal authority revocation");
        File::open(&fixture.namespace_path)
            .expect("open namespace after simulated crash")
            .sync_all()
            .expect("fsync simulated terminal revocation");

        let expected = warm_cleanup_remove_digest(&fixture.authority);
        let first = inspect_or_remove_terminal_warm_bundle(
            &fixture.physical,
            &fixture.command,
            &fixture.authority,
            &WarmSnapshotCleanupCompletion::Remove,
            Instant::now() + Duration::from_secs(2),
        )
        .expect("finish descriptor-safe Warm Stop cleanup after crash");
        assert_eq!(first, WarmSnapshotCleanupAttempt::Exact(expected.clone()));
        assert!(!fixture.memory_path.exists());

        let replay = inspect_or_remove_terminal_warm_bundle(
            &fixture.physical,
            &fixture.command,
            &fixture.authority,
            &WarmSnapshotCleanupCompletion::Remove,
            Instant::now() + Duration::from_secs(2),
        )
        .expect("replay exact Warm Stop absence");
        assert_eq!(replay, WarmSnapshotCleanupAttempt::Exact(expected));

        std::fs::write(&fixture.terminal_path, b"stale-replacement")
            .expect("write stale replacement terminal");
        let stale = inspect_or_remove_terminal_warm_bundle(
            &fixture.physical,
            &fixture.command,
            &fixture.authority,
            &WarmSnapshotCleanupCompletion::Remove,
            Instant::now() + Duration::from_secs(2),
        )
        .expect("classify stale replacement terminal");
        assert_eq!(stale, WarmSnapshotCleanupAttempt::Blocked);
        assert!(fixture.terminal_path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_warm_start_revokes_terminal_but_retains_exact_payload_and_memory() {
        let mut fixture = warm_stop_cleanup_fixture();
        let command = LifecycleCommandEnvelope::new(
            id("operation_start_from_warm"),
            fixture.command.workspace_id.clone(),
            fixture.command.cat_id.clone(),
            fixture.command.node_id.clone(),
            fixture.command.placement_identity.clone(),
            (*fixture.command.runtime_config).clone(),
            Some(fixture.authority.request.predecessor_operation_id.clone()),
            fixture.command.predecessor.clone(),
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: vec![StartVolumeAuthority {
                    volume_id: id("volume_suspend_warm_root"),
                    disk_id: id("disk_suspend_warm_root"),
                    authority: RuntimeVolumeAuthorityInput::SameNodeOwned {
                        attachment_id: id("attachment_suspend_warm_root"),
                        attachment_epoch: FenceEpoch::new(3).expect("valid attachment epoch"),
                    },
                }],
                source: StartSource::SameNodeWarm,
                effect_deadline_unix_ms: UnixMillis::new(8_000_000_003_000)
                    .expect("valid deadline"),
            })),
        )
        .expect("valid Start after Warm");
        fixture.authority.cleanup_operation_id = command.operation_id.clone();
        fixture.authority.cleanup_request_fingerprint = command.request_fingerprint.clone();
        fixture.authority.mode = WarmSnapshotCleanupMode::TransferToRuntime;
        fixture.authority.authority_digest = warm_cleanup_authority_digest(&fixture.authority)
            .expect("redigest failed-Start cleanup authority");
        validate_warm_cleanup_authority(&fixture.physical, &command, &fixture.authority)
            .expect("fixture is exact failed-Start cleanup authority");

        let prepared_binding = StepBinding {
            version: STEP_VERSION,
            operation_id: fixture.authority.prepared_operation_id.clone(),
            request_fingerprint: fixture.authority.prepared_request_fingerprint.clone(),
        };
        let intent_path = fixture.namespace_path.join(
            warm_component_name(&prepared_binding, WARM_SNAPSHOT_INTENT_SUFFIX)
                .expect("valid intent name")
                .to_str()
                .expect("UTF-8 intent name"),
        );
        let prepared_path = fixture.namespace_path.join(
            warm_component_name(&prepared_binding, WARM_SNAPSHOT_MANIFEST_SUFFIX)
                .expect("valid prepared name")
                .to_str()
                .expect("UTF-8 prepared name"),
        );
        let content_path = fixture.namespace_path.join(
            warm_component_name(&prepared_binding, WARM_SNAPSHOT_CONTENT_SUFFIX)
                .expect("valid content name")
                .to_str()
                .expect("UTF-8 content name"),
        );
        let inherited_digest = digest(110);
        let completion = WarmSnapshotCleanupCompletion::RetainForFailedStart {
            inherited_predecessor_physical_digest: inherited_digest.clone(),
        };
        let expected =
            warm_cleanup_retain_failed_start_digest(&fixture.authority, &inherited_digest);
        let first = inspect_or_remove_terminal_warm_bundle(
            &fixture.physical,
            &command,
            &fixture.authority,
            &completion,
            Instant::now() + Duration::from_secs(2),
        )
        .expect("revoke failed-Start Warm terminal authority");
        assert_eq!(first, WarmSnapshotCleanupAttempt::Exact(expected.clone()));
        assert!(!fixture.terminal_path.exists());
        assert!(intent_path.exists());
        assert!(prepared_path.exists());
        assert!(content_path.exists());
        assert!(fixture.memory_path.exists());

        let replay = inspect_or_remove_terminal_warm_bundle(
            &fixture.physical,
            &command,
            &fixture.authority,
            &completion,
            Instant::now() + Duration::from_secs(2),
        )
        .expect("replay failed-Start Warm terminal revocation");
        assert_eq!(replay, WarmSnapshotCleanupAttempt::Exact(expected));

        let carrier = seal_retained_warm_restart_source(
            &command,
            &fixture.authority,
            inherited_digest,
            match first {
                WarmSnapshotCleanupAttempt::Exact(receipt) => receipt,
                WarmSnapshotCleanupAttempt::Blocked => unreachable!("first retain was exact"),
            },
        )
        .expect("seal retained Warm restart source");
        validate_retained_warm_restart_source_for_failed_start(&command, &carrier)
            .expect("sealed carrier binds the failed Start");
        validate_retained_warm_restart_source_for_source(
            &command,
            &carrier,
            &fixture.authority,
            &digest(110),
        )
        .expect("sealed carrier binds its journaled failed-Start source");
        assert!(validate_retained_warm_restart_source_for_source(
            &command,
            &carrier,
            &fixture.authority,
            &digest(111),
        )
        .is_err());
        let mut changed_carrier = carrier.clone();
        changed_carrier.revocation_receipt_digest = digest(111);
        assert!(validate_retained_warm_restart_source(&changed_carrier).is_err());

        let failed_predecessor = LifecycleCommandResponse::new(
            &command,
            NodeResult::StartFailed(Box::new(CommandFailedResult {
                reason: CommandFailureReason::VolumeAuthorityRejected,
                not_running: absence(112),
                retained_evidence: RetainedEvidence {
                    artifact_manifest_digest: digest(117),
                    adoptable_count: 0,
                    gc_candidate_count: 0,
                    retained_authority_or_data_count: 1,
                    quarantined_count: 0,
                },
                retained_volume_receipts: vec![receipt(7, 7)],
            })),
        )
        .expect("valid failed Warm Start predecessor");
        let failed_terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(failed_predecessor.clone()),
        };
        let retry = LifecycleCommandEnvelope::new(
            id("operation_retry_retained_warm"),
            command.workspace_id.clone(),
            command.cat_id.clone(),
            command.node_id.clone(),
            command.placement_identity.clone(),
            (*command.runtime_config).clone(),
            Some(failed_predecessor.operation_id.clone()),
            LifecyclePredecessor::SameNode {
                operation_id: failed_predecessor.operation_id.clone(),
                terminal_result_kind: TerminalResultKind::StartFailed,
                terminal_result_digest: lifecycle_terminal_result_digest(&failed_terminal)
                    .expect("digest failed Warm Start"),
                node_id: failed_predecessor.node_id.clone(),
                placement_identity: failed_predecessor.placement_identity.clone(),
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: vec![StartVolumeAuthority {
                    volume_id: id("volume_suspend_warm_root"),
                    disk_id: id("disk_suspend_warm_root"),
                    authority: RuntimeVolumeAuthorityInput::SameNodeOwned {
                        attachment_id: id("attachment_suspend_warm_root"),
                        attachment_epoch: FenceEpoch::new(3).expect("valid attachment epoch"),
                    },
                }],
                source: StartSource::SameNodeRetry,
                effect_deadline_unix_ms: UnixMillis::new(8_000_000_004_000)
                    .expect("valid deadline"),
            })),
        )
        .expect("valid retained Warm retry");
        let rebound = rebind_retained_warm_for_retry(&retry, &failed_predecessor, &carrier)
            .expect("rebind retained Warm source to immediate retry");
        validate_warm_cleanup_authority_scope(&retry, &rebound)
            .expect("rebound authority binds current retry");
        let retry_binding = rebound
            .retained_retry
            .as_deref()
            .expect("rebound authority has retry chain");
        assert_eq!(
            retry_binding.failed_start_retained_manifest_digest,
            digest(117)
        );
        assert_eq!(&retry_binding.source_carrier_digest, carrier.digest());

        let remove = LifecycleCommandEnvelope::new(
            id("operation_stop_retained_warm"),
            command.workspace_id.clone(),
            command.cat_id.clone(),
            command.node_id.clone(),
            command.placement_identity.clone(),
            (*command.runtime_config).clone(),
            Some(failed_predecessor.operation_id.clone()),
            LifecyclePredecessor::SameNode {
                operation_id: failed_predecessor.operation_id.clone(),
                terminal_result_kind: TerminalResultKind::StartFailed,
                terminal_result_digest: lifecycle_terminal_result_digest(&failed_terminal)
                    .expect("digest failed Warm Start for removal"),
                node_id: failed_predecessor.node_id.clone(),
                placement_identity: failed_predecessor.placement_identity.clone(),
            },
            LifecycleCommand::Stop(StopSpec {
                grace_deadline_unix_ms: UnixMillis::new(8_000_000_005_000).expect("valid deadline"),
            }),
        )
        .expect("valid Stop after retained Warm StartFailed");
        let removal = rebind_retained_warm_for_removal(
            &remove,
            &failed_predecessor,
            &digest(117),
            Some(&carrier),
        )
        .expect("rebind retained Warm source for exact removal");
        assert_eq!(removal.mode(), WarmSnapshotCleanupMode::Remove);
        validate_retained_warm_removal_authority(
            &remove,
            &failed_predecessor,
            &digest(117),
            Some(&carrier),
            &removal,
        )
        .expect("journaled retained Warm removal authority is exact");
        assert!(
            rebind_retained_warm_for_removal(&remove, &failed_predecessor, &digest(117), None,)
                .is_err()
        );
        assert!(rebind_retained_warm_for_removal(
            &remove,
            &failed_predecessor,
            &digest(118),
            Some(&carrier),
        )
        .is_err());
        let mut consumed_carrier = carrier.clone();
        consumed_carrier.source_authority.mode = WarmSnapshotCleanupMode::Remove;
        consumed_carrier.source_authority.authority_digest =
            warm_cleanup_authority_digest(&consumed_carrier.source_authority)
                .expect("redigest consumed source authority");
        consumed_carrier.revocation_receipt_digest = warm_cleanup_retain_failed_start_digest(
            &consumed_carrier.source_authority,
            &consumed_carrier.inherited_predecessor_physical_digest,
        );
        consumed_carrier.carrier_digest =
            retained_warm_restart_source_carrier_digest(&consumed_carrier)
                .expect("redigest consumed carrier");
        assert!(rebind_retained_warm_for_removal(
            &remove,
            &failed_predecessor,
            &digest(117),
            Some(&consumed_carrier),
        )
        .is_err());

        let memory_len = std::fs::metadata(&fixture.memory_path)
            .expect("inspect retained memory")
            .len();
        std::fs::write(&fixture.memory_path, vec![b'x'; memory_len as usize])
            .expect("tamper retained memory contents");
        let changed_memory = inspect_or_remove_terminal_warm_bundle(
            &fixture.physical,
            &command,
            &fixture.authority,
            &completion,
            Instant::now() + Duration::from_secs(2),
        )
        .expect("classify changed retained memory");
        assert_eq!(changed_memory, WarmSnapshotCleanupAttempt::Blocked);
        assert!(intent_path.exists());
        assert!(prepared_path.exists());
        assert!(content_path.exists());
        assert!(fixture.memory_path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn warm_memory_remove_is_descriptor_exact_and_replays_only_absence() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("create Warm memory StateDirectory");
        let runtime_parent_path = directory.path().join("runtime-memory");
        std::fs::create_dir(&runtime_parent_path).expect("create Warm memory parent");
        let memory_path = runtime_parent_path.join("memory.bin");
        std::fs::write(&memory_path, b"exact-warm-memory")
            .expect("write exact Warm memory fixture");
        let retained_old_inode = File::open(&memory_path).expect("retain old memory inode");
        let memory_proof = memory_file_proof_from_path(
            &memory_path,
            b"exact-warm-memory".len() as u64,
            Instant::now() + Duration::from_secs(2),
            true,
        )
        .expect("prove Warm memory fixture");
        let memory_parent = File::open(&runtime_parent_path).expect("open Warm memory parent");
        let memory_parent_identity =
            directory_identity(&memory_parent).expect("inspect Warm memory parent");
        let command = suspend_command();
        let binding = StepBinding::new(&command);
        let mut authority = WarmSnapshotCleanupAuthority {
            version: STEP_VERSION,
            cleanup_operation_id: command.operation_id.clone(),
            cleanup_request_fingerprint: command.request_fingerprint.clone(),
            workspace_id: command.workspace_id.clone(),
            cat_id: command.cat_id.clone(),
            node_id: command.node_id.clone(),
            placement_identity: command.placement_identity.clone(),
            runtime_config_id: command.runtime_config.config_id.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            request: WarmSnapshotCleanupRequest {
                predecessor_operation_id: id("operation_warm"),
                predecessor_request_fingerprint: digest(70),
                predecessor_terminal_result_digest: digest(71),
                terminal_manifest_digest: digest(72),
                warm_receipt_digest: digest(73),
                source_runtime_incarnation: random(74),
                volume_receipts: vec![receipt(7, 7)],
            },
            terminal_operation_id: id("operation_warm"),
            terminal_request_fingerprint: digest(70),
            prepared_operation_id: binding.operation_id,
            prepared_request_fingerprint: binding.request_fingerprint,
            mode: WarmSnapshotCleanupMode::Remove,
            snapshot_directory: cats_api::runtime_reconciliation::HostPath::new(
                directory.path().join("unused.snapshot").to_str().unwrap(),
            )
            .expect("valid fixture snapshot path"),
            installed_runtime: None,
            memory_file: memory_proof,
            memory_parent_identity,
            namespace_identity: WarmCleanupObjectIdentity {
                device: 1,
                inode: 2,
            },
            terminal_manifest_identity: WarmCleanupObjectIdentity {
                device: 1,
                inode: 3,
            },
            intent_manifest_identity: WarmCleanupObjectIdentity {
                device: 1,
                inode: 4,
            },
            prepared_manifest_identity: WarmCleanupObjectIdentity {
                device: 1,
                inode: 5,
            },
            content_directory_identity: WarmCleanupObjectIdentity {
                device: 1,
                inode: 6,
            },
            retained_retry: None,
            authority_digest: Sha256Digest::from_bytes([0; 32]),
        };
        authority.authority_digest =
            warm_cleanup_authority_digest(&authority).expect("digest memory cleanup authority");
        let physical = physical_for_warm_inventory(
            crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf()),
            command.node_id.clone(),
        );

        let prepared = match prepare_exact_warm_memory_removal(
            &physical,
            &authority,
            Instant::now() + Duration::from_secs(2),
        )
        .expect("prepare exact memory removal")
        {
            WarmMemoryRemovalPreparation::Exact(prepared) => prepared,
            WarmMemoryRemovalPreparation::Absent | WarmMemoryRemovalPreparation::Conflict => {
                panic!("exact memory must prepare")
            }
        };
        assert!(remove_prepared_warm_memory_file(
            prepared,
            Instant::now() + Duration::from_secs(2),
        )
        .expect("remove exact retained memory inode"));
        assert!(!memory_path.exists());
        assert!(remove_exact_warm_memory_file(
            &physical,
            &authority,
            Instant::now() + Duration::from_secs(2),
        )
        .expect("replay exact memory absence"));

        std::fs::write(&memory_path, b"exact-warm-memory").expect("write replacement Warm memory");
        assert_eq!(
            inspect_warm_memory_file(
                &physical,
                &authority,
                true,
                Instant::now() + Duration::from_secs(2),
            )
            .expect("inspect replacement memory"),
            ExactWarmObjectPresence::Conflict
        );
        assert!(!remove_exact_warm_memory_file(
            &physical,
            &authority,
            Instant::now() + Duration::from_secs(2),
        )
        .expect("replacement inode is a closed refusal"));
        assert!(memory_path.exists());
        std::fs::remove_file(&memory_path).expect("remove replacement fixture");

        let symlink_target = runtime_parent_path.join("symlink-target");
        std::fs::write(&symlink_target, b"exact-warm-memory").expect("write symlink target");
        symlink(&symlink_target, &memory_path).expect("create memory replacement symlink");
        assert_eq!(
            inspect_warm_memory_file(
                &physical,
                &authority,
                true,
                Instant::now() + Duration::from_secs(2),
            )
            .expect("inspect memory symlink"),
            ExactWarmObjectPresence::Conflict
        );
        assert!(std::fs::symlink_metadata(&memory_path)
            .expect("retain memory symlink")
            .file_type()
            .is_symlink());
        std::fs::remove_file(&memory_path).expect("remove memory symlink fixture");

        std::fs::write(&memory_path, b"hard-linked-memory").expect("write hard-linked Warm memory");
        authority.memory_file = memory_file_proof_from_path(
            &memory_path,
            b"hard-linked-memory".len() as u64,
            Instant::now() + Duration::from_secs(2),
            true,
        )
        .expect("prove memory before adding a hard link");
        let second_link = runtime_parent_path.join("memory-second-link");
        std::fs::hard_link(&memory_path, &second_link).expect("add memory hard link");
        assert_eq!(
            inspect_warm_memory_file(
                &physical,
                &authority,
                true,
                Instant::now() + Duration::from_secs(2),
            )
            .expect("inspect hard-linked memory"),
            ExactWarmObjectPresence::Conflict
        );
        assert!(memory_path.exists() && second_link.exists());

        drop(retained_old_inode);
    }

    #[test]
    fn descriptor_cleanup_rejects_replacement_symlink_and_hardlink_and_replays_absence() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("create cleanup directory");
        let parent = File::open(directory.path()).expect("open cleanup directory");
        let name = CString::new("terminal.json").unwrap();
        let path = directory.path().join("terminal.json");
        std::fs::write(&path, b"terminal").expect("write terminal fixture");
        let expected = regular_single_link_identity(
            &File::open(&path).expect("open terminal fixture for identity"),
        )
        .expect("inspect terminal identity");

        let mut replacement = expected.clone();
        replacement.inode += 1;
        assert!(!remove_exact_warm_file(
            &parent,
            &name,
            &replacement,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("wrong identity is a closed refusal"));
        assert!(path.exists());

        assert!(remove_exact_warm_file(
            &parent,
            &name,
            &expected,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("remove exact terminal fixture"));
        assert!(!path.exists());
        assert!(remove_exact_warm_file(
            &parent,
            &name,
            &expected,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("replay exact terminal absence"));

        let target = directory.path().join("target");
        std::fs::write(&target, b"target").expect("write symlink target");
        symlink(&target, &path).expect("create replacement symlink");
        let target_identity = regular_single_link_identity(
            &File::open(&target).expect("open symlink target for identity"),
        )
        .expect("inspect symlink target identity");
        assert!(!remove_exact_warm_file(
            &parent,
            &name,
            &target_identity,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("symlink is a closed refusal"));
        assert!(std::fs::symlink_metadata(&path)
            .expect("inspect retained symlink")
            .file_type()
            .is_symlink());
        std::fs::remove_file(&path).expect("remove test symlink");

        std::fs::write(&path, b"linked").expect("write linked fixture");
        let link = directory.path().join("second-link");
        std::fs::hard_link(&path, &link).expect("create second hard link");
        let linked_stat = fstatat_nofollow(&parent, &name)
            .expect("stat linked fixture")
            .expect("linked fixture exists");
        let linked_identity = stat_identity(&linked_stat).expect("linked fixture identity");
        assert!(remove_exact_warm_file(
            &parent,
            &name,
            &linked_identity,
            Instant::now() + Duration::from_secs(1),
        )
        .is_err());
        assert!(path.exists() && link.exists());
    }

    #[test]
    fn blockd_response_reader_uses_one_absolute_deadline_across_trickled_bytes() {
        let (mut client, mut server) = UnixStream::pair().expect("create blockd transport pair");
        let peer = thread::spawn(move || {
            for byte in b"OK\n" {
                thread::sleep(Duration::from_millis(30));
                if server.write_all(&[*byte]).is_err() {
                    break;
                }
            }
        });
        let bound = Duration::from_millis(70);
        let started = Instant::now();
        let error = read_blockd_response_until(&mut client, started + bound)
            .expect_err("a trickled blockd line must not extend the lifecycle deadline");
        let elapsed = started.elapsed();
        assert!(
            format!("{error:#}").contains("blockd drain response")
                || format!("{error:#}").contains("Unix control deadline elapsed"),
            "{error:#}"
        );
        assert!(
            elapsed >= Duration::from_millis(40) && elapsed < Duration::from_secs(1),
            "absolute blockd deadline returned after {elapsed:?}"
        );
        drop(client);
        peer.join().expect("join blockd trickle peer");
    }
}
