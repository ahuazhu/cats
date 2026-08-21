//! Checkpoint-first production `StartCat` machine.
//!
//! This module deliberately does not adapt the superseded Desired/reconcile
//! spine.  The canonical lifecycle envelope is the only intent.  Every
//! provider mutation receives an exact request which was already fsynced in
//! the per-Cat command journal, and every provider port must discover an
//! ambiguous prior submission before it returns.  A definite failure is not
//! terminal until the shared strong-Stop barrier has run under a newly
//! journaled Stop fence.
//!
//! The operation-scoped progress file below is physical evidence, never a
//! second state machine. Crash ordering is: the executor fsyncs an Executing
//! `ExecutionStep`; the exact port applies-or-discovers that request; this
//! handler fsyncs the cumulative physical evidence; then the executor fsyncs
//! the returned successor step. If a crash leaves evidence ahead of the old
//! Executing step, only inspect/discovery of that same journal request may
//! close the ambiguity. Missing or mismatched journal authority quarantines
//! the evidence and authorizes zero physical effects.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _};
use std::os::unix::fs::MetadataExt as _;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use cats_api::runtime_inventory::ObservedArtifactClassification;
use cats_api::runtime_lifecycle::{
    lifecycle_terminal_result_digest, validate_lifecycle_successor_with_predecessor_command,
    CommandFailedResult, CommandFailureReason, ExecutionAbsenceProof, LifecycleCommand,
    LifecycleCommandEnvelope, LifecycleCommandResponse, LifecyclePredecessor,
    LifecycleTerminalResult, NodeResult, PlacementIdentity, RetainedEvidence, RuntimeNetworkConfig,
    RuntimeReadyResult, RuntimeVolumeAuthorityInput, RuntimeVolumeConfig, StartSource,
    TerminalResultKind, VolumeTerminalReceipt,
};
use cats_api::runtime_lifecycle_volume::{
    decode_lifecycle_volume_transition_response, encode_lifecycle_volume_transition_response,
    LifecycleCommandStartVolumeGrantReceipt, LifecycleServingAcquire,
    LifecycleStartVolumeGrantAuthority, LifecycleVolumeTransitionRejection,
    LifecycleVolumeTransitionResponse, LifecycleVolumeTransitionResult,
};
use cats_api::runtime_reconciliation::{
    AcquireOrigin, ContractVersion, DiskKind, HostPath, Id, PrepareDeviceFrontend, RandomId128,
    RemoteHead, RuntimeLaunchIdentity, SessionBinding, Sha256Digest, UnixMillis, WireU64,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::admission::EffectiveRuntimeReady;
use crate::state_directory::StateDirectory;

use super::super::executor::{
    LifecycleEffectAuthority, LifecycleEffectProgress, PlannedLifecycleEffect,
};
use super::super::journal::{
    CommandJournalState, ExactBytes, ExecutionStep, StartupPhysicalInventory,
};
use super::common::InstalledLifecycleContext;
use super::strong_stop::{
    execute_command_strong_stop_with_start_grants, StartStrongStopInput, StrongStopEvidence,
};

const START_STEP_NAME: &str = "atomic_start_v1";
const START_STEP_MAX_BYTES: usize = 1_048_576;
const START_PLATFORM_PLAN_MAX_BYTES: usize = 131_072;
const START_PLATFORM_RECEIPT_MAX_BYTES: usize = 131_072;
const START_PLATFORM_AGGREGATE_MAX_BYTES: usize = 786_432;
const START_RUNTIME_EFFECT_COUNT: usize = 7;
const START_SESSION_REBIND_MAX_COUNT: usize = 16;
const ATTACHMENT_ID_DOMAIN: &[u8] = b"cats.atomic-lifecycle.start-attachment.v1";
const LAUNCH_VOLUME_ID_DOMAIN: &[u8] = b"cats.atomic-lifecycle.launch-volume-id.v1";
const FAILURE_FENCE_DOMAIN: &[u8] = b"cats.atomic-lifecycle.start-failure-fence.v1";
const PLATFORM_PLAN_DOMAIN: &[u8] = b"cats.atomic-lifecycle.start-platform-plan.v1";
const PLATFORM_RECEIPT_DOMAIN: &[u8] = b"cats.atomic-lifecycle.start-platform-receipt.v1";
const SESSION_REBIND_RECEIPT_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.start-session-rebind-receipt.v1";
const VOLUME_AUTHORITY_LINEAGE_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.start-volume-authority-lineage.v1";
const VOLUME_BATCH_REQUEST_DOMAIN: &[u8] = b"cats.atomic-lifecycle.start-volume-batch-request.v1";
const VOLUME_FAILURE_EVIDENCE_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.start-volume-failure-evidence.v1";
const VOLUME_LEASE_SESSION_DOMAIN: &[u8] = b"cats.atomic-lifecycle.start-volume-lease-session.v1";
const VOLUME_LEASE_GRANT_SET_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.start-volume-lease-grant-set.v1";
pub(crate) const START_VOLUME_LEASE_SAFETY_MARGIN_MS: u64 = 5_000;
const RUNTIME_MANIFEST_DOMAIN: &[u8] = b"cats.atomic-lifecycle.installed-runtime-manifest.v1";
const RUNTIME_PROGRESS_MANIFEST_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.installed-runtime-progress-manifest.v1";
const TERMINAL_RETAINED_MANIFEST_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.terminal-retained-runtime-manifest.v1";
const RUNTIME_MANIFEST_NAMESPACE: &str = "atomic-runtime-manifests-v1";
const RUNTIME_MANIFEST_SUFFIX: &str = ".runtime.json";
const RUNTIME_MANIFEST_TEMP_SUFFIX: &str = ".runtime.tmp";
const RUNTIME_MANIFEST_MAX_BYTES: usize = 1_048_576;
const RUNTIME_PROGRESS_NAMESPACE: &str = "atomic-runtime-progress-v1";
const RUNTIME_PROGRESS_SUFFIX: &str = ".start-progress.json";
const RUNTIME_PROGRESS_TEMP_SUFFIX: &str = ".start-progress.tmp";

/// One command-scoped storage mutation.  The port consumes the whole ordered
/// batch: it must not hide a partially applied prefix behind a generic error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtomicStartVolumeAction {
    NormalAcquire {
        volume: RuntimeVolumeConfig,
        expected_unowned_epoch: cats_api::runtime_reconciliation::FenceEpoch,
        transition_id: RandomId128,
        requested_attachment_id: Id,
        lease_duration_ms: WireU64,
    },
    RenewSameNode {
        volume: RuntimeVolumeConfig,
        attachment_id: Id,
        attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
        lease_duration_ms: WireU64,
    },
    Takeover {
        volume: RuntimeVolumeConfig,
        authorization_id: Id,
    },
}

impl AtomicStartVolumeAction {
    fn volume(&self) -> &RuntimeVolumeConfig {
        match self {
            Self::NormalAcquire { volume, .. }
            | Self::RenewSameNode { volume, .. }
            | Self::Takeover { volume, .. } => volume,
        }
    }
}

/// Exact durable input to the command-scoped Volume transaction/replay port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicStartVolumeBatchRequest {
    pub version: ContractVersion,
    /// Command-local immutable grant round. Zero is the initial typed
    /// acquire/renew/takeover batch; every later lease refresh is exactly the
    /// prior durable round plus one. The Control ledger keys replay by this
    /// value and rejects skips or rollback.
    pub grant_sequence: WireU64,
    pub operation_id: Id,
    pub cat_id: Id,
    pub node_id: Id,
    pub placement_identity: PlacementIdentity,
    pub request_fingerprint: Sha256Digest,
    /// Persisted even for a takeover-only initial batch because every later
    /// physical phase renews the returned attachment under this command.
    pub renewal_lease_duration_ms: WireU64,
    pub actions: Vec<AtomicStartVolumeAction>,
}

/// One currently usable writer-authority grant joined to a planned local
/// lineage path. The typed Control receipt proves only owner/attachment/epoch,
/// current head and lease. It never contains or stands in for a blockd token,
/// frontend capability or object-write credential; those are separately
/// planned and attributed physical effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicStartVolumeGrant {
    pub volume: VolumeTerminalReceipt,
    pub acquire_origin: AcquireOrigin,
    pub authoritative_head: RemoteHead,
    pub lease_expires_at_unix_ms: UnixMillis,
    pub grant_receipt_digest: Sha256Digest,
    pub authority_receipt: LifecycleCommandStartVolumeGrantReceipt,
    /// Side-effect-free installed target chosen before Root/device mutation.
    /// Existence and contents are reported only by runtime progress evidence.
    pub planned_local_lineage_data_directory: HostPath,
}

impl AtomicStartVolumeGrant {
    pub fn new(
        volume: VolumeTerminalReceipt,
        acquire_origin: AcquireOrigin,
        authoritative_head: RemoteHead,
        lease_expires_at_unix_ms: UnixMillis,
        grant_receipt_digest: Sha256Digest,
        authority_receipt: LifecycleCommandStartVolumeGrantReceipt,
        planned_local_lineage_data_directory: HostPath,
    ) -> Self {
        Self {
            volume,
            acquire_origin,
            authoritative_head,
            lease_expires_at_unix_ms,
            grant_receipt_digest,
            authority_receipt,
            planned_local_lineage_data_directory,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MonotonicLeaseRequestKey {
    operation_id: Id,
    session_digest: [u8; 32],
    request_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MonotonicLeaseGrantSetKey {
    operation_id: Id,
    session_digest: [u8; 32],
    grant_set_digest: [u8; 32],
}

#[derive(Default)]
struct ProcessLocalStartLeaseRegistry {
    /// The first local submission instant is retained until this operation
    /// settles. Replaying the same Control request in this process therefore
    /// cannot extend an older server-side lease.
    request_started_at: BTreeMap<MonotonicLeaseRequestKey, Instant>,
    grant_valid_until: BTreeMap<MonotonicLeaseGrantSetKey, Instant>,
}

static PROCESS_LOCAL_START_LEASES: OnceLock<Mutex<ProcessLocalStartLeaseRegistry>> =
    OnceLock::new();

fn process_local_start_leases() -> &'static Mutex<ProcessLocalStartLeaseRegistry> {
    PROCESS_LOCAL_START_LEASES.get_or_init(|| Mutex::new(ProcessLocalStartLeaseRegistry::default()))
}

fn lease_session_digest(session: &SessionBinding) -> Result<Sha256Digest> {
    let value = serde_json::to_value(session).context("encode Start lease AgentSession")?;
    let canonical = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    Ok(digest_parts(VOLUME_LEASE_SESSION_DOMAIN, &[&canonical]))
}

fn lease_grant_set_digest(
    grant_sequence: WireU64,
    grants: &[AtomicStartVolumeGrant],
) -> Result<Sha256Digest> {
    anyhow::ensure!(
        !grants.is_empty()
            && grants
                .windows(2)
                .all(|pair| pair[0].volume.volume_id < pair[1].volume.volume_id)
            && grants
                .iter()
                .all(|grant| grant.authority_receipt.grant_sequence == grant_sequence),
        "monotonic Start lease witness has an invalid grant set"
    );
    let value = serde_json::json!({
        "grant_sequence": grant_sequence,
        "grants": grants,
    });
    let canonical = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    Ok(digest_parts(VOLUME_LEASE_GRANT_SET_DOMAIN, &[&canonical]))
}

/// Record the earliest local monotonic instant at which this exact batch was
/// submitted under its planned AgentSession. `None` means the durable batch
/// came from an older process/session and is discovery-only in this process.
pub(crate) fn begin_start_volume_lease_request(
    request: &AtomicStartVolumeBatchRequest,
    planned_session: &SessionBinding,
    current_session: &SessionBinding,
) -> Result<Option<Instant>> {
    begin_start_volume_lease_request_at(request, planned_session, current_session, Instant::now())
}

fn begin_start_volume_lease_request_at(
    request: &AtomicStartVolumeBatchRequest,
    planned_session: &SessionBinding,
    current_session: &SessionBinding,
    now: Instant,
) -> Result<Option<Instant>> {
    if planned_session != current_session {
        return Ok(None);
    }
    let key = MonotonicLeaseRequestKey {
        operation_id: request.operation_id.clone(),
        session_digest: *lease_session_digest(current_session)?.as_bytes(),
        request_digest: *atomic_start_volume_batch_request_digest(request)?.as_bytes(),
    };
    let mut registry = process_local_start_leases()
        .lock()
        .map_err(|_| anyhow::anyhow!("process-local Start lease registry is poisoned"))?;
    Ok(Some(*registry.request_started_at.entry(key).or_insert(now)))
}

/// Publish a monotonic witness only after the exact grant set has been fully
/// joined and validated. The deadline starts at the first request attempt,
/// not response receipt, so transport latency can only shorten local use.
pub(crate) fn publish_start_volume_lease_witness(
    request: &AtomicStartVolumeBatchRequest,
    receipt: &AtomicStartVolumeBatchReceipt,
    planned_session: &SessionBinding,
    request_started_at: Option<Instant>,
) -> Result<()> {
    let Some(request_started_at) = request_started_at else {
        return Ok(());
    };
    anyhow::ensure!(
        receipt.grant_sequence == request.grant_sequence,
        "monotonic Start lease witness changed its grant sequence"
    );
    let valid_until = request_started_at
        .checked_add(Duration::from_millis(
            request.renewal_lease_duration_ms.get(),
        ))
        .context("monotonic Start lease deadline overflow")?;
    let key = MonotonicLeaseGrantSetKey {
        operation_id: request.operation_id.clone(),
        session_digest: *lease_session_digest(planned_session)?.as_bytes(),
        grant_set_digest: *lease_grant_set_digest(receipt.grant_sequence, &receipt.grants)?
            .as_bytes(),
    };
    let mut registry = process_local_start_leases()
        .lock()
        .map_err(|_| anyhow::anyhow!("process-local Start lease registry is poisoned"))?;
    registry
        .grant_valid_until
        .entry(key)
        .and_modify(|current| *current = (*current).min(valid_until))
        .or_insert(valid_until);
    Ok(())
}

fn monotonic_volume_grants_cover_at(
    operation_id: &Id,
    session: &SessionBinding,
    grant_sequence: WireU64,
    grants: &[AtomicStartVolumeGrant],
    required: Duration,
    now: Instant,
) -> Result<bool> {
    let required_until = now
        .checked_add(required)
        .context("required Start lease budget overflows monotonic clock")?;
    let key = MonotonicLeaseGrantSetKey {
        operation_id: operation_id.clone(),
        session_digest: *lease_session_digest(session)?.as_bytes(),
        grant_set_digest: *lease_grant_set_digest(grant_sequence, grants)?.as_bytes(),
    };
    let registry = process_local_start_leases()
        .lock()
        .map_err(|_| anyhow::anyhow!("process-local Start lease registry is poisoned"))?;
    Ok(registry
        .grant_valid_until
        .get(&key)
        .is_some_and(|valid_until| *valid_until > required_until))
}

/// The sole local safety oracle for starting a new physical mutation. Wire
/// Unix expiry is intentionally absent from this calculation.
pub(crate) fn runtime_context_has_monotonic_lease_budget(
    context: &AtomicStartRuntimeContext,
    required: Duration,
) -> Result<bool> {
    let operation_id = context
        .volume_grants
        .first()
        .map(|grant| &grant.authority_receipt.scope.operation_id)
        .context("runtime lease context has no grant")?;
    anyhow::ensure!(
        context
            .volume_grants
            .iter()
            .all(|grant| grant.authority_receipt.scope.operation_id == *operation_id),
        "runtime lease context mixes lifecycle operations"
    );
    monotonic_volume_grants_cover_at(
        operation_id,
        &context.volume_lease_session,
        context.volume_grant_sequence,
        &context.volume_grants,
        required,
        Instant::now(),
    )
}

fn forget_process_local_start_lease_witnesses(operation_id: &Id) -> Result<()> {
    let mut registry = process_local_start_leases()
        .lock()
        .map_err(|_| anyhow::anyhow!("process-local Start lease registry is poisoned"))?;
    registry
        .request_started_at
        .retain(|key, _| key.operation_id != *operation_id);
    registry
        .grant_valid_until
        .retain(|key, _| key.operation_id != *operation_id);
    Ok(())
}

/// A completely discovered, ordered storage postcondition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicStartVolumeBatchReceipt {
    pub grant_sequence: WireU64,
    pub grants: Vec<AtomicStartVolumeGrant>,
}

/// Closed proof that one already-journaled Volume batch definitely made no
/// mutation. A Control rejection retains the complete canonical response,
/// including its AgentSession and typed reason; a local deadline decision is
/// a separate typed arm and can never masquerade as a provider response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtomicStartVolumeFailureOutcome {
    LocalDeadlineElapsed { observed_at_unix_ms: UnixMillis },
    ControlRejected { canonical_response: ExactBytes },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicStartVolumeFailureEvidence {
    pub request_digest: Sha256Digest,
    pub outcome: AtomicStartVolumeFailureOutcome,
    pub evidence_digest: Sha256Digest,
}

impl AtomicStartVolumeFailureEvidence {
    pub fn local_deadline_elapsed(
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartVolumeBatchRequest,
    ) -> Result<Self> {
        new_volume_failure_evidence(
            command,
            request,
            AtomicStartVolumeFailureOutcome::LocalDeadlineElapsed {
                observed_at_unix_ms: UnixMillis::new(current_unix_ms()?)
                    .context("encode atomic Start Volume deadline observation")?,
            },
        )
    }

    pub fn control_rejected(
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartVolumeBatchRequest,
        response: &LifecycleVolumeTransitionResponse,
    ) -> Result<Self> {
        let bytes = encode_lifecycle_volume_transition_response(response)
            .context("encode rejected atomic Start Volume response")?;
        new_volume_failure_evidence(
            command,
            request,
            AtomicStartVolumeFailureOutcome::ControlRejected {
                canonical_response: ExactBytes::new(bytes),
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AtomicStartFailedVolumeEffect {
    pub(crate) request: AtomicStartVolumeBatchRequest,
    pub(crate) evidence: AtomicStartVolumeFailureEvidence,
}

/// A provider-reported business failure whose physical/storage residue has
/// already been classified.  Transport errors and an undiscoverable response
/// are returned as `Err` instead, leaving the exact durable step Executing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicStartDefiniteFailure {
    pub reason: CommandFailureReason,
    pub artifact_classifications: Vec<ObservedArtifactClassification>,
    /// Runtime adapters return their freshly discovered cumulative physical
    /// attribution here. Volume-authority failures, which occur before any
    /// runtime effect, use `None`.
    pub runtime_progress: Option<InstalledRuntimeProgressManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomicStartVolumeOutcome {
    Ready(AtomicStartVolumeBatchReceipt),
    Failed {
        failure: Box<AtomicStartDefiniteFailure>,
        evidence: Box<AtomicStartVolumeFailureEvidence>,
    },
}

/// The sole Node-facing writer-authority seam used by atomic Start.
///
/// The implementation must bind every mutation/replay/evidence read to the
/// envelope's lifecycle Operation and fingerprint.  An ambiguous submission
/// must be resolved to one exact `Ready`/`Failed` postcondition or returned as
/// `Err`; blindly submitting the batch again is forbidden.
pub trait AtomicStartVolumePort: Send + Sync + 'static {
    /// Stable installed policy sampled once by `plan` and then carried only in
    /// the fsynced command step. A restart never substitutes a new value into
    /// an already Executing command.
    fn configured_lease_duration_ms(&self) -> WireU64;

    /// Current AgentSession used to authenticate the outer Control request.
    /// It is persisted in the local batch solely to invalidate process-local
    /// monotonic lease witnesses after restart or session replacement.
    fn current_agent_session_binding(&self) -> Result<SessionBinding>;

    fn inspect_or_apply_start_volumes(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartVolumeBatchRequest,
        planned_agent_session: &SessionBinding,
    ) -> Result<AtomicStartVolumeOutcome>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicStartRuntimeEffectPhase {
    PrepareRoot,
    PrepareDevices,
    PrepareNetwork,
    ActivateRuntime,
    /// Journaled `FormatStarted` plan. For each Persistent volume this either
    /// verifies an exact already-initialized UUID or carries the signed
    /// Uninitialized token/blank-head input used for probe/mkfs/flush/drain.
    FormatPersistentVolumes,
    /// Submit or discover the exact command/session-bound
    /// `commit_initialized` CAS after the format phase proved UUID and R=L.
    CommitPersistentInitialized,
    GuestReadyAndAdmission,
}

impl AtomicStartRuntimeEffectPhase {
    fn first() -> Self {
        Self::PrepareRoot
    }

    fn next(self) -> Option<Self> {
        match self {
            Self::PrepareRoot => Some(Self::PrepareDevices),
            Self::PrepareDevices => Some(Self::PrepareNetwork),
            Self::PrepareNetwork => Some(Self::ActivateRuntime),
            Self::ActivateRuntime => Some(Self::FormatPersistentVolumes),
            Self::FormatPersistentVolumes => Some(Self::CommitPersistentInitialized),
            Self::CommitPersistentInitialized => Some(Self::GuestReadyAndAdmission),
            Self::GuestReadyAndAdmission => None,
        }
    }
}

/// Exact Warm restart authority carried before the first command mutation.
/// The authority retains descriptor identities; its physical digest closes
/// the volume/lineage carrier inspected for this Start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AtomicStartWarmRestartSource {
    pub(crate) physical_manifest_digest: Sha256Digest,
    pub(crate) cleanup_authority: Box<super::WarmSnapshotCleanupAuthority>,
}

/// Immutable context passed to each one-effect runtime adapter.  Completed
/// receipts are retained only in the current bounded step, so recovery never
/// has to consult a mutable product row or a retired reconciliation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicStartRuntimeContext {
    pub runtime_incarnation: RandomId128,
    pub source: StartSource,
    /// Exact same-Node terminal result used by restore/resume/retry planning.
    /// Cross-Node/Genesis sources remain fully described by the command's
    /// typed predecessor and carry `None` here.
    pub local_predecessor: Option<LifecycleCommandResponse>,
    /// A direct Warm source, or a retained Warm source purely rebound from the
    /// exact immediate StartFailed carrier to this SameNodeRetry command.
    pub(crate) warm_restart_source: Option<AtomicStartWarmRestartSource>,
    pub effect_deadline_unix_ms: UnixMillis,
    pub volume_lease_duration_ms: WireU64,
    /// Stable installed per-phase upper bound sampled before the first
    /// mutation. It is combined with a fixed settlement margin when deciding
    /// whether a monotonic lease witness can cover another physical effect.
    pub runtime_effect_timeout_ms: WireU64,
    /// Session which planned the grant batch now carried by `volume_grants`.
    /// The wall-clock expiry remains evidence only; physical effects require
    /// an in-process monotonic witness under this exact session and grant set.
    pub volume_lease_session: SessionBinding,
    /// Sequence of the exact authoritative grant set below. It advances only
    /// after a matching command-scoped Volume receipt is returned.
    pub volume_grant_sequence: WireU64,
    pub volume_grants: Vec<AtomicStartVolumeGrant>,
    /// Latest cumulative physical attribution rebound to the current grant
    /// round. It exists immediately after authority acquisition, before Root
    /// materialization, so a failure can never lose the exact Owned lineage.
    pub runtime_progress: InstalledRuntimeProgressManifest,
    pub completed_effects: Vec<AtomicStartRuntimeEffectReceipt>,
    /// Exact zero-mutation cleanup proofs for obsolete AgentSession-bound
    /// plans. They remain in the sole journal context so a replacement plan
    /// can never erase why it was safe to abandon its predecessor.
    pub session_rebind_receipts: Vec<AtomicStartSessionRebindReceipt>,
    pub artifact_classifications: Vec<ObservedArtifactClassification>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicStartRuntimeEffectRequest {
    pub phase: AtomicStartRuntimeEffectPhase,
    pub context: AtomicStartRuntimeContext,
    /// Provider-private closed plan selected without side effects and fsynced
    /// in the sole lifecycle journal before apply/discovery. Runtime adapters
    /// must never substitute paths, process identities, device tokens, TAP
    /// capabilities or Guest CIDs after this request becomes Executing.
    pub platform_plan: ExactBytes,
}

/// Exact provider-private receipt for one completed physical edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicStartRuntimeEffectReceipt {
    pub phase: AtomicStartRuntimeEffectPhase,
    /// Exact previously journaled provider plan retained in the successor
    /// context. Later phase planners may decode it to construct joined device
    /// and VMM identities without reading mutable Host state.
    pub platform_plan: ExactBytes,
    pub platform_plan_digest: Sha256Digest,
    /// Closed provider receipt bytes for this exact effect. Later planners
    /// decode these bytes rather than rediscovering credentials, provision
    /// responses, process submissions, format proofs or initialization CAS
    /// receipts from an unjournaled sidecar.
    pub platform_receipt: ExactBytes,
    pub receipt_digest: Sha256Digest,
    pub artifact_classifications: Vec<ObservedArtifactClassification>,
    /// Full cumulative attribution after this effect, not merely the delta.
    /// It is embedded in the next durable command step and independently
    /// fsynced before that step is installed.
    pub runtime_progress: InstalledRuntimeProgressManifest,
}

/// Durable proof that an obsolete session-bound plan was unused and its
/// registration was exactly cleaned before a replacement plan was selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicStartSessionRebindReceipt {
    pub phase: AtomicStartRuntimeEffectPhase,
    pub volume_grant_sequence: WireU64,
    pub old_platform_plan: ExactBytes,
    pub old_platform_plan_digest: Sha256Digest,
    pub cleanup_receipt: ExactBytes,
    pub cleanup_receipt_digest: Sha256Digest,
    pub runtime_progress: InstalledRuntimeProgressManifest,
}

/// Kernel identity which closes PID reuse. `start_time_ticks` is field 22 of
/// `/proc/<pid>/stat`, captured and revalidated by the installed process
/// scanner together with the executable and parent Cat slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledRuntimeProcessIdentity {
    pub pid: u32,
    pub start_time_ticks: WireU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InstalledRuntimeBlockFrontend {
    KernelNbd {
        device_path: HostPath,
        client: InstalledRuntimeProcessIdentity,
    },
    VhostUserBlk {
        socket_path: HostPath,
    },
}

/// Exact installed block path for one immutable runtime-config volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledRuntimeVolumeManifest {
    pub volume_id: Id,
    pub disk_id: Id,
    pub disk_role: cats_api::runtime_lifecycle::DiskRole,
    pub attachment_id: Id,
    pub attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    pub acquire_origin: AcquireOrigin,
    /// Remote head consumed by the immutable VMM launch identity. The live
    /// Running head may advance after boot; terminal L/R receipts must be at
    /// or beyond this generation.
    pub launch_head: RemoteHead,
    /// Fresh full authority head joined at RuntimeReady. This may be later
    /// than the immutable VMM launch lower bound after filesystem
    /// initialization or Guest readiness I/O.
    pub current_authority_head: RemoteHead,
    /// Exact command-authority receipt which admitted this attachment.  A
    /// running Start always records `Some`; the optional wire shape matches
    /// `VolumeTerminalReceipt` and lets a scanner reject legacy/unknown
    /// residue without inventing authority.
    pub authority_receipt_digest: Option<Sha256Digest>,
    /// Exact local lineage root.  The control socket cannot recover retained
    /// data after blockd has exited, so strong Stop and restart inventory must
    /// retain this independently discoverable path.
    pub local_lineage_data_directory: HostPath,
    pub blockd: InstalledRuntimeProcessIdentity,
    pub blockd_control_socket_path: HostPath,
    pub frontend: InstalledRuntimeBlockFrontend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledRuntimeVmmManifest {
    pub process: InstalledRuntimeProcessIdentity,
    pub parent_slice_id: Id,
    pub systemd_unit_id: Id,
    pub api_socket_path: HostPath,
    pub vsock_socket_path: HostPath,
    pub memory_file_path: HostPath,
    /// Complete launch identity consumed by the canonical Cloud Hypervisor
    /// API inspector. Paths/PID alone cannot revalidate boot provenance,
    /// CID, device direct/queue settings or network ownership after restart.
    pub launch_identity: Box<RuntimeLaunchIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledRuntimeNetworkManifest {
    /// Full immutable reservation identity required by the canonical Host
    /// network scanner. A logical network Id and tap name cannot classify
    /// address/MAC overlap after an Agent restart.
    pub identity: Box<cats_api::runtime_reconciliation::RuntimeNetworkIdentity>,
}

/// Cumulative physical attribution while Start is still non-terminal.  Each
/// volume is always present in immutable runtime-config order; Option fields
/// mean that exact physical edge has not yet been created, never "unknown".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledRuntimeProgressVolumeManifest {
    pub volume_id: Id,
    pub disk_id: Id,
    pub disk_role: cats_api::runtime_lifecycle::DiskRole,
    pub attachment_id: Id,
    pub attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    pub acquire_origin: AcquireOrigin,
    /// Fresh authority head used by the next journal-named physical effect.
    pub authority_head: RemoteHead,
    pub authority_receipt_digest: Option<Sha256Digest>,
    pub local_lineage_data_directory: Option<HostPath>,
    pub blockd: Option<InstalledRuntimeProcessIdentity>,
    pub blockd_control_socket_path: Option<HostPath>,
    pub frontend: Option<InstalledRuntimeBlockFrontend>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledRuntimeProgressManifest {
    pub version: ContractVersion,
    pub node_id: Id,
    pub cat_id: Id,
    pub placement_identity: PlacementIdentity,
    pub source_lifecycle_operation_id: Id,
    pub request_fingerprint: Sha256Digest,
    pub runtime_config_id: Id,
    pub runtime_config_digest: Sha256Digest,
    pub runtime_incarnation: RandomId128,
    pub vmm: Option<InstalledRuntimeVmmManifest>,
    pub network: Option<InstalledRuntimeNetworkManifest>,
    pub volumes: Vec<InstalledRuntimeProgressVolumeManifest>,
    pub artifact_classifications: Vec<ObservedArtifactClassification>,
    pub manifest_digest: Sha256Digest,
}

impl InstalledRuntimeProgressManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command: &LifecycleCommandEnvelope,
        runtime_incarnation: RandomId128,
        vmm: Option<InstalledRuntimeVmmManifest>,
        network: Option<InstalledRuntimeNetworkManifest>,
        volumes: Vec<InstalledRuntimeProgressVolumeManifest>,
        artifact_classifications: Vec<ObservedArtifactClassification>,
    ) -> Result<Self> {
        let mut manifest = Self {
            version: ContractVersion::V1,
            node_id: command.node_id.clone(),
            cat_id: command.cat_id.clone(),
            placement_identity: command.placement_identity.clone(),
            source_lifecycle_operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            runtime_config_id: command.runtime_config.config_id.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            runtime_incarnation,
            vmm,
            network,
            volumes,
            artifact_classifications,
            manifest_digest: Sha256Digest::from_bytes([0; 32]),
        };
        manifest.manifest_digest = installed_runtime_progress_manifest_digest(&manifest)?;
        validate_installed_runtime_progress_manifest(&manifest, command)?;
        Ok(manifest)
    }
}

fn initial_runtime_progress_from_volume_grants(
    command: &LifecycleCommandEnvelope,
    runtime_incarnation: RandomId128,
    grants: &[AtomicStartVolumeGrant],
) -> Result<InstalledRuntimeProgressManifest> {
    let volumes = grants
        .iter()
        .map(|grant| InstalledRuntimeProgressVolumeManifest {
            volume_id: grant.volume.volume_id.clone(),
            disk_id: grant.volume.disk_id.clone(),
            disk_role: grant.volume.disk_role,
            attachment_id: grant.volume.attachment_id.clone(),
            attachment_epoch: grant.volume.attachment_epoch,
            acquire_origin: grant.acquire_origin.clone(),
            authority_head: grant.authoritative_head.clone(),
            authority_receipt_digest: Some(grant.grant_receipt_digest.clone()),
            local_lineage_data_directory: None,
            blockd: None,
            blockd_control_socket_path: None,
            frontend: None,
        })
        .collect();
    InstalledRuntimeProgressManifest::new(
        command,
        runtime_incarnation,
        None,
        None,
        volumes,
        volume_grant_artifacts(grants)?,
    )
}

fn rebind_runtime_progress_to_volume_grants(
    command: &LifecycleCommandEnvelope,
    progress: &InstalledRuntimeProgressManifest,
    grants: &[AtomicStartVolumeGrant],
) -> Result<InstalledRuntimeProgressManifest> {
    anyhow::ensure!(
        progress.volumes.len() == grants.len(),
        "atomic Start Volume refresh cannot rebind an incomplete progress set"
    );
    let mut rebound = progress.clone();
    for (volume, grant) in rebound.volumes.iter_mut().zip(grants) {
        anyhow::ensure!(
            volume.volume_id == grant.volume.volume_id
                && volume.disk_id == grant.volume.disk_id
                && volume.attachment_id == grant.volume.attachment_id
                && volume.attachment_epoch == grant.volume.attachment_epoch
                && volume.acquire_origin == grant.acquire_origin,
            "atomic Start Volume refresh changed physical progress lineage"
        );
        volume.authority_head = grant.authoritative_head.clone();
        volume.authority_receipt_digest = Some(grant.grant_receipt_digest.clone());
    }
    rebound.manifest_digest = installed_runtime_progress_manifest_digest(&rebound)?;
    validate_installed_runtime_progress_manifest(&rebound, command)?;
    validate_runtime_progress_against_volume_grants(&rebound, grants)?;
    validate_runtime_progress_authority_rebind(progress, &rebound)?;
    Ok(rebound)
}

/// A failed Start's command-bound physical evidence. This artifact is never a
/// restart source: the installed StopFence has already closed execution, and
/// successor Stop/inventory/GC may use it only to locate and classify exact
/// retained authority or data before fresh discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TerminalRetainedRuntimeDisposition {
    NonExecutable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TerminalRetainedRuntimeMode {
    /// Volume authority was acquired and is still Owned, but a fresh complete
    /// post-stop scan proves no lineage, frontend, blockd, network or VMM was
    /// ever materialized. This is not the all-Unowned empty failure arm.
    AuthorityOnlyOwnedZeroMutation {
        complete_scan_digest: Sha256Digest,
    },
    MaterializedOrAmbiguous,
    /// This Start acquired no current-operation grant and made no current
    /// physical mutation, but its exact same-Node predecessor remained Owned
    /// after the signed sequence-zero renewal batch was definitely rejected.
    /// The flat projection below bridges that predecessor into this failed
    /// operation without making either artifact executable or recursively
    /// embedding an older terminal manifest.
    InheritedPredecessorOwned {
        evidence: Box<InheritedPredecessorOwnedEvidence>,
    },
}

/// Closed same-Node predecessor projection retained by a failed sequence-zero
/// renewal. It is physical attribution only: the current command has no
/// StartGrant and this evidence cannot authorize adoption, restart, or a
/// provider mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InheritedPredecessorOwnedEvidence {
    pub(crate) predecessor_operation_id: Id,
    pub(crate) predecessor_request_fingerprint: Sha256Digest,
    pub(crate) predecessor_terminal_result_kind: TerminalResultKind,
    pub(crate) predecessor_terminal_result_digest: Sha256Digest,
    pub(crate) predecessor_physical_manifest_digest: Sha256Digest,
    pub(crate) predecessor_runtime_incarnation: Option<RandomId128>,
    pub(crate) failed_volume_effect: AtomicStartFailedVolumeEffect,
    pub(crate) volumes: Vec<InheritedPredecessorOwnedVolume>,
}

/// One freshly revalidated predecessor attachment and its descriptor-stable
/// local lineage. `retained_receipt` is the post-StrongStop L/R projection;
/// the immutable receipt digest continues to name the predecessor StartGrant,
/// never a fabricated grant for the current failed operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InheritedPredecessorOwnedVolume {
    pub(crate) retained_receipt: VolumeTerminalReceipt,
    pub(crate) acquire_origin: AcquireOrigin,
    pub(crate) authoritative_head: RemoteHead,
    pub(crate) immutable_start_grant_receipt_digest: Sha256Digest,
    pub(crate) local_lineage_data_directory: Option<HostPath>,
}

/// Read-only predecessor attribution captured before a failed Start installs
/// its strong-Stop fence. It is embedded in that Executing step so a crash
/// after stopping a Suspended runtime cannot force recovery to rescan or guess
/// the predecessor which existed before the physical effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InheritedPredecessorPhysicalProjection {
    pub(super) target_operation_id: Id,
    pub(super) target_request_fingerprint: Sha256Digest,
    pub(super) target_runtime_config_id: Id,
    pub(super) target_runtime_config_digest: Sha256Digest,
    pub(super) target_runtime_incarnation: RandomId128,
    pub(super) predecessor_operation_id: Id,
    pub(super) predecessor_request_fingerprint: Sha256Digest,
    pub(super) predecessor_terminal_result_kind: TerminalResultKind,
    pub(super) predecessor_terminal_result_digest: Sha256Digest,
    pub(super) physical_manifest_digest: Sha256Digest,
    pub(super) runtime_incarnation: Option<RandomId128>,
    pub(super) warm_restart_source: Option<AtomicStartWarmRestartSource>,
    pub(super) volumes: Vec<InheritedPredecessorPhysicalVolume>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InheritedPredecessorPhysicalVolume {
    pub(super) volume_id: Id,
    pub(super) disk_id: Id,
    pub(super) disk_role: cats_api::runtime_lifecycle::DiskRole,
    pub(super) attachment_id: Id,
    pub(super) attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    pub(super) acquire_origin: AcquireOrigin,
    pub(super) authoritative_head: RemoteHead,
    pub(super) immutable_start_grant_receipt_digest: Sha256Digest,
    pub(super) local_lineage_data_directory: Option<HostPath>,
}

impl InheritedPredecessorOwnedEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        predecessor_physical_manifest_digest: Sha256Digest,
        predecessor_runtime_incarnation: Option<RandomId128>,
        failed_volume_effect: AtomicStartFailedVolumeEffect,
        volumes: Vec<InheritedPredecessorOwnedVolume>,
    ) -> Result<Self> {
        let LifecyclePredecessor::SameNode {
            operation_id,
            terminal_result_kind,
            terminal_result_digest,
            node_id,
            placement_identity,
        } = &command.predecessor
        else {
            anyhow::bail!("inherited failed Start evidence lacks a same-Node predecessor")
        };
        let actual_terminal_digest =
            lifecycle_terminal_result_digest(&LifecycleTerminalResult::NodeResult {
                response: Box::new(predecessor.clone()),
            })
            .context("digest inherited failed Start predecessor terminal result")?;
        anyhow::ensure!(
            predecessor.operation_id == *operation_id
                && predecessor.node_id == *node_id
                && predecessor.placement_identity == *placement_identity
                && predecessor.result.kind() == *terminal_result_kind
                && actual_terminal_digest == *terminal_result_digest,
            "inherited failed Start predecessor response changed its signed identity"
        );
        let evidence = Self {
            predecessor_operation_id: operation_id.clone(),
            predecessor_request_fingerprint: predecessor.request_fingerprint.clone(),
            predecessor_terminal_result_kind: *terminal_result_kind,
            predecessor_terminal_result_digest: terminal_result_digest.clone(),
            predecessor_physical_manifest_digest,
            predecessor_runtime_incarnation,
            failed_volume_effect,
            volumes,
        };
        validate_inherited_predecessor_owned_evidence(&evidence, None, Some(command))?;
        Ok(evidence)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TerminalRetainedRuntimeManifest {
    pub(crate) version: ContractVersion,
    pub(crate) disposition: TerminalRetainedRuntimeDisposition,
    pub(crate) node_id: Id,
    pub(crate) cat_id: Id,
    pub(crate) placement_identity: PlacementIdentity,
    pub(crate) source_lifecycle_operation_id: Id,
    pub(crate) request_fingerprint: Sha256Digest,
    pub(crate) runtime_config_id: Id,
    pub(crate) runtime_config_digest: Sha256Digest,
    pub(crate) runtime_incarnation: RandomId128,
    pub(crate) retention_mode: TerminalRetainedRuntimeMode,
    pub(crate) execution_absence: ExecutionAbsenceProof,
    pub(crate) post_stop_physical_projection_digest: Sha256Digest,
    /// Original command-scoped Start grants retain the complete acquisition
    /// lineage and immutable authority receipt. They never authorize replay.
    pub(crate) volume_grants: Vec<AtomicStartVolumeGrant>,
    /// Fresh post-stop L/R and retained attachment subset. A missing entry is
    /// not guessed Unowned; consumers must perform fresh authority discovery.
    pub(crate) retained_volume_receipts: Vec<VolumeTerminalReceipt>,
    /// Present only when this failed Start itself acquired authority. An
    /// inherited-predecessor archive deliberately has no current-operation
    /// progress or grant and stores its flat closed projection in the mode.
    pub(crate) runtime_progress: Option<InstalledRuntimeProgressManifest>,
    /// Counts/digest from the fresh post-stop complete physical scan. The
    /// StartFailed result replaces only its artifact_manifest_digest with this
    /// enclosing manifest's digest.
    pub(crate) physical_retained_evidence: RetainedEvidence,
    /// Descriptor-complete Warm bundle retained as non-executable after the
    /// original terminal restart authority was revoked. Only the exact next
    /// SameNodeRetry may purely rebind this carrier.
    pub(crate) retained_warm_restart_source:
        Option<Box<super::suspend_warm::RetainedWarmRestartSourceCarrier>>,
    pub(crate) manifest_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "manifest_kind", content = "manifest", rename_all = "snake_case")]
enum DurableStartPhysicalManifest {
    Executing(Box<InstalledRuntimeProgressManifest>),
    TerminalRetained(Box<TerminalRetainedRuntimeManifest>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstalledStartPhysicalInventoryEntry {
    Executing(Box<InstalledRuntimeProgressManifest>),
    TerminalRetained(Box<TerminalRetainedRuntimeManifest>),
}

fn installed_start_physical_inventory_key(
    entry: &InstalledStartPhysicalInventoryEntry,
) -> (&Id, &Id) {
    match entry {
        InstalledStartPhysicalInventoryEntry::Executing(progress) => {
            (&progress.cat_id, &progress.source_lifecycle_operation_id)
        }
        InstalledStartPhysicalInventoryEntry::TerminalRetained(manifest) => {
            (&manifest.cat_id, &manifest.source_lifecycle_operation_id)
        }
    }
}

impl TerminalRetainedRuntimeManifest {
    fn new(
        command: &LifecycleCommandEnvelope,
        volume_grants: Vec<AtomicStartVolumeGrant>,
        runtime_progress: InstalledRuntimeProgressManifest,
        stop: &StrongStopEvidence,
    ) -> Result<Self> {
        anyhow::ensure!(
            stop.restart_source_cleanup_receipt_digest.is_some()
                == stop.retained_warm_restart_source.is_some(),
            "failed Start Warm cleanup receipt and retained carrier differ"
        );
        let retention_mode = if volume_grants
            .iter()
            .all(|grant| grant.authority_receipt.grant_sequence.get() == 0)
            && validate_authority_only_runtime_progress(&runtime_progress).is_ok()
            && runtime_progress.artifact_classifications == volume_grant_artifacts(&volume_grants)?
        {
            TerminalRetainedRuntimeMode::AuthorityOnlyOwnedZeroMutation {
                complete_scan_digest: stop.post_stop_physical_projection_digest.clone(),
            }
        } else {
            TerminalRetainedRuntimeMode::MaterializedOrAmbiguous
        };
        let mut manifest = Self {
            version: ContractVersion::V1,
            disposition: TerminalRetainedRuntimeDisposition::NonExecutable,
            node_id: command.node_id.clone(),
            cat_id: command.cat_id.clone(),
            placement_identity: command.placement_identity.clone(),
            source_lifecycle_operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            runtime_config_id: command.runtime_config.config_id.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            runtime_incarnation: runtime_progress.runtime_incarnation.clone(),
            retention_mode,
            execution_absence: stop.execution_absence.clone(),
            post_stop_physical_projection_digest: stop.post_stop_physical_projection_digest.clone(),
            volume_grants,
            retained_volume_receipts: stop.retained_volume_receipts.clone(),
            runtime_progress: Some(runtime_progress),
            physical_retained_evidence: stop.retained_evidence.clone(),
            retained_warm_restart_source: stop.retained_warm_restart_source.clone(),
            manifest_digest: Sha256Digest::from_bytes([0; 32]),
        };
        manifest.manifest_digest = terminal_retained_runtime_manifest_digest(&manifest)?;
        validate_terminal_retained_runtime_manifest(&manifest, Some(command))?;
        Ok(manifest)
    }

    fn new_inherited_predecessor_owned(
        command: &LifecycleCommandEnvelope,
        runtime_incarnation: RandomId128,
        evidence: InheritedPredecessorOwnedEvidence,
        stop: &StrongStopEvidence,
    ) -> Result<Self> {
        anyhow::ensure!(
            stop.restart_source_cleanup_receipt_digest.is_some()
                == stop.retained_warm_restart_source.is_some(),
            "inherited failed Start Warm cleanup receipt and retained carrier differ"
        );
        let mut manifest = Self {
            version: ContractVersion::V1,
            disposition: TerminalRetainedRuntimeDisposition::NonExecutable,
            node_id: command.node_id.clone(),
            cat_id: command.cat_id.clone(),
            placement_identity: command.placement_identity.clone(),
            source_lifecycle_operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            runtime_config_id: command.runtime_config.config_id.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            runtime_incarnation,
            retention_mode: TerminalRetainedRuntimeMode::InheritedPredecessorOwned {
                evidence: Box::new(evidence),
            },
            execution_absence: stop.execution_absence.clone(),
            post_stop_physical_projection_digest: stop.post_stop_physical_projection_digest.clone(),
            volume_grants: Vec::new(),
            retained_volume_receipts: stop.retained_volume_receipts.clone(),
            runtime_progress: None,
            physical_retained_evidence: stop.retained_evidence.clone(),
            retained_warm_restart_source: stop.retained_warm_restart_source.clone(),
            manifest_digest: Sha256Digest::from_bytes([0; 32]),
        };
        manifest.manifest_digest = terminal_retained_runtime_manifest_digest(&manifest)?;
        validate_terminal_retained_runtime_manifest(&manifest, Some(command))?;
        Ok(manifest)
    }
}

/// Observation-only restart/scanner anchor for one installed Running
/// runtime. It is not lifecycle or Volume authority: the exact terminal
/// response and current owner rows remain authoritative. Its purpose is to
/// make every Host path/process which those results refer to discoverable
/// after the executable command step has been compacted to terminal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledRuntimeManifest {
    pub version: ContractVersion,
    pub node_id: Id,
    pub cat_id: Id,
    pub placement_identity: PlacementIdentity,
    pub source_lifecycle_operation_id: Id,
    pub request_fingerprint: Sha256Digest,
    pub runtime_config_id: Id,
    pub runtime_config_digest: Sha256Digest,
    pub runtime_incarnation: RandomId128,
    pub execution_receipt_digest: Sha256Digest,
    pub guest_ready_receipt_digest: Sha256Digest,
    /// Present exactly for a successful direct or retained Warm restore. The
    /// old executable Warm authority is descriptor-safely retired before
    /// RuntimeReady so Running can never coexist with a second restart source.
    pub retired_restart_source_absence_digest: Option<Sha256Digest>,
    pub vmm: InstalledRuntimeVmmManifest,
    pub network: InstalledRuntimeNetworkManifest,
    pub volumes: Vec<InstalledRuntimeVolumeManifest>,
    pub manifest_digest: Sha256Digest,
}

impl InstalledRuntimeManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command: &LifecycleCommandEnvelope,
        runtime_incarnation: RandomId128,
        execution_receipt_digest: Sha256Digest,
        guest_ready_receipt_digest: Sha256Digest,
        retired_restart_source_absence_digest: Option<Sha256Digest>,
        vmm: InstalledRuntimeVmmManifest,
        network: InstalledRuntimeNetworkManifest,
        volumes: Vec<InstalledRuntimeVolumeManifest>,
    ) -> Result<Self> {
        let mut manifest = Self {
            version: ContractVersion::V1,
            node_id: command.node_id.clone(),
            cat_id: command.cat_id.clone(),
            placement_identity: command.placement_identity.clone(),
            source_lifecycle_operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            runtime_config_id: command.runtime_config.config_id.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            runtime_incarnation,
            execution_receipt_digest,
            guest_ready_receipt_digest,
            retired_restart_source_absence_digest,
            vmm,
            network,
            volumes,
            manifest_digest: Sha256Digest::from_bytes([0; 32]),
        };
        manifest.manifest_digest = installed_runtime_manifest_digest(&manifest)?;
        validate_installed_runtime_manifest(&manifest, command)?;
        Ok(manifest)
    }
}

/// Final joined proof returned only by `GuestReadyAndAdmission`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicStartRuntimeReadyEvidence {
    pub platform_plan_digest: Sha256Digest,
    pub platform_receipt: ExactBytes,
    pub platform_receipt_digest: Sha256Digest,
    pub execution_receipt_digest: Sha256Digest,
    pub guest_ready_receipt_digest: Sha256Digest,
    pub retired_restart_source_absence_digest: Option<Sha256Digest>,
    pub volume_receipts: Vec<VolumeTerminalReceipt>,
    pub artifact_classifications: Vec<ObservedArtifactClassification>,
    pub installed_runtime_manifest: Box<InstalledRuntimeManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomicStartRuntimeEffectOutcome {
    Completed(AtomicStartRuntimeEffectReceipt),
    RuntimeReady(AtomicStartRuntimeReadyEvidence),
    /// Fresh inspection proved that none of the plan's mutation happened, but
    /// its Volume lease is no longer safe for a new mutation. The handler
    /// journals an exact renewal and then resumes this same platform plan.
    VolumeRefreshRequired {
        platform_plan_digest: Sha256Digest,
        runtime_progress: Option<InstalledRuntimeProgressManifest>,
    },
    /// The exact old AgentSession-bound registration was discovered unused
    /// and descriptor-safely cleaned. The handler retains this full proof and
    /// journals a newly planned request before the replacement can execute.
    SessionRebindRequired {
        old_platform_plan_digest: Sha256Digest,
        cleanup_receipt: ExactBytes,
        cleanup_receipt_digest: Sha256Digest,
        runtime_progress: InstalledRuntimeProgressManifest,
    },
    Failed(AtomicStartDefiniteFailure),
}

/// Provider-neutral adapter over the installed Root/device/network/VMM/Guest
/// leaves.  A call performs or discovers exactly the named durable effect.
/// Before the first mutation of a plan, the implementation must recheck both
/// the persisted effect deadline and a process-local monotonic lease witness
/// for the exact grant set and AgentSession. Wire Unix expiry remains immutable
/// identity/evidence and is never a local safety clock. A missing witness
/// after process restart or session replacement forces discovery and an exact
/// renewal before any new mutation. Deadline expiry with exact zero mutation
/// is a definite command failure; it is never a reason to renew a lease. A
/// live command whose lease budget became unsafe with exact zero mutation
/// returns `VolumeRefreshRequired`, which is the only arm that journals a
/// renewal. Once any mutation may have happened, later deadline or lease
/// expiry cannot change the plan identity, repeat the effect, or abandon its
/// ambiguity: the port must discover/complete that exact plan or return
/// `Failed` for Strong Stop. A bare `Err` retains the same Executing step for
/// later discovery and must never be used as an implicit request to change
/// lease or session.
/// The final arm must revalidate the joined VMM, device, network, Guest and
/// Volume tuple and return the exact installed manifest. The Start machine
/// fsyncs that manifest and only then publishes lifecycle RuntimeReady into
/// the shared AdmissionCell; Endpoint gates remain Closed throughout.
pub trait AtomicStartRuntimePort: Send + Sync + 'static {
    /// Stable installed upper bound for any one runtime phase. The Start
    /// machine rejects a lease policy which cannot cover this bound plus its
    /// settlement margin, preventing an endless pre-mutation refresh loop.
    fn configured_effect_timeout_ms(&self) -> WireU64;

    /// Select all provider identities needed by one effect without mutation.
    /// Planning may perform a bounded read of an immutable content-addressed
    /// object (for example a verified image manifest) or a command-bound
    /// read-only authority inspection (for example a Persistent initialization
    /// token), but it may not change the filesystem, kernel, process manager,
    /// network or any external service. The exact read result is embedded in
    /// the returned canonical/opaque bytes, which become executable only after
    /// the lifecycle journal installs them in an `ExecutionStep`.
    fn plan_start_effect(
        &self,
        command: &LifecycleCommandEnvelope,
        phase: AtomicStartRuntimeEffectPhase,
        context: &AtomicStartRuntimeContext,
    ) -> Result<ExactBytes>;

    fn inspect_or_apply_start_effect(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
    ) -> Result<AtomicStartRuntimeEffectOutcome>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstalledRuntimeProgressJournalBinding {
    ExactEmbeddedEvidence,
    /// The evidence is ahead of the currently Executing request. Inventory
    /// may call only the port's inspect-or-apply operation with this exact
    /// request; it may not infer a successor phase from the evidence.
    RequiresCurrentEffectDiscovery {
        request: Box<AtomicStartRuntimeEffectRequest>,
    },
    /// Volume authority or renewal completed far enough to publish its exact
    /// attribution, but the crash preceded the successor command step. Only
    /// replay/discovery of this already-journaled Volume request may close it.
    RequiresVolumeAuthorityDiscovery {
        request: Box<AtomicStartVolumeBatchRequest>,
        planned_agent_session: SessionBinding,
    },
}

/// Closed current-operation projection used by the one startup journal/
/// physical-inventory join. The outer registry partitions predecessor
/// retained artifacts before calling this helper; every entry here must
/// therefore belong to this exact Start operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstalledStartStartupBinding {
    NoPhysicalEvidence,
    ExactEmbeddedEvidence,
    RequiresCurrentEffectDiscovery {
        request: Box<AtomicStartRuntimeEffectRequest>,
    },
    RequiresVolumeAuthorityDiscovery {
        request: Box<AtomicStartVolumeBatchRequest>,
        planned_agent_session: SessionBinding,
    },
    ReplaySealedTerminal {
        manifest: Box<TerminalRetainedRuntimeManifest>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum StartStepState {
    AcquireVolumes {
        request: AtomicStartVolumeBatchRequest,
        planned_agent_session: SessionBinding,
        runtime_incarnation: RandomId128,
        source: StartSource,
        warm_restart_source: Option<AtomicStartWarmRestartSource>,
        effect_deadline_unix_ms: UnixMillis,
        runtime_effect_timeout_ms: WireU64,
    },
    RefreshVolumes {
        request: AtomicStartVolumeBatchRequest,
        planned_agent_session: SessionBinding,
        context: AtomicStartRuntimeContext,
        next_phase: AtomicStartRuntimeEffectPhase,
        /// An already-journaled platform request whose fresh discovery proved
        /// that it made no mutation before asking for a lease refresh. Normal
        /// phase transitions leave this empty and plan only after the renewed
        /// grants themselves are durable in the successor step.
        resume_platform_plan: Option<ExactBytes>,
    },
    RuntimeEffect {
        request: AtomicStartRuntimeEffectRequest,
    },
    StrongStopFailure {
        reason: CommandFailureReason,
        artifact_classifications: Vec<ObservedArtifactClassification>,
        volume_grants: Vec<AtomicStartVolumeGrant>,
        runtime_progress: Option<InstalledRuntimeProgressManifest>,
        failed_volume_effect: Option<AtomicStartFailedVolumeEffect>,
        inherited_predecessor_physical: Option<InheritedPredecessorPhysicalProjection>,
        warm_restart_source: Option<AtomicStartWarmRestartSource>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartStepPayload {
    version: ContractVersion,
    operation_id: Id,
    request_fingerprint: Sha256Digest,
    state: StartStepState,
}

pub(super) fn plan(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor_command: Option<&LifecycleCommandEnvelope>,
    predecessor: Option<&LifecycleCommandResponse>,
    inherited_stop_fence: bool,
) -> Result<PlannedLifecycleEffect> {
    anyhow::ensure!(
        ctx.node_id() == &command.node_id,
        "atomic Start command belongs to another Node"
    );
    anyhow::ensure!(
        !inherited_stop_fence,
        "atomic Start admission did not replace its predecessor Stop fence"
    );
    let (source, deadline) = start_spec(command)?;
    validate_start_predecessor_command(command, predecessor_command, predecessor)?;
    validate_start_predecessor(command, predecessor, source)?;
    validate_start_retry_retained_manifest(ctx, command, predecessor, source)?;
    let volume_lease_duration_ms = ctx.start_volume_port().configured_lease_duration_ms();
    let runtime_effect_timeout_ms = ctx.start_runtime_port().configured_effect_timeout_ms();
    validate_start_lease_effect_policy(volume_lease_duration_ms, runtime_effect_timeout_ms)?;
    let request = volume_batch_request(command, volume_lease_duration_ms)?;
    let planned_agent_session = ctx.start_volume_port().current_agent_session_binding()?;
    validate_planned_agent_session(command, &planned_agent_session)?;
    let runtime_incarnation = start_runtime_incarnation(source, predecessor)?;
    let warm_restart_source = plan_warm_restart_source(ctx, command, predecessor, source)?;
    planned_unfenced(
        command,
        StartStepState::AcquireVolumes {
            request,
            planned_agent_session,
            runtime_incarnation,
            source,
            warm_restart_source,
            effect_deadline_unix_ms: deadline,
            runtime_effect_timeout_ms,
        },
    )
}

fn plan_warm_restart_source(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    source: StartSource,
) -> Result<Option<AtomicStartWarmRestartSource>> {
    let predecessor = match source {
        StartSource::SameNodeWarm | StartSource::SameNodeRetry => {
            predecessor.context("Warm or retry Start lacks its exact predecessor response")?
        }
        _ => return Ok(None),
    };
    let physical = if source == StartSource::SameNodeWarm {
        ctx.config()
            .suspend_warm_platform
            .inspect_same_node_owned_predecessor(command, predecessor)
            .context("freeze exact Warm restart source before Start mutation")?
    } else {
        let NodeResult::StartFailed(failed) = &predecessor.result else {
            return Ok(None);
        };
        let mut manifests = enumerate_terminal_retained_runtime_manifests(ctx.state_directory())?
            .into_iter()
            .filter(|manifest| {
                manifest.cat_id == command.cat_id
                    && manifest.source_lifecycle_operation_id == predecessor.operation_id
            })
            .collect::<Vec<_>>();
        if manifests.is_empty() {
            return Ok(None);
        }
        anyhow::ensure!(
            manifests.len() == 1,
            "retained Warm retry lacks one exact immediate StartFailed manifest"
        );
        let manifest = manifests
            .pop()
            .context("retained Warm retry manifest disappeared")?;
        validate_terminal_retained_runtime_manifest(&manifest, None)?;
        anyhow::ensure!(
            manifest.manifest_digest == failed.retained_evidence.artifact_manifest_digest
                && manifest.node_id == command.node_id
                && manifest.placement_identity == command.placement_identity
                && manifest.runtime_config_id == command.runtime_config.config_id
                && manifest.runtime_config_digest == command.runtime_config.config_digest,
            "retained Warm retry changed its immediate failed-Start manifest"
        );
        let Some(carrier) = manifest.retained_warm_restart_source.as_ref() else {
            return Ok(None);
        };
        anyhow::ensure!(
            carrier.digest().as_bytes().iter().any(|byte| *byte != 0),
            "retained Warm retry carrier has a zero digest"
        );
        let rebound =
            super::suspend_warm::rebind_retained_warm_for_retry(command, predecessor, carrier)?;
        let physical = ctx
            .config()
            .suspend_warm_platform
            .inspect_rebound_warm_retry_source(command, &rebound)
            .context("freshly reopen retained Warm retry descriptors")?;
        anyhow::ensure!(
            physical.physical_manifest_digest == manifest.manifest_digest
                && physical.warm_cleanup_authority() == Some(&rebound),
            "retained Warm retry physical carrier changed its immediate manifest binding"
        );
        physical
    };
    let cleanup_authority = physical
        .warm_cleanup_authority()
        .context("Warm predecessor physical carrier lacks transfer authority")?
        .clone();
    let restart_source = AtomicStartWarmRestartSource {
        physical_manifest_digest: physical.physical_manifest_digest,
        cleanup_authority: Box::new(cleanup_authority),
    };
    validate_warm_restart_source_shape(command, source, Some(&restart_source))?;
    Ok(Some(restart_source))
}

fn validate_warm_restart_source_shape(
    command: &LifecycleCommandEnvelope,
    source: StartSource,
    restart_source: Option<&AtomicStartWarmRestartSource>,
) -> Result<()> {
    match (source, restart_source) {
        (StartSource::SameNodeWarm, Some(restart_source)) => {
            anyhow::ensure!(
                restart_source
                    .physical_manifest_digest
                    .as_bytes()
                    .iter()
                    .any(|byte| *byte != 0)
                    && restart_source.cleanup_authority.mode()
                        == super::WarmSnapshotCleanupMode::TransferToRuntime
                    && restart_source.cleanup_authority.terminal_manifest_digest()
                        == &restart_source.physical_manifest_digest,
                "Warm Start restart source changed its descriptor authority or physical identity"
            );
            anyhow::ensure!(
                matches!(
                    command.predecessor,
                    LifecyclePredecessor::SameNode {
                        terminal_result_kind: TerminalResultKind::Warm,
                        ..
                    }
                ),
                "direct Warm restart source has another predecessor kind"
            );
        }
        (StartSource::SameNodeRetry, Some(restart_source)) => {
            anyhow::ensure!(
                restart_source
                    .physical_manifest_digest
                    .as_bytes()
                    .iter()
                    .any(|byte| *byte != 0)
                    && restart_source.cleanup_authority.mode()
                        == super::WarmSnapshotCleanupMode::TransferToRuntime
                    && matches!(
                        command.predecessor,
                        LifecyclePredecessor::SameNode {
                            terminal_result_kind: TerminalResultKind::StartFailed,
                            ..
                        }
                    ),
                "retained Warm retry changed its immediate StartFailed scope"
            );
        }
        (StartSource::SameNodeWarm, None) => {
            anyhow::bail!("Warm Start lost its journaled restart source")
        }
        (_, Some(_)) => {
            anyhow::bail!("non-Warm Start invented a retained Warm restart source")
        }
        (_, None) => {}
    }
    Ok(())
}

fn validate_planned_warm_restart_source(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    source: StartSource,
    restart_source: Option<&AtomicStartWarmRestartSource>,
) -> Result<()> {
    validate_warm_restart_source_shape(command, source, restart_source)?;
    let Some(restart_source) = restart_source else {
        return Ok(());
    };
    let physical = if source == StartSource::SameNodeWarm {
        ctx.config()
            .suspend_warm_platform
            .inspect_same_node_owned_predecessor(
                command,
                predecessor.context("Warm Start lost its predecessor during replay")?,
            )?
    } else {
        ctx.config()
            .suspend_warm_platform
            .inspect_rebound_warm_retry_source(command, &restart_source.cleanup_authority)?
    };
    anyhow::ensure!(
        physical.physical_manifest_digest == restart_source.physical_manifest_digest
            && physical.warm_cleanup_authority() == Some(restart_source.cleanup_authority.as_ref()),
        "journaled Warm restart source differs from fresh descriptor and Volume evidence"
    );
    Ok(())
}

pub(super) fn apply(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor_command: Option<&LifecycleCommandEnvelope>,
    predecessor: Option<&LifecycleCommandResponse>,
    step: &ExecutionStep,
    authority: LifecycleEffectAuthority<'_>,
) -> Result<LifecycleEffectProgress> {
    let payload = decode_step(command, step)?;
    let (source, _) = start_spec(command)?;
    validate_start_predecessor_command(command, predecessor_command, predecessor)?;
    validate_start_predecessor(command, predecessor, source)?;
    // The predecessor-retention join is a pre-acquire condition. Once an
    // exact signed grant and cumulative current-operation progress have been
    // journaled, a legitimate zero-retention retry necessarily has new Cat
    // physical state and must not be reinterpreted as failed predecessor
    // absence on every later phase.
    if matches!(&payload.state, StartStepState::AcquireVolumes { .. }) {
        validate_start_retry_retained_manifest(ctx, command, predecessor, source)?;
    }
    match payload.state {
        StartStepState::AcquireVolumes {
            request,
            planned_agent_session,
            runtime_incarnation,
            source,
            warm_restart_source,
            effect_deadline_unix_ms,
            runtime_effect_timeout_ms,
        } => {
            anyhow::ensure!(
                authority.stop_fence().is_none(),
                "atomic Start Volume effect unexpectedly retained a Stop fence"
            );
            apply_volume_effect(
                ctx,
                ctx.start_volume_port().as_ref(),
                command,
                InitialStartVolumeEffect {
                    request,
                    planned_agent_session,
                    runtime_incarnation,
                    source,
                    warm_restart_source,
                    local_predecessor: predecessor.cloned(),
                    effect_deadline_unix_ms,
                    runtime_effect_timeout_ms,
                },
            )
        }
        StartStepState::RuntimeEffect { request } => {
            anyhow::ensure!(
                authority.stop_fence().is_none(),
                "atomic Start runtime effect unexpectedly retained a Stop fence"
            );
            // Discovery of this exact already-Executing platform plan always
            // precedes a lease refresh. Otherwise a crash after the physical
            // effect but before its successor journal write could discard the
            // only request capable of closing the ambiguity.
            apply_runtime_effect(ctx, ctx.start_runtime_port().as_ref(), command, request)
        }
        StartStepState::RefreshVolumes {
            request,
            planned_agent_session,
            context,
            next_phase,
            resume_platform_plan,
        } => {
            anyhow::ensure!(
                authority.stop_fence().is_none(),
                "atomic Start Volume refresh unexpectedly retained a Stop fence"
            );
            apply_volume_refresh(
                ctx,
                ctx.start_volume_port().as_ref(),
                command,
                StartVolumeRefreshEffect {
                    request,
                    planned_agent_session,
                    context,
                    next_phase,
                    resume_platform_plan,
                },
            )
        }
        StartStepState::StrongStopFailure {
            reason,
            artifact_classifications,
            volume_grants,
            runtime_progress,
            failed_volume_effect,
            inherited_predecessor_physical,
            warm_restart_source,
        } => {
            // Sealing is deliberately ordered before the journal successor.
            // A crash in that gap therefore re-enters this same Executing
            // step with a non-executable TerminalRetained artifact already in
            // the progress slot. Load it before another physical scan: the
            // scan necessarily observes the newly sealed artifact and cannot
            // be used to manufacture a different terminal response.
            let sealed_before_replay =
                load_terminal_retained_runtime_manifest(ctx.state_directory(), command)?;
            if let Some(sealed) = sealed_before_replay.as_ref() {
                anyhow::ensure!(
                    runtime_progress.as_ref() == sealed.runtime_progress.as_ref()
                        && volume_grants == sealed.volume_grants,
                    "sealed failed-Start evidence differs from its Executing journal step"
                );
                match (
                    sealed.retained_warm_restart_source.as_ref(),
                    warm_restart_source.as_ref(),
                ) {
                    (Some(carrier), Some(source)) => {
                        super::suspend_warm::validate_retained_warm_restart_source_for_source(
                            command,
                            carrier,
                            &source.cleanup_authority,
                            &source.physical_manifest_digest,
                        )?;
                    }
                    (None, None) => {}
                    _ => anyhow::bail!(
                        "sealed failed-Start Warm carrier differs from its Executing step"
                    ),
                }
                if let Some(projection) = inherited_predecessor_physical.as_ref() {
                    let TerminalRetainedRuntimeMode::InheritedPredecessorOwned {
                        evidence: inherited,
                    } = &sealed.retention_mode
                    else {
                        anyhow::bail!(
                            "sealed failed-Start predecessor projection changed retention mode"
                        )
                    };
                    anyhow::ensure!(
                        sealed.runtime_incarnation == projection.target_runtime_incarnation
                            && inherited.predecessor_physical_manifest_digest
                                == projection.physical_manifest_digest
                            && inherited.predecessor_runtime_incarnation
                                == projection.runtime_incarnation
                            && failed_volume_effect.as_ref()
                                == Some(&inherited.failed_volume_effect),
                        "sealed failed-Start changed its journaled predecessor projection"
                    );
                }
            }
            let evidence = execute_command_strong_stop_with_start_grants(
                ctx,
                command,
                predecessor,
                authority,
                StartStrongStopInput {
                    grants: &volume_grants,
                    progress: runtime_progress.as_ref(),
                    failed_volume_effect: failed_volume_effect.as_ref(),
                    inherited_predecessor_physical: inherited_predecessor_physical.as_ref(),
                    warm_restart_source: warm_restart_source.as_ref(),
                },
            )
            .context("strong Stop failed atomic Start")?;
            // The shared barrier's fresh complete physical scan is later and
            // stronger than these accumulated per-effect classifications.
            validate_artifacts(&artifact_classifications)?;
            let (not_running, retained_evidence, retained_volume_receipts) = if let Some(progress) =
                runtime_progress
            {
                validate_installed_runtime_progress_manifest(&progress, command)?;
                validate_runtime_progress_against_volume_grants(&progress, &volume_grants)?;
                let retained = if let Some(sealed) = sealed_before_replay {
                    validate_terminal_retained_replay_evidence(&sealed, &evidence)?;
                    sealed
                } else {
                    let retained = TerminalRetainedRuntimeManifest::new(
                        command,
                        volume_grants,
                        progress,
                        &evidence,
                    )?;
                    seal_terminal_retained_runtime_manifest(ctx.state_directory(), &retained)?
                };
                let retained_evidence = RetainedEvidence {
                    artifact_manifest_digest: retained.manifest_digest,
                    ..retained.physical_retained_evidence.clone()
                };
                (
                    retained.execution_absence,
                    retained_evidence,
                    retained.retained_volume_receipts,
                )
            } else {
                anyhow::ensure!(
                    volume_grants.is_empty(),
                    "failed atomic Start lost progress for retained Volume grants"
                );
                if evidence.retained_volume_receipts.is_empty() {
                    anyhow::ensure!(
                        sealed_before_replay.is_none(),
                        "empty failed Start unexpectedly retained a sealed manifest"
                    );
                    (
                        evidence.execution_absence,
                        evidence.retained_evidence,
                        evidence.retained_volume_receipts,
                    )
                } else {
                    let predecessor = predecessor
                        .context("rejected same-Node renewal lost its predecessor response")?;
                    let projection = inherited_predecessor_physical.as_ref().context(
                        "rejected same-Node renewal retained Owned state without a predecessor projection",
                    )?;
                    let failed_volume_effect = failed_volume_effect
                        .as_ref()
                        .context("rejected same-Node renewal lost its typed Volume failure")?;
                    let retained = if let Some(sealed) = sealed_before_replay {
                        validate_terminal_retained_replay_evidence(&sealed, &evidence)?;
                        sealed
                    } else {
                        let inherited = inherited_predecessor_owned_evidence_from_strong_stop(
                            command,
                            predecessor,
                            projection,
                            failed_volume_effect,
                            &evidence,
                        )?;
                        let retained =
                            TerminalRetainedRuntimeManifest::new_inherited_predecessor_owned(
                                command,
                                projection.target_runtime_incarnation.clone(),
                                inherited,
                                &evidence,
                            )?;
                        seal_terminal_retained_runtime_manifest(ctx.state_directory(), &retained)?
                    };
                    retire_bridged_start_failed_predecessor_manifest(
                        ctx.state_directory(),
                        predecessor,
                        &retained,
                    )?;
                    let retained_evidence = RetainedEvidence {
                        artifact_manifest_digest: retained.manifest_digest,
                        ..retained.physical_retained_evidence.clone()
                    };
                    (
                        retained.execution_absence,
                        retained_evidence,
                        retained.retained_volume_receipts,
                    )
                }
            };
            forget_process_local_start_lease_witnesses(&command.operation_id)?;
            Ok(LifecycleEffectProgress::Terminal(NodeResult::StartFailed(
                Box::new(CommandFailedResult {
                    reason,
                    not_running,
                    retained_evidence,
                    retained_volume_receipts,
                }),
            )))
        }
    }
}

struct InitialStartVolumeEffect {
    request: AtomicStartVolumeBatchRequest,
    planned_agent_session: SessionBinding,
    runtime_incarnation: RandomId128,
    source: StartSource,
    warm_restart_source: Option<AtomicStartWarmRestartSource>,
    local_predecessor: Option<LifecycleCommandResponse>,
    effect_deadline_unix_ms: UnixMillis,
    runtime_effect_timeout_ms: WireU64,
}

fn apply_volume_effect(
    ctx: &InstalledLifecycleContext,
    port: &dyn AtomicStartVolumePort,
    command: &LifecycleCommandEnvelope,
    input: InitialStartVolumeEffect,
) -> Result<LifecycleEffectProgress> {
    let InitialStartVolumeEffect {
        request,
        planned_agent_session,
        runtime_incarnation,
        source,
        warm_restart_source,
        local_predecessor,
        effect_deadline_unix_ms,
        runtime_effect_timeout_ms,
    } = input;
    validate_volume_batch_request(command, &request)?;
    validate_planned_agent_session(command, &planned_agent_session)?;
    validate_start_lease_effect_policy(
        request.renewal_lease_duration_ms,
        runtime_effect_timeout_ms,
    )?;
    validate_planned_warm_restart_source(
        ctx,
        command,
        local_predecessor.as_ref(),
        source,
        warm_restart_source.as_ref(),
    )?;
    match port.inspect_or_apply_start_volumes(command, &request, &planned_agent_session)? {
        AtomicStartVolumeOutcome::Ready(receipt) => {
            validate_volume_batch_receipt(command, &request, &receipt)?;
            let artifacts = volume_grant_artifacts(&receipt.grants)?;
            let runtime_progress = initial_runtime_progress_from_volume_grants(
                command,
                runtime_incarnation.clone(),
                &receipt.grants,
            )?;
            publish_installed_runtime_progress_manifest(ctx.state_directory(), &runtime_progress)
                .context("publish atomic Start authority attribution")?;
            let context = AtomicStartRuntimeContext {
                runtime_incarnation,
                source,
                local_predecessor,
                warm_restart_source,
                effect_deadline_unix_ms,
                volume_lease_duration_ms: request.renewal_lease_duration_ms,
                runtime_effect_timeout_ms,
                volume_lease_session: planned_agent_session,
                volume_grant_sequence: receipt.grant_sequence,
                volume_grants: receipt.grants,
                runtime_progress,
                completed_effects: Vec::new(),
                session_rebind_receipts: Vec::new(),
                artifact_classifications: artifacts,
            };
            planned_runtime_effect_after_lease_gate(
                ctx,
                command,
                AtomicStartRuntimeEffectPhase::first(),
                context,
                None,
            )
            .map(LifecycleEffectProgress::Next)
        }
        AtomicStartVolumeOutcome::Failed { failure, evidence } => {
            anyhow::ensure!(
                failure.runtime_progress.is_none(),
                "Volume-authority failure invented runtime progress"
            );
            let failed_volume_effect = AtomicStartFailedVolumeEffect {
                request,
                evidence: *evidence,
            };
            let inherited_predecessor_physical = inspect_inherited_predecessor_physical_projection(
                ctx,
                command,
                source,
                runtime_incarnation,
                local_predecessor.as_ref(),
                &failed_volume_effect,
                warm_restart_source.as_ref(),
            )?;
            failure_plan(
                ctx,
                command,
                *failure,
                Vec::new(),
                Some(failed_volume_effect),
                inherited_predecessor_physical,
                warm_restart_source,
            )
        }
    }
}

fn inspect_inherited_predecessor_physical_projection(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    source: StartSource,
    target_runtime_incarnation: RandomId128,
    predecessor: Option<&LifecycleCommandResponse>,
    failed_volume_effect: &AtomicStartFailedVolumeEffect,
    planned_warm_restart_source: Option<&AtomicStartWarmRestartSource>,
) -> Result<Option<InheritedPredecessorPhysicalProjection>> {
    if !failed_volume_effect
        .request
        .actions
        .iter()
        .any(|action| matches!(action, AtomicStartVolumeAction::RenewSameNode { .. }))
    {
        return Ok(None);
    }
    let predecessor = predecessor
        .context("rejected same-Node renewal lacks its exact terminal predecessor response")?;
    let projection = match source {
        StartSource::SameNodeSuspended | StartSource::SameNodeWarm => {
            suspend_warm_predecessor_physical_projection(
                ctx,
                command,
                predecessor,
                target_runtime_incarnation.clone(),
            )?
        }
        StartSource::SameNodeStopped => stopped_predecessor_physical_projection(
            ctx,
            command,
            predecessor,
            target_runtime_incarnation.clone(),
        )?,
        StartSource::SameNodeRetry => {
            if let Some(restart_source) = planned_warm_restart_source {
                let physical = ctx
                    .config()
                    .suspend_warm_platform
                    .inspect_rebound_warm_retry_source(command, &restart_source.cleanup_authority)
                    .context("reopen exact retained Warm source after rejected retry renewal")?;
                anyhow::ensure!(
                    physical.physical_manifest_digest == restart_source.physical_manifest_digest
                        && physical.warm_cleanup_authority()
                            == Some(restart_source.cleanup_authority.as_ref()),
                    "rejected retained Warm retry changed its journaled source"
                );
                inherited_predecessor_physical_projection(
                    command,
                    predecessor,
                    target_runtime_incarnation.clone(),
                    physical.physical_manifest_digest,
                    physical.runtime_incarnation,
                    Some(restart_source.clone()),
                    physical
                        .volumes
                        .into_iter()
                        .map(|volume| InheritedPredecessorPhysicalVolume {
                            volume_id: volume.volume_id,
                            disk_id: volume.disk_id,
                            disk_role: volume.disk_role,
                            attachment_id: volume.attachment_id,
                            attachment_epoch: volume.attachment_epoch,
                            acquire_origin: volume.acquire_origin,
                            authoritative_head: volume.authoritative_head,
                            immutable_start_grant_receipt_digest: volume
                                .immutable_start_grant_receipt_digest,
                            local_lineage_data_directory: volume.local_lineage_data_directory,
                        })
                        .collect(),
                )?
            } else if matches!(
                predecessor.result,
                NodeResult::SuspendFailed(_) | NodeResult::WarmFailed(_)
            ) {
                suspend_warm_predecessor_physical_projection(
                    ctx,
                    command,
                    predecessor,
                    target_runtime_incarnation.clone(),
                )?
            } else {
                retry_predecessor_physical_projection(
                    ctx.state_directory(),
                    command,
                    predecessor,
                    target_runtime_incarnation.clone(),
                )?
            }
        }
        StartSource::Genesis
        | StartSource::ColdHandoff
        | StartSource::HostFenceRecovery
        | StartSource::SameNodeCold => {
            anyhow::bail!("non-Owned Start source produced a same-Node renewal action")
        }
    };
    anyhow::ensure!(
        projection.warm_restart_source.as_ref() == planned_warm_restart_source,
        "rejected Start changed its pre-mutation Warm restart source"
    );
    validate_inherited_predecessor_physical_projection(command, failed_volume_effect, &projection)?;
    Ok(Some(projection))
}

fn suspend_warm_predecessor_physical_projection(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    target_runtime_incarnation: RandomId128,
) -> Result<InheritedPredecessorPhysicalProjection> {
    let physical = ctx
        .config()
        .suspend_warm_platform
        .inspect_same_node_owned_predecessor(command, predecessor)
        .context("inspect exact Suspend/Warm predecessor before strong Stop")?;
    let warm_restart_source =
        physical
            .warm_cleanup_authority()
            .cloned()
            .map(|authority| AtomicStartWarmRestartSource {
                physical_manifest_digest: physical.physical_manifest_digest.clone(),
                cleanup_authority: Box::new(authority),
            });
    inherited_predecessor_physical_projection(
        command,
        predecessor,
        target_runtime_incarnation,
        physical.physical_manifest_digest,
        physical.runtime_incarnation,
        warm_restart_source,
        physical
            .volumes
            .into_iter()
            .map(|volume| InheritedPredecessorPhysicalVolume {
                volume_id: volume.volume_id,
                disk_id: volume.disk_id,
                disk_role: volume.disk_role,
                attachment_id: volume.attachment_id,
                attachment_epoch: volume.attachment_epoch,
                acquire_origin: volume.acquire_origin,
                authoritative_head: volume.authoritative_head,
                immutable_start_grant_receipt_digest: volume.immutable_start_grant_receipt_digest,
                local_lineage_data_directory: volume.local_lineage_data_directory,
            })
            .collect(),
    )
}

fn stopped_predecessor_physical_projection(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    target_runtime_incarnation: RandomId128,
) -> Result<InheritedPredecessorPhysicalProjection> {
    let NodeResult::Killed(killed) = &predecessor.result else {
        anyhow::bail!("SameNodeStopped predecessor is not Killed")
    };
    anyhow::ensure!(
        !killed.retained_volume_receipts.is_empty(),
        "rejected SameNodeStopped renewal has no retained predecessor receipts"
    );
    let volumes = killed
        .retained_volume_receipts
        .iter()
        .map(|receipt| exact_predecessor_volume_projection(ctx.state_directory(), command, receipt))
        .collect::<Result<Vec<_>>>()?;
    inherited_predecessor_physical_projection(
        command,
        predecessor,
        target_runtime_incarnation,
        killed.retained_evidence.artifact_manifest_digest.clone(),
        killed.stopped_runtime_incarnation.clone(),
        None,
        volumes,
    )
}

fn retry_predecessor_physical_projection(
    state_directory: &StateDirectory,
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    target_runtime_incarnation: RandomId128,
) -> Result<InheritedPredecessorPhysicalProjection> {
    let NodeResult::StartFailed(failed) = &predecessor.result else {
        anyhow::bail!(
            "SameNodeRetry renewal requires an exact StartFailed terminal-retained carrier"
        )
    };
    let mut manifests = enumerate_terminal_retained_runtime_manifests(state_directory)?
        .into_iter()
        .filter(|manifest| {
            manifest.cat_id == command.cat_id
                && manifest.source_lifecycle_operation_id == predecessor.operation_id
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        manifests.len() == 1,
        "SameNodeRetry renewal lacks one exact predecessor terminal-retained manifest"
    );
    let manifest = manifests
        .pop()
        .context("SameNodeRetry predecessor manifest disappeared")?;
    validate_terminal_retained_runtime_manifest(&manifest, None)?;
    anyhow::ensure!(
        manifest.manifest_digest == failed.retained_evidence.artifact_manifest_digest
            && manifest.node_id == command.node_id
            && manifest.placement_identity == command.placement_identity
            && manifest.runtime_config_id == command.runtime_config.config_id
            && manifest.runtime_config_digest == command.runtime_config.config_digest,
        "SameNodeRetry predecessor retained manifest changed terminal or runtime identity"
    );
    let predecessor_runtime_incarnation = match &manifest.retention_mode {
        TerminalRetainedRuntimeMode::InheritedPredecessorOwned { evidence } => {
            evidence.predecessor_runtime_incarnation.clone()
        }
        TerminalRetainedRuntimeMode::AuthorityOnlyOwnedZeroMutation { .. }
        | TerminalRetainedRuntimeMode::MaterializedOrAmbiguous => {
            Some(manifest.runtime_incarnation.clone())
        }
    };
    let volumes = terminal_retained_physical_volumes(&manifest)?;
    anyhow::ensure!(
        !volumes.is_empty(),
        "SameNodeRetry renewal predecessor has no retained Owned projection"
    );
    inherited_predecessor_physical_projection(
        command,
        predecessor,
        target_runtime_incarnation,
        manifest.manifest_digest,
        predecessor_runtime_incarnation,
        None,
        volumes,
    )
}

#[allow(clippy::too_many_arguments)]
fn inherited_predecessor_physical_projection(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    target_runtime_incarnation: RandomId128,
    physical_manifest_digest: Sha256Digest,
    runtime_incarnation: Option<RandomId128>,
    warm_restart_source: Option<AtomicStartWarmRestartSource>,
    volumes: Vec<InheritedPredecessorPhysicalVolume>,
) -> Result<InheritedPredecessorPhysicalProjection> {
    let LifecyclePredecessor::SameNode {
        operation_id,
        terminal_result_kind,
        terminal_result_digest,
        node_id,
        placement_identity,
    } = &command.predecessor
    else {
        anyhow::bail!("inherited predecessor projection lacks a same-Node predecessor")
    };
    let actual_terminal_result_digest =
        lifecycle_terminal_result_digest(&LifecycleTerminalResult::NodeResult {
            response: Box::new(predecessor.clone()),
        })?;
    anyhow::ensure!(
        predecessor.operation_id == *operation_id
            && predecessor.node_id == *node_id
            && predecessor.placement_identity == *placement_identity
            && predecessor.result.kind() == *terminal_result_kind
            && actual_terminal_result_digest == *terminal_result_digest,
        "inherited predecessor projection changed its signed terminal response"
    );
    Ok(InheritedPredecessorPhysicalProjection {
        target_operation_id: command.operation_id.clone(),
        target_request_fingerprint: command.request_fingerprint.clone(),
        target_runtime_config_id: command.runtime_config.config_id.clone(),
        target_runtime_config_digest: command.runtime_config.config_digest.clone(),
        target_runtime_incarnation,
        predecessor_operation_id: predecessor.operation_id.clone(),
        predecessor_request_fingerprint: predecessor.request_fingerprint.clone(),
        predecessor_terminal_result_kind: predecessor.result.kind(),
        predecessor_terminal_result_digest: actual_terminal_result_digest,
        physical_manifest_digest,
        runtime_incarnation,
        warm_restart_source,
        volumes,
    })
}

pub(super) fn terminal_retained_physical_volumes(
    manifest: &TerminalRetainedRuntimeManifest,
) -> Result<Vec<InheritedPredecessorPhysicalVolume>> {
    validate_terminal_retained_runtime_manifest(manifest, None)?;
    match &manifest.retention_mode {
        TerminalRetainedRuntimeMode::InheritedPredecessorOwned { evidence } => Ok(evidence
            .volumes
            .iter()
            .map(|volume| InheritedPredecessorPhysicalVolume {
                volume_id: volume.retained_receipt.volume_id.clone(),
                disk_id: volume.retained_receipt.disk_id.clone(),
                disk_role: volume.retained_receipt.disk_role,
                attachment_id: volume.retained_receipt.attachment_id.clone(),
                attachment_epoch: volume.retained_receipt.attachment_epoch,
                acquire_origin: volume.acquire_origin.clone(),
                authoritative_head: volume.authoritative_head.clone(),
                immutable_start_grant_receipt_digest: volume
                    .immutable_start_grant_receipt_digest
                    .clone(),
                local_lineage_data_directory: volume.local_lineage_data_directory.clone(),
            })
            .collect()),
        TerminalRetainedRuntimeMode::AuthorityOnlyOwnedZeroMutation { .. }
        | TerminalRetainedRuntimeMode::MaterializedOrAmbiguous => {
            let progress = manifest
                .runtime_progress
                .as_ref()
                .context("retained Start predecessor lost physical progress")?;
            manifest
                .retained_volume_receipts
                .iter()
                .map(|receipt| {
                    let grant = manifest
                        .volume_grants
                        .iter()
                        .find(|grant| grant.volume.volume_id == receipt.volume_id)
                        .context("retained Start predecessor receipt lost its grant")?;
                    let installed = progress
                        .volumes
                        .iter()
                        .find(|volume| volume.volume_id == receipt.volume_id)
                        .context("retained Start predecessor receipt lost its progress")?;
                    anyhow::ensure!(
                        receipt.authority_receipt_digest.as_ref()
                            == Some(&grant.grant_receipt_digest)
                            && installed.authority_receipt_digest.as_ref()
                                == Some(&grant.grant_receipt_digest),
                        "retained Start predecessor changed its immutable grant digest"
                    );
                    Ok(InheritedPredecessorPhysicalVolume {
                        volume_id: receipt.volume_id.clone(),
                        disk_id: receipt.disk_id.clone(),
                        disk_role: receipt.disk_role,
                        attachment_id: receipt.attachment_id.clone(),
                        attachment_epoch: receipt.attachment_epoch,
                        acquire_origin: grant.acquire_origin.clone(),
                        authoritative_head: installed.authority_head.clone(),
                        immutable_start_grant_receipt_digest: grant.grant_receipt_digest.clone(),
                        local_lineage_data_directory: installed
                            .local_lineage_data_directory
                            .clone(),
                    })
                })
                .collect()
        }
    }
}

fn inherited_predecessor_owned_evidence_from_strong_stop(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    projection: &InheritedPredecessorPhysicalProjection,
    failed_volume_effect: &AtomicStartFailedVolumeEffect,
    stop: &StrongStopEvidence,
) -> Result<InheritedPredecessorOwnedEvidence> {
    validate_inherited_predecessor_physical_projection(command, failed_volume_effect, projection)?;
    anyhow::ensure!(
        predecessor.operation_id == projection.predecessor_operation_id
            && predecessor.request_fingerprint == projection.predecessor_request_fingerprint
            && predecessor.result.kind() == projection.predecessor_terminal_result_kind
            && stop.retained_volume_receipts.len() == projection.volumes.len(),
        "rejected same-Node renewal changed only part of the predecessor Owned set"
    );
    let volumes = stop
        .retained_volume_receipts
        .iter()
        .zip(&projection.volumes)
        .map(|(receipt, physical)| {
            anyhow::ensure!(
                receipt.volume_id == physical.volume_id
                    && receipt.disk_id == physical.disk_id
                    && receipt.disk_role == physical.disk_role
                    && receipt.attachment_id == physical.attachment_id
                    && receipt.attachment_epoch == physical.attachment_epoch
                    && receipt.authority_receipt_digest.as_ref()
                        == Some(&physical.immutable_start_grant_receipt_digest)
                    && physical.authoritative_head.generation <= receipt.remote_durable_generation
                    && receipt.remote_durable_generation <= receipt.local_durable_generation,
                "fresh strong-Stop receipt changed predecessor attachment or durability lineage"
            );
            if physical.local_lineage_data_directory.is_none() {
                anyhow::ensure!(
                    receipt.local_durable_generation == receipt.remote_durable_generation
                        && receipt.remote_durable_generation
                            == physical.authoritative_head.generation,
                    "fresh strong-Stop inferred absent predecessor lineage with unique data"
                );
            }
            Ok(InheritedPredecessorOwnedVolume {
                retained_receipt: receipt.clone(),
                acquire_origin: physical.acquire_origin.clone(),
                authoritative_head: physical.authoritative_head.clone(),
                immutable_start_grant_receipt_digest: physical
                    .immutable_start_grant_receipt_digest
                    .clone(),
                local_lineage_data_directory: physical.local_lineage_data_directory.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    InheritedPredecessorOwnedEvidence::new(
        command,
        predecessor,
        projection.physical_manifest_digest.clone(),
        projection.runtime_incarnation.clone(),
        failed_volume_effect.clone(),
        volumes,
    )
}

fn retire_bridged_start_failed_predecessor_manifest(
    state_directory: &StateDirectory,
    predecessor: &LifecycleCommandResponse,
    current: &TerminalRetainedRuntimeManifest,
) -> Result<()> {
    let NodeResult::StartFailed(failed) = &predecessor.result else {
        return Ok(());
    };
    let TerminalRetainedRuntimeMode::InheritedPredecessorOwned { evidence } =
        &current.retention_mode
    else {
        anyhow::bail!("predecessor retirement lacks inherited current-op evidence")
    };
    anyhow::ensure!(
        evidence.predecessor_operation_id == predecessor.operation_id
            && evidence.predecessor_physical_manifest_digest
                == failed.retained_evidence.artifact_manifest_digest,
        "current failed Start did not exactly bridge its predecessor manifest"
    );
    let mut predecessors = enumerate_terminal_retained_runtime_manifests(state_directory)?
        .into_iter()
        .filter(|manifest| {
            manifest.cat_id == predecessor.cat_id
                && manifest.source_lifecycle_operation_id == predecessor.operation_id
        })
        .collect::<Vec<_>>();
    if predecessors.is_empty() {
        return Ok(());
    }
    anyhow::ensure!(
        predecessors.len() == 1,
        "failed Start bridge found duplicate predecessor manifests"
    );
    let predecessor_manifest = predecessors
        .pop()
        .context("failed Start predecessor manifest disappeared")?;
    anyhow::ensure!(
        predecessor_manifest.manifest_digest == evidence.predecessor_physical_manifest_digest,
        "failed Start bridge predecessor manifest changed after capture"
    );
    anyhow::ensure!(
        remove_terminal_retained_runtime_manifest_exact(state_directory, &predecessor_manifest)?,
        "failed Start bridge predecessor manifest disappeared before retirement"
    );
    Ok(())
}

fn exact_predecessor_volume_projection(
    state_directory: &StateDirectory,
    command: &LifecycleCommandEnvelope,
    receipt: &VolumeTerminalReceipt,
) -> Result<InheritedPredecessorPhysicalVolume> {
    let mut candidates = Vec::new();
    if let Some(manifest) = load_installed_runtime_manifest(state_directory, &command.cat_id)? {
        anyhow::ensure!(
            manifest.node_id == command.node_id
                && manifest.placement_identity == command.placement_identity
                && manifest.runtime_config_id == command.runtime_config.config_id
                && manifest.runtime_config_digest == command.runtime_config.config_digest,
            "Killed predecessor installed runtime belongs to another immutable runtime"
        );
        if let Some(volume) = manifest.volumes.iter().find(|volume| {
            volume.volume_id == receipt.volume_id
                && volume.disk_id == receipt.disk_id
                && volume.disk_role == receipt.disk_role
                && volume.attachment_id == receipt.attachment_id
                && volume.attachment_epoch == receipt.attachment_epoch
                && volume.authority_receipt_digest == receipt.authority_receipt_digest
        }) {
            candidates.push(InheritedPredecessorPhysicalVolume {
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
                    .context("Killed predecessor installed Volume lost its StartGrant digest")?,
                local_lineage_data_directory: Some(volume.local_lineage_data_directory.clone()),
            });
        }
    }
    for manifest in enumerate_terminal_retained_runtime_manifests(state_directory)? {
        if manifest.cat_id != command.cat_id
            || manifest.node_id != command.node_id
            || manifest.placement_identity != command.placement_identity
            || manifest.runtime_config_id != command.runtime_config.config_id
            || manifest.runtime_config_digest != command.runtime_config.config_digest
        {
            continue;
        }
        for volume in terminal_retained_physical_volumes(&manifest)? {
            if volume.volume_id == receipt.volume_id
                && volume.disk_id == receipt.disk_id
                && volume.disk_role == receipt.disk_role
                && volume.attachment_id == receipt.attachment_id
                && volume.attachment_epoch == receipt.attachment_epoch
                && receipt.authority_receipt_digest.as_ref()
                    == Some(&volume.immutable_start_grant_receipt_digest)
            {
                candidates.push(volume);
            }
        }
    }
    let first = candidates
        .first()
        .cloned()
        .context("Killed predecessor retained receipt has no exact physical carrier")?;
    anyhow::ensure!(
        candidates.iter().all(|candidate| candidate == &first),
        "Killed predecessor has conflicting retained physical carriers"
    );
    Ok(first)
}

struct StartVolumeRefreshEffect {
    request: AtomicStartVolumeBatchRequest,
    planned_agent_session: SessionBinding,
    context: AtomicStartRuntimeContext,
    next_phase: AtomicStartRuntimeEffectPhase,
    resume_platform_plan: Option<ExactBytes>,
}

fn apply_volume_refresh(
    ctx: &InstalledLifecycleContext,
    port: &dyn AtomicStartVolumePort,
    command: &LifecycleCommandEnvelope,
    input: StartVolumeRefreshEffect,
) -> Result<LifecycleEffectProgress> {
    let StartVolumeRefreshEffect {
        request,
        planned_agent_session,
        mut context,
        next_phase,
        resume_platform_plan,
    } = input;
    validate_refresh_request(
        command,
        &context,
        next_phase,
        resume_platform_plan.as_ref(),
        &request,
    )?;
    validate_planned_agent_session(command, &planned_agent_session)?;
    match port.inspect_or_apply_start_volumes(command, &request, &planned_agent_session)? {
        AtomicStartVolumeOutcome::Ready(receipt) => {
            validate_volume_batch_receipt(command, &request, &receipt)?;
            anyhow::ensure!(
                volume_grants_are_live(&receipt.grants)?,
                "command-scoped Volume refresh returned an expired grant"
            );
            for (previous, current) in context.volume_grants.iter().zip(&receipt.grants) {
                anyhow::ensure!(
                    previous.volume.volume_id == current.volume.volume_id
                        && previous.volume.attachment_id == current.volume.attachment_id
                        && previous.volume.attachment_epoch == current.volume.attachment_epoch
                        && previous.acquire_origin == current.acquire_origin
                        && remote_head_is_unchanged_or_advanced(
                            &previous.authoritative_head,
                            &current.authoritative_head,
                        ),
                    "atomic Start Volume renewal changed or regressed attachment lineage"
                );
            }
            context.artifact_classifications = merge_artifacts(
                context.artifact_classifications,
                volume_grant_artifacts(&receipt.grants)?,
            )?;
            let rebound_progress = rebind_runtime_progress_to_volume_grants(
                command,
                &context.runtime_progress,
                &receipt.grants,
            )?;
            publish_installed_runtime_progress_manifest(ctx.state_directory(), &rebound_progress)
                .context("publish renewed atomic Start authority attribution")?;
            context.volume_grant_sequence = receipt.grant_sequence;
            context.volume_grants = receipt.grants;
            context.volume_lease_session = planned_agent_session;
            context.runtime_progress = rebound_progress;
            planned_runtime_effect_after_lease_gate(
                ctx,
                command,
                next_phase,
                context,
                resume_platform_plan,
            )
            .map(LifecycleEffectProgress::Next)
        }
        AtomicStartVolumeOutcome::Failed {
            mut failure,
            evidence,
        } => {
            let retained_volume_grants = context.volume_grants;
            failure.artifact_classifications = merge_artifacts(
                context.artifact_classifications,
                failure.artifact_classifications,
            )?;
            anyhow::ensure!(
                failure.runtime_progress.is_none(),
                "Volume refresh failure invented runtime progress"
            );
            let mut retained_progress = context.runtime_progress;
            retained_progress.artifact_classifications = failure.artifact_classifications.clone();
            retained_progress.manifest_digest =
                installed_runtime_progress_manifest_digest(&retained_progress)?;
            validate_installed_runtime_progress_manifest(&retained_progress, command)?;
            failure.runtime_progress = Some(retained_progress);
            let failed_volume_effect = AtomicStartFailedVolumeEffect {
                request,
                evidence: *evidence,
            };
            failure_plan(
                ctx,
                command,
                *failure,
                retained_volume_grants,
                Some(failed_volume_effect),
                None,
                context.warm_restart_source,
            )
        }
    }
}

fn apply_runtime_effect(
    ctx: &InstalledLifecycleContext,
    port: &dyn AtomicStartRuntimePort,
    command: &LifecycleCommandEnvelope,
    request: AtomicStartRuntimeEffectRequest,
) -> Result<LifecycleEffectProgress> {
    validate_runtime_effect_request(command, &request)?;
    let phase = request.phase;
    match port.inspect_or_apply_start_effect(command, &request)? {
        AtomicStartRuntimeEffectOutcome::Completed(receipt) => {
            anyhow::ensure!(
                phase != AtomicStartRuntimeEffectPhase::GuestReadyAndAdmission,
                "final atomic Start effect returned an intermediate receipt"
            );
            anyhow::ensure!(
                receipt.phase == phase
                    && receipt.platform_plan == request.platform_plan
                    && receipt.platform_plan_digest
                        == platform_plan_digest(command, phase, &request.platform_plan)
                    && receipt.receipt_digest
                        == atomic_start_platform_receipt_digest(
                            command,
                            phase,
                            &receipt.platform_plan_digest,
                            &receipt.platform_receipt,
                        )?,
                "atomic Start runtime receipt changed its journaled platform plan"
            );
            validate_platform_receipt(&receipt.platform_receipt)?;
            validate_artifacts(&receipt.artifact_classifications)?;
            let mut context = request.context;
            let merged_artifacts = merge_artifacts(
                context.artifact_classifications,
                receipt.artifact_classifications.clone(),
            )?;
            validate_completed_runtime_progress_manifest(
                &receipt.runtime_progress,
                command,
                phase,
            )?;
            validate_runtime_progress_against_volume_grants(
                &receipt.runtime_progress,
                &context.volume_grants,
            )?;
            anyhow::ensure!(
                receipt.runtime_progress.runtime_incarnation == context.runtime_incarnation
                    && receipt.runtime_progress.artifact_classifications == merged_artifacts,
                "completed atomic Start progress does not join the exact effect context"
            );
            validate_runtime_progress_advances(
                &context.runtime_progress,
                &receipt.runtime_progress,
            )?;
            publish_installed_runtime_progress_manifest(
                ctx.state_directory(),
                &receipt.runtime_progress,
            )
            .context("publish cumulative atomic Start runtime progress")?;
            context.artifact_classifications = merged_artifacts;
            context.runtime_progress = receipt.runtime_progress.clone();
            context.completed_effects.push(receipt);
            planned_successor_after_completed_runtime_effect(
                port,
                command,
                phase,
                context,
                ctx.start_volume_port().current_agent_session_binding()?,
            )
            .map(LifecycleEffectProgress::Next)
        }
        AtomicStartRuntimeEffectOutcome::RuntimeReady(evidence) => {
            anyhow::ensure!(
                phase == AtomicStartRuntimeEffectPhase::GuestReadyAndAdmission,
                "non-final atomic Start effect returned RuntimeReady"
            );
            anyhow::ensure!(
                evidence.platform_plan_digest
                    == platform_plan_digest(command, phase, &request.platform_plan),
                "RuntimeReady evidence changed its journaled platform plan"
            );
            anyhow::ensure!(
                evidence.platform_receipt_digest
                    == atomic_start_platform_receipt_digest(
                        command,
                        phase,
                        &evidence.platform_plan_digest,
                        &evidence.platform_receipt,
                    )?,
                "RuntimeReady evidence changed its exact platform receipt"
            );
            validate_platform_receipt(&evidence.platform_receipt)?;
            validate_artifacts(&evidence.artifact_classifications)?;
            anyhow::ensure!(
                artifacts_are_exact_subset(
                    &request.context.artifact_classifications,
                    &evidence.artifact_classifications,
                ),
                "RuntimeReady joined proof dropped physical artifact evidence"
            );
            validate_runtime_ready_volume_receipts(
                command,
                &request.context.volume_grants,
                &evidence.volume_receipts,
            )?;
            validate_installed_runtime_manifest(&evidence.installed_runtime_manifest, command)?;
            validate_manifest_volume_receipts(
                &evidence.installed_runtime_manifest,
                &evidence.volume_receipts,
            )?;
            let last_progress = request
                .context
                .completed_effects
                .last()
                .context("RuntimeReady lacks durable runtime activation attribution")?;
            validate_final_manifest_extends_progress(
                &last_progress.runtime_progress,
                &evidence.installed_runtime_manifest,
            )?;
            anyhow::ensure!(
                evidence.installed_runtime_manifest.runtime_incarnation
                    == request.context.runtime_incarnation
                    && evidence.installed_runtime_manifest.execution_receipt_digest
                        == evidence.execution_receipt_digest
                    && evidence
                        .installed_runtime_manifest
                        .guest_ready_receipt_digest
                        == evidence.guest_ready_receipt_digest
                    && evidence
                        .installed_runtime_manifest
                        .retired_restart_source_absence_digest
                        == evidence.retired_restart_source_absence_digest
                    && evidence.retired_restart_source_absence_digest.is_some()
                        == request.context.warm_restart_source.is_some(),
                "RuntimeReady manifest and joined evidence differ"
            );
            if !runtime_context_has_monotonic_lease_budget(
                &request.context,
                Duration::from_millis(START_VOLUME_LEASE_SAFETY_MARGIN_MS),
            )? {
                // The exact final plan may already have completed while its
                // response was in flight. Preserve that same plan across a
                // journaled renewal; replay discovers Guest readiness and any
                // Warm-source retirement before terminal publication.
                return planned_refresh_volumes(
                    command,
                    request.context,
                    phase,
                    Some(request.platform_plan),
                    ctx.start_volume_port().current_agent_session_binding()?,
                )
                .map(LifecycleEffectProgress::Next);
            }
            publish_installed_runtime_manifest(
                ctx.state_directory(),
                &evidence.installed_runtime_manifest,
            )
            .context("publish exact installed RuntimeReady manifest")?;
            retire_consumed_start_retry_manifest(
                ctx.state_directory(),
                command,
                request.context.local_predecessor.as_ref(),
            )
            .context("retire consumed failed-Start predecessor retention")?;
            remove_installed_runtime_progress_manifest(ctx.state_directory(), command)
                .context("remove superseded atomic Start progress manifest")?;
            let cell = ctx
                .admission_registry()
                .ensure_initial_target_fail_closed(command)
                .context("obtain exact fail-closed Start admission cell")?;
            let ready = EffectiveRuntimeReady::new(
                command.operation_id.clone(),
                request.context.runtime_incarnation.clone(),
                command_guest_ipv4(command),
            );
            cell.publish_runtime_ready(start_closed_anchor(command), ready)
                .context("publish lifecycle RuntimeReady while Endpoint gates remain Closed")?;
            forget_process_local_start_lease_witnesses(&command.operation_id)?;
            Ok(LifecycleEffectProgress::Terminal(NodeResult::RuntimeReady(
                Box::new(RuntimeReadyResult {
                    runtime_incarnation: request.context.runtime_incarnation,
                    runtime_config_digest: command.runtime_config.config_digest.clone(),
                    execution_receipt_digest: evidence.execution_receipt_digest,
                    guest_ready_receipt_digest: evidence.guest_ready_receipt_digest,
                    volume_receipts: evidence.volume_receipts,
                }),
            )))
        }
        AtomicStartRuntimeEffectOutcome::VolumeRefreshRequired {
            platform_plan_digest: returned_plan_digest,
            runtime_progress,
        } => planned_runtime_requested_volume_refresh(
            command,
            request,
            returned_plan_digest,
            runtime_progress,
            ctx.start_volume_port().current_agent_session_binding()?,
        )
        .map(LifecycleEffectProgress::Next),
        AtomicStartRuntimeEffectOutcome::SessionRebindRequired {
            old_platform_plan_digest,
            cleanup_receipt,
            cleanup_receipt_digest,
            runtime_progress,
        } => {
            let expected_old_plan_digest =
                platform_plan_digest(command, phase, &request.platform_plan);
            anyhow::ensure!(
                old_platform_plan_digest == expected_old_plan_digest
                    && cleanup_receipt_digest
                        == atomic_start_session_rebind_receipt_digest(
                            command,
                            phase,
                            request.context.volume_grant_sequence,
                            &old_platform_plan_digest,
                            &cleanup_receipt,
                        )?
                    && runtime_progress == request.context.runtime_progress,
                "atomic Start session rebind lacks exact zero-mutation cleanup evidence"
            );
            validate_platform_receipt(&cleanup_receipt)?;
            let mut context = request.context;
            if context.session_rebind_receipts.len() == START_SESSION_REBIND_MAX_COUNT {
                return failure_plan(
                    ctx,
                    command,
                    AtomicStartDefiniteFailure {
                        reason: CommandFailureReason::InvalidLocalPrecondition,
                        artifact_classifications: context.artifact_classifications.clone(),
                        runtime_progress: Some(context.runtime_progress.clone()),
                    },
                    context.volume_grants,
                    None,
                    None,
                    context.warm_restart_source,
                );
            }
            context
                .session_rebind_receipts
                .push(AtomicStartSessionRebindReceipt {
                    phase,
                    volume_grant_sequence: context.volume_grant_sequence,
                    old_platform_plan: request.platform_plan,
                    old_platform_plan_digest,
                    cleanup_receipt,
                    cleanup_receipt_digest,
                    runtime_progress,
                });
            let replacement_plan = port.plan_start_effect(command, phase, &context)?;
            anyhow::ensure!(
                platform_plan_digest(command, phase, &replacement_plan) != expected_old_plan_digest,
                "atomic Start session rebind reused the obsolete platform plan"
            );
            planned_runtime_effect(command, phase, context, replacement_plan)
                .map(LifecycleEffectProgress::Next)
        }
        AtomicStartRuntimeEffectOutcome::Failed(mut failure) => {
            failure.artifact_classifications = merge_artifacts(
                request.context.artifact_classifications,
                failure.artifact_classifications,
            )?;
            let progress = failure
                .runtime_progress
                .as_ref()
                .context("runtime failure omitted fresh cumulative physical attribution")?;
            validate_installed_runtime_progress_manifest(progress, command)?;
            validate_runtime_progress_against_volume_grants(
                progress,
                &request.context.volume_grants,
            )?;
            anyhow::ensure!(
                progress.runtime_incarnation == request.context.runtime_incarnation
                    && progress.artifact_classifications == failure.artifact_classifications,
                "failed atomic Start progress does not join the exact effect context"
            );
            validate_runtime_progress_advances(&request.context.runtime_progress, progress)?;
            failure_plan(
                ctx,
                command,
                failure,
                request.context.volume_grants,
                None,
                None,
                request.context.warm_restart_source,
            )
        }
    }
}

fn planned_successor_after_completed_runtime_effect(
    port: &dyn AtomicStartRuntimePort,
    command: &LifecycleCommandEnvelope,
    completed_phase: AtomicStartRuntimeEffectPhase,
    context: AtomicStartRuntimeContext,
    planned_agent_session: SessionBinding,
) -> Result<PlannedLifecycleEffect> {
    let next_phase = completed_phase
        .next()
        .context("atomic Start runtime phase has no successor")?;
    if completed_phase == AtomicStartRuntimeEffectPhase::FormatPersistentVolumes {
        // The format receipt carries the exact initialization authority bound
        // to the current immutable StartGrant. Renewing here would change the
        // grant receipt before `commit_initialized` consumes that binding.
        // Commit is therefore the sole phase transition which preserves the
        // exact grant sequence and digests without an intervening renewal.
        let platform_plan = port.plan_start_effect(command, next_phase, &context)?;
        return planned_runtime_effect(command, next_phase, context, platform_plan);
    }
    planned_refresh_volumes(command, context, next_phase, None, planned_agent_session)
}

fn planned_runtime_requested_volume_refresh(
    command: &LifecycleCommandEnvelope,
    request: AtomicStartRuntimeEffectRequest,
    returned_plan_digest: Sha256Digest,
    runtime_progress: Option<InstalledRuntimeProgressManifest>,
    planned_agent_session: SessionBinding,
) -> Result<PlannedLifecycleEffect> {
    anyhow::ensure!(
        returned_plan_digest
            == platform_plan_digest(command, request.phase, &request.platform_plan),
        "Volume refresh discovery changed its journaled platform plan"
    );
    anyhow::ensure!(
        runtime_progress.as_ref() == Some(&request.context.runtime_progress),
        "Volume refresh was requested after an undisclosed physical mutation"
    );
    planned_refresh_volumes(
        command,
        request.context,
        request.phase,
        Some(request.platform_plan),
        planned_agent_session,
    )
}

fn failure_plan(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    failure: AtomicStartDefiniteFailure,
    volume_grants: Vec<AtomicStartVolumeGrant>,
    failed_volume_effect: Option<AtomicStartFailedVolumeEffect>,
    inherited_predecessor_physical: Option<InheritedPredecessorPhysicalProjection>,
    warm_restart_source: Option<AtomicStartWarmRestartSource>,
) -> Result<LifecycleEffectProgress> {
    validate_artifacts(&failure.artifact_classifications)?;
    if let Some(progress) = &failure.runtime_progress {
        publish_installed_runtime_progress_manifest(ctx.state_directory(), progress)
            .context("publish failed atomic Start runtime progress before Stop fence")?;
    }
    let step = execution_step(
        command,
        StartStepState::StrongStopFailure {
            reason: failure.reason,
            artifact_classifications: failure.artifact_classifications,
            volume_grants,
            runtime_progress: failure.runtime_progress,
            failed_volume_effect,
            inherited_predecessor_physical,
            warm_restart_source,
        },
    )?;
    Ok(LifecycleEffectProgress::Next(
        PlannedLifecycleEffect::install_stop_fence(step, failure_fence_payload(command)?),
    ))
}

fn planned_runtime_effect_after_lease_gate(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    phase: AtomicStartRuntimeEffectPhase,
    context: AtomicStartRuntimeContext,
    resume_platform_plan: Option<ExactBytes>,
) -> Result<PlannedLifecycleEffect> {
    let required = runtime_phase_required_lease_budget(&context)?;
    if !runtime_context_has_monotonic_lease_budget(&context, required)? {
        return planned_refresh_volumes(
            command,
            context,
            phase,
            resume_platform_plan,
            ctx.start_volume_port().current_agent_session_binding()?,
        );
    }
    let platform_plan = match resume_platform_plan {
        Some(platform_plan) => platform_plan,
        None => ctx
            .start_runtime_port()
            .plan_start_effect(command, phase, &context)?,
    };
    planned_runtime_effect(command, phase, context, platform_plan)
}

fn planned_runtime_effect(
    command: &LifecycleCommandEnvelope,
    phase: AtomicStartRuntimeEffectPhase,
    context: AtomicStartRuntimeContext,
    platform_plan: ExactBytes,
) -> Result<PlannedLifecycleEffect> {
    validate_runtime_context(command, &context, phase)?;
    validate_platform_plan(&platform_plan)?;
    planned_unfenced(
        command,
        StartStepState::RuntimeEffect {
            request: AtomicStartRuntimeEffectRequest {
                phase,
                context,
                platform_plan,
            },
        },
    )
}

fn planned_refresh_volumes(
    command: &LifecycleCommandEnvelope,
    context: AtomicStartRuntimeContext,
    next_phase: AtomicStartRuntimeEffectPhase,
    resume_platform_plan: Option<ExactBytes>,
    planned_agent_session: SessionBinding,
) -> Result<PlannedLifecycleEffect> {
    validate_runtime_context(command, &context, next_phase)?;
    validate_planned_agent_session(command, &planned_agent_session)?;
    if let Some(platform_plan) = resume_platform_plan.as_ref() {
        validate_platform_plan(platform_plan)?;
    }
    let request = refresh_volume_batch_request(
        command,
        context.volume_lease_duration_ms,
        context.volume_grant_sequence,
        &context.volume_grants,
    )?;
    planned_unfenced(
        command,
        StartStepState::RefreshVolumes {
            request,
            planned_agent_session,
            context,
            next_phase,
            resume_platform_plan,
        },
    )
}

fn planned_unfenced(
    command: &LifecycleCommandEnvelope,
    state: StartStepState,
) -> Result<PlannedLifecycleEffect> {
    execution_step(command, state).map(PlannedLifecycleEffect::unfenced)
}

fn execution_step(
    command: &LifecycleCommandEnvelope,
    state: StartStepState,
) -> Result<ExecutionStep> {
    let payload = StartStepPayload {
        version: ContractVersion::V1,
        operation_id: command.operation_id.clone(),
        request_fingerprint: command.request_fingerprint.clone(),
        state,
    };
    validate_step_payload(command, &payload)?;
    let value = serde_json::to_value(&payload).context("encode atomic Start durable step")?;
    let bytes = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= START_STEP_MAX_BYTES,
        "atomic Start durable step exceeds its byte cap"
    );
    Ok(ExecutionStep {
        name: Id::new(START_STEP_NAME).context("atomic Start step name is invalid")?,
        recovery_payload: ExactBytes::new(bytes),
    })
}

fn decode_step(
    command: &LifecycleCommandEnvelope,
    step: &ExecutionStep,
) -> Result<StartStepPayload> {
    anyhow::ensure!(
        step.name.as_str() == START_STEP_NAME,
        "atomic Start received another handler's durable step"
    );
    anyhow::ensure!(
        !step.recovery_payload.as_slice().is_empty()
            && step.recovery_payload.as_slice().len() <= START_STEP_MAX_BYTES,
        "atomic Start durable step has an invalid size"
    );
    let value: serde_json::Value = serde_json::from_slice(step.recovery_payload.as_slice())
        .context("decode atomic Start durable step JSON")?;
    anyhow::ensure!(
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&value)
            == step.recovery_payload.as_slice(),
        "atomic Start durable step is not canonical JSON"
    );
    let payload: StartStepPayload =
        serde_json::from_value(value).context("decode atomic Start durable step")?;
    validate_step_payload(command, &payload)?;
    Ok(payload)
}

/// Bind non-terminal physical evidence to the sole executable journal state.
/// An `Err` is a quarantine result and grants no permission to invoke a
/// provider. The discovery arm still carries only the exact already-Executing
/// request; callers must not construct a request from manifest fields.
pub(crate) fn bind_installed_runtime_progress_to_journal(
    command: Option<&LifecycleCommandEnvelope>,
    step: Option<&ExecutionStep>,
    manifest: &InstalledRuntimeProgressManifest,
) -> Result<InstalledRuntimeProgressJournalBinding> {
    let command = command.context(
        "atomic Start progress has no lifecycle command journal; quarantine without effects",
    )?;
    let step = step.context(
        "atomic Start progress has no Executing journal step; quarantine without effects",
    )?;
    validate_installed_runtime_progress_manifest(manifest, command)?;
    let payload = decode_step(command, step)?;
    let embedded = match &payload.state {
        StartStepState::AcquireVolumes { .. } => None,
        StartStepState::RefreshVolumes { context, .. }
        | StartStepState::RuntimeEffect {
            request: AtomicStartRuntimeEffectRequest { context, .. },
        } => Some(&context.runtime_progress),
        StartStepState::StrongStopFailure {
            runtime_progress, ..
        } => runtime_progress.as_ref(),
    };
    if embedded == Some(manifest) {
        return Ok(InstalledRuntimeProgressJournalBinding::ExactEmbeddedEvidence);
    }
    match &payload.state {
        StartStepState::RuntimeEffect { request } => {
            if let Some(previous) = embedded {
                validate_runtime_progress_advances(previous, manifest).context(
                    "atomic Start progress is not a monotonic ambiguity of its Executing request",
                )?;
            }
            Ok(
                InstalledRuntimeProgressJournalBinding::RequiresCurrentEffectDiscovery {
                    request: Box::new(request.clone()),
                },
            )
        }
        StartStepState::AcquireVolumes {
            request,
            planned_agent_session,
            ..
        } => {
            validate_authority_only_runtime_progress(manifest)?;
            Ok(
                InstalledRuntimeProgressJournalBinding::RequiresVolumeAuthorityDiscovery {
                    request: Box::new(request.clone()),
                    planned_agent_session: planned_agent_session.clone(),
                },
            )
        }
        StartStepState::RefreshVolumes {
            request,
            planned_agent_session,
            context,
            ..
        } => {
            validate_runtime_progress_authority_rebind(&context.runtime_progress, manifest)?;
            Ok(
                InstalledRuntimeProgressJournalBinding::RequiresVolumeAuthorityDiscovery {
                    request: Box::new(request.clone()),
                    planned_agent_session: planned_agent_session.clone(),
                },
            )
        }
        StartStepState::StrongStopFailure { .. } => anyhow::bail!(
            "atomic Start progress differs from its journal step; quarantine without effects"
        ),
    }
}

/// Bind the exact current-operation slice from the single startup physical
/// scan to the sole lifecycle journal state. Any mismatch is a quarantine
/// result and authorizes no provider call. Predecessor retained manifests are
/// validated by the outer registry and must not be included in `entries`.
pub(crate) fn bind_installed_start_physical_to_journal(
    command: &LifecycleCommandEnvelope,
    state: &CommandJournalState,
    entries: &[InstalledStartPhysicalInventoryEntry],
) -> Result<InstalledStartStartupBinding> {
    anyhow::ensure!(
        matches!(command.command, LifecycleCommand::Start(_)) && entries.len() <= 1,
        "atomic Start startup binding has another command or multiple current artifacts"
    );
    for entry in entries {
        match entry {
            InstalledStartPhysicalInventoryEntry::Executing(progress) => {
                validate_installed_runtime_progress_manifest(progress, command)?;
            }
            InstalledStartPhysicalInventoryEntry::TerminalRetained(manifest) => {
                validate_terminal_retained_runtime_manifest(manifest, Some(command))?;
            }
        }
    }
    match state {
        CommandJournalState::Accepted { .. } => {
            anyhow::ensure!(
                entries.is_empty(),
                "Accepted atomic Start already has current-operation physical evidence"
            );
            Ok(InstalledStartStartupBinding::NoPhysicalEvidence)
        }
        CommandJournalState::Executing { step, .. } => {
            let payload = decode_step(command, step)?;
            match entries.first() {
                None => match payload.state {
                    StartStepState::AcquireVolumes { .. } => {
                        Ok(InstalledStartStartupBinding::NoPhysicalEvidence)
                    }
                    StartStepState::StrongStopFailure {
                        volume_grants,
                        runtime_progress,
                        failed_volume_effect,
                        ..
                    } if volume_grants.is_empty()
                        && runtime_progress.is_none()
                        && failed_volume_effect.is_some() =>
                    {
                        // An exact initial no-mutation Volume rejection has
                        // no local progress file. Strong Stop still performs
                        // a complete target-absence/current-authority scan.
                        Ok(InstalledStartStartupBinding::NoPhysicalEvidence)
                    }
                    StartStepState::RefreshVolumes { .. }
                    | StartStepState::RuntimeEffect { .. }
                    | StartStepState::StrongStopFailure { .. } => anyhow::bail!(
                        "Executing atomic Start lost its current physical evidence"
                    ),
                },
                Some(InstalledStartPhysicalInventoryEntry::Executing(progress)) => {
                    match bind_installed_runtime_progress_to_journal(
                        Some(command),
                        Some(step),
                        progress,
                    )? {
                        InstalledRuntimeProgressJournalBinding::ExactEmbeddedEvidence => {
                            Ok(InstalledStartStartupBinding::ExactEmbeddedEvidence)
                        }
                        InstalledRuntimeProgressJournalBinding::RequiresCurrentEffectDiscovery {
                            request,
                        } => Ok(
                            InstalledStartStartupBinding::RequiresCurrentEffectDiscovery {
                                request,
                            },
                        ),
                        InstalledRuntimeProgressJournalBinding::RequiresVolumeAuthorityDiscovery {
                            request,
                            planned_agent_session,
                        } => Ok(
                            InstalledStartStartupBinding::RequiresVolumeAuthorityDiscovery {
                                request,
                                planned_agent_session,
                            },
                        ),
                    }
                }
                Some(InstalledStartPhysicalInventoryEntry::TerminalRetained(manifest)) => {
                    let StartStepState::StrongStopFailure {
                        volume_grants,
                        runtime_progress,
                        warm_restart_source,
                        ..
                    } = payload.state
                    else {
                        anyhow::bail!(
                            "sealed retained Start evidence has no Executing failure edge"
                        )
                    };
                    anyhow::ensure!(
                        manifest.volume_grants == volume_grants
                            && manifest.runtime_progress == runtime_progress,
                        "sealed retained Start evidence changed its Executing failure step"
                    );
                    match (
                        manifest.retained_warm_restart_source.as_ref(),
                        warm_restart_source.as_ref(),
                    ) {
                        (Some(carrier), Some(source)) => {
                            super::suspend_warm::validate_retained_warm_restart_source_for_source(
                                command,
                                carrier,
                                &source.cleanup_authority,
                                &source.physical_manifest_digest,
                            )?;
                        }
                        (None, None) => {}
                        _ => anyhow::bail!(
                            "sealed retained Warm carrier changed its Executing source"
                        ),
                    }
                    Ok(InstalledStartStartupBinding::ReplaySealedTerminal {
                        manifest: manifest.clone(),
                    })
                }
            }
        }
        CommandJournalState::Terminal { result, .. } => {
            let response = result
                .decode_api()
                .context("decode terminal atomic Start result for startup binding")?;
            anyhow::ensure!(
                response.operation_id == command.operation_id
                    && response.request_fingerprint == command.request_fingerprint
                    && response.cat_id == command.cat_id
                    && response.node_id == command.node_id
                    && response.placement_identity == command.placement_identity,
                "terminal atomic Start response changed its command identity"
            );
            match &response.result {
                NodeResult::RuntimeReady(_) => {
                    anyhow::ensure!(
                        entries.is_empty(),
                        "RuntimeReady retained current-operation Start progress"
                    );
                    Ok(InstalledStartStartupBinding::NoPhysicalEvidence)
                }
                NodeResult::StartFailed(failed) => match entries.first() {
                    Some(InstalledStartPhysicalInventoryEntry::TerminalRetained(manifest)) => {
                        anyhow::ensure!(
                            failed.retained_evidence.artifact_manifest_digest
                                == manifest.manifest_digest,
                            "StartFailed terminal result changed its retained manifest"
                        );
                        Ok(InstalledStartStartupBinding::ReplaySealedTerminal {
                            manifest: manifest.clone(),
                        })
                    }
                    None => {
                        anyhow::ensure!(
                            failed.retained_evidence.adoptable_count == 0
                                && failed.retained_evidence.gc_candidate_count == 0
                                && failed.retained_evidence.retained_authority_or_data_count == 0
                                && failed.retained_evidence.quarantined_count == 0,
                            "StartFailed lost non-empty retained physical evidence"
                        );
                        Ok(InstalledStartStartupBinding::NoPhysicalEvidence)
                    }
                    Some(InstalledStartPhysicalInventoryEntry::Executing(_)) => {
                        anyhow::bail!("terminal StartFailed still has executable progress")
                    }
                },
                _ => anyhow::bail!("atomic Start journal has another terminal result kind"),
            }
        }
    }
}

fn validate_step_payload(
    command: &LifecycleCommandEnvelope,
    payload: &StartStepPayload,
) -> Result<()> {
    anyhow::ensure!(
        payload.version == ContractVersion::V1
            && payload.operation_id == command.operation_id
            && payload.request_fingerprint == command.request_fingerprint,
        "atomic Start durable step belongs to another command"
    );
    match &payload.state {
        StartStepState::AcquireVolumes {
            request,
            planned_agent_session,
            source,
            warm_restart_source,
            runtime_effect_timeout_ms,
            ..
        } => {
            let (expected_source, _) = start_spec(command)?;
            anyhow::ensure!(
                *source == expected_source,
                "atomic Start durable source changed"
            );
            validate_warm_restart_source_shape(command, *source, warm_restart_source.as_ref())?;
            validate_planned_agent_session(command, planned_agent_session)?;
            validate_start_lease_effect_policy(
                request.renewal_lease_duration_ms,
                *runtime_effect_timeout_ms,
            )?;
            validate_volume_batch_request(command, request)
        }
        StartStepState::RuntimeEffect { request } => {
            validate_runtime_effect_request(command, request)
        }
        StartStepState::RefreshVolumes {
            request,
            planned_agent_session,
            context,
            next_phase,
            resume_platform_plan,
        } => {
            validate_planned_agent_session(command, planned_agent_session)?;
            validate_refresh_request(
                command,
                context,
                *next_phase,
                resume_platform_plan.as_ref(),
                request,
            )
        }
        StartStepState::StrongStopFailure {
            reason,
            artifact_classifications,
            volume_grants,
            runtime_progress,
            failed_volume_effect,
            inherited_predecessor_physical,
            warm_restart_source,
        } => {
            let (source, _) = start_spec(command)?;
            validate_warm_restart_source_shape(command, source, warm_restart_source.as_ref())?;
            if let Some(projection) = inherited_predecessor_physical {
                anyhow::ensure!(
                    projection.warm_restart_source.as_ref() == warm_restart_source.as_ref(),
                    "failed Start step changed its Warm predecessor projection"
                );
            }
            validate_artifacts(artifact_classifications)?;
            if let Some(progress) = runtime_progress {
                validate_start_volume_grant_set(command, volume_grants)?;
                validate_installed_runtime_progress_manifest(progress, command)?;
                validate_runtime_progress_against_volume_grants(progress, volume_grants)?;
                anyhow::ensure!(
                    progress.artifact_classifications == *artifact_classifications,
                    "failed atomic Start progress changed retained artifact evidence"
                );
            } else {
                anyhow::ensure!(
                    volume_grants.is_empty(),
                    "failed atomic Start retained Volume grants without physical attribution"
                );
            }
            anyhow::ensure!(
                runtime_progress.is_none() || inherited_predecessor_physical.is_none(),
                "failed atomic Start mixed current-operation progress with predecessor projection"
            );
            match failed_volume_effect {
                Some(effect) => {
                    let disposition = validate_atomic_start_volume_failure_evidence(
                        command,
                        &effect.request,
                        &effect.evidence,
                    )?;
                    anyhow::ensure!(
                        (*reason == CommandFailureReason::InvalidLocalPrecondition
                            && disposition
                                == AtomicStartVolumeFailureDisposition::LocalDeadlineElapsed)
                            || (*reason == CommandFailureReason::VolumeAuthorityRejected
                                && matches!(
                                    disposition,
                                    AtomicStartVolumeFailureDisposition::AuthorityRejected
                                        | AtomicStartVolumeFailureDisposition::TakeoverUnavailable
                                )),
                        "atomic Start Volume failure reason changed its typed outcome"
                    );
                    match runtime_progress {
                        None => {
                            anyhow::ensure!(
                                effect.request.grant_sequence.get() == 0,
                                "initial atomic Start Volume rejection has a later grant sequence"
                            );
                            if let Some(projection) = inherited_predecessor_physical {
                                validate_inherited_predecessor_physical_projection(
                                    command, effect, projection,
                                )?;
                            }
                        }
                        Some(_) => {
                            anyhow::ensure!(
                                effect.request.grant_sequence.get() > 0
                                    && effect.request.actions.len() == volume_grants.len(),
                                "atomic Start Volume refresh rejection lost its prior grant set"
                            );
                            for (action, grant) in effect.request.actions.iter().zip(volume_grants)
                            {
                                let AtomicStartVolumeAction::RenewSameNode {
                                    volume,
                                    attachment_id,
                                    attachment_epoch,
                                    ..
                                } = action
                                else {
                                    anyhow::bail!(
                                        "atomic Start Volume refresh rejection is not a renewal"
                                    )
                                };
                                anyhow::ensure!(
                                    volume.volume_id == grant.volume.volume_id
                                        && attachment_id == &grant.volume.attachment_id
                                        && *attachment_epoch == grant.volume.attachment_epoch,
                                    "atomic Start Volume refresh rejection changed retained authority"
                                );
                            }
                        }
                    }
                }
                None => anyhow::ensure!(
                    runtime_progress.is_some() && inherited_predecessor_physical.is_none(),
                    "failed atomic Start without runtime progress or typed Volume rejection"
                ),
            }
            Ok(())
        }
    }
}

fn start_spec(command: &LifecycleCommandEnvelope) -> Result<(StartSource, UnixMillis)> {
    let LifecycleCommand::Start(spec) = &command.command else {
        anyhow::bail!("atomic Start handler received a non-Start command")
    };
    Ok((spec.source, spec.effect_deadline_unix_ms))
}

/// Re-run the shared operation-aware successor gate from the exact bounded
/// journal pair before every Start effect. In particular, a failed retry may
/// reuse `NormalUnowned` only from the canonical failed Start command; its
/// terminal response alone cannot supply that transition identity.
fn validate_start_predecessor_command(
    command: &LifecycleCommandEnvelope,
    predecessor_command: Option<&LifecycleCommandEnvelope>,
    predecessor: Option<&LifecycleCommandResponse>,
) -> Result<()> {
    let Some(predecessor) = predecessor else {
        anyhow::ensure!(
            predecessor_command.is_none(),
            "initial Start retained a predecessor command without its terminal response"
        );
        return Ok(());
    };
    let predecessor_command = predecessor_command
        .context("same-Node Start lacks its exact canonical predecessor command")?;
    let terminal = LifecycleTerminalResult::NodeResult {
        response: Box::new(predecessor.clone()),
    };
    validate_lifecycle_successor_with_predecessor_command(
        Some(&terminal),
        Some(predecessor_command),
        command,
    )
    .context("validate exact operation-aware Start predecessor")
}

fn validate_start_predecessor(
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    source: StartSource,
) -> Result<()> {
    match source {
        StartSource::Genesis => {
            anyhow::ensure!(
                predecessor.is_none()
                    && matches!(command.predecessor, LifecyclePredecessor::Genesis { .. }),
                "Genesis Start has local predecessor evidence"
            );
        }
        StartSource::ColdHandoff => {
            anyhow::ensure!(
                predecessor.is_none()
                    && matches!(
                        command.predecessor,
                        LifecyclePredecessor::CrossNodeColdHandoff { .. }
                    ),
                "Cold-handoff Start has local predecessor evidence"
            );
        }
        StartSource::HostFenceRecovery => {
            anyhow::ensure!(
                predecessor.is_none()
                    && matches!(
                        command.predecessor,
                        LifecyclePredecessor::HostFenceRecovery { .. }
                    ),
                "Host-fence Start has local predecessor evidence"
            );
        }
        StartSource::SameNodeSuspended
        | StartSource::SameNodeWarm
        | StartSource::SameNodeCold
        | StartSource::SameNodeStopped
        | StartSource::SameNodeRetry => {
            let response = predecessor.context("same-Node Start lacks terminal predecessor")?;
            let LifecyclePredecessor::SameNode {
                operation_id,
                terminal_result_kind,
                terminal_result_digest,
                node_id,
                placement_identity,
            } = &command.predecessor
            else {
                anyhow::bail!("same-Node Start has a non-local predecessor")
            };
            let actual_terminal_result_digest =
                lifecycle_terminal_result_digest(&LifecycleTerminalResult::NodeResult {
                    response: Box::new(response.clone()),
                })?;
            anyhow::ensure!(
                response.operation_id == *operation_id
                    && response.node_id == *node_id
                    && response.placement_identity == *placement_identity
                    && response.result.kind() == *terminal_result_kind
                    && actual_terminal_result_digest == *terminal_result_digest,
                "same-Node Start predecessor response changed"
            );
            let expected = match source {
                StartSource::SameNodeSuspended => TerminalResultKind::Suspended,
                StartSource::SameNodeWarm => TerminalResultKind::Warm,
                StartSource::SameNodeCold => TerminalResultKind::Cold,
                StartSource::SameNodeStopped => TerminalResultKind::Killed,
                StartSource::SameNodeRetry => response.result.kind(),
                _ => unreachable!("same-Node sources were matched"),
            };
            anyhow::ensure!(
                response.result.kind() == expected
                    && (source != StartSource::SameNodeRetry
                        || matches!(
                            expected,
                            TerminalResultKind::StartFailed
                                | TerminalResultKind::SuspendFailed
                                | TerminalResultKind::WarmFailed
                        )),
                "same-Node Start source does not match its predecessor result"
            );
            validate_same_node_volume_inputs(command, response, source)?;
        }
    }
    Ok(())
}

fn validate_same_node_volume_inputs(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    source: StartSource,
) -> Result<()> {
    let LifecycleCommand::Start(spec) = &command.command else {
        anyhow::bail!("same-Node volume validation received another command")
    };
    let retained = match (source, &predecessor.result) {
        (StartSource::SameNodeSuspended, NodeResult::Suspended(value)) => {
            Some((value.local_durability_receipts.as_slice(), true))
        }
        (StartSource::SameNodeWarm, NodeResult::Warm(value)) => {
            Some((value.volume_receipts.as_slice(), true))
        }
        (StartSource::SameNodeStopped, NodeResult::Killed(value)) => {
            Some((value.retained_volume_receipts.as_slice(), false))
        }
        (StartSource::SameNodeCold, NodeResult::Cold(_))
        | (
            StartSource::SameNodeRetry,
            NodeResult::StartFailed(_) | NodeResult::SuspendFailed(_) | NodeResult::WarmFailed(_),
        ) => None,
        _ => anyhow::bail!("same-Node Start result/source pair is not closed"),
    };
    if source == StartSource::SameNodeCold {
        anyhow::ensure!(
            spec.volume_authorities.iter().all(|authority| matches!(
                authority.authority,
                RuntimeVolumeAuthorityInput::NormalUnowned { .. }
            )),
            "Cold Start tried to retain an Owned Volume"
        );
        return Ok(());
    }
    let Some((receipts, require_full)) = retained else {
        return Ok(());
    };
    anyhow::ensure!(
        !require_full || receipts.len() == spec.volume_authorities.len(),
        "same-Node retained Volume receipt set is incomplete"
    );
    for authority in &spec.volume_authorities {
        let retained = receipts
            .binary_search_by(|receipt| receipt.volume_id.cmp(&authority.volume_id))
            .ok()
            .map(|index| &receipts[index]);
        match (retained, &authority.authority, require_full) {
            (
                Some(receipt),
                RuntimeVolumeAuthorityInput::SameNodeOwned {
                    attachment_id,
                    attachment_epoch,
                },
                _,
            ) => anyhow::ensure!(
                receipt.disk_id == authority.disk_id
                    && &receipt.attachment_id == attachment_id
                    && receipt.attachment_epoch == *attachment_epoch,
                "same-Node Start changed retained Volume authority"
            ),
            (None, RuntimeVolumeAuthorityInput::NormalUnowned { .. }, false) => {}
            _ => anyhow::bail!("same-Node Start authority does not match retained evidence"),
        }
    }
    Ok(())
}

fn validate_start_retry_retained_manifest(
    ctx: &InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
    source: StartSource,
) -> Result<()> {
    if source != StartSource::SameNodeRetry {
        return Ok(());
    }
    let response = predecessor.context("same-Node retry lacks its terminal response")?;
    let NodeResult::StartFailed(failed) = &response.result else {
        // Other command handlers own their failed-operation retention codec.
        return Ok(());
    };
    let physical_manifests = enumerate_installed_start_physical_manifests(ctx.state_directory())?;
    let mut matches = physical_manifests
        .iter()
        .filter_map(|entry| match entry {
            InstalledStartPhysicalInventoryEntry::Executing(_) => None,
            InstalledStartPhysicalInventoryEntry::TerminalRetained(manifest)
                if manifest.cat_id == command.cat_id
                    && manifest.source_lifecycle_operation_id == response.operation_id =>
            {
                Some(manifest.clone())
            }
            InstalledStartPhysicalInventoryEntry::TerminalRetained(_) => None,
        })
        .collect::<Vec<_>>();
    if matches.is_empty() {
        let physical = super::scan_startup_inventory(ctx.config())
            .context("fresh scan all-Unowned Start retry physical absence")?;
        return validate_empty_start_retry_physical_absence(
            command,
            failed,
            &physical_manifests,
            &physical,
        );
    }
    anyhow::ensure!(
        matches.len() == 1,
        "same-Node Start retry lacks one exact current-predecessor retained manifest"
    );
    let manifest = matches
        .pop()
        .context("same-Node Start retry retained manifest disappeared")?;
    validate_terminal_retained_runtime_manifest(&manifest, None)?;
    anyhow::ensure!(
        manifest.manifest_digest == failed.retained_evidence.artifact_manifest_digest
            && manifest.node_id == response.node_id
            && manifest.placement_identity == response.placement_identity
            && manifest.runtime_config_id == command.runtime_config.config_id
            && manifest.runtime_config_digest == command.runtime_config.config_digest,
        "same-Node Start retry changed terminal retained evidence or runtime config"
    );
    let LifecycleCommand::Start(spec) = &command.command else {
        anyhow::bail!("same-Node retry validation received another command")
    };
    let retained = terminal_retained_physical_volumes(&manifest)?;
    for (authority, config) in spec
        .volume_authorities
        .iter()
        .zip(&command.runtime_config.volumes)
    {
        anyhow::ensure!(
            authority.volume_id == config.volume_id && authority.disk_id == config.disk_id,
            "same-Node Start retry reordered terminal retained Volumes"
        );
        let retained = retained
            .binary_search_by(|volume| volume.volume_id.cmp(&config.volume_id))
            .ok()
            .map(|index| &retained[index]);
        match (&authority.authority, retained) {
            (
                RuntimeVolumeAuthorityInput::SameNodeOwned {
                    attachment_id,
                    attachment_epoch,
                },
                Some(retained),
            ) => anyhow::ensure!(
                retained.disk_id == config.disk_id
                    && retained.disk_role == config.disk_role
                    && *attachment_id == retained.attachment_id
                    && *attachment_epoch == retained.attachment_epoch,
                "same-Node Start retry changed retained owner/epoch"
            ),
            (RuntimeVolumeAuthorityInput::NormalUnowned { .. }, None) => {}
            _ => anyhow::bail!(
                "same-Node Start retry changed retained authority or requested unavailable takeover"
            ),
        }
    }
    anyhow::ensure!(
        retained.iter().all(|volume| {
            spec.volume_authorities.iter().any(|authority| {
                authority.volume_id == volume.volume_id
                    && matches!(
                        &authority.authority,
                        RuntimeVolumeAuthorityInput::SameNodeOwned {
                            attachment_id,
                            attachment_epoch,
                        } if *attachment_id == volume.attachment_id
                            && *attachment_epoch == volume.attachment_epoch
                    )
            })
        }),
        "same-Node Start retry omitted a retained predecessor attachment"
    );
    Ok(())
}

fn validate_empty_start_retry_physical_absence(
    command: &LifecycleCommandEnvelope,
    failed: &CommandFailedResult,
    manifests: &[InstalledStartPhysicalInventoryEntry],
    physical: &StartupPhysicalInventory,
) -> Result<()> {
    let LifecycleCommand::Start(spec) = &command.command else {
        anyhow::bail!("empty Start retry validation received another command")
    };
    let StartupPhysicalInventory::Complete {
        cats,
        unattributed_artifacts,
        ..
    } = physical
    else {
        anyhow::bail!("empty Start retry physical inventory is incomplete")
    };
    anyhow::ensure!(
        failed.retained_volume_receipts.is_empty()
            && failed.retained_evidence.adoptable_count == 0
            && failed.retained_evidence.gc_candidate_count == 0
            && failed.retained_evidence.retained_authority_or_data_count == 0
            && failed.retained_evidence.quarantined_count == 0
            && !manifests.iter().any(|entry| {
                installed_start_physical_inventory_key(entry).0 == &command.cat_id
            })
            && !cats.iter().any(|cat| cat.cat_id == command.cat_id)
            && unattributed_artifacts.is_empty()
            && cats.windows(2).all(|pair| pair[0].cat_id < pair[1].cat_id)
            && spec.volume_authorities.iter().all(|authority| matches!(
                authority.authority,
                RuntimeVolumeAuthorityInput::NormalUnowned { .. }
            )),
        "Start retry without terminal retained evidence lacks exact all-Unowned physical absence"
    );
    Ok(())
}

/// Retire the exact non-executable failed-Start predecessor only after the
/// successor's complete RuntimeReady manifest is already durable. A crash
/// before removal leaves conservative duplicate retained attribution; a crash
/// after removal can recover solely from the new installed runtime manifest.
fn retire_consumed_start_retry_manifest(
    state_directory: &StateDirectory,
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
) -> Result<()> {
    let (source, _) = start_spec(command)?;
    if source != StartSource::SameNodeRetry {
        return Ok(());
    }
    let predecessor = predecessor.context("same-Node retry lost its predecessor response")?;
    let NodeResult::StartFailed(failed) = &predecessor.result else {
        return Ok(());
    };
    let mut retained = enumerate_installed_start_physical_manifests(state_directory)?
        .into_iter()
        .filter_map(|entry| match entry {
            InstalledStartPhysicalInventoryEntry::TerminalRetained(manifest)
                if manifest.cat_id == command.cat_id
                    && manifest.source_lifecycle_operation_id == predecessor.operation_id =>
            {
                Some(manifest)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if retained.is_empty() {
        let predecessor_was_empty = failed.retained_evidence.adoptable_count == 0
            && failed.retained_evidence.gc_candidate_count == 0
            && failed.retained_evidence.retained_authority_or_data_count == 0
            && failed.retained_evidence.quarantined_count == 0;
        if !predecessor_was_empty {
            let installed = load_installed_runtime_manifest(state_directory, &command.cat_id)?
                .context(
                    "consumed failed-Start retention disappeared before successor became durable",
                )?;
            validate_installed_runtime_manifest(&installed, command).context(
                "consumed failed-Start retention lacks its exact durable RuntimeReady successor",
            )?;
        }
        return Ok(());
    }
    anyhow::ensure!(
        retained.len() == 1,
        "RuntimeReady successor found multiple failed-Start predecessor manifests"
    );
    let manifest = retained
        .pop()
        .context("failed-Start predecessor manifest disappeared")?;
    validate_terminal_retained_runtime_manifest(&manifest, None)?;
    anyhow::ensure!(
        manifest.manifest_digest == failed.retained_evidence.artifact_manifest_digest
            && manifest.node_id == command.node_id
            && manifest.placement_identity == command.placement_identity
            && manifest.runtime_config_id == command.runtime_config.config_id
            && manifest.runtime_config_digest == command.runtime_config.config_digest,
        "RuntimeReady successor changed failed-Start predecessor retention"
    );
    anyhow::ensure!(
        remove_terminal_retained_runtime_manifest_exact(state_directory, &manifest)?,
        "RuntimeReady successor failed to retire consumed failed-Start predecessor"
    );
    Ok(())
}

fn start_runtime_incarnation(
    source: StartSource,
    predecessor: Option<&LifecycleCommandResponse>,
) -> Result<RandomId128> {
    if source == StartSource::SameNodeSuspended {
        let response = predecessor.context("Suspended resume lacks its predecessor")?;
        let NodeResult::Suspended(suspended) = &response.result else {
            anyhow::bail!("Suspended resume predecessor is not Suspended")
        };
        return Ok(suspended.runtime_incarnation.clone());
    }
    RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
        .context("generate atomic Start runtime incarnation")
}

fn volume_batch_request(
    command: &LifecycleCommandEnvelope,
    lease_duration_ms: WireU64,
) -> Result<AtomicStartVolumeBatchRequest> {
    let LifecycleCommand::Start(spec) = &command.command else {
        anyhow::bail!("atomic Start volume planning received another command")
    };
    anyhow::ensure!(
        spec.volume_authorities.len() == command.runtime_config.volumes.len(),
        "atomic Start authority/config sets differ"
    );
    let actions = spec
        .volume_authorities
        .iter()
        .zip(&command.runtime_config.volumes)
        .map(|(authority, volume)| {
            anyhow::ensure!(
                authority.volume_id == volume.volume_id && authority.disk_id == volume.disk_id,
                "atomic Start authority order differs from runtime config"
            );
            Ok(match &authority.authority {
                RuntimeVolumeAuthorityInput::NormalUnowned {
                    expected_unowned_epoch,
                    transition_id,
                } => AtomicStartVolumeAction::NormalAcquire {
                    volume: volume.clone(),
                    expected_unowned_epoch: *expected_unowned_epoch,
                    transition_id: transition_id.clone(),
                    requested_attachment_id: deterministic_attachment_id(command, volume)?,
                    lease_duration_ms,
                },
                RuntimeVolumeAuthorityInput::SameNodeOwned {
                    attachment_id,
                    attachment_epoch,
                } => AtomicStartVolumeAction::RenewSameNode {
                    volume: volume.clone(),
                    attachment_id: attachment_id.clone(),
                    attachment_epoch: *attachment_epoch,
                    lease_duration_ms,
                },
                RuntimeVolumeAuthorityInput::Takeover { authorization_id } => {
                    AtomicStartVolumeAction::Takeover {
                        volume: volume.clone(),
                        authorization_id: authorization_id.clone(),
                    }
                }
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let request = AtomicStartVolumeBatchRequest {
        version: ContractVersion::V1,
        grant_sequence: WireU64::new(0)
            .context("zero atomic Start Volume grant sequence is not wire-safe")?,
        operation_id: command.operation_id.clone(),
        cat_id: command.cat_id.clone(),
        node_id: command.node_id.clone(),
        placement_identity: command.placement_identity.clone(),
        request_fingerprint: command.request_fingerprint.clone(),
        renewal_lease_duration_ms: lease_duration_ms,
        actions,
    };
    validate_volume_batch_request(command, &request)?;
    Ok(request)
}

fn refresh_volume_batch_request(
    command: &LifecycleCommandEnvelope,
    lease_duration_ms: WireU64,
    current_grant_sequence: WireU64,
    grants: &[AtomicStartVolumeGrant],
) -> Result<AtomicStartVolumeBatchRequest> {
    let grant_sequence = current_grant_sequence
        .get()
        .checked_add(1)
        .and_then(WireU64::new)
        .context("atomic Start Volume grant sequence exhausted")?;
    renew_volume_batch_request(command, lease_duration_ms, grant_sequence, grants)
}

fn renew_volume_batch_request(
    command: &LifecycleCommandEnvelope,
    lease_duration_ms: WireU64,
    grant_sequence: WireU64,
    grants: &[AtomicStartVolumeGrant],
) -> Result<AtomicStartVolumeBatchRequest> {
    anyhow::ensure!(
        grant_sequence.get() > 0,
        "atomic Start Volume renewal reused initial grant sequence"
    );
    anyhow::ensure!(
        grants.len() == command.runtime_config.volumes.len(),
        "atomic Start Volume refresh lacks a full grant set"
    );
    let actions = grants
        .iter()
        .zip(&command.runtime_config.volumes)
        .map(|(grant, volume)| {
            anyhow::ensure!(
                grant.volume.volume_id == volume.volume_id
                    && grant.volume.disk_id == volume.disk_id
                    && grant.volume.disk_role == volume.disk_role,
                "atomic Start Volume refresh changed immutable config"
            );
            Ok(AtomicStartVolumeAction::RenewSameNode {
                volume: volume.clone(),
                attachment_id: grant.volume.attachment_id.clone(),
                attachment_epoch: grant.volume.attachment_epoch,
                lease_duration_ms,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(AtomicStartVolumeBatchRequest {
        version: ContractVersion::V1,
        grant_sequence,
        operation_id: command.operation_id.clone(),
        cat_id: command.cat_id.clone(),
        node_id: command.node_id.clone(),
        placement_identity: command.placement_identity.clone(),
        request_fingerprint: command.request_fingerprint.clone(),
        renewal_lease_duration_ms: lease_duration_ms,
        actions,
    })
}

fn validate_volume_batch_request(
    command: &LifecycleCommandEnvelope,
    request: &AtomicStartVolumeBatchRequest,
) -> Result<()> {
    anyhow::ensure!(
        request.version == ContractVersion::V1
            && request.operation_id == command.operation_id
            && request.cat_id == command.cat_id
            && request.node_id == command.node_id
            && request.placement_identity == command.placement_identity
            && request.request_fingerprint == command.request_fingerprint
            && (1..=i64::MAX as u64).contains(&request.renewal_lease_duration_ms.get())
            && request.actions.len() == command.runtime_config.volumes.len()
            && !request.actions.is_empty(),
        "atomic Start Volume batch does not bind the command"
    );
    for (action, volume) in request.actions.iter().zip(&command.runtime_config.volumes) {
        anyhow::ensure!(
            action.volume() == volume,
            "atomic Start Volume action changed immutable config"
        );
        match action {
            AtomicStartVolumeAction::NormalAcquire {
                lease_duration_ms, ..
            }
            | AtomicStartVolumeAction::RenewSameNode {
                lease_duration_ms, ..
            } => anyhow::ensure!(
                *lease_duration_ms == request.renewal_lease_duration_ms,
                "atomic Start Volume action changed its durable lease policy"
            ),
            AtomicStartVolumeAction::Takeover { .. } => {}
        }
    }
    let LifecycleCommand::Start(spec) = &command.command else {
        anyhow::bail!("atomic Start Volume batch belongs to another command kind")
    };
    if request.grant_sequence.get() == 0 {
        anyhow::ensure!(
            spec.volume_authorities.len() == request.actions.len(),
            "initial atomic Start Volume authority set is incomplete"
        );
        for ((action, authority), volume) in request
            .actions
            .iter()
            .zip(&spec.volume_authorities)
            .zip(&command.runtime_config.volumes)
        {
            let exact = match (action, &authority.authority) {
                (
                    AtomicStartVolumeAction::NormalAcquire {
                        expected_unowned_epoch,
                        transition_id,
                        requested_attachment_id,
                        ..
                    },
                    RuntimeVolumeAuthorityInput::NormalUnowned {
                        expected_unowned_epoch: expected,
                        transition_id: expected_transition,
                    },
                ) => {
                    expected_unowned_epoch == expected
                        && transition_id == expected_transition
                        && requested_attachment_id == &deterministic_attachment_id(command, volume)?
                }
                (
                    AtomicStartVolumeAction::RenewSameNode {
                        attachment_id,
                        attachment_epoch,
                        ..
                    },
                    RuntimeVolumeAuthorityInput::SameNodeOwned {
                        attachment_id: expected_attachment,
                        attachment_epoch: expected_epoch,
                    },
                ) => attachment_id == expected_attachment && attachment_epoch == expected_epoch,
                (
                    AtomicStartVolumeAction::Takeover {
                        authorization_id, ..
                    },
                    RuntimeVolumeAuthorityInput::Takeover {
                        authorization_id: expected,
                    },
                ) => authorization_id == expected,
                _ => false,
            };
            anyhow::ensure!(
                authority.volume_id == volume.volume_id
                    && authority.disk_id == volume.disk_id
                    && exact,
                "initial atomic Start Volume action changed command authority"
            );
        }
    } else {
        anyhow::ensure!(
            request
                .actions
                .iter()
                .all(|action| matches!(action, AtomicStartVolumeAction::RenewSameNode { .. })),
            "later atomic Start Volume grant round is not a pure renewal"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtomicStartVolumeFailureDisposition {
    LocalDeadlineElapsed,
    AuthorityRejected,
    TakeoverUnavailable,
}

fn atomic_start_volume_batch_request_digest(
    request: &AtomicStartVolumeBatchRequest,
) -> Result<Sha256Digest> {
    let value = serde_json::to_value(request)
        .context("encode atomic Start Volume batch request for digest")?;
    let canonical = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    Ok(digest_parts(VOLUME_BATCH_REQUEST_DOMAIN, &[&canonical]))
}

fn atomic_start_volume_failure_evidence_digest(
    command: &LifecycleCommandEnvelope,
    request_digest: &Sha256Digest,
    outcome: &AtomicStartVolumeFailureOutcome,
) -> Result<Sha256Digest> {
    atomic_start_volume_failure_evidence_digest_parts(
        &command.operation_id,
        &command.request_fingerprint,
        request_digest,
        outcome,
    )
}

fn atomic_start_volume_failure_evidence_digest_parts(
    operation_id: &Id,
    request_fingerprint: &Sha256Digest,
    request_digest: &Sha256Digest,
    outcome: &AtomicStartVolumeFailureOutcome,
) -> Result<Sha256Digest> {
    let value = serde_json::to_value(outcome)
        .context("encode atomic Start Volume failure evidence for digest")?;
    let canonical = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    Ok(digest_parts(
        VOLUME_FAILURE_EVIDENCE_DOMAIN,
        &[
            operation_id.as_str().as_bytes(),
            request_fingerprint.as_bytes(),
            request_digest.as_bytes(),
            &canonical,
        ],
    ))
}

fn new_volume_failure_evidence(
    command: &LifecycleCommandEnvelope,
    request: &AtomicStartVolumeBatchRequest,
    outcome: AtomicStartVolumeFailureOutcome,
) -> Result<AtomicStartVolumeFailureEvidence> {
    validate_volume_batch_request(command, request)?;
    let request_digest = atomic_start_volume_batch_request_digest(request)?;
    let evidence_digest =
        atomic_start_volume_failure_evidence_digest(command, &request_digest, &outcome)?;
    let evidence = AtomicStartVolumeFailureEvidence {
        request_digest,
        outcome,
        evidence_digest,
    };
    validate_atomic_start_volume_failure_evidence(command, request, &evidence)?;
    Ok(evidence)
}

pub(crate) fn validate_atomic_start_volume_failure_evidence(
    command: &LifecycleCommandEnvelope,
    request: &AtomicStartVolumeBatchRequest,
    evidence: &AtomicStartVolumeFailureEvidence,
) -> Result<AtomicStartVolumeFailureDisposition> {
    validate_volume_batch_request(command, request)?;
    anyhow::ensure!(
        evidence.request_digest == atomic_start_volume_batch_request_digest(request)?
            && evidence.evidence_digest
                == atomic_start_volume_failure_evidence_digest(
                    command,
                    &evidence.request_digest,
                    &evidence.outcome,
                )?,
        "atomic Start Volume failure evidence changed its exact request or outcome"
    );
    match &evidence.outcome {
        AtomicStartVolumeFailureOutcome::LocalDeadlineElapsed {
            observed_at_unix_ms,
        } => {
            let (_, deadline) = start_spec(command)?;
            anyhow::ensure!(
                *observed_at_unix_ms >= deadline,
                "atomic Start Volume local deadline evidence predates its deadline"
            );
            Ok(AtomicStartVolumeFailureDisposition::LocalDeadlineElapsed)
        }
        AtomicStartVolumeFailureOutcome::ControlRejected { canonical_response } => {
            let response =
                decode_lifecycle_volume_transition_response(canonical_response.as_slice())
                    .context("decode rejected atomic Start Volume response")?;
            anyhow::ensure!(
                encode_lifecycle_volume_transition_response(&response)
                    .context("re-encode rejected atomic Start Volume response")?
                    == canonical_response.as_slice()
                    && response.operation_id == command.operation_id
                    && response.request_fingerprint == command.request_fingerprint
                    && response.session.node_id == command.node_id,
                "rejected atomic Start Volume response changed command or session"
            );
            match response.result {
                LifecycleVolumeTransitionResult::Rejected {
                    reason: LifecycleVolumeTransitionRejection::AuthorityRejected,
                } => Ok(AtomicStartVolumeFailureDisposition::AuthorityRejected),
                LifecycleVolumeTransitionResult::Rejected {
                    reason: LifecycleVolumeTransitionRejection::TakeoverUnavailable,
                } => {
                    anyhow::ensure!(
                        request.actions.iter().any(|action| {
                            matches!(action, AtomicStartVolumeAction::Takeover { .. })
                        }),
                        "Takeover-unavailable rejection contains no Takeover action"
                    );
                    Ok(AtomicStartVolumeFailureDisposition::TakeoverUnavailable)
                }
                _ => anyhow::bail!(
                    "atomic Start Volume failure evidence is not a definite no-mutation rejection"
                ),
            }
        }
    }
}

fn validate_volume_batch_receipt(
    command: &LifecycleCommandEnvelope,
    request: &AtomicStartVolumeBatchRequest,
    receipt: &AtomicStartVolumeBatchReceipt,
) -> Result<()> {
    anyhow::ensure!(
        receipt.grant_sequence == request.grant_sequence
            && receipt.grants.len() == request.actions.len(),
        "atomic Start Volume receipt is incomplete"
    );
    for ((grant, action), config) in receipt
        .grants
        .iter()
        .zip(&request.actions)
        .zip(&command.runtime_config.volumes)
    {
        let (
            authority_attachment_id,
            authority_attachment_epoch,
            authority_origin,
            authority_head,
            authority_expiry,
        ) = start_grant_authority_projection(&grant.authority_receipt)?;
        anyhow::ensure!(
            grant.volume.volume_id == config.volume_id
                && grant.volume.disk_id == config.disk_id
                && grant.volume.disk_role == config.disk_role
                && grant.volume.remote_durable_generation <= grant.volume.local_durable_generation
                && grant.authoritative_head.generation == grant.volume.remote_durable_generation
                && grant.volume.attachment_epoch.get() > 0
                && grant.volume.authority_receipt_digest.as_ref()
                    == Some(&grant.grant_receipt_digest)
                && grant.lease_expires_at_unix_ms.get() > 0
                && grant.authority_receipt.scope.operation_id == command.operation_id
                && grant.authority_receipt.scope.request_fingerprint == command.request_fingerprint
                && grant.authority_receipt.scope.cat_id == command.cat_id
                && grant.authority_receipt.scope.node_id == command.node_id
                && grant.authority_receipt.scope.placement_identity == command.placement_identity
                && grant.authority_receipt.grant_sequence == request.grant_sequence
                && grant.authority_receipt.volume == *config
                && authority_attachment_id == grant.volume.attachment_id
                && authority_attachment_epoch == grant.volume.attachment_epoch
                && authority_origin == grant.acquire_origin
                && remote_head_is_unchanged_or_advanced(&authority_head, &grant.authoritative_head,)
                && grant.lease_expires_at_unix_ms.get() >= authority_expiry.get(),
            "atomic Start Volume grant is not a live exact config projection"
        );
        match action {
            AtomicStartVolumeAction::NormalAcquire {
                requested_attachment_id,
                transition_id,
                ..
            } => anyhow::ensure!(
                grant.volume.attachment_id == *requested_attachment_id
                    && grant.acquire_origin
                        == (AcquireOrigin::Normal {
                            transition_id: transition_id.clone(),
                        })
                    && matches!(
                        &grant.authority_receipt.authority,
                        LifecycleStartVolumeGrantAuthority::NormalAcquire { request, result }
                            if request.transition_id == *transition_id
                                && request.attachment_id == *requested_attachment_id
                                && result.transition_id == *transition_id
                                && result.attachment_id == *requested_attachment_id
                    ),
                "normal atomic Start grant changed attachment/acquire origin"
            ),
            AtomicStartVolumeAction::RenewSameNode {
                attachment_id: requested_attachment_id,
                ..
            } => anyhow::ensure!(
                grant.volume.attachment_id == *requested_attachment_id
                    && matches!(
                        &grant.authority_receipt.authority,
                        LifecycleStartVolumeGrantAuthority::RenewSameNode { request, result, .. }
                            if request.attachment_id == *requested_attachment_id
                                && result.attachment_id == *requested_attachment_id
                    ),
                "same-Node atomic Start grant changed its attachment"
            ),
            AtomicStartVolumeAction::Takeover {
                authorization_id, ..
            } => anyhow::ensure!(
                grant.acquire_origin
                    == (AcquireOrigin::Takeover {
                        authorization_id: authorization_id.clone(),
                    }),
                "takeover atomic Start grant changed its authorization origin"
            ),
        }
    }
    validate_artifacts(&volume_grant_artifacts(&receipt.grants)?)
}

fn validate_start_volume_grant_set(
    command: &LifecycleCommandEnvelope,
    grants: &[AtomicStartVolumeGrant],
) -> Result<()> {
    let first = grants
        .first()
        .context("atomic Start retained Volume grant set is empty")?;
    let grant_sequence = first.authority_receipt.grant_sequence;
    anyhow::ensure!(
        grants
            .iter()
            .all(|grant| grant.authority_receipt.grant_sequence == grant_sequence),
        "atomic Start retained Volume grants mix authority rounds"
    );
    let request = if grant_sequence.get() == 0 {
        let lease_duration_ms = grants
            .iter()
            .find_map(|grant| match &grant.authority_receipt.authority {
                LifecycleStartVolumeGrantAuthority::NormalAcquire { request, .. } => {
                    WireU64::new(request.lease_duration_ms)
                }
                LifecycleStartVolumeGrantAuthority::RenewSameNode { request, .. } => {
                    Some(request.lease_duration_ms)
                }
            })
            .context("initial atomic Start grant set has no lease policy")?;
        volume_batch_request(command, lease_duration_ms)?
    } else {
        let lease_duration_ms = match &first.authority_receipt.authority {
            LifecycleStartVolumeGrantAuthority::RenewSameNode { request, .. } => {
                request.lease_duration_ms
            }
            _ => anyhow::bail!("later atomic Start grant round is not a renewal"),
        };
        renew_volume_batch_request(command, lease_duration_ms, grant_sequence, grants)?
    };
    validate_volume_batch_receipt(
        command,
        &request,
        &AtomicStartVolumeBatchReceipt {
            grant_sequence,
            grants: grants.to_vec(),
        },
    )
}

fn validate_refresh_request(
    command: &LifecycleCommandEnvelope,
    context: &AtomicStartRuntimeContext,
    next_phase: AtomicStartRuntimeEffectPhase,
    resume_platform_plan: Option<&ExactBytes>,
    request: &AtomicStartVolumeBatchRequest,
) -> Result<()> {
    validate_runtime_context(command, context, next_phase)?;
    if let Some(platform_plan) = resume_platform_plan {
        validate_platform_plan(platform_plan)?;
    }
    validate_volume_batch_request(command, request)?;
    anyhow::ensure!(
        request.actions.len() == context.volume_grants.len(),
        "atomic Start Volume refresh action/grant sets differ"
    );
    for (action, grant) in request.actions.iter().zip(&context.volume_grants) {
        let AtomicStartVolumeAction::RenewSameNode {
            attachment_id,
            attachment_epoch,
            lease_duration_ms,
            ..
        } = action
        else {
            anyhow::bail!("atomic Start Volume refresh contains a non-renew action")
        };
        anyhow::ensure!(
            attachment_id == &grant.volume.attachment_id
                && *attachment_epoch == grant.volume.attachment_epoch
                && *lease_duration_ms == context.volume_lease_duration_ms
                && request.renewal_lease_duration_ms == context.volume_lease_duration_ms,
            "atomic Start Volume refresh changed its attachment lineage"
        );
    }
    Ok(())
}

fn validate_planned_agent_session(
    command: &LifecycleCommandEnvelope,
    session: &SessionBinding,
) -> Result<()> {
    anyhow::ensure!(
        session.node_id == command.node_id && session.agent_session_epoch.get() > 0,
        "atomic Start lease AgentSession belongs to another Node or invalid epoch"
    );
    Ok(())
}

fn validate_start_lease_effect_policy(
    lease_duration_ms: WireU64,
    runtime_effect_timeout_ms: WireU64,
) -> Result<()> {
    let required = runtime_effect_timeout_ms
        .get()
        .checked_add(START_VOLUME_LEASE_SAFETY_MARGIN_MS)
        .context("atomic Start effect timeout plus lease margin overflows")?;
    anyhow::ensure!(
        runtime_effect_timeout_ms.get() > 0 && lease_duration_ms.get() > required,
        "atomic Start Volume lease cannot cover one bounded runtime effect plus safety margin"
    );
    Ok(())
}

fn runtime_phase_required_lease_budget(context: &AtomicStartRuntimeContext) -> Result<Duration> {
    let now = current_unix_ms()?;
    let command_remaining = context.effect_deadline_unix_ms.get().saturating_sub(now);
    let phase_budget = command_remaining.min(context.runtime_effect_timeout_ms.get());
    anyhow::ensure!(phase_budget > 0, "atomic Start effect deadline elapsed");
    let required = phase_budget
        .checked_add(START_VOLUME_LEASE_SAFETY_MARGIN_MS)
        .context("atomic Start phase lease budget overflows")?;
    Ok(Duration::from_millis(required))
}

fn volume_grants_are_live(grants: &[AtomicStartVolumeGrant]) -> Result<bool> {
    let now = current_unix_ms()?;
    Ok(!grants.is_empty()
        && grants
            .iter()
            .all(|grant| grant.lease_expires_at_unix_ms.get() > now))
}

fn start_grant_authority_projection(
    receipt: &LifecycleCommandStartVolumeGrantReceipt,
) -> Result<(
    Id,
    cats_api::runtime_reconciliation::FenceEpoch,
    AcquireOrigin,
    RemoteHead,
    UnixMillis,
)> {
    Ok(match &receipt.authority {
        LifecycleStartVolumeGrantAuthority::NormalAcquire { request, result } => {
            anyhow::ensure!(
                request.volume_id == receipt.volume.volume_id
                    && result.volume_id == receipt.volume.volume_id
                    && request.transition_id == result.transition_id
                    && request.attachment_id == result.attachment_id
                    && request.lease_duration_ms > 0,
                "normal atomic Start authority receipt is internally inconsistent"
            );
            (
                result.attachment_id.clone(),
                result.resulting_epoch,
                AcquireOrigin::Normal {
                    transition_id: result.transition_id.clone(),
                },
                result.resulting_head.clone(),
                result.lease_expires_at,
            )
        }
        LifecycleStartVolumeGrantAuthority::RenewSameNode {
            expected_source,
            serving_acquire,
            request,
            result,
        } => {
            let cats_api::runtime_reconciliation::VolumeTransitionSource::Lifecycle { .. } =
                expected_source
            else {
                anyhow::bail!("same-Node renewal references independent authority")
            };
            let LifecycleServingAcquire::Normal {
                request: acquire_request,
                result: acquire_result,
            } = &**serving_acquire;
            anyhow::ensure!(
                request.volume_id == receipt.volume.volume_id
                    && result.volume_id == receipt.volume.volume_id
                    && request.attachment_id == result.attachment_id
                    && request.expected_epoch == result.epoch
                    && request.lease_duration_ms.get() > 0
                    && acquire_request.volume_id == receipt.volume.volume_id
                    && acquire_result.volume_id == receipt.volume.volume_id
                    && acquire_request.transition_id == acquire_result.transition_id
                    && acquire_request.attachment_id == acquire_result.attachment_id
                    && acquire_result.attachment_id == result.attachment_id
                    && acquire_result.resulting_epoch == result.epoch,
                "renewed atomic Start authority receipt lost its serving acquire lineage"
            );
            (
                result.attachment_id.clone(),
                result.epoch,
                AcquireOrigin::Normal {
                    transition_id: acquire_result.transition_id.clone(),
                },
                result.resulting_head.clone(),
                result.lease_expires_at,
            )
        }
    })
}

fn validate_runtime_effect_request(
    command: &LifecycleCommandEnvelope,
    request: &AtomicStartRuntimeEffectRequest,
) -> Result<()> {
    validate_runtime_context(command, &request.context, request.phase)?;
    validate_platform_plan(&request.platform_plan)?;
    let aggregate = completed_platform_bytes(&request.context)?
        .checked_add(request.platform_plan.as_slice().len())
        .context("atomic Start platform evidence size overflowed")?;
    anyhow::ensure!(
        aggregate <= START_PLATFORM_AGGREGATE_MAX_BYTES,
        "atomic Start platform plan/receipt aggregate exceeds its journal budget"
    );
    Ok(())
}

fn validate_platform_plan(plan: &ExactBytes) -> Result<()> {
    anyhow::ensure!(
        !plan.as_slice().is_empty() && plan.as_slice().len() <= START_PLATFORM_PLAN_MAX_BYTES,
        "atomic Start platform plan has an invalid size"
    );
    Ok(())
}

fn validate_platform_receipt(receipt: &ExactBytes) -> Result<()> {
    anyhow::ensure!(
        !receipt.as_slice().is_empty()
            && receipt.as_slice().len() <= START_PLATFORM_RECEIPT_MAX_BYTES,
        "atomic Start platform receipt has an invalid size"
    );
    Ok(())
}

fn platform_phase_label(phase: AtomicStartRuntimeEffectPhase) -> &'static [u8] {
    match phase {
        AtomicStartRuntimeEffectPhase::PrepareRoot => b"prepare_root",
        AtomicStartRuntimeEffectPhase::PrepareDevices => b"prepare_devices",
        AtomicStartRuntimeEffectPhase::PrepareNetwork => b"prepare_network",
        AtomicStartRuntimeEffectPhase::ActivateRuntime => b"activate_runtime",
        AtomicStartRuntimeEffectPhase::FormatPersistentVolumes => b"format_persistent_volumes",
        AtomicStartRuntimeEffectPhase::CommitPersistentInitialized => {
            b"commit_persistent_initialized"
        }
        AtomicStartRuntimeEffectPhase::GuestReadyAndAdmission => b"guest_ready_and_admission",
    }
}

fn platform_plan_digest(
    command: &LifecycleCommandEnvelope,
    phase: AtomicStartRuntimeEffectPhase,
    plan: &ExactBytes,
) -> Sha256Digest {
    digest_parts(
        PLATFORM_PLAN_DOMAIN,
        &[
            command.operation_id.as_str().as_bytes(),
            command.request_fingerprint.as_bytes(),
            platform_phase_label(phase),
            plan.as_slice(),
        ],
    )
}

/// Domain-separated digest used by production runtime adapters for the exact
/// closed provider receipt retained across Start phases.
pub fn atomic_start_platform_receipt_digest(
    command: &LifecycleCommandEnvelope,
    phase: AtomicStartRuntimeEffectPhase,
    platform_plan_digest: &Sha256Digest,
    platform_receipt: &ExactBytes,
) -> Result<Sha256Digest> {
    validate_platform_receipt(platform_receipt)?;
    Ok(digest_parts(
        PLATFORM_RECEIPT_DOMAIN,
        &[
            command.operation_id.as_str().as_bytes(),
            command.request_fingerprint.as_bytes(),
            platform_phase_label(phase),
            platform_plan_digest.as_bytes(),
            platform_receipt.as_slice(),
        ],
    ))
}

pub(crate) fn atomic_start_session_rebind_receipt_digest(
    command: &LifecycleCommandEnvelope,
    phase: AtomicStartRuntimeEffectPhase,
    volume_grant_sequence: WireU64,
    old_platform_plan_digest: &Sha256Digest,
    cleanup_receipt: &ExactBytes,
) -> Result<Sha256Digest> {
    validate_platform_receipt(cleanup_receipt)?;
    Ok(digest_parts(
        SESSION_REBIND_RECEIPT_DOMAIN,
        &[
            command.operation_id.as_str().as_bytes(),
            command.request_fingerprint.as_bytes(),
            platform_phase_label(phase),
            &volume_grant_sequence.get().to_be_bytes(),
            old_platform_plan_digest.as_bytes(),
            cleanup_receipt.as_slice(),
        ],
    ))
}

fn completed_platform_bytes(context: &AtomicStartRuntimeContext) -> Result<usize> {
    let completed = context
        .completed_effects
        .iter()
        .try_fold(0usize, |sum, effect| {
            sum.checked_add(effect.platform_plan.as_slice().len())
                .and_then(|sum| sum.checked_add(effect.platform_receipt.as_slice().len()))
                .context("atomic Start completed platform evidence size overflowed")
        })?;
    context
        .session_rebind_receipts
        .iter()
        .try_fold(completed, |sum, receipt| {
            sum.checked_add(receipt.old_platform_plan.as_slice().len())
                .and_then(|sum| sum.checked_add(receipt.cleanup_receipt.as_slice().len()))
                .context("atomic Start session-rebind evidence size overflowed")
        })
}

fn validate_runtime_context(
    command: &LifecycleCommandEnvelope,
    context: &AtomicStartRuntimeContext,
    next_phase: AtomicStartRuntimeEffectPhase,
) -> Result<()> {
    let (source, deadline) = start_spec(command)?;
    validate_start_predecessor(command, context.local_predecessor.as_ref(), source)?;
    validate_warm_restart_source_shape(command, source, context.warm_restart_source.as_ref())?;
    anyhow::ensure!(
        context.source == source
            && context.effect_deadline_unix_ms == deadline
            && (1..=i64::MAX as u64).contains(&context.volume_lease_duration_ms.get())
            && context.volume_grants.len() == command.runtime_config.volumes.len()
            && context.completed_effects.len() < START_RUNTIME_EFFECT_COUNT
            && context.session_rebind_receipts.len() <= START_SESSION_REBIND_MAX_COUNT
            && context
                .session_rebind_receipts
                .windows(2)
                .all(|pair| pair[0].phase <= pair[1].phase),
        "atomic Start runtime context changed its command input"
    );
    validate_planned_agent_session(command, &context.volume_lease_session)?;
    validate_start_lease_effect_policy(
        context.volume_lease_duration_ms,
        context.runtime_effect_timeout_ms,
    )?;
    let mut expected_artifacts = volume_grant_artifacts(&context.volume_grants)?;
    validate_installed_runtime_progress_manifest(&context.runtime_progress, command)?;
    validate_runtime_progress_against_volume_grants(
        &context.runtime_progress,
        &context.volume_grants,
    )?;
    anyhow::ensure!(
        context.runtime_progress.runtime_incarnation == context.runtime_incarnation,
        "atomic Start current progress changed runtime incarnation attribution"
    );
    for receipt in &context.session_rebind_receipts {
        anyhow::ensure!(
            receipt.phase <= next_phase
                && receipt.volume_grant_sequence.get() <= context.volume_grant_sequence.get()
                && receipt.old_platform_plan_digest
                    == platform_plan_digest(command, receipt.phase, &receipt.old_platform_plan)
                && receipt.cleanup_receipt_digest
                    == atomic_start_session_rebind_receipt_digest(
                        command,
                        receipt.phase,
                        receipt.volume_grant_sequence,
                        &receipt.old_platform_plan_digest,
                        &receipt.cleanup_receipt,
                    )?
                && receipt.runtime_progress.runtime_incarnation == context.runtime_incarnation
                && artifacts_are_exact_subset(
                    &receipt.runtime_progress.artifact_classifications,
                    &context.artifact_classifications,
                ),
            "atomic Start session-rebind receipt changed plan, cleanup, or context"
        );
        validate_platform_plan(&receipt.old_platform_plan)?;
        validate_platform_receipt(&receipt.cleanup_receipt)?;
        validate_installed_runtime_progress_manifest(&receipt.runtime_progress, command)?;
        validate_runtime_progress_advances(&receipt.runtime_progress, &context.runtime_progress)?;
    }
    for (index, receipt) in context.completed_effects.iter().enumerate() {
        let expected = match index {
            0 => AtomicStartRuntimeEffectPhase::PrepareRoot,
            1 => AtomicStartRuntimeEffectPhase::PrepareDevices,
            2 => AtomicStartRuntimeEffectPhase::PrepareNetwork,
            3 => AtomicStartRuntimeEffectPhase::ActivateRuntime,
            4 => AtomicStartRuntimeEffectPhase::FormatPersistentVolumes,
            5 => AtomicStartRuntimeEffectPhase::CommitPersistentInitialized,
            _ => anyhow::bail!("atomic Start retained too many intermediate receipts"),
        };
        anyhow::ensure!(
            receipt.phase == expected
                && receipt.phase < next_phase
                && receipt.platform_plan_digest
                    == platform_plan_digest(command, receipt.phase, &receipt.platform_plan)
                && receipt.receipt_digest
                    == atomic_start_platform_receipt_digest(
                        command,
                        receipt.phase,
                        &receipt.platform_plan_digest,
                        &receipt.platform_receipt,
                    )?,
            "atomic Start intermediate receipt order is invalid"
        );
        validate_platform_plan(&receipt.platform_plan)?;
        validate_platform_receipt(&receipt.platform_receipt)?;
        validate_artifacts(&receipt.artifact_classifications)?;
        expected_artifacts =
            merge_artifacts(expected_artifacts, receipt.artifact_classifications.clone())?;
        validate_completed_runtime_progress_manifest(
            &receipt.runtime_progress,
            command,
            receipt.phase,
        )?;
        anyhow::ensure!(
            receipt.runtime_progress.runtime_incarnation == context.runtime_incarnation
                && receipt.runtime_progress.artifact_classifications == expected_artifacts,
            "atomic Start intermediate progress is not a completed exact incarnation"
        );
        if index > 0 {
            validate_runtime_progress_advances(
                &context.completed_effects[index - 1].runtime_progress,
                &receipt.runtime_progress,
            )?;
        }
    }
    anyhow::ensure!(
        completed_platform_bytes(context)? <= START_PLATFORM_AGGREGATE_MAX_BYTES,
        "atomic Start completed platform plan/receipt aggregate exceeds its journal budget"
    );
    anyhow::ensure!(
        context.artifact_classifications == expected_artifacts
            && context.runtime_progress.artifact_classifications == expected_artifacts,
        "atomic Start context changed completed physical artifact evidence"
    );
    if let Some(completed) = context.completed_effects.last() {
        validate_runtime_progress_advances(&completed.runtime_progress, &context.runtime_progress)?;
    }
    let synthetic = AtomicStartVolumeBatchReceipt {
        grant_sequence: context.volume_grant_sequence,
        grants: context.volume_grants.clone(),
    };
    let request = if context.volume_grant_sequence.get() == 0 {
        volume_batch_request(command, context.volume_lease_duration_ms)?
    } else {
        renew_volume_batch_request(
            command,
            context.volume_lease_duration_ms,
            context.volume_grant_sequence,
            &context.volume_grants,
        )?
    };
    validate_volume_batch_receipt(command, &request, &synthetic)?;
    validate_artifacts(&context.artifact_classifications)?;
    if let Some(latest) = context.completed_effects.last() {
        anyhow::ensure!(
            artifacts_are_exact_subset(
                &latest.runtime_progress.artifact_classifications,
                &context.artifact_classifications,
            ),
            "atomic Start durable context lost or changed physical progress evidence"
        );
    }
    Ok(())
}

fn validate_runtime_ready_volume_receipts(
    command: &LifecycleCommandEnvelope,
    grants: &[AtomicStartVolumeGrant],
    receipts: &[VolumeTerminalReceipt],
) -> Result<()> {
    anyhow::ensure!(
        receipts.len() == command.runtime_config.volumes.len() && receipts.len() == grants.len(),
        "RuntimeReady Volume proof is incomplete"
    );
    for ((receipt, grant), config) in receipts
        .iter()
        .zip(grants)
        .zip(&command.runtime_config.volumes)
    {
        anyhow::ensure!(
            receipt.volume_id == config.volume_id
                && receipt.disk_id == config.disk_id
                && receipt.disk_role == config.disk_role
                && receipt.attachment_id == grant.volume.attachment_id
                && receipt.attachment_epoch == grant.volume.attachment_epoch
                && receipt.authority_receipt_digest == grant.volume.authority_receipt_digest
                && grant.authoritative_head.generation <= receipt.remote_durable_generation
                && receipt.remote_durable_generation <= receipt.local_durable_generation,
            "RuntimeReady Volume proof changed its authority lineage"
        );
    }
    Ok(())
}

fn validate_manifest_volume_receipts(
    manifest: &InstalledRuntimeManifest,
    receipts: &[VolumeTerminalReceipt],
) -> Result<()> {
    anyhow::ensure!(
        manifest.volumes.len() == receipts.len()
            && manifest
                .volumes
                .iter()
                .zip(receipts)
                .all(|(installed, receipt)| {
                    installed.volume_id == receipt.volume_id
                        && installed.disk_id == receipt.disk_id
                        && installed.disk_role == receipt.disk_role
                        && installed.attachment_id == receipt.attachment_id
                        && installed.attachment_epoch == receipt.attachment_epoch
                        && installed.authority_receipt_digest == receipt.authority_receipt_digest
                        && remote_head_is_unchanged_or_advanced(
                            &installed.launch_head,
                            &installed.current_authority_head,
                        )
                        && installed.current_authority_head.generation
                            <= receipt.remote_durable_generation
                }),
        "installed RuntimeReady manifest and Volume proof differ"
    );
    Ok(())
}

fn validate_final_manifest_extends_progress(
    progress: &InstalledRuntimeProgressManifest,
    manifest: &InstalledRuntimeManifest,
) -> Result<()> {
    anyhow::ensure!(
        progress.node_id == manifest.node_id
            && progress.cat_id == manifest.cat_id
            && progress.placement_identity == manifest.placement_identity
            && progress.source_lifecycle_operation_id == manifest.source_lifecycle_operation_id
            && progress.request_fingerprint == manifest.request_fingerprint
            && progress.runtime_config_id == manifest.runtime_config_id
            && progress.runtime_config_digest == manifest.runtime_config_digest
            && progress.runtime_incarnation == manifest.runtime_incarnation
            && progress.vmm.as_ref() == Some(&manifest.vmm)
            && progress.network.as_ref() == Some(&manifest.network)
            && progress.volumes.len() == manifest.volumes.len(),
        "RuntimeReady manifest does not extend the exact activated runtime"
    );
    for (partial, installed) in progress.volumes.iter().zip(&manifest.volumes) {
        anyhow::ensure!(
            partial.volume_id == installed.volume_id
                && partial.disk_id == installed.disk_id
                && partial.disk_role == installed.disk_role
                && partial.attachment_id == installed.attachment_id
                && partial.attachment_epoch == installed.attachment_epoch
                && partial.acquire_origin == installed.acquire_origin
                && remote_head_is_unchanged_or_advanced(
                    &installed.launch_head,
                    &partial.authority_head,
                )
                && remote_head_is_unchanged_or_advanced(
                    &partial.authority_head,
                    &installed.current_authority_head,
                )
                && partial.authority_receipt_digest.is_some()
                && installed.authority_receipt_digest.is_some()
                && partial.local_lineage_data_directory.as_ref()
                    == Some(&installed.local_lineage_data_directory)
                && partial.blockd.as_ref() == Some(&installed.blockd)
                && partial.blockd_control_socket_path.as_ref()
                    == Some(&installed.blockd_control_socket_path)
                && partial.frontend.as_ref() == Some(&installed.frontend),
            "RuntimeReady manifest changed activated Volume attribution"
        );
    }
    Ok(())
}

fn volume_grant_artifacts(
    grants: &[AtomicStartVolumeGrant],
) -> Result<Vec<ObservedArtifactClassification>> {
    let mut artifacts = grants
        .iter()
        .map(|grant| {
            let evidence_digest = volume_authority_lineage_digest(grant);
            Ok(ObservedArtifactClassification::RetainedAuthorityOrData {
                artifact_id: super::artifact_id(
                    "atomic-start-volume-authority",
                    evidence_digest.as_bytes(),
                )?,
                evidence_digest,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    artifacts.sort_by(|left, right| left.artifact_id().cmp(right.artifact_id()));
    Ok(artifacts)
}

fn volume_authority_lineage_digest(grant: &AtomicStartVolumeGrant) -> Sha256Digest {
    let (origin_kind, origin_id): (&[u8], &[u8]) = match &grant.acquire_origin {
        AcquireOrigin::Normal { transition_id } => (b"normal", transition_id.as_str().as_bytes()),
        AcquireOrigin::Takeover { authorization_id } => {
            (b"takeover", authorization_id.as_str().as_bytes())
        }
    };
    digest_parts(
        VOLUME_AUTHORITY_LINEAGE_DOMAIN,
        &[
            grant.volume.volume_id.as_str().as_bytes(),
            grant.volume.disk_id.as_str().as_bytes(),
            grant.volume.attachment_id.as_str().as_bytes(),
            &grant.volume.attachment_epoch.get().to_be_bytes(),
            origin_kind,
            origin_id,
        ],
    )
}

fn merge_artifacts(
    current: Vec<ObservedArtifactClassification>,
    updates: Vec<ObservedArtifactClassification>,
) -> Result<Vec<ObservedArtifactClassification>> {
    validate_artifacts(&current)?;
    validate_artifacts(&updates)?;
    let mut merged = BTreeMap::new();
    for artifact in current.into_iter().chain(updates) {
        merged.insert(artifact.artifact_id().clone(), artifact);
    }
    let merged = merged.into_values().collect::<Vec<_>>();
    validate_artifacts(&merged)?;
    Ok(merged)
}

fn validate_artifacts(artifacts: &[ObservedArtifactClassification]) -> Result<()> {
    anyhow::ensure!(
        artifacts.len() <= 1_024
            && artifacts
                .windows(2)
                .all(|pair| pair[0].artifact_id() < pair[1].artifact_id()),
        "atomic Start artifacts are not a bounded sorted unique set"
    );
    Ok(())
}

fn artifacts_are_exact_subset(
    subset: &[ObservedArtifactClassification],
    superset: &[ObservedArtifactClassification],
) -> bool {
    subset.iter().all(|artifact| {
        superset
            .binary_search_by(|candidate| candidate.artifact_id().cmp(artifact.artifact_id()))
            .ok()
            .is_some_and(|index| superset[index] == *artifact)
    })
}

fn command_guest_ipv4(
    command: &LifecycleCommandEnvelope,
) -> cats_api::runtime_reconciliation::Ipv4Address {
    match &command.runtime_config.network_config {
        RuntimeNetworkConfig::IsolatedIpv4 { guest_ipv4, .. } => guest_ipv4.clone(),
    }
}

fn start_closed_anchor(command: &LifecycleCommandEnvelope) -> &Id {
    match &command.predecessor {
        LifecyclePredecessor::Genesis {
            cat_creation_id, ..
        } => cat_creation_id,
        LifecyclePredecessor::SameNode { operation_id, .. } => operation_id,
        LifecyclePredecessor::CrossNodeColdHandoff {
            cold_operation_id, ..
        } => cold_operation_id,
        LifecyclePredecessor::HostFenceRecovery {
            interrupted_operation_id,
            ..
        } => interrupted_operation_id,
    }
}

pub(crate) fn validate_installed_runtime_progress_manifest(
    manifest: &InstalledRuntimeProgressManifest,
    command: &LifecycleCommandEnvelope,
) -> Result<()> {
    anyhow::ensure!(
        manifest.version == ContractVersion::V1
            && manifest.node_id == command.node_id
            && manifest.cat_id == command.cat_id
            && manifest.placement_identity == command.placement_identity
            && manifest.source_lifecycle_operation_id == command.operation_id
            && manifest.request_fingerprint == command.request_fingerprint
            && manifest.runtime_config_id == command.runtime_config.config_id
            && manifest.runtime_config_digest == command.runtime_config.config_digest
            && manifest.volumes.len() == command.runtime_config.volumes.len(),
        "installed atomic Start progress does not bind the exact command"
    );
    validate_artifacts(&manifest.artifact_classifications)?;
    for (installed, config) in manifest.volumes.iter().zip(&command.runtime_config.volumes) {
        anyhow::ensure!(
            installed.volume_id == config.volume_id
                && installed.disk_id == config.disk_id
                && installed.disk_role == config.disk_role
                && installed.attachment_epoch.get() > 0
                && installed.authority_receipt_digest.is_some()
                && installed.blockd.is_some() == installed.blockd_control_socket_path.is_some()
                && (installed.frontend.is_none() || installed.blockd.is_some()),
            "installed atomic Start progress changed its Volume identity or partial edge"
        );
        if let Some(process) = &installed.blockd {
            anyhow::ensure!(
                process.pid > 0 && process.start_time_ticks.get() > 0,
                "installed atomic Start progress has an incomplete blockd identity"
            );
        }
        if let Some(InstalledRuntimeBlockFrontend::KernelNbd { client, .. }) = &installed.frontend {
            anyhow::ensure!(
                client.pid > 0 && client.start_time_ticks.get() > 0,
                "installed atomic Start progress has an incomplete kernel-NBD identity"
            );
        }
    }
    if let Some(network) = &manifest.network {
        match &command.runtime_config.network_config {
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id,
                guest_mac,
                guest_ipv4,
                prefix_length,
                gateway_ipv4,
            } => anyhow::ensure!(
                network.identity.network_config.kind
                    == cats_api::runtime_reconciliation::IsolatedIpv4Kind::IsolatedIpv4
                    && network.identity.network_config.network_id == *network_id
                    && network.identity.network_config.guest_mac == *guest_mac
                    && network.identity.network_config.guest_ipv4 == *guest_ipv4
                    && network.identity.network_config.prefix_length == *prefix_length
                    && network.identity.network_config.gateway_ipv4 == *gateway_ipv4,
                "installed atomic Start progress changed its complete network"
            ),
        }
    }
    if let Some(vmm) = &manifest.vmm {
        anyhow::ensure!(
            vmm.process.pid > 0
                && vmm.process.start_time_ticks.get() > 0
                && vmm.parent_slice_id.as_str()
                    == crate::cat_execution_scope::cat_execution_slice_id(&command.cat_id).as_str(),
            "installed atomic Start progress has an invalid VMM identity"
        );
        let network = manifest
            .network
            .as_ref()
            .context("installed atomic Start VMM progress lacks its network identity")?;
        validate_runtime_launch_identity(command, &manifest.runtime_incarnation, vmm, network)?;
        for ((device, installed), config) in vmm
            .launch_identity
            .devices
            .iter()
            .zip(&manifest.volumes)
            .zip(&command.runtime_config.volumes)
        {
            anyhow::ensure!(
                installed
                    .local_lineage_data_directory
                    .as_ref()
                    .is_some_and(|path| path == &device.serving_process.data_directory)
                    && installed
                        .blockd_control_socket_path
                        .as_ref()
                        .is_some_and(|path| path == &device.serving_process.control_socket_path)
                    && installed.frontend.as_ref().is_some_and(|frontend| {
                        launch_frontend_matches(frontend, &device.frontend)
                    })
                    && launch_device_matches_config(
                        command,
                        device,
                        &installed.attachment_id,
                        installed.attachment_epoch,
                        &installed.acquire_origin,
                        &installed.authority_head,
                        config,
                    )?,
                "installed atomic Start progress changed its VMM device launch identity"
            );
        }
    }
    anyhow::ensure!(
        manifest.manifest_digest == installed_runtime_progress_manifest_digest(manifest)?,
        "installed atomic Start progress manifest digest is invalid"
    );
    Ok(())
}

fn validate_completed_runtime_progress_manifest(
    manifest: &InstalledRuntimeProgressManifest,
    command: &LifecycleCommandEnvelope,
    journal_phase: AtomicStartRuntimeEffectPhase,
) -> Result<()> {
    validate_installed_runtime_progress_manifest(manifest, command)?;
    if journal_phase >= AtomicStartRuntimeEffectPhase::PrepareRoot {
        anyhow::ensure!(
            manifest
                .volumes
                .iter()
                .zip(&command.runtime_config.volumes)
                .filter(|(_, volume)| {
                    volume.disk_role == cats_api::runtime_lifecycle::DiskRole::Root
                })
                .all(|(installed, _)| installed.local_lineage_data_directory.is_some()),
            "completed Root preparation lacks exact local lineage attribution"
        );
    }
    if journal_phase >= AtomicStartRuntimeEffectPhase::PrepareDevices {
        anyhow::ensure!(
            manifest.volumes.iter().all(|installed| {
                installed.local_lineage_data_directory.is_some()
                    && installed.blockd.is_some()
                    && installed.blockd_control_socket_path.is_some()
                    && installed.frontend.is_some()
            }),
            "completed device preparation lacks exact blockd/frontend attribution"
        );
    }
    if journal_phase >= AtomicStartRuntimeEffectPhase::PrepareNetwork {
        anyhow::ensure!(
            manifest.network.is_some(),
            "completed network preparation lacks exact attribution"
        );
    }
    if journal_phase >= AtomicStartRuntimeEffectPhase::ActivateRuntime {
        anyhow::ensure!(
            manifest.vmm.is_some(),
            "completed runtime activation lacks exact VMM attribution"
        );
    }
    Ok(())
}

fn validate_runtime_progress_against_volume_grants(
    manifest: &InstalledRuntimeProgressManifest,
    grants: &[AtomicStartVolumeGrant],
) -> Result<()> {
    anyhow::ensure!(
        manifest.volumes.len() == grants.len(),
        "atomic Start physical progress omitted a Volume grant"
    );
    for (installed, grant) in manifest.volumes.iter().zip(grants) {
        anyhow::ensure!(
            installed.volume_id == grant.volume.volume_id
                && installed.disk_id == grant.volume.disk_id
                && installed.disk_role == grant.volume.disk_role
                && installed.attachment_id == grant.volume.attachment_id
                && installed.attachment_epoch == grant.volume.attachment_epoch
                && installed.acquire_origin == grant.acquire_origin
                && remote_head_is_unchanged_or_advanced(
                    &grant.authoritative_head,
                    &installed.authority_head,
                )
                && installed.authority_receipt_digest == grant.volume.authority_receipt_digest
                && installed
                    .local_lineage_data_directory
                    .as_ref()
                    .is_none_or(|path| path == &grant.planned_local_lineage_data_directory),
            "atomic Start physical progress changed its exact Volume grant"
        );
    }
    Ok(())
}

fn validate_runtime_progress_advances(
    previous: &InstalledRuntimeProgressManifest,
    current: &InstalledRuntimeProgressManifest,
) -> Result<()> {
    anyhow::ensure!(
        previous.version == current.version
            && previous.node_id == current.node_id
            && previous.cat_id == current.cat_id
            && previous.placement_identity == current.placement_identity
            && previous.source_lifecycle_operation_id == current.source_lifecycle_operation_id
            && previous.request_fingerprint == current.request_fingerprint
            && previous.runtime_config_id == current.runtime_config_id
            && previous.runtime_config_digest == current.runtime_config_digest
            && previous.runtime_incarnation == current.runtime_incarnation
            && previous.volumes.len() == current.volumes.len(),
        "atomic Start physical progress did not advance one immutable incarnation"
    );
    for (old, new) in previous.volumes.iter().zip(&current.volumes) {
        anyhow::ensure!(
            old.volume_id == new.volume_id
                && old.disk_id == new.disk_id
                && old.disk_role == new.disk_role
                && old.attachment_id == new.attachment_id
                && old.attachment_epoch == new.attachment_epoch
                && old.acquire_origin == new.acquire_origin
                && remote_head_is_unchanged_or_advanced(&old.authority_head, &new.authority_head,)
                && old.authority_receipt_digest.is_some()
                && new.authority_receipt_digest.is_some()
                && option_is_unchanged_or_filled(
                    &old.local_lineage_data_directory,
                    &new.local_lineage_data_directory,
                )
                && option_is_unchanged_or_filled(&old.blockd, &new.blockd)
                && option_is_unchanged_or_filled(
                    &old.blockd_control_socket_path,
                    &new.blockd_control_socket_path,
                )
                && option_is_unchanged_or_filled(&old.frontend, &new.frontend),
            "atomic Start physical Volume attribution disappeared or changed"
        );
    }
    anyhow::ensure!(
        option_is_unchanged_or_filled(&previous.network, &current.network)
            && option_is_unchanged_or_filled(&previous.vmm, &current.vmm),
        "atomic Start physical runtime attribution disappeared or changed"
    );
    let current_artifacts = current
        .artifact_classifications
        .iter()
        .map(|artifact| (artifact.artifact_id(), artifact))
        .collect::<BTreeMap<_, _>>();
    anyhow::ensure!(
        previous.artifact_classifications.iter().all(|artifact| {
            current_artifacts
                .get(artifact.artifact_id())
                .is_some_and(|current| *current == artifact)
        }),
        "atomic Start retained artifact evidence disappeared or changed"
    );
    Ok(())
}

pub(super) fn validate_authority_only_runtime_progress(
    progress: &InstalledRuntimeProgressManifest,
) -> Result<()> {
    anyhow::ensure!(
        progress.vmm.is_none()
            && progress.network.is_none()
            && progress.volumes.iter().all(|volume| {
                volume.local_lineage_data_directory.is_none()
                    && volume.blockd.is_none()
                    && volume.blockd_control_socket_path.is_none()
                    && volume.frontend.is_none()
            }),
        "acquire ambiguity contains runtime materialization outside its Volume request"
    );
    Ok(())
}

fn validate_runtime_progress_authority_rebind(
    previous: &InstalledRuntimeProgressManifest,
    current: &InstalledRuntimeProgressManifest,
) -> Result<()> {
    validate_runtime_progress_advances(previous, current)?;
    anyhow::ensure!(
        previous.vmm == current.vmm
            && previous.network == current.network
            && previous.artifact_classifications == current.artifact_classifications
            && previous
                .volumes
                .iter()
                .zip(&current.volumes)
                .all(|(old, new)| {
                    old.volume_id == new.volume_id
                        && old.disk_id == new.disk_id
                        && old.disk_role == new.disk_role
                        && old.attachment_id == new.attachment_id
                        && old.attachment_epoch == new.attachment_epoch
                        && old.acquire_origin == new.acquire_origin
                        && old.local_lineage_data_directory == new.local_lineage_data_directory
                        && old.blockd == new.blockd
                        && old.blockd_control_socket_path == new.blockd_control_socket_path
                        && old.frontend == new.frontend
                }),
        "Volume refresh ambiguity contains a non-authority physical mutation"
    );
    Ok(())
}

fn option_is_unchanged_or_filled<T: PartialEq>(old: &Option<T>, new: &Option<T>) -> bool {
    match (old, new) {
        (None, _) => true,
        (Some(old), Some(new)) => old == new,
        (Some(_), None) => false,
    }
}

fn remote_head_is_unchanged_or_advanced(old: &RemoteHead, new: &RemoteHead) -> bool {
    new.generation > old.generation || new == old
}

pub(crate) fn installed_runtime_progress_manifest_digest(
    manifest: &InstalledRuntimeProgressManifest,
) -> Result<Sha256Digest> {
    let mut value = serde_json::to_value(manifest)
        .context("encode installed atomic Start progress for digest")?;
    let object = value
        .as_object_mut()
        .context("installed atomic Start progress is not an object")?;
    object.remove("manifest_digest");
    let canonical = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    Ok(digest_parts(
        RUNTIME_PROGRESS_MANIFEST_DOMAIN,
        &[&canonical],
    ))
}

pub(crate) fn terminal_retained_runtime_manifest_digest(
    manifest: &TerminalRetainedRuntimeManifest,
) -> Result<Sha256Digest> {
    let mut value = serde_json::to_value(manifest)
        .context("encode terminal retained runtime manifest for digest")?;
    let object = value
        .as_object_mut()
        .context("terminal retained runtime manifest is not an object")?;
    object.remove("manifest_digest");
    let canonical = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    Ok(digest_parts(
        TERMINAL_RETAINED_MANIFEST_DOMAIN,
        &[&canonical],
    ))
}

pub(super) fn validate_inherited_predecessor_physical_projection(
    command: &LifecycleCommandEnvelope,
    failed_volume_effect: &AtomicStartFailedVolumeEffect,
    projection: &InheritedPredecessorPhysicalProjection,
) -> Result<()> {
    let nonzero = |digest: &Sha256Digest| digest.as_bytes().iter().any(|byte| *byte != 0);
    let (source, _) = start_spec(command)?;
    let LifecyclePredecessor::SameNode {
        operation_id,
        terminal_result_kind,
        terminal_result_digest,
        node_id,
        placement_identity,
    } = &command.predecessor
    else {
        anyhow::bail!("inherited predecessor projection lacks a same-Node command predecessor")
    };
    anyhow::ensure!(
        matches!(
            source,
            StartSource::SameNodeSuspended
                | StartSource::SameNodeWarm
                | StartSource::SameNodeStopped
                | StartSource::SameNodeRetry
        ) && projection.target_operation_id == command.operation_id
            && projection.target_request_fingerprint == command.request_fingerprint
            && projection.target_runtime_config_id == command.runtime_config.config_id
            && projection.target_runtime_config_digest == command.runtime_config.config_digest
            && projection.predecessor_operation_id == *operation_id
            && projection.predecessor_terminal_result_kind == *terminal_result_kind
            && projection.predecessor_terminal_result_digest == *terminal_result_digest
            && *node_id == command.node_id
            && *placement_identity == command.placement_identity
            && nonzero(&projection.predecessor_request_fingerprint)
            && nonzero(&projection.physical_manifest_digest)
            && !projection.volumes.is_empty()
            && projection
                .volumes
                .windows(2)
                .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "inherited predecessor physical projection has an invalid source or identity"
    );
    if source == StartSource::SameNodeRetry {
        anyhow::ensure!(
            matches!(
                terminal_result_kind,
                TerminalResultKind::StartFailed
                    | TerminalResultKind::SuspendFailed
                    | TerminalResultKind::WarmFailed
            ),
            "inherited retry projection has an unsupported predecessor kind"
        );
    }
    if matches!(
        source,
        StartSource::SameNodeSuspended | StartSource::SameNodeWarm
    ) {
        anyhow::ensure!(
            projection.runtime_incarnation.is_some(),
            "resumable predecessor projection lost its runtime incarnation"
        );
    }
    match (
        source,
        terminal_result_kind,
        projection.warm_restart_source.as_ref(),
    ) {
        (StartSource::SameNodeWarm, TerminalResultKind::Warm, Some(restart_source)) => {
            anyhow::ensure!(
                restart_source.cleanup_authority.mode()
                    == super::WarmSnapshotCleanupMode::TransferToRuntime
                    && restart_source.cleanup_authority.terminal_manifest_digest()
                        == &projection.physical_manifest_digest
                    && restart_source.physical_manifest_digest
                        == projection.physical_manifest_digest
                    && projection.runtime_incarnation.as_ref()
                        == Some(
                            restart_source
                                .cleanup_authority
                                .source_runtime_incarnation()
                        ),
                "Warm predecessor projection changed its exact cleanup authority"
            )
        }
        (StartSource::SameNodeWarm, TerminalResultKind::Warm, None) => {
            anyhow::bail!("Warm predecessor projection lost its cleanup authority")
        }
        (StartSource::SameNodeRetry, TerminalResultKind::StartFailed, Some(restart_source)) => {
            anyhow::ensure!(
                restart_source.cleanup_authority.mode()
                    == super::WarmSnapshotCleanupMode::TransferToRuntime
                    && restart_source.physical_manifest_digest
                        == projection.physical_manifest_digest
                    && projection.runtime_incarnation.as_ref()
                        == Some(
                            restart_source
                                .cleanup_authority
                                .source_runtime_incarnation()
                        ),
                "retained Warm retry projection changed its rebound cleanup authority"
            )
        }
        (_, _, None) => {}
        (_, _, Some(_)) => {
            anyhow::bail!("non-Warm predecessor projection invented Warm cleanup authority")
        }
    }
    validate_volume_batch_request(command, &failed_volume_effect.request)?;
    validate_atomic_start_volume_failure_evidence(
        command,
        &failed_volume_effect.request,
        &failed_volume_effect.evidence,
    )?;
    anyhow::ensure!(
        failed_volume_effect.request.grant_sequence.get() == 0,
        "inherited predecessor projection is not a sequence-zero rejection"
    );
    for volume in &projection.volumes {
        let index = command
            .runtime_config
            .volumes
            .binary_search_by(|configured| configured.volume_id.cmp(&volume.volume_id))
            .map_err(|_| anyhow::anyhow!("inherited predecessor Volume is outside config"))?;
        let configured = &command.runtime_config.volumes[index];
        let action = &failed_volume_effect.request.actions[index];
        anyhow::ensure!(
            volume.disk_id == configured.disk_id
                && volume.disk_role == configured.disk_role
                && volume.attachment_epoch.get() > 0
                && nonzero(&volume.immutable_start_grant_receipt_digest)
                && matches!(
                    action,
                    AtomicStartVolumeAction::RenewSameNode {
                        volume: action_volume,
                        attachment_id,
                        attachment_epoch,
                        ..
                    } if action_volume == configured
                        && *attachment_id == volume.attachment_id
                        && *attachment_epoch == volume.attachment_epoch
                ),
            "inherited predecessor projection changed its exact renewal lineage"
        );
    }
    Ok(())
}

fn validate_inherited_predecessor_owned_evidence(
    evidence: &InheritedPredecessorOwnedEvidence,
    manifest: Option<&TerminalRetainedRuntimeManifest>,
    command: Option<&LifecycleCommandEnvelope>,
) -> Result<()> {
    let nonzero = |digest: &Sha256Digest| digest.as_bytes().iter().any(|byte| *byte != 0);
    anyhow::ensure!(
        nonzero(&evidence.predecessor_request_fingerprint)
            && nonzero(&evidence.predecessor_terminal_result_digest)
            && nonzero(&evidence.predecessor_physical_manifest_digest)
            && !evidence.volumes.is_empty()
            && evidence
                .volumes
                .windows(2)
                .all(|pair| pair[0].retained_receipt.volume_id
                    < pair[1].retained_receipt.volume_id),
        "inherited failed Start evidence has an incomplete predecessor identity or Volume set"
    );
    anyhow::ensure!(
        evidence.failed_volume_effect.request.grant_sequence.get() == 0,
        "inherited failed Start is not a sequence-zero Volume rejection"
    );
    for volume in &evidence.volumes {
        let receipt = &volume.retained_receipt;
        anyhow::ensure!(
            receipt.attachment_epoch.get() > 0
                && receipt.authority_receipt_digest.as_ref()
                    == Some(&volume.immutable_start_grant_receipt_digest)
                && nonzero(&volume.immutable_start_grant_receipt_digest)
                && volume.authoritative_head.generation <= receipt.remote_durable_generation
                && receipt.remote_durable_generation <= receipt.local_durable_generation,
            "inherited failed Start changed predecessor owner, authority, or L/R lineage"
        );
        if volume.local_lineage_data_directory.is_none() {
            anyhow::ensure!(
                receipt.local_durable_generation == receipt.remote_durable_generation
                    && receipt.remote_durable_generation == volume.authoritative_head.generation,
                "inherited failed Start inferred absent lineage with unique or unbound data"
            );
        }
    }
    if let Some(manifest) = manifest {
        anyhow::ensure!(
            manifest.runtime_progress.is_none()
                && manifest.volume_grants.is_empty()
                && manifest.retained_volume_receipts.len() == evidence.volumes.len()
                && evidence
                    .volumes
                    .iter()
                    .map(|volume| &volume.retained_receipt)
                    .eq(manifest.retained_volume_receipts.iter()),
            "inherited failed Start evidence changed its enclosing retained projection"
        );
    }
    if let Some(command) = command {
        let (source, _) = start_spec(command)?;
        let LifecyclePredecessor::SameNode {
            operation_id,
            terminal_result_kind,
            terminal_result_digest,
            node_id,
            placement_identity,
        } = &command.predecessor
        else {
            anyhow::bail!("inherited failed Start evidence lacks a same-Node command predecessor")
        };
        let expected_kind = match source {
            StartSource::SameNodeSuspended => Some(TerminalResultKind::Suspended),
            StartSource::SameNodeWarm => Some(TerminalResultKind::Warm),
            StartSource::SameNodeStopped => Some(TerminalResultKind::Killed),
            StartSource::SameNodeRetry => None,
            StartSource::Genesis
            | StartSource::ColdHandoff
            | StartSource::HostFenceRecovery
            | StartSource::SameNodeCold => {
                anyhow::bail!("this Start source cannot inherit same-Node Owned authority")
            }
        };
        if let Some(expected_kind) = expected_kind {
            anyhow::ensure!(
                *terminal_result_kind == expected_kind,
                "inherited failed Start predecessor kind differs from its Start source"
            );
        } else {
            anyhow::ensure!(
                matches!(
                    terminal_result_kind,
                    TerminalResultKind::StartFailed
                        | TerminalResultKind::SuspendFailed
                        | TerminalResultKind::WarmFailed
                ),
                "inherited failed Start retry has a non-failure predecessor"
            );
        }
        anyhow::ensure!(
            evidence.predecessor_operation_id == *operation_id
                && evidence.predecessor_terminal_result_kind == *terminal_result_kind
                && evidence.predecessor_terminal_result_digest == *terminal_result_digest
                && *node_id == command.node_id
                && *placement_identity == command.placement_identity,
            "inherited failed Start changed its signed same-Node predecessor"
        );
        validate_volume_batch_request(command, &evidence.failed_volume_effect.request)?;
        validate_atomic_start_volume_failure_evidence(
            command,
            &evidence.failed_volume_effect.request,
            &evidence.failed_volume_effect.evidence,
        )?;
        anyhow::ensure!(
            evidence
                .failed_volume_effect
                .request
                .actions
                .iter()
                .any(|action| matches!(action, AtomicStartVolumeAction::RenewSameNode { .. })),
            "inherited failed Start batch contains no same-Node renewal"
        );
        for volume in &evidence.volumes {
            let receipt = &volume.retained_receipt;
            let index = command
                .runtime_config
                .volumes
                .binary_search_by(|configured| configured.volume_id.cmp(&receipt.volume_id))
                .map_err(|_| anyhow::anyhow!("inherited Volume is outside runtime config"))?;
            let configured = &command.runtime_config.volumes[index];
            let action = &evidence.failed_volume_effect.request.actions[index];
            anyhow::ensure!(
                receipt.disk_id == configured.disk_id
                    && receipt.disk_role == configured.disk_role
                    && matches!(
                        action,
                        AtomicStartVolumeAction::RenewSameNode {
                            volume: action_volume,
                            attachment_id,
                            attachment_epoch,
                            ..
                        } if action_volume == configured
                            && *attachment_id == receipt.attachment_id
                            && *attachment_epoch == receipt.attachment_epoch
                    ),
                "inherited failed Start Volume is not an exact rejected renewal"
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_terminal_retained_runtime_manifest(
    manifest: &TerminalRetainedRuntimeManifest,
    command: Option<&LifecycleCommandEnvelope>,
) -> Result<()> {
    let nonzero = |digest: &Sha256Digest| digest.as_bytes().iter().any(|byte| *byte != 0);
    anyhow::ensure!(
        manifest.version == ContractVersion::V1
            && manifest.disposition == TerminalRetainedRuntimeDisposition::NonExecutable
            && !manifest.retained_volume_receipts.is_empty()
            && manifest
                .retained_volume_receipts
                .windows(2)
                .all(|pair| pair[0].volume_id < pair[1].volume_id)
            && nonzero(&manifest.execution_absence.stop_fence_receipt_digest)
            && nonzero(&manifest.execution_absence.admission_closed_receipt_digest)
            && nonzero(
                &manifest
                    .execution_absence
                    .dedicated_scope_absence_receipt_digest,
            )
            && nonzero(&manifest.execution_absence.frontend_absence_receipt_digest)
            && nonzero(
                &manifest
                    .execution_absence
                    .restart_source_absence_receipt_digest,
            )
            && nonzero(&manifest.post_stop_physical_projection_digest)
            && nonzero(&manifest.physical_retained_evidence.artifact_manifest_digest,),
        "terminal retained runtime manifest changed its command or physical identity"
    );
    if let Some(carrier) = manifest.retained_warm_restart_source.as_ref() {
        super::suspend_warm::validate_retained_warm_restart_source(carrier)?;
        if let Some(command) = command {
            super::suspend_warm::validate_retained_warm_restart_source_for_failed_start(
                command, carrier,
            )?;
            let (source, _) = start_spec(command)?;
            anyhow::ensure!(
                matches!(
                    source,
                    StartSource::SameNodeWarm | StartSource::SameNodeRetry
                ),
                "non-Warm failed Start retained a Warm restart source"
            );
        }
    }
    match &manifest.retention_mode {
        TerminalRetainedRuntimeMode::AuthorityOnlyOwnedZeroMutation { .. }
        | TerminalRetainedRuntimeMode::MaterializedOrAmbiguous => {
            let progress = manifest
                .runtime_progress
                .as_ref()
                .context("current-operation retained Start manifest lost its progress")?;
            anyhow::ensure!(
                progress.version == ContractVersion::V1
                    && manifest.node_id == progress.node_id
                    && manifest.cat_id == progress.cat_id
                    && manifest.placement_identity == progress.placement_identity
                    && manifest.source_lifecycle_operation_id
                        == progress.source_lifecycle_operation_id
                    && manifest.request_fingerprint == progress.request_fingerprint
                    && manifest.runtime_config_id == progress.runtime_config_id
                    && manifest.runtime_config_digest == progress.runtime_config_digest
                    && manifest.runtime_incarnation == progress.runtime_incarnation
                    && !manifest.volume_grants.is_empty()
                    && manifest.volume_grants.len() == progress.volumes.len()
                    && manifest.retained_volume_receipts.len() == manifest.volume_grants.len()
                    && progress.manifest_digest
                        == installed_runtime_progress_manifest_digest(progress)?,
                "terminal current-operation retention changed its progress identity"
            );
            for (grant, progress_volume) in manifest.volume_grants.iter().zip(&progress.volumes) {
                anyhow::ensure!(
                    grant.volume.volume_id == progress_volume.volume_id
                        && grant.volume.disk_id == progress_volume.disk_id
                        && grant.volume.disk_role == progress_volume.disk_role
                        && grant.volume.attachment_id == progress_volume.attachment_id
                        && grant.volume.attachment_epoch == progress_volume.attachment_epoch
                        && grant.acquire_origin == progress_volume.acquire_origin
                        && remote_head_is_unchanged_or_advanced(
                            &grant.authoritative_head,
                            &progress_volume.authority_head,
                        )
                        && progress_volume.authority_receipt_digest.as_ref()
                            == Some(&grant.grant_receipt_digest),
                    "terminal retained runtime manifest lost Start grant lineage"
                );
            }
            for receipt in &manifest.retained_volume_receipts {
                let grant = manifest
                    .volume_grants
                    .iter()
                    .find(|grant| grant.volume.volume_id == receipt.volume_id)
                    .context("terminal retained L/R receipt is outside the Start grant set")?;
                anyhow::ensure!(
                    receipt.disk_id == grant.volume.disk_id
                        && receipt.disk_role == grant.volume.disk_role
                        && receipt.attachment_id == grant.volume.attachment_id
                        && receipt.attachment_epoch == grant.volume.attachment_epoch
                        && receipt.authority_receipt_digest.as_ref()
                            == Some(&grant.grant_receipt_digest)
                        && receipt.remote_durable_generation <= receipt.local_durable_generation
                        && receipt.remote_durable_generation >= grant.authoritative_head.generation,
                    "terminal retained L/R receipt changed owner, epoch, authority, or durability"
                );
            }
            if let TerminalRetainedRuntimeMode::AuthorityOnlyOwnedZeroMutation {
                complete_scan_digest,
            } = &manifest.retention_mode
            {
                anyhow::ensure!(
                    complete_scan_digest == &manifest.post_stop_physical_projection_digest
                        && manifest.volume_grants.iter().all(|grant| grant
                            .authority_receipt
                            .grant_sequence
                            .get()
                            == 0)
                        && validate_authority_only_runtime_progress(progress).is_ok()
                        && progress.artifact_classifications
                            == volume_grant_artifacts(&manifest.volume_grants)?
                        && manifest.retained_volume_receipts.iter().all(|receipt| {
                            receipt.local_durable_generation == receipt.remote_durable_generation
                        }),
                    "terminal authority-only retention lacks complete zero-mutation Owned evidence"
                );
            }
            if let Some(command) = command {
                validate_installed_runtime_progress_manifest(progress, command)?;
                validate_start_volume_grant_set(command, &manifest.volume_grants)?;
                validate_runtime_progress_against_volume_grants(progress, &manifest.volume_grants)?;
            }
        }
        TerminalRetainedRuntimeMode::InheritedPredecessorOwned { evidence } => {
            anyhow::ensure!(
                manifest.runtime_progress.is_none()
                    && manifest.volume_grants.is_empty()
                    && manifest.retained_volume_receipts.len() == evidence.volumes.len()
                    && manifest
                        .physical_retained_evidence
                        .retained_authority_or_data_count
                        >= u16::try_from(evidence.volumes.len())
                            .context("inherited retained Volume count exceeds u16")?,
                "inherited failed Start invented current grants/progress or lost retention"
            );
            validate_inherited_predecessor_owned_evidence(evidence, Some(manifest), command)?;
            anyhow::ensure!(
                evidence
                    .volumes
                    .iter()
                    .map(|volume| &volume.retained_receipt)
                    .eq(manifest.retained_volume_receipts.iter()),
                "inherited failed Start changed its fresh retained L/R projection"
            );
        }
    }
    if let Some(command) = command {
        anyhow::ensure!(
            manifest.node_id == command.node_id
                && manifest.cat_id == command.cat_id
                && manifest.placement_identity == command.placement_identity
                && manifest.source_lifecycle_operation_id == command.operation_id
                && manifest.request_fingerprint == command.request_fingerprint
                && manifest.runtime_config_id == command.runtime_config.config_id
                && manifest.runtime_config_digest == command.runtime_config.config_digest,
            "terminal retained runtime manifest belongs to another Start command"
        );
    }
    anyhow::ensure!(
        manifest.manifest_digest == terminal_retained_runtime_manifest_digest(manifest)?,
        "terminal retained runtime manifest digest is invalid"
    );
    Ok(())
}

/// Revalidate a command whose non-executable retained manifest was sealed but
/// whose terminal journal successor was not. The fresh strong-Stop execution
/// proves current execution absence and reopens current Volume authority; the
/// original sealed evidence remains the only response identity because the
/// fresh physical scan now necessarily includes that retained artifact.
fn validate_terminal_retained_replay_evidence(
    sealed: &TerminalRetainedRuntimeManifest,
    fresh: &StrongStopEvidence,
) -> Result<()> {
    validate_terminal_retained_runtime_manifest(sealed, None)?;
    let nonzero = |digest: &Sha256Digest| digest.as_bytes().iter().any(|byte| *byte != 0);
    let stopped_runtime_incarnation = match &sealed.retention_mode {
        TerminalRetainedRuntimeMode::InheritedPredecessorOwned { evidence } => {
            evidence.predecessor_runtime_incarnation.as_ref()
        }
        TerminalRetainedRuntimeMode::AuthorityOnlyOwnedZeroMutation { .. }
        | TerminalRetainedRuntimeMode::MaterializedOrAmbiguous => Some(&sealed.runtime_incarnation),
    };
    anyhow::ensure!(
        nonzero(&fresh.execution_absence.stop_fence_receipt_digest)
            && nonzero(&fresh.execution_absence.admission_closed_receipt_digest)
            && nonzero(
                &fresh
                    .execution_absence
                    .dedicated_scope_absence_receipt_digest,
            )
            && nonzero(&fresh.execution_absence.frontend_absence_receipt_digest)
            && nonzero(
                &fresh
                    .execution_absence
                    .restart_source_absence_receipt_digest,
            )
            && nonzero(&fresh.post_stop_physical_projection_digest)
            && fresh
                .stopped_runtime_incarnation
                .as_ref()
                .is_none_or(|incarnation| Some(incarnation) == stopped_runtime_incarnation)
            && fresh.retained_warm_restart_source == sealed.retained_warm_restart_source,
        "replayed failed Start no longer has exact execution absence"
    );
    anyhow::ensure!(
        fresh.retained_volume_receipts.len() == sealed.retained_volume_receipts.len(),
        "replayed failed Start changed its retained Volume set"
    );
    for (old, current) in sealed
        .retained_volume_receipts
        .iter()
        .zip(&fresh.retained_volume_receipts)
    {
        anyhow::ensure!(
            old.volume_id == current.volume_id
                && old.disk_id == current.disk_id
                && old.disk_role == current.disk_role
                && old.attachment_id == current.attachment_id
                && old.attachment_epoch == current.attachment_epoch
                && old.authority_receipt_digest == current.authority_receipt_digest
                && current.remote_durable_generation >= old.remote_durable_generation
                && current.local_durable_generation >= old.local_durable_generation
                && current.remote_durable_generation <= current.local_durable_generation,
            "replayed failed Start changed owner, epoch, authority, or durability lineage"
        );
    }
    if matches!(
        sealed.retention_mode,
        TerminalRetainedRuntimeMode::AuthorityOnlyOwnedZeroMutation { .. }
    ) {
        anyhow::ensure!(
            fresh.retained_volume_receipts.iter().all(|receipt| {
                receipt.local_durable_generation == receipt.remote_durable_generation
            }),
            "replayed authority-only failed Start no longer has L=R"
        );
    }
    Ok(())
}

pub(crate) fn validate_installed_runtime_manifest(
    manifest: &InstalledRuntimeManifest,
    command: &LifecycleCommandEnvelope,
) -> Result<()> {
    let (source, _) = start_spec(command)?;
    anyhow::ensure!(
        manifest.version == ContractVersion::V1
            && manifest.node_id == command.node_id
            && manifest.cat_id == command.cat_id
            && manifest.placement_identity == command.placement_identity
            && manifest.source_lifecycle_operation_id == command.operation_id
            && manifest.request_fingerprint == command.request_fingerprint
            && manifest.runtime_config_id == command.runtime_config.config_id
            && manifest.runtime_config_digest == command.runtime_config.config_digest
            && manifest.vmm.process.pid > 0
            && manifest.vmm.process.start_time_ticks.get() > 0
            && manifest.vmm.parent_slice_id.as_str()
                == crate::cat_execution_scope::cat_execution_slice_id(&command.cat_id).as_str()
            && manifest.volumes.len() == command.runtime_config.volumes.len()
            && match source {
                StartSource::SameNodeWarm => {
                    manifest.retired_restart_source_absence_digest.is_some()
                }
                StartSource::SameNodeRetry => true,
                _ => manifest.retired_restart_source_absence_digest.is_none(),
            },
        "installed RuntimeReady manifest does not bind the exact command"
    );
    match &command.runtime_config.network_config {
        RuntimeNetworkConfig::IsolatedIpv4 {
            network_id,
            guest_mac,
            guest_ipv4,
            prefix_length,
            gateway_ipv4,
        } => anyhow::ensure!(
            manifest.network.identity.network_config.kind
                == cats_api::runtime_reconciliation::IsolatedIpv4Kind::IsolatedIpv4
                && manifest.network.identity.network_config.network_id == *network_id
                && manifest.network.identity.network_config.guest_mac == *guest_mac
                && manifest.network.identity.network_config.guest_ipv4 == *guest_ipv4
                && manifest.network.identity.network_config.prefix_length == *prefix_length
                && manifest.network.identity.network_config.gateway_ipv4 == *gateway_ipv4,
            "installed RuntimeReady manifest changed its complete network"
        ),
    }
    for (installed, config) in manifest.volumes.iter().zip(&command.runtime_config.volumes) {
        anyhow::ensure!(
            installed.volume_id == config.volume_id
                && installed.disk_id == config.disk_id
                && installed.disk_role == config.disk_role
                && installed.attachment_epoch.get() > 0
                && installed.authority_receipt_digest.is_some()
                && remote_head_is_unchanged_or_advanced(
                    &installed.launch_head,
                    &installed.current_authority_head,
                )
                && installed.blockd.pid > 0
                && installed.blockd.start_time_ticks.get() > 0,
            "installed RuntimeReady manifest changed its Volume set"
        );
        if let InstalledRuntimeBlockFrontend::KernelNbd { client, .. } = &installed.frontend {
            anyhow::ensure!(
                client.pid > 0 && client.start_time_ticks.get() > 0,
                "installed kernel-NBD client identity is incomplete"
            );
        }
    }
    validate_runtime_launch_identity(
        command,
        &manifest.runtime_incarnation,
        &manifest.vmm,
        &manifest.network,
    )?;
    for ((device, installed), config) in manifest
        .vmm
        .launch_identity
        .devices
        .iter()
        .zip(&manifest.volumes)
        .zip(&command.runtime_config.volumes)
    {
        anyhow::ensure!(
            device.serving_process.data_directory == installed.local_lineage_data_directory
                && device.serving_process.control_socket_path
                    == installed.blockd_control_socket_path
                && launch_frontend_matches(&installed.frontend, &device.frontend)
                && launch_device_matches_config(
                    command,
                    device,
                    &installed.attachment_id,
                    installed.attachment_epoch,
                    &installed.acquire_origin,
                    &installed.launch_head,
                    config,
                )?,
            "installed RuntimeReady manifest changed its VMM device launch identity"
        );
    }
    anyhow::ensure!(
        manifest.manifest_digest == installed_runtime_manifest_digest(manifest)?,
        "installed RuntimeReady manifest digest is invalid"
    );
    Ok(())
}

fn validate_runtime_launch_identity(
    command: &LifecycleCommandEnvelope,
    runtime_incarnation: &RandomId128,
    vmm: &InstalledRuntimeVmmManifest,
    network: &InstalledRuntimeNetworkManifest,
) -> Result<()> {
    let launch = vmm.launch_identity.as_ref();
    let RuntimeNetworkConfig::IsolatedIpv4 {
        network_id,
        guest_mac,
        guest_ipv4,
        prefix_length,
        gateway_ipv4,
    } = &command.runtime_config.network_config;
    anyhow::ensure!(
        launch.runtime_incarnation == *runtime_incarnation
            && launch.scope_id == vmm.parent_slice_id
            && launch.vcpus == command.runtime_config.vcpus
            && launch.memory_bytes == command.runtime_config.memory_bytes
            && launch.boot_image_digest == command.runtime_config.boot_image_digest
            && launch.guest_config_digest == command.runtime_config.guest_runtime_profile_digest
            && launch.api_socket_path == vmm.api_socket_path
            && launch.vsock_socket_path == vmm.vsock_socket_path
            && launch.memory_file_path == vmm.memory_file_path
            && launch.guest_cid >= 3
            && launch.network.network_config.kind
                == cats_api::runtime_reconciliation::IsolatedIpv4Kind::IsolatedIpv4
            && launch.network.network_config.network_id == *network_id
            && launch.network.network_config.guest_mac == *guest_mac
            && launch.network.network_config.guest_ipv4 == *guest_ipv4
            && launch.network.network_config.prefix_length == *prefix_length
            && launch.network.network_config.gateway_ipv4 == *gateway_ipv4
            && launch.network.as_ref() == network.identity.as_ref()
            && launch.devices.len() == command.runtime_config.volumes.len(),
        "installed VMM launch identity does not bind the immutable runtime command"
    );
    Ok(())
}

fn launch_device_matches_config(
    command: &LifecycleCommandEnvelope,
    device: &cats_api::runtime_reconciliation::PreparedDeviceInput,
    attachment_id: &Id,
    attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    acquire_origin: &AcquireOrigin,
    launch_head: &RemoteHead,
    config: &RuntimeVolumeConfig,
) -> Result<bool> {
    Ok(
        device.volume_intent_id == atomic_start_launch_volume_id(command, config)?
            && device.disk_id == config.disk_id
            && device.volume_id == config.volume_id
            && device.disk_kind
                == match config.disk_role {
                    cats_api::runtime_lifecycle::DiskRole::Root => DiskKind::Root,
                    cats_api::runtime_lifecycle::DiskRole::Persistent => DiskKind::Persistent,
                }
            && device.attachment_id == *attachment_id
            && device.attachment_epoch == attachment_epoch
            && device.acquire_origin == *acquire_origin
            && device.expected_head == *launch_head
            && device.size_bytes == config.size_bytes
            && device.durability == config.durability
            && device.guest_device.serial == config.guest_device_serial
            && device.guest_device.slot == config.guest_device_slot,
    )
}

fn launch_frontend_matches(
    installed: &InstalledRuntimeBlockFrontend,
    launch: &PrepareDeviceFrontend,
) -> bool {
    match (installed, launch) {
        (
            InstalledRuntimeBlockFrontend::KernelNbd { device_path, .. },
            PrepareDeviceFrontend::KernelNbd {
                device_path: launch_path,
                ..
            },
        ) => device_path == launch_path,
        (
            InstalledRuntimeBlockFrontend::VhostUserBlk { socket_path },
            PrepareDeviceFrontend::VhostUserBlk {
                socket_path: launch_path,
                ..
            },
        ) => socket_path == launch_path,
        _ => false,
    }
}

pub(crate) fn installed_runtime_manifest_digest(
    manifest: &InstalledRuntimeManifest,
) -> Result<Sha256Digest> {
    let mut value = serde_json::to_value(manifest)
        .context("encode installed RuntimeReady manifest for digest")?;
    let object = value
        .as_object_mut()
        .context("installed RuntimeReady manifest is not an object")?;
    object.remove("manifest_digest");
    let canonical = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    Ok(digest_parts(RUNTIME_MANIFEST_DOMAIN, &[&canonical]))
}

/// Descriptor-relative exact replay publication. The target is visible only
/// after file fsync + rename; the directory fsync closes the crash boundary.
pub(super) fn publish_installed_runtime_manifest(
    state_directory: &StateDirectory,
    manifest: &InstalledRuntimeManifest,
) -> Result<()> {
    anyhow::ensure!(
        manifest.manifest_digest == installed_runtime_manifest_digest(manifest)?,
        "refuse to publish an invalid installed RuntimeReady manifest digest"
    );
    let value = serde_json::to_value(manifest).context("encode installed RuntimeReady manifest")?;
    let bytes = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= RUNTIME_MANIFEST_MAX_BYTES,
        "installed RuntimeReady manifest exceeds its byte cap"
    );
    let directory = open_runtime_manifest_namespace(state_directory, true)?;
    let target_name = runtime_manifest_name(&manifest.cat_id, RUNTIME_MANIFEST_SUFFIX)?;
    let temp_name = runtime_manifest_name(&manifest.cat_id, RUNTIME_MANIFEST_TEMP_SUFFIX)?;
    unlinkat_if_exists(&directory, &temp_name)
        .context("remove stale installed RuntimeReady manifest temp")?;
    let mut temp = openat_file(
        &directory,
        &temp_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
    .context("create installed RuntimeReady manifest temp")?;
    temp.write_all(&bytes)
        .context("write installed RuntimeReady manifest temp")?;
    temp.sync_all()
        .context("fsync installed RuntimeReady manifest temp")?;
    verify_regular_single_link(&temp).context("verify installed RuntimeReady manifest temp")?;
    renameat(&directory, &temp_name, &target_name)
        .context("publish installed RuntimeReady manifest")?;
    directory
        .sync_all()
        .context("fsync installed RuntimeReady manifest directory")?;
    let reloaded = load_installed_runtime_manifest_from_directory(&directory, &manifest.cat_id)?
        .context("published installed RuntimeReady manifest disappeared")?;
    anyhow::ensure!(
        &reloaded == manifest,
        "published installed RuntimeReady manifest changed"
    );
    Ok(())
}

pub(super) fn load_installed_runtime_manifest(
    state_directory: &StateDirectory,
    cat_id: &Id,
) -> Result<Option<InstalledRuntimeManifest>> {
    let Some(directory) = open_runtime_manifest_namespace_optional(state_directory)? else {
        return Ok(None);
    };
    load_installed_runtime_manifest_from_directory(&directory, cat_id)
}

/// Descriptor-relative startup enumeration.  A partial publication, unknown
/// entry, duplicate logical Cat identity, symlink, non-regular file or one
/// corrupt manifest fails the complete scan closed; callers must not turn a
/// partial list into an inventory attestation.
pub(super) fn enumerate_installed_runtime_manifests(
    state_directory: &StateDirectory,
) -> Result<Vec<InstalledRuntimeManifest>> {
    let Some(directory) = open_runtime_manifest_namespace_optional(state_directory)? else {
        return Ok(Vec::new());
    };
    let mut cat_ids = Vec::new();
    for name in directory_entry_names(&directory)
        .context("enumerate installed RuntimeReady manifest namespace")?
    {
        if name == b"." || name == b".." {
            continue;
        }
        let name = std::str::from_utf8(&name)
            .context("installed RuntimeReady manifest name is not UTF-8")?;
        anyhow::ensure!(
            !name.ends_with(RUNTIME_MANIFEST_TEMP_SUFFIX),
            "installed RuntimeReady manifest publication is incomplete"
        );
        let cat = name
            .strip_suffix(RUNTIME_MANIFEST_SUFFIX)
            .context("unknown entry in installed RuntimeReady manifest namespace")?;
        let cat_id = Id::new(cat.to_owned())
            .context("installed RuntimeReady manifest filename has an invalid Cat identity")?;
        anyhow::ensure!(
            runtime_manifest_name(&cat_id, RUNTIME_MANIFEST_SUFFIX)?.to_bytes() == name.as_bytes(),
            "installed RuntimeReady manifest filename is not canonical"
        );
        cat_ids.push(cat_id);
    }
    cat_ids.sort();
    anyhow::ensure!(
        cat_ids.windows(2).all(|pair| pair[0] < pair[1]),
        "installed RuntimeReady manifest namespace has duplicate Cat identities"
    );

    let mut manifests = Vec::with_capacity(cat_ids.len());
    for cat_id in cat_ids {
        let manifest = load_installed_runtime_manifest_from_directory(&directory, &cat_id)?
            .context("enumerated installed RuntimeReady manifest disappeared")?;
        manifests.push(manifest);
    }
    Ok(manifests)
}

pub(super) fn remove_installed_runtime_manifest(
    state_directory: &StateDirectory,
    cat_id: &Id,
) -> Result<bool> {
    let Some(directory) = open_runtime_manifest_namespace_optional(state_directory)? else {
        return Ok(false);
    };
    let target_name = runtime_manifest_name(cat_id, RUNTIME_MANIFEST_SUFFIX)?;
    let removed = unlinkat_if_exists(&directory, &target_name)
        .context("remove installed RuntimeReady manifest")?;
    if removed {
        directory
            .sync_all()
            .context("fsync installed RuntimeReady manifest removal")?;
    }
    Ok(removed)
}

#[cfg(test)]
fn installed_runtime_manifest_path(state_directory: &StateDirectory, cat_id: &Id) -> PathBuf {
    state_directory
        .path()
        .join(RUNTIME_MANIFEST_NAMESPACE)
        .join(format!("{}{RUNTIME_MANIFEST_SUFFIX}", cat_id.as_str()))
}

fn load_installed_runtime_manifest_from_directory(
    directory: &File,
    cat_id: &Id,
) -> Result<Option<InstalledRuntimeManifest>> {
    let name = runtime_manifest_name(cat_id, RUNTIME_MANIFEST_SUFFIX)?;
    let Some(mut file) = openat_file_optional(
        directory,
        &name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
    )?
    else {
        return Ok(None);
    };
    verify_regular_single_link(&file).context("verify installed RuntimeReady manifest")?;
    let length = usize::try_from(file.metadata()?.len())
        .context("installed RuntimeReady manifest length overflows usize")?;
    anyhow::ensure!(
        (1..=RUNTIME_MANIFEST_MAX_BYTES).contains(&length),
        "installed RuntimeReady manifest has an invalid length"
    );
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)
        .context("read installed RuntimeReady manifest")?;
    anyhow::ensure!(
        bytes.len() == length,
        "installed RuntimeReady manifest changed while reading"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("decode installed RuntimeReady manifest JSON")?;
    anyhow::ensure!(
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&value) == bytes,
        "installed RuntimeReady manifest is not canonical JSON"
    );
    let manifest: InstalledRuntimeManifest =
        serde_json::from_value(value).context("decode installed RuntimeReady manifest")?;
    anyhow::ensure!(
        manifest.cat_id == *cat_id
            && manifest.version == ContractVersion::V1
            && manifest.manifest_digest == installed_runtime_manifest_digest(&manifest)?,
        "installed RuntimeReady manifest identity or digest is invalid"
    );
    Ok(Some(manifest))
}

/// Fsync the latest cumulative non-terminal Start attribution.  The
/// operation-scoped target is monotonic: an old replay cannot overwrite later
/// physical discovery for the same command.
pub(super) fn publish_installed_runtime_progress_manifest(
    state_directory: &StateDirectory,
    manifest: &InstalledRuntimeProgressManifest,
) -> Result<()> {
    anyhow::ensure!(
        manifest.manifest_digest == installed_runtime_progress_manifest_digest(manifest)?,
        "refuse to publish an invalid atomic Start progress digest"
    );
    let durable = DurableStartPhysicalManifest::Executing(Box::new(manifest.clone()));
    let value = serde_json::to_value(&durable)
        .context("encode installed atomic Start progress manifest")?;
    let bytes = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= RUNTIME_MANIFEST_MAX_BYTES,
        "installed atomic Start progress exceeds its byte cap"
    );
    let directory = open_runtime_progress_namespace(state_directory, true)?;
    let target_name =
        runtime_progress_manifest_name_from_manifest(manifest, RUNTIME_PROGRESS_SUFFIX)?;
    let temp_name =
        runtime_progress_manifest_name_from_manifest(manifest, RUNTIME_PROGRESS_TEMP_SUFFIX)?;
    if let Some(current) = load_installed_runtime_progress_from_directory(&directory, &target_name)?
    {
        let DurableStartPhysicalManifest::Executing(current) = current else {
            anyhow::bail!(
                "refuse to replace sealed terminal retained evidence with executing progress"
            )
        };
        if current.as_ref() == manifest {
            return Ok(());
        }
        validate_runtime_progress_advances(&current, manifest)
            .context("refuse to regress durable atomic Start physical attribution")?;
    }
    unlinkat_if_exists(&directory, &temp_name)
        .context("remove stale atomic Start progress temp")?;
    let mut temp = openat_file(
        &directory,
        &temp_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
    .context("create atomic Start progress temp")?;
    temp.write_all(&bytes)
        .context("write atomic Start progress temp")?;
    temp.sync_all()
        .context("fsync atomic Start progress temp")?;
    verify_regular_single_link(&temp).context("verify atomic Start progress temp")?;
    renameat(&directory, &temp_name, &target_name)
        .context("publish atomic Start progress manifest")?;
    directory
        .sync_all()
        .context("fsync atomic Start progress namespace")?;
    let reloaded = load_installed_runtime_progress_from_directory(&directory, &target_name)?
        .context("published atomic Start progress disappeared")?;
    anyhow::ensure!(
        reloaded == durable,
        "published atomic Start progress changed"
    );
    Ok(())
}

pub(super) fn load_installed_runtime_progress_manifest(
    state_directory: &StateDirectory,
    command: &LifecycleCommandEnvelope,
) -> Result<Option<InstalledRuntimeProgressManifest>> {
    let Some(directory) = open_runtime_progress_namespace_optional(state_directory)? else {
        return Ok(None);
    };
    let name = runtime_progress_manifest_name(command, RUNTIME_PROGRESS_SUFFIX)?;
    let Some(durable) = load_installed_runtime_progress_from_directory(&directory, &name)? else {
        return Ok(None);
    };
    let DurableStartPhysicalManifest::Executing(manifest) = durable else {
        anyhow::bail!("atomic Start progress has already been sealed non-executable")
    };
    validate_installed_runtime_progress_manifest(&manifest, command)?;
    Ok(Some(*manifest))
}

/// Load the exact non-executable retained artifact for this Start command.
/// A caller may use it only to replay the already-Executing failure edge; it
/// is never a restart or provider-effect authority.
pub(crate) fn load_terminal_retained_runtime_manifest(
    state_directory: &StateDirectory,
    command: &LifecycleCommandEnvelope,
) -> Result<Option<TerminalRetainedRuntimeManifest>> {
    let Some(directory) = open_runtime_progress_namespace_optional(state_directory)? else {
        return Ok(None);
    };
    let name = runtime_progress_manifest_name(command, RUNTIME_PROGRESS_SUFFIX)?;
    let Some(durable) = load_installed_runtime_progress_from_directory(&directory, &name)? else {
        return Ok(None);
    };
    let DurableStartPhysicalManifest::TerminalRetained(manifest) = durable else {
        return Ok(None);
    };
    validate_terminal_retained_runtime_manifest(&manifest, Some(command))?;
    Ok(Some(*manifest))
}

/// One descriptor-stable scan of every operation-scoped Start physical
/// artifact. Startup inventory must consume this combined projection so a
/// concurrent Executing->TerminalRetained seal cannot appear in neither (or
/// both) of two independently sampled lists.
pub(crate) fn enumerate_installed_start_physical_manifests(
    state_directory: &StateDirectory,
) -> Result<Vec<InstalledStartPhysicalInventoryEntry>> {
    let Some(directory) = open_runtime_progress_namespace_optional(state_directory)? else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    for bytes in directory_entry_names(&directory)
        .context("enumerate installed Start physical manifest namespace")?
    {
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name = std::str::from_utf8(&bytes)
            .context("installed Start physical manifest name is not UTF-8")?;
        anyhow::ensure!(
            !name.ends_with(RUNTIME_PROGRESS_TEMP_SUFFIX),
            "installed Start physical manifest publication is incomplete"
        );
        let key = name
            .strip_suffix(RUNTIME_PROGRESS_SUFFIX)
            .context("unknown entry in installed Start physical manifest namespace")?;
        anyhow::ensure!(
            key.len() == 64
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "installed Start physical manifest filename is not canonical"
        );
        names.push(cstring(name)?);
    }
    names.sort_by(|left, right| left.to_bytes().cmp(right.to_bytes()));
    anyhow::ensure!(
        names
            .windows(2)
            .all(|pair| pair[0].to_bytes() < pair[1].to_bytes()),
        "installed Start physical manifest namespace has duplicate operation keys"
    );
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        let durable = load_installed_runtime_progress_from_directory(&directory, &name)?
            .context("enumerated installed Start physical manifest disappeared")?;
        let entry = match durable {
            DurableStartPhysicalManifest::Executing(progress) => {
                anyhow::ensure!(
                    runtime_progress_manifest_name_from_manifest(
                        &progress,
                        RUNTIME_PROGRESS_SUFFIX,
                    )? == name,
                    "installed Start physical manifest filename and signed identity differ"
                );
                InstalledStartPhysicalInventoryEntry::Executing(progress)
            }
            DurableStartPhysicalManifest::TerminalRetained(manifest) => {
                anyhow::ensure!(
                    runtime_progress_manifest_name_from_retained_manifest(
                        &manifest,
                        RUNTIME_PROGRESS_SUFFIX,
                    )? == name,
                    "installed Start physical manifest filename and signed identity differ"
                );
                InstalledStartPhysicalInventoryEntry::TerminalRetained(manifest)
            }
        };
        entries.push(entry);
    }
    entries.sort_by(|left, right| {
        installed_start_physical_inventory_key(left)
            .cmp(&installed_start_physical_inventory_key(right))
    });
    anyhow::ensure!(
        entries
            .windows(2)
            .all(|pair| installed_start_physical_inventory_key(&pair[0])
                < installed_start_physical_inventory_key(&pair[1])),
        "installed Start physical manifest scan has duplicate command identities"
    );
    Ok(entries)
}

/// Complete descriptor-relative recovery scan of all executing Start
/// operations. Unknown/temp/corrupt entries make the whole inventory fail
/// closed rather than silently losing NBD or blockd attribution.
pub(super) fn enumerate_installed_runtime_progress_manifests(
    state_directory: &StateDirectory,
) -> Result<Vec<InstalledRuntimeProgressManifest>> {
    let Some(directory) = open_runtime_progress_namespace_optional(state_directory)? else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    for bytes in
        directory_entry_names(&directory).context("enumerate atomic Start progress namespace")?
    {
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name =
            std::str::from_utf8(&bytes).context("atomic Start progress filename is not UTF-8")?;
        anyhow::ensure!(
            !name.ends_with(RUNTIME_PROGRESS_TEMP_SUFFIX),
            "atomic Start progress publication is incomplete"
        );
        let key = name
            .strip_suffix(RUNTIME_PROGRESS_SUFFIX)
            .context("unknown entry in atomic Start progress namespace")?;
        anyhow::ensure!(
            key.len() == 64
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "atomic Start progress filename is not canonical"
        );
        entries.push(cstring(name)?);
    }
    entries.sort_by(|left, right| left.to_bytes().cmp(right.to_bytes()));
    anyhow::ensure!(
        entries
            .windows(2)
            .all(|pair| pair[0].to_bytes() < pair[1].to_bytes()),
        "atomic Start progress namespace has duplicate operation keys"
    );
    let mut manifests = Vec::with_capacity(entries.len());
    for entry in entries {
        let durable = load_installed_runtime_progress_from_directory(&directory, &entry)?
            .context("enumerated atomic Start progress disappeared")?;
        let manifest = match durable {
            DurableStartPhysicalManifest::Executing(manifest) => manifest,
            DurableStartPhysicalManifest::TerminalRetained(_) => continue,
        };
        anyhow::ensure!(
            runtime_progress_manifest_name_from_manifest(&manifest, RUNTIME_PROGRESS_SUFFIX)?
                == entry,
            "atomic Start progress filename and signed identity differ"
        );
        manifests.push(*manifest);
    }
    manifests.sort_by(|left, right| {
        (&left.cat_id, &left.source_lifecycle_operation_id)
            .cmp(&(&right.cat_id, &right.source_lifecycle_operation_id))
    });
    Ok(manifests)
}

/// Atomically replace the exact executing-progress slot with a non-executable
/// terminal retained manifest. The operation-scoped filename is unchanged,
/// so a crash observes either the prior Executing evidence or the complete
/// terminal archive, never an absent attribution gap or two competing files.
pub(crate) fn seal_terminal_retained_runtime_manifest(
    state_directory: &StateDirectory,
    manifest: &TerminalRetainedRuntimeManifest,
) -> Result<TerminalRetainedRuntimeManifest> {
    validate_terminal_retained_runtime_manifest(manifest, None)?;
    let durable = DurableStartPhysicalManifest::TerminalRetained(Box::new(manifest.clone()));
    let value =
        serde_json::to_value(&durable).context("encode terminal retained runtime manifest")?;
    let bytes = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= RUNTIME_MANIFEST_MAX_BYTES,
        "terminal retained runtime manifest exceeds its byte cap"
    );
    let directory = open_runtime_progress_namespace(state_directory, true)?;
    let target_name =
        runtime_progress_manifest_name_from_retained_manifest(manifest, RUNTIME_PROGRESS_SUFFIX)?;
    let temp_name = runtime_progress_manifest_name_from_retained_manifest(
        manifest,
        RUNTIME_PROGRESS_TEMP_SUFFIX,
    )?;
    match load_installed_runtime_progress_from_directory(&directory, &target_name)? {
        Some(DurableStartPhysicalManifest::Executing(progress)) => anyhow::ensure!(
            manifest.runtime_progress.as_ref() == Some(progress.as_ref()),
            "terminal retained seal does not match the latest executing progress"
        ),
        Some(DurableStartPhysicalManifest::TerminalRetained(current)) => {
            anyhow::ensure!(
                current.node_id == manifest.node_id
                    && current.cat_id == manifest.cat_id
                    && current.placement_identity == manifest.placement_identity
                    && current.source_lifecycle_operation_id
                        == manifest.source_lifecycle_operation_id
                    && current.request_fingerprint == manifest.request_fingerprint
                    && current.runtime_config_digest == manifest.runtime_config_digest
                    && current.runtime_incarnation == manifest.runtime_incarnation
                    && current.volume_grants == manifest.volume_grants
                    && current.runtime_progress == manifest.runtime_progress,
                "terminal retained replay changed its command-bound attribution"
            );
            // A repeated strong-Stop may produce a later scan id or advanced
            // retained L/R. The first sealed proof already closed the command
            // and determines the immutable StartFailed result digest.
            return Ok(*current);
        }
        None => anyhow::ensure!(
            manifest.runtime_progress.is_none()
                && manifest.volume_grants.is_empty()
                && matches!(
                    manifest.retention_mode,
                    TerminalRetainedRuntimeMode::InheritedPredecessorOwned { .. }
                ),
            "terminal retained seal has no exact executing progress"
        ),
    }
    unlinkat_if_exists(&directory, &temp_name)
        .context("remove stale terminal retained manifest temp")?;
    let mut temp = openat_file(
        &directory,
        &temp_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
    .context("create terminal retained manifest temp")?;
    temp.write_all(&bytes)
        .context("write terminal retained manifest temp")?;
    temp.sync_all()
        .context("fsync terminal retained manifest temp")?;
    verify_regular_single_link(&temp).context("verify terminal retained manifest temp")?;
    renameat(&directory, &temp_name, &target_name)
        .context("seal terminal retained runtime manifest")?;
    directory
        .sync_all()
        .context("fsync terminal retained runtime manifest seal")?;
    let reloaded = load_installed_runtime_progress_from_directory(&directory, &target_name)?
        .context("sealed terminal retained runtime manifest disappeared")?;
    let DurableStartPhysicalManifest::TerminalRetained(reloaded) = reloaded else {
        anyhow::bail!("sealed terminal retained runtime manifest changed kind")
    };
    anyhow::ensure!(
        reloaded.as_ref() == manifest,
        "sealed terminal retained runtime manifest changed"
    );
    Ok(*reloaded)
}

/// Strict complete scan of non-executable failed-Start retention artifacts.
/// The shared slot decoder validates executing entries too, so a corrupt or
/// partial sibling can never be omitted from a supposedly complete inventory.
pub(crate) fn enumerate_terminal_retained_runtime_manifests(
    state_directory: &StateDirectory,
) -> Result<Vec<TerminalRetainedRuntimeManifest>> {
    let Some(directory) = open_runtime_progress_namespace_optional(state_directory)? else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    for bytes in
        directory_entry_names(&directory).context("enumerate terminal retained namespace")?
    {
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name =
            std::str::from_utf8(&bytes).context("terminal retained filename is not UTF-8")?;
        anyhow::ensure!(
            !name.ends_with(RUNTIME_PROGRESS_TEMP_SUFFIX),
            "terminal retained publication is incomplete"
        );
        let key = name
            .strip_suffix(RUNTIME_PROGRESS_SUFFIX)
            .context("unknown entry in terminal retained namespace")?;
        anyhow::ensure!(
            key.len() == 64
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "terminal retained filename is not canonical"
        );
        entries.push(cstring(name)?);
    }
    entries.sort_by(|left, right| left.to_bytes().cmp(right.to_bytes()));
    anyhow::ensure!(
        entries
            .windows(2)
            .all(|pair| pair[0].to_bytes() < pair[1].to_bytes()),
        "terminal retained namespace has duplicate operation keys"
    );
    let mut manifests = Vec::new();
    for entry in entries {
        let durable = load_installed_runtime_progress_from_directory(&directory, &entry)?
            .context("enumerated terminal retained evidence disappeared")?;
        let manifest = match durable {
            DurableStartPhysicalManifest::Executing(_) => continue,
            DurableStartPhysicalManifest::TerminalRetained(manifest) => manifest,
        };
        anyhow::ensure!(
            runtime_progress_manifest_name_from_retained_manifest(
                &manifest,
                RUNTIME_PROGRESS_SUFFIX,
            )? == entry,
            "terminal retained filename and signed identity differ"
        );
        manifests.push(*manifest);
    }
    manifests.sort_by(|left, right| {
        (&left.cat_id, &left.source_lifecycle_operation_id)
            .cmp(&(&right.cat_id, &right.source_lifecycle_operation_id))
    });
    Ok(manifests)
}

pub(crate) fn remove_terminal_retained_runtime_manifest_exact(
    state_directory: &StateDirectory,
    manifest: &TerminalRetainedRuntimeManifest,
) -> Result<bool> {
    validate_terminal_retained_runtime_manifest(manifest, None)?;
    let Some(directory) = open_runtime_progress_namespace_optional(state_directory)? else {
        return Ok(false);
    };
    let target_name =
        runtime_progress_manifest_name_from_retained_manifest(manifest, RUNTIME_PROGRESS_SUFFIX)?;
    let Some(current) = load_installed_runtime_progress_from_directory(&directory, &target_name)?
    else {
        return Ok(false);
    };
    anyhow::ensure!(
        current == DurableStartPhysicalManifest::TerminalRetained(Box::new(manifest.clone())),
        "terminal retained evidence changed after cleanup discovery"
    );
    anyhow::ensure!(
        unlinkat_if_exists(&directory, &target_name)?,
        "terminal retained evidence disappeared before cleanup unlink"
    );
    directory
        .sync_all()
        .context("fsync terminal retained evidence removal")?;
    Ok(true)
}

pub(super) fn remove_installed_runtime_progress_manifest(
    state_directory: &StateDirectory,
    command: &LifecycleCommandEnvelope,
) -> Result<bool> {
    let Some(directory) = open_runtime_progress_namespace_optional(state_directory)? else {
        return Ok(false);
    };
    let target_name = runtime_progress_manifest_name(command, RUNTIME_PROGRESS_SUFFIX)?;
    let Some(current) = load_installed_runtime_progress_from_directory(&directory, &target_name)?
    else {
        return Ok(false);
    };
    anyhow::ensure!(
        matches!(current, DurableStartPhysicalManifest::Executing(_)),
        "refuse to remove sealed terminal retained evidence as executing progress"
    );
    let removed = unlinkat_if_exists(&directory, &target_name)
        .context("remove installed atomic Start progress")?;
    if removed {
        directory
            .sync_all()
            .context("fsync atomic Start progress removal")?;
    }
    Ok(removed)
}

/// Remove the exact progress artifact previously returned by the strict
/// namespace enumerator. This is used by a successor Cold/Delete command,
/// whose own operation-derived key intentionally differs from the predecessor
/// Start key. The file is reloaded through the same descriptor and must still
/// equal the caller's digested manifest; a concurrently advanced artifact is
/// never unlinked by a stale cleanup decision.
pub(super) fn remove_installed_runtime_progress_manifest_exact(
    state_directory: &StateDirectory,
    manifest: &InstalledRuntimeProgressManifest,
) -> Result<bool> {
    anyhow::ensure!(
        manifest.version == ContractVersion::V1
            && manifest.manifest_digest == installed_runtime_progress_manifest_digest(manifest)?,
        "refuse to remove invalid atomic Start progress evidence"
    );
    let Some(directory) = open_runtime_progress_namespace_optional(state_directory)? else {
        return Ok(false);
    };
    let target_name =
        runtime_progress_manifest_name_from_manifest(manifest, RUNTIME_PROGRESS_SUFFIX)?;
    let Some(current) = load_installed_runtime_progress_from_directory(&directory, &target_name)?
    else {
        return Ok(false);
    };
    let DurableStartPhysicalManifest::Executing(current) = current else {
        anyhow::bail!("refuse to remove sealed terminal retained evidence as progress")
    };
    anyhow::ensure!(
        current.as_ref() == manifest,
        "atomic Start progress advanced after cleanup discovery"
    );
    let removed = unlinkat_if_exists(&directory, &target_name)
        .context("remove exact installed atomic Start progress")?;
    anyhow::ensure!(
        removed,
        "exact atomic Start progress disappeared before cleanup unlink"
    );
    directory
        .sync_all()
        .context("fsync exact atomic Start progress removal")?;
    Ok(true)
}

fn load_installed_runtime_progress_from_directory(
    directory: &File,
    name: &CString,
) -> Result<Option<DurableStartPhysicalManifest>> {
    let Some(mut file) = openat_file_optional(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
    )?
    else {
        return Ok(None);
    };
    verify_regular_single_link(&file).context("verify installed atomic Start progress")?;
    let length = usize::try_from(file.metadata()?.len())
        .context("installed atomic Start progress length overflows usize")?;
    anyhow::ensure!(
        (1..=RUNTIME_MANIFEST_MAX_BYTES).contains(&length),
        "installed atomic Start progress has an invalid length"
    );
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)
        .context("read installed atomic Start progress")?;
    anyhow::ensure!(
        bytes.len() == length,
        "installed atomic Start progress changed while reading"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("decode installed atomic Start progress JSON")?;
    anyhow::ensure!(
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&value) == bytes,
        "installed atomic Start progress is not canonical JSON"
    );
    let manifest: DurableStartPhysicalManifest = serde_json::from_value(value)
        .context("decode installed Start physical evidence manifest")?;
    match &manifest {
        DurableStartPhysicalManifest::Executing(progress) => anyhow::ensure!(
            progress.version == ContractVersion::V1
                && progress.manifest_digest
                    == installed_runtime_progress_manifest_digest(progress)?,
            "installed atomic Start progress version or digest is invalid"
        ),
        DurableStartPhysicalManifest::TerminalRetained(retained) => {
            validate_terminal_retained_runtime_manifest(retained, None)?
        }
    }
    Ok(Some(manifest))
}

fn runtime_progress_manifest_name(
    command: &LifecycleCommandEnvelope,
    suffix: &str,
) -> Result<CString> {
    runtime_progress_manifest_name_parts(
        &command.cat_id,
        &command.operation_id,
        &command.request_fingerprint,
        suffix,
    )
}

fn runtime_progress_manifest_name_from_manifest(
    manifest: &InstalledRuntimeProgressManifest,
    suffix: &str,
) -> Result<CString> {
    runtime_progress_manifest_name_parts(
        &manifest.cat_id,
        &manifest.source_lifecycle_operation_id,
        &manifest.request_fingerprint,
        suffix,
    )
}

fn runtime_progress_manifest_name_from_retained_manifest(
    manifest: &TerminalRetainedRuntimeManifest,
    suffix: &str,
) -> Result<CString> {
    runtime_progress_manifest_name_parts(
        &manifest.cat_id,
        &manifest.source_lifecycle_operation_id,
        &manifest.request_fingerprint,
        suffix,
    )
}

fn runtime_progress_manifest_name_parts(
    cat_id: &Id,
    operation_id: &Id,
    request_fingerprint: &Sha256Digest,
    suffix: &str,
) -> Result<CString> {
    let digest = digest_parts(
        RUNTIME_PROGRESS_MANIFEST_DOMAIN,
        &[
            b"filename",
            cat_id.as_str().as_bytes(),
            operation_id.as_str().as_bytes(),
            request_fingerprint.as_bytes(),
        ],
    );
    let mut key = String::with_capacity(64 + suffix.len());
    for byte in digest.as_bytes() {
        write!(&mut key, "{byte:02x}").expect("formatting into String is infallible");
    }
    key.push_str(suffix);
    cstring(&key)
}

fn directory_entry_names(directory: &File) -> Result<Vec<Vec<u8>>> {
    let duplicate = directory
        .try_clone()
        .context("duplicate RuntimeReady manifest namespace descriptor")?
        .into_raw_fd();
    // SAFETY: ownership of the duplicate transfers to `fdopendir` on
    // success; `DirectoryStream` closes it exactly once through `closedir`.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let source = std::io::Error::last_os_error();
        // SAFETY: failed `fdopendir` did not consume the descriptor.
        unsafe { libc::close(duplicate) };
        return Err(source).context("open RuntimeReady manifest directory stream");
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
        // SAFETY: the DIR remains exclusively owned and live for this call.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() != Some(0) {
                return Err(source).context("read RuntimeReady manifest directory entry");
            }
            break;
        }
        // SAFETY: POSIX supplies a NUL-terminated d_name which remains live
        // through this call; copy the bytes before the next `readdir`.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        names.push(name.to_bytes().to_vec());
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    // SAFETY: this is the calling thread's errno slot and is cleared only for
    // distinguishing EOF from an error on the immediately following readdir.
    unsafe { *libc::__errno_location() = 0 }
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    // SAFETY: this is the calling thread's errno slot and is cleared only for
    // distinguishing EOF from an error on the immediately following readdir.
    unsafe { *libc::__error() = 0 }
}

fn open_runtime_manifest_namespace(state: &StateDirectory, create: bool) -> Result<File> {
    open_manifest_namespace(state, RUNTIME_MANIFEST_NAMESPACE, create)
}

fn open_runtime_progress_namespace(state: &StateDirectory, create: bool) -> Result<File> {
    open_manifest_namespace(state, RUNTIME_PROGRESS_NAMESPACE, create)
}

fn open_manifest_namespace(state: &StateDirectory, namespace: &str, create: bool) -> Result<File> {
    let base = state
        .try_clone_directory()
        .context("open identity-selected Node state directory")?;
    let name = cstring(namespace)?;
    if create {
        loop {
            // SAFETY: `base` is a live directory descriptor and `name` is a
            // NUL-terminated single component. mkdirat retains neither.
            let result = unsafe { libc::mkdirat(base.as_raw_fd(), name.as_ptr(), 0o700) };
            if result == 0 {
                base.sync_all()
                    .context("fsync new RuntimeReady manifest namespace")?;
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                break;
            }
            return Err(error).context("create RuntimeReady manifest namespace");
        }
    }
    openat_file(
        &base,
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )
    .context("open RuntimeReady manifest namespace")
}

fn open_runtime_manifest_namespace_optional(state: &StateDirectory) -> Result<Option<File>> {
    open_manifest_namespace_optional(state, RUNTIME_MANIFEST_NAMESPACE)
}

fn open_runtime_progress_namespace_optional(state: &StateDirectory) -> Result<Option<File>> {
    open_manifest_namespace_optional(state, RUNTIME_PROGRESS_NAMESPACE)
}

fn open_manifest_namespace_optional(
    state: &StateDirectory,
    namespace: &str,
) -> Result<Option<File>> {
    match open_manifest_namespace(state, namespace, false) {
        Ok(directory) => Ok(Some(directory)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|source| source.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn runtime_manifest_name(cat_id: &Id, suffix: &str) -> Result<CString> {
    cstring(&format!("{}{suffix}", cat_id.as_str()))
}

fn cstring(value: &str) -> Result<CString> {
    CString::new(value.as_bytes()).context("RuntimeReady manifest name contains NUL")
}

fn openat_file(directory: &File, name: &CString, flags: i32, mode: u32) -> Result<File> {
    loop {
        // SAFETY: `directory` and `name` remain live for this call. A
        // successful descriptor is transferred exactly once into `File`.
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
        if descriptor >= 0 {
            // SAFETY: successful openat returned a fresh owned descriptor.
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

fn openat_file_optional(directory: &File, name: &CString, flags: i32) -> Result<Option<File>> {
    match openat_file(directory, name, flags, 0) {
        Ok(file) => Ok(Some(file)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|source| source.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn unlinkat_if_exists(directory: &File, name: &CString) -> Result<bool> {
    loop {
        // SAFETY: descriptor/name are live; unlinkat retains neither.
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(false);
        }
        return Err(error.into());
    }
}

fn renameat(directory: &File, source: &CString, target: &CString) -> Result<()> {
    loop {
        // SAFETY: both names and the directory descriptor are live for this
        // call; renameat retains none of them.
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
            return Err(error.into());
        }
    }
}

fn verify_regular_single_link(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_file() && metadata.nlink() == 1,
        "RuntimeReady manifest is not a single-link regular file"
    );
    Ok(())
}

fn deterministic_attachment_id(
    command: &LifecycleCommandEnvelope,
    volume: &RuntimeVolumeConfig,
) -> Result<Id> {
    let digest = digest_parts(
        ATTACHMENT_ID_DOMAIN,
        &[
            command.operation_id.as_str().as_bytes(),
            command.request_fingerprint.as_bytes(),
            volume.volume_id.as_str().as_bytes(),
            volume.disk_id.as_str().as_bytes(),
        ],
    );
    let mut suffix = String::with_capacity(32);
    for byte in &digest.as_bytes()[..16] {
        write!(&mut suffix, "{byte:02x}").expect("formatting into String is infallible");
    }
    Id::new(format!("attachment:{suffix}"))
        .context("derived atomic Start attachment identity is invalid")
}

/// Stable physical-launch identity used only to populate the legacy-named
/// `RuntimeLaunchIdentity::devices[].volume_intent_id` field. It is derived
/// from immutable atomic config, not from a Desired row or lifecycle phase,
/// and therefore remains exact across Suspended resume.
pub fn atomic_start_launch_volume_id(
    command: &LifecycleCommandEnvelope,
    volume: &RuntimeVolumeConfig,
) -> Result<Id> {
    let digest = digest_parts(
        LAUNCH_VOLUME_ID_DOMAIN,
        &[
            command.runtime_config.config_digest.as_bytes(),
            volume.volume_id.as_str().as_bytes(),
            volume.disk_id.as_str().as_bytes(),
        ],
    );
    let mut suffix = String::with_capacity(32);
    for byte in &digest.as_bytes()[..16] {
        write!(&mut suffix, "{byte:02x}").expect("formatting into String is infallible");
    }
    Id::new(format!("launch-volume:{suffix}"))
        .context("derived atomic Start launch Volume identity is invalid")
}

fn failure_fence_payload(command: &LifecycleCommandEnvelope) -> Result<ExactBytes> {
    let digest = digest_parts(
        FAILURE_FENCE_DOMAIN,
        &[
            command.cat_id.as_str().as_bytes(),
            command.operation_id.as_str().as_bytes(),
            command.request_fingerprint.as_bytes(),
        ],
    );
    let value = serde_json::json!({
        "version": 1,
        "operation_id": command.operation_id,
        "request_fingerprint": command.request_fingerprint,
        "fence_digest": digest,
    });
    Ok(ExactBytes::new(
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&value),
    ))
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn current_unix_ms() -> Result<u64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("Host clock precedes Unix epoch")?;
    u64::try_from(elapsed.as_millis()).context("Host clock exceeds lifecycle wire range")
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use cats_api::runtime_lifecycle::{
        ColdResult, ColdVolumeDisposition, ColdVolumeDispositionDigest, CommandFailedResult,
        DiskRole, ExecutionAbsenceProof, ImmutableRuntimeConfig, KilledResult, OldNodeIdentity,
        RetainedEvidence, RuntimeVolumeGuestBinding, StartSpec, StartVolumeAuthority,
        SuspendedResult, VolumeAuthorizationId, WarmResult,
    };
    use cats_api::runtime_reconciliation::{
        DirectAuthorizedAttachmentIdentity, DirectAuthorizedAttachmentPurpose, Durability, Epoch,
        FenceEpoch, Generation, GuestDeviceIdentity, Ipv4Address, IsolatedIpv4Kind, MacAddress,
        NetworkConfig, NodeBootId, NormalAcquireRequest, NormalAcquireResult, PreparedDeviceInput,
        RuntimeLaunchArtifact, RuntimeNetworkIdentity, ServingAuthorityProvenance,
        ServingBlockdIdentity, SessionBinding, VmmBootProvenance,
    };

    use crate::lifecycle_command::journal::ExactCommandResult;

    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).expect("valid test Id")
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn random(byte: u8) -> RandomId128 {
        RandomId128::new(format!("{byte:02x}").repeat(16)).expect("valid random Id")
    }

    fn millis(value: u64) -> UnixMillis {
        UnixMillis::new(value).expect("valid test timestamp")
    }

    fn wire(value: u64) -> WireU64 {
        WireU64::new(value).expect("valid wire integer")
    }

    fn placement(node: &str, epoch: u64) -> PlacementIdentity {
        PlacementIdentity {
            node_id: id(node),
            placement_epoch: Epoch::new(epoch).expect("positive placement epoch"),
        }
    }

    fn session(epoch: u64) -> SessionBinding {
        SessionBinding {
            node_id: id("node_start"),
            node_boot_id: NodeBootId::new(format!("{epoch:032x}")).unwrap(),
            agent_instance_id: random(u8::try_from(epoch).unwrap_or(1)),
            agent_session_epoch: Epoch::new(epoch).unwrap(),
        }
    }

    fn runtime_config() -> ImmutableRuntimeConfig {
        ImmutableRuntimeConfig::new(
            id("config_start"),
            digest(1),
            2,
            512 * 1024 * 1024,
            digest(2),
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id: id("network_start"),
                guest_mac: MacAddress::new("02:00:00:00:00:11").unwrap(),
                guest_ipv4: Ipv4Address::new("10.10.0.2").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.10.0.1").unwrap(),
            },
            vec![RuntimeVolumeConfig {
                volume_id: id("volume_root"),
                disk_id: id("disk_root"),
                disk_role: DiskRole::Root,
                size_bytes: 16 * 1024 * 1024,
                durability: Durability::Strict,
                guest_device_serial: id("root_serial"),
                guest_device_slot: 0,
                guest_binding: RuntimeVolumeGuestBinding::RootBoot,
            }],
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

    fn retained_evidence() -> RetainedEvidence {
        RetainedEvidence {
            artifact_manifest_digest: digest(15),
            adoptable_count: 0,
            gc_candidate_count: 0,
            retained_authority_or_data_count: 1,
            quarantined_count: 0,
        }
    }

    fn retained_receipt() -> VolumeTerminalReceipt {
        VolumeTerminalReceipt {
            volume_id: id("volume_root"),
            disk_id: id("disk_root"),
            disk_role: DiskRole::Root,
            attachment_id: id("attachment_retained"),
            attachment_epoch: FenceEpoch::new(7).unwrap(),
            local_durable_generation: Generation::new(9).unwrap(),
            remote_durable_generation: Generation::new(9).unwrap(),
            authority_receipt_digest: Some(digest(16)),
        }
    }

    fn predecessor_response(source: StartSource) -> LifecycleCommandResponse {
        let config = runtime_config();
        let receipt = retained_receipt();
        let result = match source {
            StartSource::SameNodeSuspended => NodeResult::Suspended(Box::new(SuspendedResult {
                runtime_incarnation: random(20),
                runtime_config_digest: config.config_digest,
                pause_receipt_digest: digest(21),
                local_durability_receipts: vec![receipt],
            })),
            StartSource::SameNodeWarm => NodeResult::Warm(Box::new(WarmResult {
                runtime_config_digest: config.config_digest,
                source_runtime_incarnation: random(22),
                warm_snapshot_receipt_digest: digest(23),
                warm_snapshot_manifest_digest: digest(24),
                volume_receipts: vec![receipt],
            })),
            StartSource::SameNodeCold => NodeResult::Cold(Box::new(ColdResult {
                runtime_config_digest: config.config_digest,
                execution_absence: absence(),
                volume_dispositions: vec![ColdVolumeDisposition::NormallyReleased {
                    volume: Box::new(receipt),
                    normal_release_receipt_digest: digest(16),
                }],
                local_recovery_dependency_absent_digest: digest(24),
            })),
            StartSource::SameNodeStopped => NodeResult::Killed(Box::new(KilledResult {
                stopped_runtime_incarnation: Some(random(25)),
                execution_absence: absence(),
                stop_fence_receipt_digest: digest(26),
                retained_volume_receipts: vec![receipt],
                retained_evidence: retained_evidence(),
            })),
            StartSource::SameNodeRetry => NodeResult::StartFailed(Box::new(CommandFailedResult {
                reason: CommandFailureReason::VmmFailed,
                not_running: absence(),
                retained_evidence: retained_evidence(),
                retained_volume_receipts: Vec::new(),
            })),
            _ => panic!("not a same-Node source"),
        };
        LifecycleCommandResponse {
            version: ContractVersion::V1,
            operation_id: id("operation_predecessor"),
            workspace_id: id("workspace_start"),
            cat_id: id("cat_start"),
            node_id: id("node_start"),
            placement_identity: placement("node_start", 4),
            request_fingerprint: digest(27),
            result,
        }
    }

    fn command_for_source(
        source: StartSource,
    ) -> (LifecycleCommandEnvelope, Option<LifecycleCommandResponse>) {
        let config = runtime_config();
        let target = placement("node_start", 4);
        let response = matches!(
            source,
            StartSource::SameNodeSuspended
                | StartSource::SameNodeWarm
                | StartSource::SameNodeCold
                | StartSource::SameNodeStopped
                | StartSource::SameNodeRetry
        )
        .then(|| predecessor_response(source));
        let authority = match source {
            StartSource::SameNodeSuspended
            | StartSource::SameNodeWarm
            | StartSource::SameNodeStopped => RuntimeVolumeAuthorityInput::SameNodeOwned {
                attachment_id: id("attachment_retained"),
                attachment_epoch: FenceEpoch::new(7).unwrap(),
            },
            StartSource::HostFenceRecovery => RuntimeVolumeAuthorityInput::Takeover {
                authorization_id: id("takeover_root"),
            },
            StartSource::Genesis
            | StartSource::SameNodeCold
            | StartSource::SameNodeRetry
            | StartSource::ColdHandoff => RuntimeVolumeAuthorityInput::NormalUnowned {
                expected_unowned_epoch: FenceEpoch::new(7).unwrap(),
                transition_id: random(30),
            },
        };
        let (expected_predecessor_operation_id, predecessor) = match source {
            StartSource::Genesis => (
                None,
                LifecyclePredecessor::Genesis {
                    cat_creation_id: id("creation_start"),
                    target_placement: target.clone(),
                },
            ),
            StartSource::ColdHandoff => (
                Some(id("operation_cold_source")),
                LifecyclePredecessor::CrossNodeColdHandoff {
                    cold_operation_id: id("operation_cold_source"),
                    cold_result_digest: digest(31),
                    source_node_id: id("node_source"),
                    source_placement: placement("node_source", 3),
                    volume_disposition_receipts: vec![
                        ColdVolumeDispositionDigest::NormallyReleased {
                            volume_id: id("volume_root"),
                            normal_release_receipt_digest: digest(32),
                        },
                    ],
                    target_placement: target.clone(),
                },
            ),
            StartSource::HostFenceRecovery => (
                Some(id("operation_interrupted")),
                LifecyclePredecessor::HostFenceRecovery {
                    interrupted_operation_id: id("operation_interrupted"),
                    host_lost_result_digest: digest(33),
                    host_fence_event_id: id("host_fence_event"),
                    old_node_identity: OldNodeIdentity {
                        node_id: id("node_source"),
                        immutable_host_id: id("host_source"),
                        state_path_id: id("state_source"),
                    },
                    takeover_authorization_ids: vec![VolumeAuthorizationId {
                        volume_id: id("volume_root"),
                        authorization_id: id("takeover_root"),
                    }],
                    target_placement: target.clone(),
                },
            ),
            _ => {
                let response = response.as_ref().expect("same-Node response");
                let terminal_result_digest =
                    lifecycle_terminal_result_digest(&LifecycleTerminalResult::NodeResult {
                        response: Box::new(response.clone()),
                    })
                    .unwrap();
                (
                    Some(response.operation_id.clone()),
                    LifecyclePredecessor::SameNode {
                        operation_id: response.operation_id.clone(),
                        terminal_result_kind: response.result.kind(),
                        terminal_result_digest,
                        node_id: response.node_id.clone(),
                        placement_identity: response.placement_identity.clone(),
                    },
                )
            }
        };
        let command = LifecycleCommandEnvelope::new(
            id(match source {
                StartSource::Genesis => "operation_start_genesis",
                StartSource::SameNodeSuspended => "operation_start_suspended",
                StartSource::SameNodeWarm => "operation_start_warm",
                StartSource::SameNodeCold => "operation_start_cold",
                StartSource::SameNodeStopped => "operation_start_stopped",
                StartSource::SameNodeRetry => "operation_start_retry",
                StartSource::ColdHandoff => "operation_start_handoff",
                StartSource::HostFenceRecovery => "operation_start_recovery",
            }),
            id("workspace_start"),
            id("cat_start"),
            target.node_id.clone(),
            target,
            config,
            expected_predecessor_operation_id,
            predecessor,
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: vec![StartVolumeAuthority {
                    volume_id: id("volume_root"),
                    disk_id: id("disk_root"),
                    authority,
                }],
                source,
                effect_deadline_unix_ms: millis(100_000),
            })),
        )
        .expect("valid source-specific Start command");
        (command, response)
    }

    fn failed_predecessor(kind: TerminalResultKind) -> LifecycleCommandResponse {
        let result = match kind {
            TerminalResultKind::StartFailed => {
                NodeResult::StartFailed(Box::new(CommandFailedResult {
                    reason: CommandFailureReason::VmmFailed,
                    not_running: absence(),
                    retained_evidence: retained_evidence(),
                    retained_volume_receipts: vec![retained_receipt()],
                }))
            }
            TerminalResultKind::SuspendFailed => {
                NodeResult::SuspendFailed(Box::new(CommandFailedResult {
                    reason: CommandFailureReason::VmmFailed,
                    not_running: absence(),
                    retained_evidence: retained_evidence(),
                    retained_volume_receipts: vec![retained_receipt()],
                }))
            }
            TerminalResultKind::WarmFailed => {
                NodeResult::WarmFailed(Box::new(CommandFailedResult {
                    reason: CommandFailureReason::VmmFailed,
                    not_running: absence(),
                    retained_evidence: retained_evidence(),
                    retained_volume_receipts: vec![retained_receipt()],
                }))
            }
            _ => panic!("unsupported failed predecessor fixture"),
        };
        LifecycleCommandResponse {
            version: ContractVersion::V1,
            operation_id: id("operation_failed_predecessor"),
            workspace_id: id("workspace_start"),
            cat_id: id("cat_start"),
            node_id: id("node_start"),
            placement_identity: placement("node_start", 4),
            request_fingerprint: digest(91),
            result,
        }
    }

    fn owned_retry_command(
        operation_id: &str,
        predecessor: &LifecycleCommandResponse,
    ) -> LifecycleCommandEnvelope {
        let terminal_result_digest =
            lifecycle_terminal_result_digest(&LifecycleTerminalResult::NodeResult {
                response: Box::new(predecessor.clone()),
            })
            .unwrap();
        let target = placement("node_start", 4);
        LifecycleCommandEnvelope::new(
            id(operation_id),
            id("workspace_start"),
            id("cat_start"),
            target.node_id.clone(),
            target,
            runtime_config(),
            Some(predecessor.operation_id.clone()),
            LifecyclePredecessor::SameNode {
                operation_id: predecessor.operation_id.clone(),
                terminal_result_kind: predecessor.result.kind(),
                terminal_result_digest,
                node_id: predecessor.node_id.clone(),
                placement_identity: predecessor.placement_identity.clone(),
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: vec![StartVolumeAuthority {
                    volume_id: id("volume_root"),
                    disk_id: id("disk_root"),
                    authority: RuntimeVolumeAuthorityInput::SameNodeOwned {
                        attachment_id: id("attachment_retained"),
                        attachment_epoch: FenceEpoch::new(7).unwrap(),
                    },
                }],
                source: StartSource::SameNodeRetry,
                effect_deadline_unix_ms: millis(100_000),
            })),
        )
        .unwrap()
    }

    fn inherited_projection_fixture(
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        target_runtime_incarnation: RandomId128,
        predecessor_runtime_incarnation: Option<RandomId128>,
    ) -> InheritedPredecessorPhysicalProjection {
        inherited_predecessor_physical_projection(
            command,
            predecessor,
            target_runtime_incarnation,
            digest(92),
            predecessor_runtime_incarnation,
            None,
            vec![InheritedPredecessorPhysicalVolume {
                volume_id: id("volume_root"),
                disk_id: id("disk_root"),
                disk_role: DiskRole::Root,
                attachment_id: id("attachment_retained"),
                attachment_epoch: FenceEpoch::new(7).unwrap(),
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: random(30),
                },
                authoritative_head: RemoteHead {
                    generation: Generation::new(9).unwrap(),
                    root_hash: None,
                    root_object_id: None,
                },
                immutable_start_grant_receipt_digest: digest(16),
                local_lineage_data_directory: None,
            }],
        )
        .unwrap()
    }

    fn command_volume_receipt(command: &LifecycleCommandEnvelope) -> VolumeTerminalReceipt {
        VolumeTerminalReceipt {
            volume_id: id("volume_root"),
            disk_id: id("disk_root"),
            disk_role: DiskRole::Root,
            attachment_id: deterministic_attachment_id(command, &command.runtime_config.volumes[0])
                .unwrap(),
            attachment_epoch: FenceEpoch::new(8).unwrap(),
            local_durable_generation: Generation::new(3).unwrap(),
            remote_durable_generation: Generation::new(3).unwrap(),
            authority_receipt_digest: Some(digest(41)),
        }
    }

    fn command_grant(command: &LifecycleCommandEnvelope) -> AtomicStartVolumeGrant {
        let volume = command_volume_receipt(command);
        let expiry = millis(current_unix_ms().unwrap() + 120_000);
        let head = RemoteHead {
            generation: Generation::new(3).unwrap(),
            root_hash: None,
            root_object_id: None,
        };
        let transition_id = random(30);
        let authority_receipt = LifecycleCommandStartVolumeGrantReceipt {
            scope: cats_api::runtime_lifecycle_volume::LifecycleVolumeCommandScope {
                operation_id: command.operation_id.clone(),
                request_fingerprint: command.request_fingerprint.clone(),
                cat_id: command.cat_id.clone(),
                node_id: command.node_id.clone(),
                placement_identity: command.placement_identity.clone(),
            },
            grant_sequence: wire(0),
            volume: command.runtime_config.volumes[0].clone(),
            authority: LifecycleStartVolumeGrantAuthority::NormalAcquire {
                request: NormalAcquireRequest {
                    volume_id: volume.volume_id.clone(),
                    transition_id: transition_id.clone(),
                    attachment_id: volume.attachment_id.clone(),
                    expected_unowned_epoch: FenceEpoch::new(7).unwrap(),
                    placement_epoch: command.placement_identity.placement_epoch,
                    lease_duration_ms: 60_000,
                },
                result: NormalAcquireResult {
                    volume_id: volume.volume_id.clone(),
                    transition_id: transition_id.clone(),
                    attachment_id: volume.attachment_id.clone(),
                    resulting_epoch: volume.attachment_epoch,
                    resulting_head: head.clone(),
                    lease_expires_at: expiry,
                },
            },
        };
        AtomicStartVolumeGrant::new(
            volume,
            AcquireOrigin::Normal { transition_id },
            head,
            expiry,
            digest(41),
            authority_receipt,
            HostPath::new("/var/lib/cats/root-lineage").unwrap(),
        )
    }

    fn progress_volume(
        receipt: &VolumeTerminalReceipt,
        with_device: bool,
    ) -> InstalledRuntimeProgressVolumeManifest {
        InstalledRuntimeProgressVolumeManifest {
            volume_id: receipt.volume_id.clone(),
            disk_id: receipt.disk_id.clone(),
            disk_role: receipt.disk_role,
            attachment_id: receipt.attachment_id.clone(),
            attachment_epoch: receipt.attachment_epoch,
            acquire_origin: AcquireOrigin::Normal {
                transition_id: random(30),
            },
            authority_head: RemoteHead {
                generation: receipt.remote_durable_generation,
                root_hash: None,
                root_object_id: None,
            },
            authority_receipt_digest: receipt.authority_receipt_digest.clone(),
            local_lineage_data_directory: Some(
                HostPath::new("/var/lib/cats/root-lineage").unwrap(),
            ),
            blockd: with_device.then(|| InstalledRuntimeProcessIdentity {
                pid: 310,
                start_time_ticks: wire(31_000),
            }),
            blockd_control_socket_path: with_device
                .then(|| HostPath::new("/run/cats/root-blockd.sock").unwrap()),
            frontend: with_device.then(|| InstalledRuntimeBlockFrontend::KernelNbd {
                device_path: HostPath::new("/dev/nbd7").unwrap(),
                client: InstalledRuntimeProcessIdentity {
                    pid: 311,
                    start_time_ticks: wire(31_100),
                },
            }),
        }
    }

    fn network_manifest() -> InstalledRuntimeNetworkManifest {
        InstalledRuntimeNetworkManifest {
            identity: Box::new(RuntimeNetworkIdentity {
                network_config: NetworkConfig {
                    kind: IsolatedIpv4Kind::IsolatedIpv4,
                    network_id: id("network_start"),
                    guest_mac: MacAddress::new("02:00:00:00:00:11").unwrap(),
                    guest_ipv4: Ipv4Address::new("10.10.0.2").unwrap(),
                    prefix_length: 30,
                    gateway_ipv4: Ipv4Address::new("10.10.0.1").unwrap(),
                },
                tap_name: id("tap_start"),
                ownership_token: random(42),
            }),
        }
    }

    fn launch_artifact(path: &str, byte: u8) -> RuntimeLaunchArtifact {
        RuntimeLaunchArtifact {
            path: HostPath::new(path).unwrap(),
            length: wire(4096),
            content_sha256: digest(byte),
        }
    }

    fn vmm_manifest(
        command: &LifecycleCommandEnvelope,
        runtime_incarnation: &RandomId128,
        receipt: &VolumeTerminalReceipt,
        network: &InstalledRuntimeNetworkManifest,
    ) -> InstalledRuntimeVmmManifest {
        let slice = crate::cat_execution_scope::cat_execution_slice_id(&command.cat_id);
        let RuntimeNetworkConfig::IsolatedIpv4 {
            network_id,
            guest_mac,
            guest_ipv4,
            prefix_length,
            gateway_ipv4,
        } = &command.runtime_config.network_config;
        let data_directory = HostPath::new("/var/lib/cats/root-lineage").unwrap();
        let control_socket = HostPath::new("/run/cats/root-blockd.sock").unwrap();
        let api_socket = HostPath::new("/run/cats/ch-api.sock").unwrap();
        let vsock_socket = HostPath::new("/run/cats/ch-vsock.sock").unwrap();
        let memory_file = HostPath::new("/var/lib/cats/ch-memory").unwrap();
        let launch = RuntimeLaunchIdentity {
            runtime_incarnation: runtime_incarnation.clone(),
            scope_id: slice.clone(),
            launcher_executable: Box::new(launch_artifact("/usr/lib/cats/vmm-launcher", 43)),
            boot: Box::new(VmmBootProvenance {
                vmm_executable: launch_artifact("/usr/bin/cloud-hypervisor", 44),
                kernel: launch_artifact("/usr/lib/cats/vmlinux", 45),
                initramfs: Some(launch_artifact("/usr/lib/cats/initramfs", 46)),
                kernel_cmdline: cats_api::runtime_reconciliation::AsciiText::new(
                    "console=hvc0 root=/dev/vda",
                )
                .unwrap(),
            }),
            process_identity_token: random(47),
            vcpus: command.runtime_config.vcpus,
            memory_bytes: command.runtime_config.memory_bytes,
            boot_image_digest: command.runtime_config.boot_image_digest.clone(),
            guest_config_digest: command.runtime_config.guest_runtime_profile_digest.clone(),
            api_socket_path: api_socket.clone(),
            vsock_socket_path: vsock_socket.clone(),
            guest_cid: 8,
            memory_file_path: memory_file.clone(),
            serial_log_path: HostPath::new("/var/log/cats/ch-serial.log").unwrap(),
            vmm_log_path: HostPath::new("/var/log/cats/ch.log").unwrap(),
            network: Box::new(RuntimeNetworkIdentity {
                network_config: NetworkConfig {
                    kind: IsolatedIpv4Kind::IsolatedIpv4,
                    network_id: network_id.clone(),
                    guest_mac: guest_mac.clone(),
                    guest_ipv4: guest_ipv4.clone(),
                    prefix_length: *prefix_length,
                    gateway_ipv4: gateway_ipv4.clone(),
                },
                tap_name: network.identity.tap_name.clone(),
                ownership_token: network.identity.ownership_token.clone(),
            }),
            devices: vec![PreparedDeviceInput {
                volume_intent_id: atomic_start_launch_volume_id(
                    command,
                    &command.runtime_config.volumes[0],
                )
                .unwrap(),
                disk_id: receipt.disk_id.clone(),
                volume_id: receipt.volume_id.clone(),
                disk_kind: DiskKind::Root,
                attachment_id: receipt.attachment_id.clone(),
                attachment_epoch: receipt.attachment_epoch,
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: random(30),
                },
                expected_head: RemoteHead {
                    generation: receipt.remote_durable_generation,
                    root_hash: None,
                    root_object_id: None,
                },
                size_bytes: command.runtime_config.volumes[0].size_bytes,
                durability: command.runtime_config.volumes[0].durability,
                guest_device: GuestDeviceIdentity {
                    serial: command.runtime_config.volumes[0]
                        .guest_device_serial
                        .clone(),
                    slot: command.runtime_config.volumes[0].guest_device_slot,
                },
                ownership_token: random(48),
                serving_authority: Box::new(
                    ServingAuthorityProvenance::DirectAuthorizedAttachment {
                        authorization: DirectAuthorizedAttachmentIdentity {
                            path: HostPath::new("/run/cats/root-authority.json").unwrap(),
                            device: wire(1),
                            inode: wire(2),
                            length: wire(3),
                            content_sha256: digest(49),
                        },
                        purpose: DirectAuthorizedAttachmentPurpose::ExistingRoot,
                    },
                ),
                serving_process: ServingBlockdIdentity {
                    scope_id: slice.clone(),
                    control_socket_path: control_socket,
                    data_directory,
                    executable_path: HostPath::new("/usr/bin/cats-blockd").unwrap(),
                    process_identity_token: random(50),
                },
                frontend: PrepareDeviceFrontend::KernelNbd {
                    listener_socket_path: HostPath::new("/run/cats/root-nbd.sock").unwrap(),
                    device_path: HostPath::new("/dev/nbd7").unwrap(),
                    direct: true,
                },
            }],
        };
        InstalledRuntimeVmmManifest {
            process: InstalledRuntimeProcessIdentity {
                pid: 410,
                start_time_ticks: wire(41_000),
            },
            parent_slice_id: slice,
            systemd_unit_id: id("cats_vmm_start"),
            api_socket_path: api_socket,
            vsock_socket_path: vsock_socket,
            memory_file_path: memory_file,
            launch_identity: Box::new(launch),
        }
    }

    fn partial_progress(
        command: &LifecycleCommandEnvelope,
        incarnation: &RandomId128,
    ) -> InstalledRuntimeProgressManifest {
        let grant = command_grant(command);
        InstalledRuntimeProgressManifest::new(
            command,
            incarnation.clone(),
            None,
            None,
            vec![progress_volume(&grant.volume, false)],
            volume_grant_artifacts(std::slice::from_ref(&grant)).unwrap(),
        )
        .unwrap()
    }

    fn full_progress(
        command: &LifecycleCommandEnvelope,
        incarnation: &RandomId128,
    ) -> InstalledRuntimeProgressManifest {
        let grant = command_grant(command);
        let network = network_manifest();
        let vmm = vmm_manifest(command, incarnation, &grant.volume, &network);
        InstalledRuntimeProgressManifest::new(
            command,
            incarnation.clone(),
            Some(vmm),
            Some(network),
            vec![progress_volume(&grant.volume, true)],
            volume_grant_artifacts(std::slice::from_ref(&grant)).unwrap(),
        )
        .unwrap()
    }

    fn context_after_prepare_root(
        command: &LifecycleCommandEnvelope,
        incarnation: RandomId128,
    ) -> AtomicStartRuntimeContext {
        let grant = command_grant(command);
        let artifacts = volume_grant_artifacts(std::slice::from_ref(&grant)).unwrap();
        let progress = partial_progress(command, &incarnation);
        let platform_plan = ExactBytes::new(vec![1]);
        let platform_plan_digest = platform_plan_digest(
            command,
            AtomicStartRuntimeEffectPhase::PrepareRoot,
            &platform_plan,
        );
        let platform_receipt = ExactBytes::new(vec![2]);
        let receipt_digest = atomic_start_platform_receipt_digest(
            command,
            AtomicStartRuntimeEffectPhase::PrepareRoot,
            &platform_plan_digest,
            &platform_receipt,
        )
        .unwrap();
        AtomicStartRuntimeContext {
            runtime_incarnation: incarnation,
            source: StartSource::Genesis,
            local_predecessor: None,
            warm_restart_source: None,
            effect_deadline_unix_ms: millis(100_000),
            volume_lease_duration_ms: wire(60_000),
            runtime_effect_timeout_ms: wire(30_000),
            volume_lease_session: session(1),
            volume_grant_sequence: wire(0),
            volume_grants: vec![grant],
            runtime_progress: progress.clone(),
            completed_effects: vec![AtomicStartRuntimeEffectReceipt {
                phase: AtomicStartRuntimeEffectPhase::PrepareRoot,
                platform_plan,
                platform_plan_digest,
                platform_receipt,
                receipt_digest,
                artifact_classifications: Vec::new(),
                runtime_progress: progress,
            }],
            session_rebind_receipts: Vec::new(),
            artifact_classifications: artifacts,
        }
    }

    fn progress_after_phase(
        command: &LifecycleCommandEnvelope,
        incarnation: &RandomId128,
        phase: AtomicStartRuntimeEffectPhase,
    ) -> InstalledRuntimeProgressManifest {
        let grant = command_grant(command);
        let network =
            (phase >= AtomicStartRuntimeEffectPhase::PrepareNetwork).then(network_manifest);
        let vmm = (phase >= AtomicStartRuntimeEffectPhase::ActivateRuntime).then(|| {
            vmm_manifest(
                command,
                incarnation,
                &grant.volume,
                network.as_ref().expect("activated runtime has network"),
            )
        });
        InstalledRuntimeProgressManifest::new(
            command,
            incarnation.clone(),
            vmm,
            network,
            vec![progress_volume(
                &grant.volume,
                phase >= AtomicStartRuntimeEffectPhase::PrepareDevices,
            )],
            volume_grant_artifacts(std::slice::from_ref(&grant)).unwrap(),
        )
        .unwrap()
    }

    fn context_before_phase(
        command: &LifecycleCommandEnvelope,
        incarnation: RandomId128,
        phase: AtomicStartRuntimeEffectPhase,
    ) -> AtomicStartRuntimeContext {
        let grant = command_grant(command);
        let artifacts = volume_grant_artifacts(std::slice::from_ref(&grant)).unwrap();
        let phases = [
            AtomicStartRuntimeEffectPhase::PrepareRoot,
            AtomicStartRuntimeEffectPhase::PrepareDevices,
            AtomicStartRuntimeEffectPhase::PrepareNetwork,
            AtomicStartRuntimeEffectPhase::ActivateRuntime,
            AtomicStartRuntimeEffectPhase::FormatPersistentVolumes,
            AtomicStartRuntimeEffectPhase::CommitPersistentInitialized,
        ];
        let mut completed_effects = Vec::new();
        for (index, completed_phase) in phases
            .into_iter()
            .take_while(|completed| *completed < phase)
            .enumerate()
        {
            let platform_plan = ExactBytes::new(vec![index as u8 + 1]);
            let platform_plan_digest =
                platform_plan_digest(command, completed_phase, &platform_plan);
            let platform_receipt = ExactBytes::new(vec![index as u8 + 32]);
            let receipt_digest = atomic_start_platform_receipt_digest(
                command,
                completed_phase,
                &platform_plan_digest,
                &platform_receipt,
            )
            .unwrap();
            completed_effects.push(AtomicStartRuntimeEffectReceipt {
                phase: completed_phase,
                platform_plan,
                platform_plan_digest,
                platform_receipt,
                receipt_digest,
                artifact_classifications: Vec::new(),
                runtime_progress: progress_after_phase(command, &incarnation, completed_phase),
            });
        }
        let runtime_progress = completed_effects
            .last()
            .map(|receipt| receipt.runtime_progress.clone())
            .unwrap_or_else(|| {
                initial_runtime_progress_from_volume_grants(
                    command,
                    incarnation.clone(),
                    std::slice::from_ref(&grant),
                )
                .unwrap()
            });
        AtomicStartRuntimeContext {
            runtime_incarnation: incarnation,
            source: StartSource::Genesis,
            local_predecessor: None,
            warm_restart_source: None,
            effect_deadline_unix_ms: millis(100_000),
            volume_lease_duration_ms: wire(60_000),
            runtime_effect_timeout_ms: wire(30_000),
            volume_lease_session: session(1),
            volume_grant_sequence: wire(0),
            volume_grants: vec![grant],
            runtime_progress,
            completed_effects,
            session_rebind_receipts: Vec::new(),
            artifact_classifications: artifacts,
        }
    }

    fn final_manifest(
        command: &LifecycleCommandEnvelope,
        incarnation: &RandomId128,
    ) -> InstalledRuntimeManifest {
        let receipt = command_volume_receipt(command);
        let network = network_manifest();
        let vmm = vmm_manifest(command, incarnation, &receipt, &network);
        InstalledRuntimeManifest::new(
            command,
            incarnation.clone(),
            digest(51),
            digest(52),
            None,
            vmm,
            network,
            vec![InstalledRuntimeVolumeManifest {
                volume_id: receipt.volume_id,
                disk_id: receipt.disk_id,
                disk_role: receipt.disk_role,
                attachment_id: receipt.attachment_id,
                attachment_epoch: receipt.attachment_epoch,
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: random(30),
                },
                launch_head: RemoteHead {
                    generation: receipt.remote_durable_generation,
                    root_hash: None,
                    root_object_id: None,
                },
                current_authority_head: RemoteHead {
                    generation: receipt.remote_durable_generation,
                    root_hash: None,
                    root_object_id: None,
                },
                authority_receipt_digest: receipt.authority_receipt_digest,
                local_lineage_data_directory: HostPath::new("/var/lib/cats/root-lineage").unwrap(),
                blockd: InstalledRuntimeProcessIdentity {
                    pid: 310,
                    start_time_ticks: wire(31_000),
                },
                blockd_control_socket_path: HostPath::new("/run/cats/root-blockd.sock").unwrap(),
                frontend: InstalledRuntimeBlockFrontend::KernelNbd {
                    device_path: HostPath::new("/dev/nbd7").unwrap(),
                    client: InstalledRuntimeProcessIdentity {
                        pid: 311,
                        start_time_ticks: wire(31_100),
                    },
                },
            }],
        )
        .unwrap()
    }

    #[test]
    fn all_start_sources_select_only_their_typed_volume_authority() {
        for source in [
            StartSource::Genesis,
            StartSource::SameNodeSuspended,
            StartSource::SameNodeWarm,
            StartSource::SameNodeCold,
            StartSource::SameNodeStopped,
            StartSource::SameNodeRetry,
            StartSource::ColdHandoff,
            StartSource::HostFenceRecovery,
        ] {
            let (command, predecessor) = command_for_source(source);
            validate_start_predecessor(&command, predecessor.as_ref(), source).unwrap();
            let lease = wire(60_000);
            let request = volume_batch_request(&command, lease).unwrap();
            assert_eq!(request.renewal_lease_duration_ms, lease);
            match (&request.actions[0], source) {
                (
                    AtomicStartVolumeAction::RenewSameNode {
                        attachment_id,
                        attachment_epoch,
                        lease_duration_ms,
                        ..
                    },
                    StartSource::SameNodeSuspended
                    | StartSource::SameNodeWarm
                    | StartSource::SameNodeStopped,
                ) => {
                    assert_eq!(attachment_id, &id("attachment_retained"));
                    assert_eq!(*attachment_epoch, FenceEpoch::new(7).unwrap());
                    assert_eq!(*lease_duration_ms, lease);
                }
                (
                    AtomicStartVolumeAction::Takeover {
                        authorization_id, ..
                    },
                    StartSource::HostFenceRecovery,
                ) => assert_eq!(authorization_id, &id("takeover_root")),
                (
                    AtomicStartVolumeAction::NormalAcquire {
                        expected_unowned_epoch,
                        transition_id,
                        lease_duration_ms,
                        ..
                    },
                    StartSource::Genesis
                    | StartSource::SameNodeCold
                    | StartSource::SameNodeRetry
                    | StartSource::ColdHandoff,
                ) => {
                    assert_eq!(*expected_unowned_epoch, FenceEpoch::new(7).unwrap());
                    assert_eq!(transition_id, &random(30));
                    assert_eq!(*lease_duration_ms, lease);
                }
                pair => panic!("unexpected source/action pair: {pair:?}"),
            }
            if source == StartSource::SameNodeSuspended {
                let expected = match &predecessor.as_ref().unwrap().result {
                    NodeResult::Suspended(value) => &value.runtime_incarnation,
                    _ => unreachable!(),
                };
                assert_eq!(
                    &start_runtime_incarnation(source, predecessor.as_ref()).unwrap(),
                    expected
                );
            }
        }
    }

    #[test]
    fn retry_without_terminal_manifest_requires_zero_evidence_and_rich_absence() {
        let (command, predecessor) = command_for_source(StartSource::SameNodeRetry);
        let mut predecessor = predecessor.unwrap();
        let NodeResult::StartFailed(failed) = &mut predecessor.result else {
            panic!("retry fixture is not StartFailed")
        };
        let physical = StartupPhysicalInventory::Complete {
            scan_id: random(58),
            collected_at_unix_ms: millis(59),
            cats: Vec::new(),
            unattributed_artifacts: Vec::new(),
        };

        assert!(
            validate_empty_start_retry_physical_absence(&command, failed, &[], &physical,).is_err()
        );

        failed.retained_evidence = RetainedEvidence {
            artifact_manifest_digest: digest(60),
            adoptable_count: 0,
            gc_candidate_count: 0,
            retained_authority_or_data_count: 0,
            quarantined_count: 0,
        };
        validate_empty_start_retry_physical_absence(&command, failed, &[], &physical).unwrap();

        failed.retained_volume_receipts = vec![retained_receipt()];
        assert!(
            validate_empty_start_retry_physical_absence(&command, failed, &[], &physical).is_err()
        );
        failed.retained_volume_receipts.clear();

        let mut ambiguous = physical;
        let StartupPhysicalInventory::Complete {
            unattributed_artifacts,
            ..
        } = &mut ambiguous
        else {
            unreachable!()
        };
        unattributed_artifacts.push(ObservedArtifactClassification::RetainedAuthorityOrData {
            artifact_id: id("unknown_retry_artifact"),
            evidence_digest: digest(61),
        });
        assert!(
            validate_empty_start_retry_physical_absence(&command, failed, &[], &ambiguous,)
                .is_err()
        );
    }

    #[test]
    fn exact_volume_request_replay_is_deterministic_and_ambiguity_is_not_hidden() {
        #[derive(Default)]
        struct AmbiguousPort {
            requests: Mutex<Vec<AtomicStartVolumeBatchRequest>>,
        }
        impl AtomicStartVolumePort for AmbiguousPort {
            fn configured_lease_duration_ms(&self) -> WireU64 {
                wire(60_000)
            }

            fn current_agent_session_binding(&self) -> Result<SessionBinding> {
                Ok(session(1))
            }

            fn inspect_or_apply_start_volumes(
                &self,
                _command: &LifecycleCommandEnvelope,
                request: &AtomicStartVolumeBatchRequest,
                _planned_agent_session: &SessionBinding,
            ) -> Result<AtomicStartVolumeOutcome> {
                self.requests.lock().unwrap().push(request.clone());
                anyhow::bail!("transport ambiguous; discovery unavailable")
            }
        }

        let (command, _) = command_for_source(StartSource::Genesis);
        let request_a = volume_batch_request(&command, wire(60_000)).unwrap();
        let request_b = volume_batch_request(&command, wire(60_000)).unwrap();
        assert_eq!(request_a, request_b);
        let port = AmbiguousPort::default();
        assert!(port
            .inspect_or_apply_start_volumes(&command, &request_a, &session(1))
            .is_err());
        assert!(port
            .inspect_or_apply_start_volumes(&command, &request_b, &session(1))
            .is_err());
        assert_eq!(
            port.requests.into_inner().unwrap(),
            vec![request_a, request_b]
        );
    }

    #[test]
    fn volume_grant_rounds_are_durable_strict_successors() {
        let (command, _) = command_for_source(StartSource::Genesis);
        let grant = command_grant(&command);
        let initial = volume_batch_request(&command, wire(60_000)).unwrap();
        assert_eq!(initial.grant_sequence, wire(0));

        let first = refresh_volume_batch_request(
            &command,
            wire(60_000),
            initial.grant_sequence,
            std::slice::from_ref(&grant),
        )
        .unwrap();
        let second = refresh_volume_batch_request(
            &command,
            wire(60_000),
            first.grant_sequence,
            std::slice::from_ref(&grant),
        )
        .unwrap();
        assert_eq!(first.grant_sequence, wire(1));
        assert_eq!(second.grant_sequence, wire(2));
        assert_eq!(first.actions, second.actions);

        assert!(validate_volume_batch_receipt(
            &command,
            &first,
            &AtomicStartVolumeBatchReceipt {
                grant_sequence: wire(0),
                grants: vec![grant.clone()],
            },
        )
        .is_err());
        assert!(refresh_volume_batch_request(
            &command,
            wire(60_000),
            wire(i64::MAX as u64),
            &[grant],
        )
        .is_err());

        let evidence =
            AtomicStartVolumeFailureEvidence::local_deadline_elapsed(&command, &initial).unwrap();
        assert_eq!(
            validate_atomic_start_volume_failure_evidence(&command, &initial, &evidence).unwrap(),
            AtomicStartVolumeFailureDisposition::LocalDeadlineElapsed
        );
        let mut tampered = evidence;
        tampered.request_digest = digest(99);
        assert!(
            validate_atomic_start_volume_failure_evidence(&command, &initial, &tampered).is_err()
        );
    }

    #[test]
    fn journal_binding_rejects_absence_or_mismatch_without_selecting_an_effect() {
        let (command, _) = command_for_source(StartSource::Genesis);
        let incarnation = random(60);
        let progress = partial_progress(&command, &incarnation);
        assert!(bind_installed_runtime_progress_to_journal(None, None, &progress).is_err());

        let request = volume_batch_request(&command, wire(60_000)).unwrap();
        let acquire = execution_step(
            &command,
            StartStepState::AcquireVolumes {
                request: request.clone(),
                planned_agent_session: session(1),
                runtime_incarnation: incarnation.clone(),
                source: StartSource::Genesis,
                warm_restart_source: None,
                effect_deadline_unix_ms: millis(100_000),
                runtime_effect_timeout_ms: wire(30_000),
            },
        )
        .unwrap();
        assert!(bind_installed_runtime_progress_to_journal(
            Some(&command),
            Some(&acquire),
            &progress,
        )
        .is_err());

        let grant = command_grant(&command);
        let authority_only = initial_runtime_progress_from_volume_grants(
            &command,
            incarnation.clone(),
            std::slice::from_ref(&grant),
        )
        .unwrap();
        assert_eq!(
            bind_installed_runtime_progress_to_journal(
                Some(&command),
                Some(&acquire),
                &authority_only,
            )
            .unwrap(),
            InstalledRuntimeProgressJournalBinding::RequiresVolumeAuthorityDiscovery {
                request: Box::new(request),
                planned_agent_session: session(1),
            }
        );
        let artifacts = volume_grant_artifacts(std::slice::from_ref(&grant)).unwrap();
        let authority_progress = initial_runtime_progress_from_volume_grants(
            &command,
            incarnation.clone(),
            std::slice::from_ref(&grant),
        )
        .unwrap();
        let runtime_request = AtomicStartRuntimeEffectRequest {
            phase: AtomicStartRuntimeEffectPhase::PrepareRoot,
            context: AtomicStartRuntimeContext {
                runtime_incarnation: incarnation,
                source: StartSource::Genesis,
                local_predecessor: None,
                warm_restart_source: None,
                effect_deadline_unix_ms: millis(100_000),
                volume_lease_duration_ms: wire(60_000),
                runtime_effect_timeout_ms: wire(30_000),
                volume_lease_session: session(1),
                volume_grant_sequence: wire(0),
                volume_grants: vec![grant],
                runtime_progress: authority_progress,
                completed_effects: Vec::new(),
                session_rebind_receipts: Vec::new(),
                artifact_classifications: artifacts,
            },
            platform_plan: ExactBytes::new(vec![1]),
        };
        let executing = execution_step(
            &command,
            StartStepState::RuntimeEffect {
                request: runtime_request.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            bind_installed_runtime_progress_to_journal(
                Some(&command),
                Some(&executing),
                &progress,
            )
            .unwrap(),
            InstalledRuntimeProgressJournalBinding::RequiresCurrentEffectDiscovery {
                request: Box::new(runtime_request)
            }
        );

        let (other_command, _) = command_for_source(StartSource::ColdHandoff);
        assert!(bind_installed_runtime_progress_to_journal(
            Some(&other_command),
            Some(&executing),
            &progress,
        )
        .is_err());
    }

    #[test]
    fn startup_slice_binding_closes_acquire_and_every_runtime_ambiguity() {
        let (command, _) = command_for_source(StartSource::Genesis);
        let incarnation = random(62);
        assert_eq!(
            bind_installed_start_physical_to_journal(
                &command,
                &CommandJournalState::Accepted { stop_fence: None },
                &[],
            )
            .unwrap(),
            InstalledStartStartupBinding::NoPhysicalEvidence
        );
        let acquire_request = volume_batch_request(&command, wire(60_000)).unwrap();
        let acquire_step = execution_step(
            &command,
            StartStepState::AcquireVolumes {
                request: acquire_request.clone(),
                planned_agent_session: session(1),
                runtime_incarnation: incarnation.clone(),
                source: StartSource::Genesis,
                warm_restart_source: None,
                effect_deadline_unix_ms: millis(100_000),
                runtime_effect_timeout_ms: wire(30_000),
            },
        )
        .unwrap();
        let acquire_state = CommandJournalState::Executing {
            step: acquire_step,
            stop_fence: None,
        };
        assert_eq!(
            bind_installed_start_physical_to_journal(&command, &acquire_state, &[]).unwrap(),
            InstalledStartStartupBinding::NoPhysicalEvidence
        );
        let grant = command_grant(&command);
        let authority_progress = initial_runtime_progress_from_volume_grants(
            &command,
            incarnation.clone(),
            std::slice::from_ref(&grant),
        )
        .unwrap();
        assert_eq!(
            bind_installed_start_physical_to_journal(
                &command,
                &acquire_state,
                &[InstalledStartPhysicalInventoryEntry::Executing(Box::new(
                    authority_progress
                ),)],
            )
            .unwrap(),
            InstalledStartStartupBinding::RequiresVolumeAuthorityDiscovery {
                request: Box::new(acquire_request),
                planned_agent_session: session(1),
            }
        );
        let rejected_request = volume_batch_request(&command, wire(60_000)).unwrap();
        let rejected_evidence =
            AtomicStartVolumeFailureEvidence::local_deadline_elapsed(&command, &rejected_request)
                .unwrap();
        let rejected_step = execution_step(
            &command,
            StartStepState::StrongStopFailure {
                reason: CommandFailureReason::InvalidLocalPrecondition,
                artifact_classifications: Vec::new(),
                volume_grants: Vec::new(),
                runtime_progress: None,
                failed_volume_effect: Some(AtomicStartFailedVolumeEffect {
                    request: rejected_request,
                    evidence: rejected_evidence,
                }),
                inherited_predecessor_physical: None,
                warm_restart_source: None,
            },
        )
        .unwrap();
        assert_eq!(
            bind_installed_start_physical_to_journal(
                &command,
                &CommandJournalState::Executing {
                    step: rejected_step,
                    stop_fence: None,
                },
                &[],
            )
            .unwrap(),
            InstalledStartStartupBinding::NoPhysicalEvidence
        );

        let phases = [
            AtomicStartRuntimeEffectPhase::PrepareRoot,
            AtomicStartRuntimeEffectPhase::PrepareDevices,
            AtomicStartRuntimeEffectPhase::PrepareNetwork,
            AtomicStartRuntimeEffectPhase::ActivateRuntime,
            AtomicStartRuntimeEffectPhase::FormatPersistentVolumes,
            AtomicStartRuntimeEffectPhase::CommitPersistentInitialized,
            AtomicStartRuntimeEffectPhase::GuestReadyAndAdmission,
        ];
        for (index, phase) in phases.into_iter().enumerate() {
            let context = context_before_phase(&command, incarnation.clone(), phase);
            let request = AtomicStartRuntimeEffectRequest {
                phase,
                context: context.clone(),
                platform_plan: ExactBytes::new(vec![90 + index as u8]),
            };
            let step = execution_step(
                &command,
                StartStepState::RuntimeEffect {
                    request: request.clone(),
                },
            )
            .unwrap();
            let state = CommandJournalState::Executing {
                step,
                stop_fence: None,
            };
            assert!(bind_installed_start_physical_to_journal(&command, &state, &[]).is_err());
            let discovered = progress_after_phase(&command, &incarnation, phase);
            let expected = if discovered == context.runtime_progress {
                // Format/commit/readiness phases may have no additional
                // inventory projection. Their exact embedded evidence resumes
                // the same journal request, whose provider entry point must
                // inspect that phase before attempting any mutation.
                InstalledStartStartupBinding::ExactEmbeddedEvidence
            } else {
                InstalledStartStartupBinding::RequiresCurrentEffectDiscovery {
                    request: Box::new(request.clone()),
                }
            };
            assert_eq!(
                bind_installed_start_physical_to_journal(
                    &command,
                    &state,
                    &[InstalledStartPhysicalInventoryEntry::Executing(Box::new(
                        discovered,
                    ))],
                )
                .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn completed_progress_is_embedded_in_the_successor_step() {
        let (command, _) = command_for_source(StartSource::Genesis);
        let incarnation = random(61);
        let progress = partial_progress(&command, &incarnation);
        validate_completed_runtime_progress_manifest(
            &progress,
            &command,
            AtomicStartRuntimeEffectPhase::PrepareRoot,
        )
        .unwrap();
        let grant = command_grant(&command);
        let artifacts = volume_grant_artifacts(std::slice::from_ref(&grant)).unwrap();
        let completed_plan = ExactBytes::new(vec![1]);
        let completed_plan_digest = platform_plan_digest(
            &command,
            AtomicStartRuntimeEffectPhase::PrepareRoot,
            &completed_plan,
        );
        let completed_platform_receipt = ExactBytes::new(vec![61]);
        let completed_receipt_digest = atomic_start_platform_receipt_digest(
            &command,
            AtomicStartRuntimeEffectPhase::PrepareRoot,
            &completed_plan_digest,
            &completed_platform_receipt,
        )
        .unwrap();
        let context = AtomicStartRuntimeContext {
            runtime_incarnation: incarnation,
            source: StartSource::Genesis,
            local_predecessor: None,
            warm_restart_source: None,
            effect_deadline_unix_ms: millis(100_000),
            volume_lease_duration_ms: wire(60_000),
            runtime_effect_timeout_ms: wire(30_000),
            volume_lease_session: session(1),
            volume_grant_sequence: wire(0),
            volume_grants: vec![grant],
            runtime_progress: progress.clone(),
            completed_effects: vec![AtomicStartRuntimeEffectReceipt {
                phase: AtomicStartRuntimeEffectPhase::PrepareRoot,
                platform_plan: completed_plan.clone(),
                platform_plan_digest: completed_plan_digest,
                platform_receipt: completed_platform_receipt,
                receipt_digest: completed_receipt_digest,
                artifact_classifications: Vec::new(),
                runtime_progress: progress.clone(),
            }],
            session_rebind_receipts: Vec::new(),
            artifact_classifications: artifacts,
        };
        let successor = planned_refresh_volumes(
            &command,
            context,
            AtomicStartRuntimeEffectPhase::PrepareDevices,
            Some(ExactBytes::new(vec![2])),
            session(1),
        )
        .unwrap();
        assert_eq!(
            bind_installed_runtime_progress_to_journal(
                Some(&command),
                Some(&successor.step),
                &progress,
            )
            .unwrap(),
            InstalledRuntimeProgressJournalBinding::ExactEmbeddedEvidence
        );
        assert_eq!(
            bind_installed_start_physical_to_journal(
                &command,
                &CommandJournalState::Executing {
                    step: successor.step,
                    stop_fence: None,
                },
                &[InstalledStartPhysicalInventoryEntry::Executing(Box::new(
                    progress,
                ))],
            )
            .unwrap(),
            InstalledStartStartupBinding::ExactEmbeddedEvidence
        );
    }

    #[test]
    fn platform_receipts_are_bound_to_command_phase_plan_and_aggregate_budget() {
        let (command, _) = command_for_source(StartSource::Genesis);
        let context = context_after_prepare_root(&command, random(63));
        validate_runtime_context(
            &command,
            &context,
            AtomicStartRuntimeEffectPhase::PrepareDevices,
        )
        .unwrap();

        let mut tampered = context.clone();
        tampered.completed_effects[0].platform_receipt = ExactBytes::new(vec![3]);
        assert!(validate_runtime_context(
            &command,
            &tampered,
            AtomicStartRuntimeEffectPhase::PrepareDevices,
        )
        .is_err());

        let mut phase_swapped = context.clone();
        phase_swapped.completed_effects[0].phase = AtomicStartRuntimeEffectPhase::PrepareDevices;
        assert!(validate_runtime_context(
            &command,
            &phase_swapped,
            AtomicStartRuntimeEffectPhase::PrepareDevices,
        )
        .is_err());

        assert!(validate_platform_receipt(&ExactBytes::new(vec![0; 131_073])).is_err());

        let mut rebound = context_before_phase(
            &command,
            random(64),
            AtomicStartRuntimeEffectPhase::PrepareRoot,
        );
        let old_plan = ExactBytes::new(vec![7]);
        let old_plan_digest = platform_plan_digest(
            &command,
            AtomicStartRuntimeEffectPhase::PrepareRoot,
            &old_plan,
        );
        let cleanup = ExactBytes::new(vec![8]);
        let cleanup_digest = atomic_start_session_rebind_receipt_digest(
            &command,
            AtomicStartRuntimeEffectPhase::PrepareRoot,
            rebound.volume_grant_sequence,
            &old_plan_digest,
            &cleanup,
        )
        .unwrap();
        rebound
            .session_rebind_receipts
            .push(AtomicStartSessionRebindReceipt {
                phase: AtomicStartRuntimeEffectPhase::PrepareRoot,
                volume_grant_sequence: rebound.volume_grant_sequence,
                old_platform_plan: old_plan,
                old_platform_plan_digest: old_plan_digest,
                cleanup_receipt: cleanup,
                cleanup_receipt_digest: cleanup_digest,
                runtime_progress: rebound.runtime_progress.clone(),
            });
        validate_runtime_context(
            &command,
            &rebound,
            AtomicStartRuntimeEffectPhase::PrepareRoot,
        )
        .unwrap();
        rebound.session_rebind_receipts[0].cleanup_receipt = ExactBytes::new(vec![9]);
        assert!(validate_runtime_context(
            &command,
            &rebound,
            AtomicStartRuntimeEffectPhase::PrepareRoot,
        )
        .is_err());

        let grant = command_grant(&command);
        let artifacts = volume_grant_artifacts(std::slice::from_ref(&grant)).unwrap();
        let incarnation = random(64);
        let partial = partial_progress(&command, &incarnation);
        let full = full_progress(&command, &incarnation);
        let phases = [
            AtomicStartRuntimeEffectPhase::PrepareRoot,
            AtomicStartRuntimeEffectPhase::PrepareDevices,
            AtomicStartRuntimeEffectPhase::PrepareNetwork,
            AtomicStartRuntimeEffectPhase::ActivateRuntime,
            AtomicStartRuntimeEffectPhase::FormatPersistentVolumes,
            AtomicStartRuntimeEffectPhase::CommitPersistentInitialized,
        ];
        let mut completed_effects = Vec::new();
        for (index, phase) in phases.into_iter().enumerate() {
            let plan = ExactBytes::new(vec![index as u8 + 1]);
            let plan_digest = platform_plan_digest(&command, phase, &plan);
            let platform_receipt = ExactBytes::new(vec![index as u8 + 10; 131_072]);
            let receipt_digest = atomic_start_platform_receipt_digest(
                &command,
                phase,
                &plan_digest,
                &platform_receipt,
            )
            .unwrap();
            completed_effects.push(AtomicStartRuntimeEffectReceipt {
                phase,
                platform_plan: plan,
                platform_plan_digest: plan_digest,
                platform_receipt,
                receipt_digest,
                artifact_classifications: Vec::new(),
                runtime_progress: if index == 0 {
                    partial.clone()
                } else {
                    full.clone()
                },
            });
        }
        let oversized = AtomicStartRuntimeEffectRequest {
            phase: AtomicStartRuntimeEffectPhase::GuestReadyAndAdmission,
            context: AtomicStartRuntimeContext {
                runtime_incarnation: incarnation,
                source: StartSource::Genesis,
                local_predecessor: None,
                warm_restart_source: None,
                effect_deadline_unix_ms: millis(100_000),
                volume_lease_duration_ms: wire(60_000),
                runtime_effect_timeout_ms: wire(30_000),
                volume_lease_session: session(1),
                volume_grant_sequence: wire(0),
                volume_grants: vec![grant],
                runtime_progress: full,
                completed_effects,
                session_rebind_receipts: Vec::new(),
                artifact_classifications: artifacts,
            },
            platform_plan: ExactBytes::new(vec![99]),
        };
        assert!(validate_runtime_effect_request(&command, &oversized).is_err());
    }

    #[test]
    fn normal_phase_transition_journals_renewal_before_planning_successor() {
        let (command, _) = command_for_source(StartSource::Genesis);
        let context = context_after_prepare_root(&command, random(65));
        let step = planned_refresh_volumes(
            &command,
            context,
            AtomicStartRuntimeEffectPhase::PrepareDevices,
            None,
            session(1),
        )
        .unwrap()
        .step;
        let payload = decode_step(&command, &step).unwrap();
        let StartStepState::RefreshVolumes {
            request,
            next_phase,
            resume_platform_plan,
            ..
        } = payload.state
        else {
            panic!("normal successor did not journal Volume refresh")
        };
        assert_eq!(request.grant_sequence, wire(1));
        assert_eq!(next_phase, AtomicStartRuntimeEffectPhase::PrepareDevices);
        assert_eq!(resume_platform_plan, None);
    }

    #[test]
    fn persistent_format_commit_preserves_grant_then_guest_ready_renews() {
        struct PlanningRuntimePort;

        impl AtomicStartRuntimePort for PlanningRuntimePort {
            fn configured_effect_timeout_ms(&self) -> WireU64 {
                wire(30_000)
            }

            fn plan_start_effect(
                &self,
                _command: &LifecycleCommandEnvelope,
                phase: AtomicStartRuntimeEffectPhase,
                _context: &AtomicStartRuntimeContext,
            ) -> Result<ExactBytes> {
                anyhow::ensure!(
                    phase == AtomicStartRuntimeEffectPhase::CommitPersistentInitialized,
                    "test port planned an unexpected phase"
                );
                Ok(ExactBytes::new(vec![65]))
            }

            fn inspect_or_apply_start_effect(
                &self,
                _command: &LifecycleCommandEnvelope,
                _request: &AtomicStartRuntimeEffectRequest,
            ) -> Result<AtomicStartRuntimeEffectOutcome> {
                anyhow::bail!("test port must not apply an effect")
            }
        }

        let (command, _) = command_for_source(StartSource::Genesis);
        let port = PlanningRuntimePort;
        let commit_context = context_before_phase(
            &command,
            random(103),
            AtomicStartRuntimeEffectPhase::CommitPersistentInitialized,
        );
        let immutable_sequence = commit_context.volume_grant_sequence;
        let immutable_grants = commit_context.volume_grants.clone();
        let successor = planned_successor_after_completed_runtime_effect(
            &port,
            &command,
            AtomicStartRuntimeEffectPhase::FormatPersistentVolumes,
            commit_context.clone(),
            session(1),
        )
        .unwrap();
        let payload = decode_step(&command, &successor.step).unwrap();
        let StartStepState::RuntimeEffect { request } = payload.state else {
            panic!("Format completion inserted a Volume renewal before commit")
        };
        assert_eq!(
            request.phase,
            AtomicStartRuntimeEffectPhase::CommitPersistentInitialized
        );
        assert_eq!(request.platform_plan, ExactBytes::new(vec![65]));
        assert_eq!(request.context, commit_context);
        assert_eq!(request.context.volume_grant_sequence, immutable_sequence);
        assert_eq!(request.context.volume_grants, immutable_grants);

        let ready_context = context_before_phase(
            &command,
            random(104),
            AtomicStartRuntimeEffectPhase::GuestReadyAndAdmission,
        );
        let immutable_sequence = ready_context.volume_grant_sequence;
        let immutable_grants = ready_context.volume_grants.clone();
        let successor = planned_successor_after_completed_runtime_effect(
            &port,
            &command,
            AtomicStartRuntimeEffectPhase::CommitPersistentInitialized,
            ready_context.clone(),
            session(1),
        )
        .unwrap();
        let payload = decode_step(&command, &successor.step).unwrap();
        let StartStepState::RefreshVolumes {
            request,
            context,
            next_phase,
            resume_platform_plan,
            ..
        } = payload.state
        else {
            panic!("Commit completion did not restore the Volume renewal gate")
        };
        assert_eq!(
            next_phase,
            AtomicStartRuntimeEffectPhase::GuestReadyAndAdmission
        );
        assert_eq!(resume_platform_plan, None);
        assert_eq!(request.grant_sequence.get(), immutable_sequence.get() + 1);
        assert_eq!(context, ready_context);
        assert_eq!(context.volume_grant_sequence, immutable_sequence);
        assert_eq!(context.volume_grants, immutable_grants);
    }

    #[test]
    fn runtime_ready_manifest_uses_the_latest_renewed_start_grant_digest() {
        let (command, _) = command_for_source(StartSource::Genesis);
        let latest_digest = digest(105);
        let mut latest_receipt = command_volume_receipt(&command);
        latest_receipt.authority_receipt_digest = Some(latest_digest.clone());
        let mut latest_grant = command_grant(&command);
        latest_grant.grant_receipt_digest = latest_digest.clone();
        latest_grant.volume.authority_receipt_digest = Some(latest_digest.clone());

        validate_runtime_ready_volume_receipts(
            &command,
            std::slice::from_ref(&latest_grant),
            std::slice::from_ref(&latest_receipt),
        )
        .expect("RuntimeReady accepts the latest renewed StartGrant digest");
        assert!(validate_runtime_ready_volume_receipts(
            &command,
            &[latest_grant],
            &[command_volume_receipt(&command)],
        )
        .is_err());

        let mut latest_manifest = final_manifest(&command, &random(106));
        latest_manifest.volumes[0].authority_receipt_digest = Some(latest_digest);
        latest_manifest.manifest_digest =
            installed_runtime_manifest_digest(&latest_manifest).unwrap();
        validate_installed_runtime_manifest(&latest_manifest, &command)
            .expect("latest-grant installed manifest is canonical");
        validate_manifest_volume_receipts(&latest_manifest, &[latest_receipt])
            .expect("installed manifest retains the latest renewed StartGrant digest");
    }

    #[test]
    fn lease_expiry_can_journal_renewal_only_with_exact_zero_mutation() {
        let (command, _) = command_for_source(StartSource::Genesis);
        let incarnation = random(66);
        let context = context_before_phase(
            &command,
            incarnation.clone(),
            AtomicStartRuntimeEffectPhase::PrepareRoot,
        );
        let plan = ExactBytes::new(vec![66]);
        let request = AtomicStartRuntimeEffectRequest {
            phase: AtomicStartRuntimeEffectPhase::PrepareRoot,
            context: context.clone(),
            platform_plan: plan.clone(),
        };
        let plan_digest =
            platform_plan_digest(&command, AtomicStartRuntimeEffectPhase::PrepareRoot, &plan);
        let successor = planned_runtime_requested_volume_refresh(
            &command,
            request.clone(),
            plan_digest.clone(),
            Some(context.runtime_progress.clone()),
            session(1),
        )
        .unwrap();
        let payload = decode_step(&command, &successor.step).unwrap();
        let StartStepState::RefreshVolumes {
            next_phase,
            resume_platform_plan,
            ..
        } = payload.state
        else {
            panic!("lease expiry did not journal a Volume refresh")
        };
        assert_eq!(next_phase, AtomicStartRuntimeEffectPhase::PrepareRoot);
        assert_eq!(resume_platform_plan, Some(plan));

        let mutated = progress_after_phase(
            &command,
            &incarnation,
            AtomicStartRuntimeEffectPhase::PrepareRoot,
        );
        assert!(planned_runtime_requested_volume_refresh(
            &command,
            request,
            plan_digest,
            Some(mutated),
            session(1),
        )
        .is_err());
    }

    #[test]
    fn monotonic_lease_witness_is_session_local_restart_closed_and_wall_clock_independent() {
        let (command, _) = command_for_source(StartSource::Genesis);
        let request = volume_batch_request(&command, wire(60_000)).unwrap();
        let mut grant = command_grant(&command);
        // The wire expiry remains immutable evidence, but even an already
        // elapsed wall value is not consulted by the local safety oracle.
        grant.lease_expires_at_unix_ms = millis(1);
        let receipt = AtomicStartVolumeBatchReceipt {
            grant_sequence: wire(0),
            grants: vec![grant.clone()],
        };
        let context = AtomicStartRuntimeContext {
            runtime_incarnation: random(102),
            source: StartSource::Genesis,
            local_predecessor: None,
            warm_restart_source: None,
            effect_deadline_unix_ms: millis(i64::MAX as u64),
            volume_lease_duration_ms: wire(60_000),
            runtime_effect_timeout_ms: wire(30_000),
            volume_lease_session: session(1),
            volume_grant_sequence: wire(0),
            volume_grants: vec![grant],
            runtime_progress: initial_runtime_progress_from_volume_grants(
                &command,
                random(102),
                &receipt.grants,
            )
            .unwrap(),
            completed_effects: Vec::new(),
            session_rebind_receipts: Vec::new(),
            artifact_classifications: volume_grant_artifacts(&receipt.grants).unwrap(),
        };

        forget_process_local_start_lease_witnesses(&command.operation_id).unwrap();
        let started =
            begin_start_volume_lease_request_at(&request, &session(1), &session(1), Instant::now())
                .unwrap();
        publish_start_volume_lease_witness(&request, &receipt, &session(1), started).unwrap();
        assert!(runtime_context_has_monotonic_lease_budget(
            &context,
            Duration::from_millis(35_000),
        )
        .unwrap());

        // A restarted process has an empty registry even though the durable
        // grant still carries a future-looking Unix expiry.
        forget_process_local_start_lease_witnesses(&command.operation_id).unwrap();
        assert!(
            !runtime_context_has_monotonic_lease_budget(&context, Duration::from_millis(1),)
                .unwrap()
        );

        // Replaying an old-session durable request discovers its response but
        // cannot mint a witness in the replacement session.
        let stale =
            begin_start_volume_lease_request_at(&request, &session(1), &session(2), Instant::now())
                .unwrap();
        assert!(stale.is_none());
        publish_start_volume_lease_witness(&request, &receipt, &session(1), stale).unwrap();
        assert!(
            !runtime_context_has_monotonic_lease_budget(&context, Duration::from_millis(1),)
                .unwrap()
        );

        // An exact replay in one session retains the first request instant;
        // receiving the same response again cannot extend server authority.
        let old_start = Instant::now()
            .checked_sub(Duration::from_millis(59_000))
            .unwrap();
        let first =
            begin_start_volume_lease_request_at(&request, &session(1), &session(1), old_start)
                .unwrap();
        let replay =
            begin_start_volume_lease_request_at(&request, &session(1), &session(1), Instant::now())
                .unwrap();
        assert_eq!(first, replay);
        publish_start_volume_lease_witness(&request, &receipt, &session(1), replay).unwrap();
        assert!(!runtime_context_has_monotonic_lease_budget(
            &context,
            Duration::from_millis(2_000),
        )
        .unwrap());

        assert!(validate_start_lease_effect_policy(wire(35_000), wire(30_000)).is_err());
        validate_start_lease_effect_policy(wire(35_001), wire(30_000)).unwrap();
        forget_process_local_start_lease_witnesses(&command.operation_id).unwrap();
    }

    #[test]
    fn progress_publication_is_exact_monotonic_and_strictly_enumerated() {
        let directory = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(directory.path().to_path_buf());
        let (command, _) = command_for_source(StartSource::Genesis);
        let incarnation = random(70);
        let partial = partial_progress(&command, &incarnation);
        let full = full_progress(&command, &incarnation);
        validate_completed_runtime_progress_manifest(
            &full,
            &command,
            AtomicStartRuntimeEffectPhase::ActivateRuntime,
        )
        .unwrap();

        publish_installed_runtime_progress_manifest(&state, &partial).unwrap();
        assert_eq!(
            load_installed_runtime_progress_manifest(&state, &command).unwrap(),
            Some(partial.clone())
        );
        publish_installed_runtime_progress_manifest(&state, &full).unwrap();
        assert_eq!(
            load_installed_runtime_progress_manifest(&state, &command).unwrap(),
            Some(full.clone())
        );
        assert_eq!(
            enumerate_installed_runtime_progress_manifests(&state).unwrap(),
            vec![full]
        );
        assert!(publish_installed_runtime_progress_manifest(&state, &partial).is_err());
        assert!(remove_installed_runtime_progress_manifest_exact(&state, &partial).is_err());

        std::fs::write(
            directory
                .path()
                .join(RUNTIME_PROGRESS_NAMESPACE)
                .join(format!("{}{RUNTIME_PROGRESS_TEMP_SUFFIX}", "a".repeat(64))),
            b"partial",
        )
        .unwrap();
        assert!(enumerate_installed_runtime_progress_manifests(&state).is_err());
    }

    #[test]
    fn failed_start_progress_is_atomically_sealed_non_executable() {
        let directory = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(directory.path().to_path_buf());
        let (command, _) = command_for_source(StartSource::Genesis);
        let incarnation = random(75);
        let progress = partial_progress(&command, &incarnation);
        let grant = command_grant(&command);
        let failure_step = execution_step(
            &command,
            StartStepState::StrongStopFailure {
                reason: CommandFailureReason::VmmFailed,
                artifact_classifications: progress.artifact_classifications.clone(),
                volume_grants: vec![grant.clone()],
                runtime_progress: Some(progress.clone()),
                failed_volume_effect: None,
                inherited_predecessor_physical: None,
                warm_restart_source: None,
            },
        )
        .unwrap();
        publish_installed_runtime_progress_manifest(&state, &progress).unwrap();
        let stop = StrongStopEvidence {
            execution_absence: absence(),
            restart_source_cleanup_receipt_digest: None,
            retained_warm_restart_source: None,
            stopped_runtime_incarnation: Some(incarnation),
            retained_volume_receipts: vec![command_volume_receipt(&command)],
            retained_evidence: retained_evidence(),
            post_stop_physical_projection_digest: digest(76),
        };
        let manifest =
            TerminalRetainedRuntimeManifest::new(&command, vec![grant], progress, &stop).unwrap();
        assert_eq!(
            manifest.retention_mode,
            TerminalRetainedRuntimeMode::MaterializedOrAmbiguous
        );
        let sealed = seal_terminal_retained_runtime_manifest(&state, &manifest).unwrap();
        assert_eq!(sealed, manifest);
        assert_eq!(
            bind_installed_start_physical_to_journal(
                &command,
                &CommandJournalState::Executing {
                    step: failure_step,
                    stop_fence: None,
                },
                &[InstalledStartPhysicalInventoryEntry::TerminalRetained(
                    Box::new(manifest.clone()),
                )],
            )
            .unwrap(),
            InstalledStartStartupBinding::ReplaySealedTerminal {
                manifest: Box::new(manifest.clone()),
            }
        );
        assert_eq!(
            load_terminal_retained_runtime_manifest(&state, &command).unwrap(),
            Some(manifest.clone())
        );
        assert!(load_installed_runtime_progress_manifest(&state, &command).is_err());
        assert!(enumerate_installed_runtime_progress_manifests(&state)
            .unwrap()
            .is_empty());
        assert_eq!(
            enumerate_terminal_retained_runtime_manifests(&state).unwrap(),
            vec![manifest.clone()]
        );
        assert_eq!(
            enumerate_installed_start_physical_manifests(&state).unwrap(),
            vec![InstalledStartPhysicalInventoryEntry::TerminalRetained(
                Box::new(manifest.clone())
            )]
        );

        let mut later_stop = stop;
        later_stop.post_stop_physical_projection_digest = digest(77);
        later_stop
            .retained_evidence
            .retained_authority_or_data_count = 2;
        validate_terminal_retained_replay_evidence(&manifest, &later_stop).unwrap();
        let mut changed_owner = later_stop.clone();
        changed_owner.retained_volume_receipts[0].attachment_id = id("another_attachment");
        assert!(validate_terminal_retained_replay_evidence(&manifest, &changed_owner).is_err());
        let later = TerminalRetainedRuntimeManifest::new(
            &command,
            manifest.volume_grants.clone(),
            manifest
                .runtime_progress
                .clone()
                .expect("materialized fixture retains runtime progress"),
            &later_stop,
        )
        .unwrap();
        assert_ne!(later.manifest_digest, manifest.manifest_digest);
        assert_eq!(
            seal_terminal_retained_runtime_manifest(&state, &later).unwrap(),
            manifest
        );

        let terminal_response = LifecycleCommandResponse {
            version: ContractVersion::V1,
            operation_id: command.operation_id.clone(),
            workspace_id: command.workspace_id.clone(),
            cat_id: command.cat_id.clone(),
            node_id: command.node_id.clone(),
            placement_identity: command.placement_identity.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            result: NodeResult::StartFailed(Box::new(CommandFailedResult {
                reason: CommandFailureReason::VmmFailed,
                not_running: manifest.execution_absence.clone(),
                retained_evidence: RetainedEvidence {
                    artifact_manifest_digest: manifest.manifest_digest.clone(),
                    ..manifest.physical_retained_evidence.clone()
                },
                retained_volume_receipts: manifest.retained_volume_receipts.clone(),
            })),
        };
        assert!(matches!(
            bind_installed_start_physical_to_journal(
                &command,
                &CommandJournalState::Terminal {
                    result: ExactCommandResult::from_api(&terminal_response).unwrap(),
                    stop_fence: None,
                },
                &[InstalledStartPhysicalInventoryEntry::TerminalRetained(
                    Box::new(manifest.clone()),
                )],
            )
            .unwrap(),
            InstalledStartStartupBinding::ReplaySealedTerminal { .. }
        ));
        assert!(remove_terminal_retained_runtime_manifest_exact(&state, &sealed).unwrap());
        assert!(enumerate_installed_start_physical_manifests(&state)
            .unwrap()
            .is_empty());

        let authority_grant = command_grant(&command);
        let authority_progress = initial_runtime_progress_from_volume_grants(
            &command,
            random(78),
            std::slice::from_ref(&authority_grant),
        )
        .unwrap();
        let authority_only = TerminalRetainedRuntimeManifest::new(
            &command,
            vec![authority_grant],
            authority_progress,
            &StrongStopEvidence {
                execution_absence: absence(),
                restart_source_cleanup_receipt_digest: None,
                retained_warm_restart_source: None,
                stopped_runtime_incarnation: None,
                retained_volume_receipts: vec![command_volume_receipt(&command)],
                retained_evidence: retained_evidence(),
                post_stop_physical_projection_digest: digest(79),
            },
        )
        .unwrap();
        assert!(matches!(
            authority_only.retention_mode,
            TerminalRetainedRuntimeMode::AuthorityOnlyOwnedZeroMutation { .. }
        ));
        let mut renewed_authority_only = authority_only;
        renewed_authority_only.volume_grants[0]
            .authority_receipt
            .grant_sequence = wire(1);
        renewed_authority_only.manifest_digest =
            terminal_retained_runtime_manifest_digest(&renewed_authority_only).unwrap();
        assert!(
            validate_terminal_retained_runtime_manifest(&renewed_authority_only, None).is_err()
        );
    }

    #[test]
    fn inherited_predecessor_owned_is_sealed_replayed_and_tamper_closed() {
        for (suffix, kind) in [
            ("start", TerminalResultKind::StartFailed),
            ("suspend", TerminalResultKind::SuspendFailed),
            ("warm", TerminalResultKind::WarmFailed),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let state = StateDirectory::unanchored(directory.path().to_path_buf());
            let predecessor = failed_predecessor(kind);
            let command =
                owned_retry_command(&format!("operation_inherited_{suffix}"), &predecessor);
            validate_start_predecessor(&command, Some(&predecessor), StartSource::SameNodeRetry)
                .unwrap();
            let request = volume_batch_request(&command, wire(60_000)).unwrap();
            let failed_volume_effect = AtomicStartFailedVolumeEffect {
                evidence: AtomicStartVolumeFailureEvidence::local_deadline_elapsed(
                    &command, &request,
                )
                .unwrap(),
                request,
            };
            let target_incarnation = random(93);
            let physical_incarnation = random(94);
            let projection = inherited_projection_fixture(
                &command,
                &predecessor,
                target_incarnation.clone(),
                Some(physical_incarnation.clone()),
            );
            validate_inherited_predecessor_physical_projection(
                &command,
                &failed_volume_effect,
                &projection,
            )
            .unwrap();

            let stop = StrongStopEvidence {
                execution_absence: absence(),
                restart_source_cleanup_receipt_digest: None,
                retained_warm_restart_source: None,
                stopped_runtime_incarnation: Some(physical_incarnation.clone()),
                retained_volume_receipts: vec![retained_receipt()],
                retained_evidence: retained_evidence(),
                post_stop_physical_projection_digest: digest(95),
            };
            let evidence = inherited_predecessor_owned_evidence_from_strong_stop(
                &command,
                &predecessor,
                &projection,
                &failed_volume_effect,
                &stop,
            )
            .unwrap();
            let manifest = TerminalRetainedRuntimeManifest::new_inherited_predecessor_owned(
                &command,
                target_incarnation,
                evidence,
                &stop,
            )
            .unwrap();
            assert!(manifest.runtime_progress.is_none());
            assert!(manifest.volume_grants.is_empty());
            assert!(matches!(
                manifest.retention_mode,
                TerminalRetainedRuntimeMode::InheritedPredecessorOwned { .. }
            ));

            let failure_step = execution_step(
                &command,
                StartStepState::StrongStopFailure {
                    reason: CommandFailureReason::InvalidLocalPrecondition,
                    artifact_classifications: Vec::new(),
                    volume_grants: Vec::new(),
                    runtime_progress: None,
                    failed_volume_effect: Some(failed_volume_effect.clone()),
                    inherited_predecessor_physical: Some(projection.clone()),
                    warm_restart_source: projection.warm_restart_source.clone(),
                },
            )
            .unwrap();
            let sealed = seal_terminal_retained_runtime_manifest(&state, &manifest).unwrap();
            assert_eq!(sealed, manifest);
            assert_eq!(
                bind_installed_start_physical_to_journal(
                    &command,
                    &CommandJournalState::Executing {
                        step: failure_step,
                        stop_fence: None,
                    },
                    &[InstalledStartPhysicalInventoryEntry::TerminalRetained(
                        Box::new(manifest.clone()),
                    )],
                )
                .unwrap(),
                InstalledStartStartupBinding::ReplaySealedTerminal {
                    manifest: Box::new(manifest.clone()),
                }
            );
            validate_terminal_retained_replay_evidence(&manifest, &stop).unwrap();

            let mut changed_projection = projection;
            changed_projection.target_request_fingerprint = digest(96);
            assert!(validate_inherited_predecessor_physical_projection(
                &command,
                &failed_volume_effect,
                &changed_projection,
            )
            .is_err());

            let mut invented_absent_tail = manifest.clone();
            let TerminalRetainedRuntimeMode::InheritedPredecessorOwned { evidence } =
                &mut invented_absent_tail.retention_mode
            else {
                unreachable!()
            };
            evidence.volumes[0]
                .retained_receipt
                .local_durable_generation = Generation::new(10).unwrap();
            invented_absent_tail.retained_volume_receipts[0].local_durable_generation =
                Generation::new(10).unwrap();
            invented_absent_tail.manifest_digest =
                terminal_retained_runtime_manifest_digest(&invented_absent_tail).unwrap();
            assert!(validate_terminal_retained_runtime_manifest(
                &invented_absent_tail,
                Some(&command),
            )
            .is_err());

            let mut changed_terminal = manifest;
            let TerminalRetainedRuntimeMode::InheritedPredecessorOwned { evidence } =
                &mut changed_terminal.retention_mode
            else {
                unreachable!()
            };
            evidence.predecessor_terminal_result_digest = digest(97);
            changed_terminal.manifest_digest =
                terminal_retained_runtime_manifest_digest(&changed_terminal).unwrap();
            assert!(
                validate_terminal_retained_runtime_manifest(&changed_terminal, Some(&command),)
                    .is_err()
            );
        }
    }

    #[test]
    fn inherited_renew_rejection_never_accepts_takeover_unavailable() {
        let predecessor = failed_predecessor(TerminalResultKind::StartFailed);
        let command = owned_retry_command("operation_inherited_rejection", &predecessor);
        let request = volume_batch_request(&command, wire(60_000)).unwrap();
        assert!(request
            .actions
            .iter()
            .all(|action| matches!(action, AtomicStartVolumeAction::RenewSameNode { .. })));

        let rejected = |reason| LifecycleVolumeTransitionResponse {
            version: ContractVersion::V1,
            session: session(1),
            operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            result: LifecycleVolumeTransitionResult::Rejected { reason },
        };
        let authority_rejected = AtomicStartVolumeFailureEvidence::control_rejected(
            &command,
            &request,
            &rejected(LifecycleVolumeTransitionRejection::AuthorityRejected),
        )
        .unwrap();
        let authority_failure = AtomicStartFailedVolumeEffect {
            request: request.clone(),
            evidence: authority_rejected,
        };
        let projection =
            inherited_projection_fixture(&command, &predecessor, random(101), Some(random(102)));
        validate_inherited_predecessor_physical_projection(
            &command,
            &authority_failure,
            &projection,
        )
        .unwrap();

        let takeover_outcome = AtomicStartVolumeFailureOutcome::ControlRejected {
            canonical_response: ExactBytes::new(
                encode_lifecycle_volume_transition_response(&rejected(
                    LifecycleVolumeTransitionRejection::TakeoverUnavailable,
                ))
                .unwrap(),
            ),
        };
        let request_digest = atomic_start_volume_batch_request_digest(&request).unwrap();
        let takeover_unavailable = AtomicStartVolumeFailureEvidence {
            evidence_digest: atomic_start_volume_failure_evidence_digest(
                &command,
                &request_digest,
                &takeover_outcome,
            )
            .unwrap(),
            request_digest,
            outcome: takeover_outcome,
        };
        let takeover_failure = AtomicStartFailedVolumeEffect {
            request,
            evidence: takeover_unavailable,
        };
        assert!(validate_inherited_predecessor_physical_projection(
            &command,
            &takeover_failure,
            &projection,
        )
        .is_err());
    }

    #[test]
    fn inherited_retry_chain_keeps_the_original_physical_incarnation() {
        let directory = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(directory.path().to_path_buf());
        let predecessor = failed_predecessor(TerminalResultKind::WarmFailed);
        let first = owned_retry_command("operation_inherited_first", &predecessor);
        let request = volume_batch_request(&first, wire(60_000)).unwrap();
        let failed_volume_effect = AtomicStartFailedVolumeEffect {
            evidence: AtomicStartVolumeFailureEvidence::local_deadline_elapsed(&first, &request)
                .unwrap(),
            request,
        };
        let target_incarnation = random(98);
        let physical_incarnation = random(99);
        let projection = inherited_projection_fixture(
            &first,
            &predecessor,
            target_incarnation.clone(),
            Some(physical_incarnation.clone()),
        );
        let stop = StrongStopEvidence {
            execution_absence: absence(),
            restart_source_cleanup_receipt_digest: None,
            retained_warm_restart_source: None,
            stopped_runtime_incarnation: Some(physical_incarnation.clone()),
            retained_volume_receipts: vec![retained_receipt()],
            retained_evidence: retained_evidence(),
            post_stop_physical_projection_digest: digest(100),
        };
        let inherited = inherited_predecessor_owned_evidence_from_strong_stop(
            &first,
            &predecessor,
            &projection,
            &failed_volume_effect,
            &stop,
        )
        .unwrap();
        let first_manifest = TerminalRetainedRuntimeManifest::new_inherited_predecessor_owned(
            &first,
            target_incarnation.clone(),
            inherited,
            &stop,
        )
        .unwrap();
        seal_terminal_retained_runtime_manifest(&state, &first_manifest).unwrap();
        let first_response = LifecycleCommandResponse {
            version: ContractVersion::V1,
            operation_id: first.operation_id.clone(),
            workspace_id: first.workspace_id.clone(),
            cat_id: first.cat_id.clone(),
            node_id: first.node_id.clone(),
            placement_identity: first.placement_identity.clone(),
            request_fingerprint: first.request_fingerprint.clone(),
            result: NodeResult::StartFailed(Box::new(CommandFailedResult {
                reason: CommandFailureReason::InvalidLocalPrecondition,
                not_running: first_manifest.execution_absence.clone(),
                retained_evidence: RetainedEvidence {
                    artifact_manifest_digest: first_manifest.manifest_digest.clone(),
                    ..first_manifest.physical_retained_evidence.clone()
                },
                retained_volume_receipts: first_manifest.retained_volume_receipts.clone(),
            })),
        };
        let second = owned_retry_command("operation_inherited_second", &first_response);
        let second_projection =
            retry_predecessor_physical_projection(&state, &second, &first_response, random(101))
                .unwrap();
        assert_eq!(
            second_projection.runtime_incarnation,
            Some(physical_incarnation)
        );
        assert_ne!(
            second_projection.runtime_incarnation,
            Some(target_incarnation)
        );
    }

    #[test]
    fn final_manifest_publish_load_enumerate_and_corruption_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(directory.path().to_path_buf());
        let (command, _) = command_for_source(StartSource::Genesis);
        let manifest = final_manifest(&command, &random(80));

        publish_installed_runtime_manifest(&state, &manifest).unwrap();
        publish_installed_runtime_manifest(&state, &manifest).unwrap();
        assert_eq!(
            load_installed_runtime_manifest(&state, &command.cat_id).unwrap(),
            Some(manifest.clone())
        );
        assert_eq!(
            enumerate_installed_runtime_manifests(&state).unwrap(),
            vec![manifest]
        );

        let path = installed_runtime_manifest_path(&state, &command.cat_id);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.push(b'\n');
        std::fs::write(&path, bytes).unwrap();
        assert!(load_installed_runtime_manifest(&state, &command.cat_id).is_err());
        assert!(enumerate_installed_runtime_manifests(&state).is_err());
    }

    #[test]
    fn executable_restart_source_absence_is_bound_only_to_warm_restore() {
        let (command, _) = command_for_source(StartSource::Genesis);
        let mut manifest = final_manifest(&command, &random(81));
        manifest.retired_restart_source_absence_digest = Some(digest(82));
        manifest.manifest_digest = installed_runtime_manifest_digest(&manifest).unwrap();
        assert!(validate_installed_runtime_manifest(&manifest, &command).is_err());
    }

    #[test]
    fn stale_or_non_authoritative_volume_evidence_fails_closed() {
        let (command, _) = command_for_source(StartSource::Genesis);
        let request = volume_batch_request(&command, wire(60_000)).unwrap();
        let mut advanced = command_grant(&command);
        advanced.volume.local_durable_generation = Generation::new(4).unwrap();
        advanced.volume.remote_durable_generation = Generation::new(4).unwrap();
        advanced.authoritative_head = RemoteHead {
            generation: Generation::new(4).unwrap(),
            root_hash: None,
            root_object_id: None,
        };
        advanced.lease_expires_at_unix_ms = millis(advanced.lease_expires_at_unix_ms.get() + 1_000);
        validate_volume_batch_receipt(
            &command,
            &request,
            &AtomicStartVolumeBatchReceipt {
                grant_sequence: wire(0),
                grants: vec![advanced],
            },
        )
        .unwrap();

        let mut grant = command_grant(&command);
        grant.volume.authority_receipt_digest = None;
        assert!(validate_volume_batch_receipt(
            &command,
            &request,
            &AtomicStartVolumeBatchReceipt {
                grant_sequence: wire(0),
                grants: vec![grant]
            },
        )
        .is_err());

        let mut expired = command_grant(&command);
        expired.lease_expires_at_unix_ms = millis(1);
        assert!(!volume_grants_are_live(&[expired]).unwrap());
    }
}
