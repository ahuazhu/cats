//! Atomic per-Cat lifecycle v1 shared wire.
//!
//! PostgreSQL admits one command and stores one exact terminal result. The
//! Node owns all physical effects and recovery. Observation is intentionally
//! absent from command settlement. AgentSession authenticates transport only;
//! it is never part of durable command or result identity.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::runtime_reconciliation::{
    encode_agent_session, AgentSession, AsciiText, ContractVersion, Durability, Epoch, FenceEpoch,
    Generation, Id, Ipv4Address, MacAddress, RandomId128, RemoteHead, Sequence, SessionBinding,
    Sha256Digest, UnixMillis, WireU64,
};

pub const LIFECYCLE_INTERNAL_METHOD: &str = "POST";
pub const LIFECYCLE_COMMAND_POLL_PATH: &str = "/v1/internal/runtime/lifecycle-command-polls";
pub const LIFECYCLE_RESULT_COMMIT_PATH: &str = "/v1/internal/runtime/lifecycle-result-commits";

pub const LIFECYCLE_COMMAND_ENVELOPE_MAX_WIRE_BYTES: usize = 1_048_576;
pub const LIFECYCLE_COMMAND_RESPONSE_MAX_WIRE_BYTES: usize = 1_048_576;
pub const LIFECYCLE_COMMAND_QUERY_MAX_WIRE_BYTES: usize = 16_384;
pub const LIFECYCLE_RESULT_STORED_ACK_MAX_WIRE_BYTES: usize = 16_384;
pub const COMPLETED_COMMAND_RECEIPT_MAX_WIRE_BYTES: usize = 1_048_576;
pub const ATOMIC_LIFECYCLE_ERROR_MAX_WIRE_BYTES: usize = 16_384;
pub const IMMUTABLE_RUNTIME_CONFIG_MAX_WIRE_BYTES: usize = 1_048_576;

pub const LIFECYCLE_COMMAND_POLL_MAX_WIRE_BYTES: usize = 16_384;
pub const LIFECYCLE_COMMAND_BATCH_MAX_WIRE_BYTES: usize = 16_777_216;
pub const LIFECYCLE_RESULT_COMMIT_MAX_WIRE_BYTES: usize = 1_048_576;
pub const LIFECYCLE_OPERATION_MAX_WIRE_BYTES: usize = 4_194_304;
pub const LIFECYCLE_COMMAND_BATCH_MAX_COMMANDS: usize = 64;
pub const LIFECYCLE_MAX_VOLUMES: usize = 64;
pub const LIFECYCLE_MAX_TAKEOVER_AUTHORIZATIONS: usize = 64;
pub const LIFECYCLE_MAX_ARTIFACT_CLASSIFICATIONS: usize = 1_024;

const REQUEST_FINGERPRINT_DOMAIN: &[u8] = b"cats.atomic-lifecycle.request.v1";
const TERMINAL_RESULT_DIGEST_DOMAIN: &[u8] = b"cats.atomic-lifecycle.result.v1";
const RUNTIME_CONFIG_DIGEST_DOMAIN: &[u8] = b"cats.atomic-lifecycle.runtime-config.v1";
const COMPLETED_RECEIPT_DIGEST_DOMAIN: &[u8] = b"cats.atomic-lifecycle.completed-receipt.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementIdentity {
    pub node_id: Id,
    pub placement_epoch: Epoch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleCommandKind {
    Start,
    Suspend,
    Warm,
    Cold,
    Stop,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskRole {
    Root,
    Persistent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeVolumeAuthorityInput {
    NormalUnowned {
        expected_unowned_epoch: FenceEpoch,
        transition_id: RandomId128,
    },
    SameNodeOwned {
        attachment_id: Id,
        attachment_epoch: FenceEpoch,
    },
    Takeover {
        authorization_id: Id,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeVolumeConfig {
    pub volume_id: Id,
    pub disk_id: Id,
    pub disk_role: DiskRole,
    pub size_bytes: u64,
    pub durability: Durability,
    pub guest_device_serial: Id,
    pub guest_device_slot: u16,
    pub guest_binding: RuntimeVolumeGuestBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeVolumeGuestBinding {
    RootBoot,
    PersistentExt4 {
        filesystem_uuid: RandomId128,
        mount_path: AsciiText,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartVolumeAuthority {
    pub volume_id: Id,
    pub disk_id: Id,
    pub authority: RuntimeVolumeAuthorityInput,
}

/// Complete, immutable network input for one runtime. This clean-slate wire
/// deliberately does not reuse the legacy Desired reconciliation config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeNetworkConfig {
    IsolatedIpv4 {
        network_id: Id,
        guest_mac: MacAddress,
        guest_ipv4: Ipv4Address,
        prefix_length: u8,
        gateway_ipv4: Ipv4Address,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImmutableRuntimeConfig {
    pub version: ContractVersion,
    pub config_id: Id,
    pub config_digest: Sha256Digest,
    pub boot_image_digest: Sha256Digest,
    pub vcpus: u32,
    pub memory_bytes: u64,
    pub guest_runtime_profile_digest: Sha256Digest,
    pub network_config: RuntimeNetworkConfig,
    pub volumes: Vec<RuntimeVolumeConfig>,
}

impl ImmutableRuntimeConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config_id: Id,
        boot_image_digest: Sha256Digest,
        vcpus: u32,
        memory_bytes: u64,
        guest_runtime_profile_digest: Sha256Digest,
        network_config: RuntimeNetworkConfig,
        volumes: Vec<RuntimeVolumeConfig>,
    ) -> Result<Self, RuntimeLifecycleContractError> {
        let mut config = Self {
            version: ContractVersion::V1,
            config_id,
            config_digest: Sha256Digest::from_bytes([0; 32]),
            boot_image_digest,
            vcpus,
            memory_bytes,
            guest_runtime_profile_digest,
            network_config,
            volumes,
        };
        config.config_digest = immutable_runtime_config_digest(&config)?;
        validate_immutable_runtime_config(&config)?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StartSource {
    Genesis,
    SameNodeSuspended,
    SameNodeWarm,
    SameNodeCold,
    SameNodeStopped,
    SameNodeRetry,
    ColdHandoff,
    HostFenceRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspendAdmissionPolicy {
    RequireIdle,
    CloseAndDrain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartSpec {
    pub volume_authorities: Vec<StartVolumeAuthority>,
    pub source: StartSource,
    pub effect_deadline_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspendSpec {
    pub admission_policy: SuspendAdmissionPolicy,
    pub grace_deadline_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmSpec {
    pub grace_deadline_unix_ms: UnixMillis,
    pub convergence_deadline_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdSpec {
    pub grace_deadline_unix_ms: UnixMillis,
    pub convergence_deadline_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopSpec {
    pub grace_deadline_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestedVolumeDisposition {
    DiscardWithCat {
        volume_id: Id,
        disk_id: Id,
        disk_role: DiskRole,
    },
    RetainDetached {
        volume_id: Id,
        disk_id: Id,
        disk_role: DiskRole,
    },
}

impl RequestedVolumeDisposition {
    pub fn volume_id(&self) -> &Id {
        match self {
            Self::DiscardWithCat { volume_id, .. } | Self::RetainDetached { volume_id, .. } => {
                volume_id
            }
        }
    }

    pub fn disk_id(&self) -> &Id {
        match self {
            Self::DiscardWithCat { disk_id, .. } | Self::RetainDetached { disk_id, .. } => disk_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteSpec {
    pub delete_id: Id,
    pub grace_deadline_unix_ms: UnixMillis,
    pub convergence_deadline_unix_ms: UnixMillis,
    pub volume_dispositions: Vec<RequestedVolumeDisposition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "spec",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LifecycleCommand {
    Start(Box<StartSpec>),
    Suspend(SuspendSpec),
    Warm(WarmSpec),
    Cold(ColdSpec),
    Stop(StopSpec),
    Delete(DeleteSpec),
}

impl LifecycleCommand {
    pub const fn kind(&self) -> LifecycleCommandKind {
        match self {
            Self::Start(_) => LifecycleCommandKind::Start,
            Self::Suspend(_) => LifecycleCommandKind::Suspend,
            Self::Warm(_) => LifecycleCommandKind::Warm,
            Self::Cold(_) => LifecycleCommandKind::Cold,
            Self::Stop(_) => LifecycleCommandKind::Stop,
            Self::Delete(_) => LifecycleCommandKind::Delete,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalResultKind {
    RuntimeReady,
    StartFailed,
    Suspended,
    SuspendDeclined,
    SuspendFailed,
    Warm,
    WarmFailed,
    Cold,
    Killed,
    Deleted,
    NeedsIntervention,
    HostLost,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeReceiptDigest {
    pub volume_id: Id,
    pub receipt_digest: Sha256Digest,
}

/// Immutable Volume Authority evidence referenced by a cross-Node Cold
/// handoff.  The variant is part of the authority: a normal release digest
/// must never be replayed as proof that an already-Unowned slot was inspected
/// by the Cold command (or vice versa).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ColdVolumeDispositionDigest {
    NormallyReleased {
        volume_id: Id,
        normal_release_receipt_digest: Sha256Digest,
    },
    AlreadyUnowned {
        volume_id: Id,
        already_unowned_receipt_digest: Sha256Digest,
    },
}

impl ColdVolumeDispositionDigest {
    pub fn volume_id(&self) -> &Id {
        match self {
            Self::NormallyReleased { volume_id, .. } | Self::AlreadyUnowned { volume_id, .. } => {
                volume_id
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeAuthorizationId {
    pub volume_id: Id,
    pub authorization_id: Id,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OldNodeIdentity {
    pub node_id: Id,
    pub immutable_host_id: Id,
    pub state_path_id: Id,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecyclePredecessor {
    Genesis {
        cat_creation_id: Id,
        target_placement: PlacementIdentity,
    },
    SameNode {
        operation_id: Id,
        terminal_result_kind: TerminalResultKind,
        terminal_result_digest: Sha256Digest,
        node_id: Id,
        placement_identity: PlacementIdentity,
    },
    CrossNodeColdHandoff {
        cold_operation_id: Id,
        cold_result_digest: Sha256Digest,
        source_node_id: Id,
        source_placement: PlacementIdentity,
        volume_disposition_receipts: Vec<ColdVolumeDispositionDigest>,
        target_placement: PlacementIdentity,
    },
    HostFenceRecovery {
        interrupted_operation_id: Id,
        host_lost_result_digest: Sha256Digest,
        host_fence_event_id: Id,
        old_node_identity: OldNodeIdentity,
        takeover_authorization_ids: Vec<VolumeAuthorizationId>,
        target_placement: PlacementIdentity,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCommandEnvelope {
    pub version: ContractVersion,
    pub operation_id: Id,
    pub workspace_id: Id,
    pub cat_id: Id,
    pub node_id: Id,
    pub placement_identity: PlacementIdentity,
    pub runtime_config: Box<ImmutableRuntimeConfig>,
    pub expected_predecessor_operation_id: Option<Id>,
    pub predecessor: LifecyclePredecessor,
    pub command: LifecycleCommand,
    pub request_fingerprint: Sha256Digest,
}

impl LifecycleCommandEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: Id,
        workspace_id: Id,
        cat_id: Id,
        node_id: Id,
        placement_identity: PlacementIdentity,
        runtime_config: ImmutableRuntimeConfig,
        expected_predecessor_operation_id: Option<Id>,
        predecessor: LifecyclePredecessor,
        command: LifecycleCommand,
    ) -> Result<Self, RuntimeLifecycleContractError> {
        let mut envelope = Self {
            version: ContractVersion::V1,
            operation_id,
            workspace_id,
            cat_id,
            node_id,
            placement_identity,
            runtime_config: Box::new(runtime_config),
            expected_predecessor_operation_id,
            predecessor,
            command,
            request_fingerprint: Sha256Digest::from_bytes([0; 32]),
        };
        envelope.request_fingerprint = lifecycle_command_request_fingerprint(&envelope)?;
        validate_lifecycle_command_envelope(&envelope)?;
        Ok(envelope)
    }

    pub const fn command_kind(&self) -> LifecycleCommandKind {
        self.command.kind()
    }

    pub fn runtime_config(&self) -> &ImmutableRuntimeConfig {
        &self.runtime_config
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAbsenceProof {
    pub stop_fence_receipt_digest: Sha256Digest,
    pub admission_closed_receipt_digest: Sha256Digest,
    pub dedicated_scope_absence_receipt_digest: Sha256Digest,
    pub frontend_absence_receipt_digest: Sha256Digest,
    pub restart_source_absence_receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedEvidence {
    pub artifact_manifest_digest: Sha256Digest,
    pub adoptable_count: u16,
    pub gc_candidate_count: u16,
    pub retained_authority_or_data_count: u16,
    pub quarantined_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveRuntimeReady {
    pub source_lifecycle_operation_id: Id,
    pub runtime_incarnation: RandomId128,
    pub runtime_config_digest: Sha256Digest,
    pub runtime_ready_receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeTerminalReceipt {
    pub volume_id: Id,
    pub disk_id: Id,
    pub disk_role: DiskRole,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub local_durable_generation: Generation,
    pub remote_durable_generation: Generation,
    pub authority_receipt_digest: Option<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReadyResult {
    pub runtime_incarnation: RandomId128,
    pub runtime_config_digest: Sha256Digest,
    pub execution_receipt_digest: Sha256Digest,
    pub guest_ready_receipt_digest: Sha256Digest,
    pub volume_receipts: Vec<VolumeTerminalReceipt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandFailureReason {
    InvalidLocalPrecondition,
    CapacityUnavailable,
    VolumeAuthorityRejected,
    ImageUnavailable,
    DevicePrepareFailed,
    NetworkPrepareFailed,
    VmmFailed,
    GuestNotReady,
    SnapshotInvalid,
    DurabilityConvergenceTimeout,
    NormalReleaseFailed,
    LocalCleanupFailed,
    StoredEvidenceConflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandFailedResult {
    pub reason: CommandFailureReason,
    pub not_running: ExecutionAbsenceProof,
    pub retained_evidence: RetainedEvidence,
    /// Exact Owned identities which survived the failed command. This is a
    /// canonical, possibly-empty subset of the command's immutable runtime
    /// config; absence is not by itself proof that a slot is Unowned.
    pub retained_volume_receipts: Vec<VolumeTerminalReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspendedResult {
    pub runtime_incarnation: RandomId128,
    pub runtime_config_digest: Sha256Digest,
    pub pause_receipt_digest: Sha256Digest,
    pub local_durability_receipts: Vec<VolumeTerminalReceipt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspendDeclineReason {
    Busy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspendDeclinedResult {
    pub reason: SuspendDeclineReason,
    pub admission_cell_never_closed_receipt_digest: Sha256Digest,
    pub effective_runtime_ready: EffectiveRuntimeReady,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmResult {
    pub runtime_config_digest: Sha256Digest,
    pub source_runtime_incarnation: RandomId128,
    pub warm_snapshot_receipt_digest: Sha256Digest,
    /// Digest of the terminal two-phase Warm manifest. This is distinct from
    /// the command receipt and binds the pre-stop snapshot content, final
    /// absence proof, Volume receipts and exact command identity.
    pub warm_snapshot_manifest_digest: Sha256Digest,
    pub volume_receipts: Vec<VolumeTerminalReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdResult {
    pub runtime_config_digest: Sha256Digest,
    pub execution_absence: ExecutionAbsenceProof,
    pub volume_dispositions: Vec<ColdVolumeDisposition>,
    pub local_recovery_dependency_absent_digest: Sha256Digest,
}

/// Exact terminal authority for each immutable runtime-config slot after a
/// Cold command.  `AlreadyUnowned` deliberately carries no synthetic
/// attachment identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ColdVolumeDisposition {
    NormallyReleased {
        volume: Box<VolumeTerminalReceipt>,
        normal_release_receipt_digest: Sha256Digest,
    },
    AlreadyUnowned {
        volume_id: Id,
        disk_id: Id,
        disk_role: DiskRole,
        unowned_epoch: FenceEpoch,
        remote_head: RemoteHead,
        already_unowned_receipt_digest: Sha256Digest,
    },
}

impl ColdVolumeDisposition {
    pub fn volume_id(&self) -> &Id {
        match self {
            Self::NormallyReleased { volume, .. } => &volume.volume_id,
            Self::AlreadyUnowned { volume_id, .. } => volume_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KilledResult {
    pub stopped_runtime_incarnation: Option<RandomId128>,
    pub execution_absence: ExecutionAbsenceProof,
    pub stop_fence_receipt_digest: Sha256Digest,
    pub retained_volume_receipts: Vec<VolumeTerminalReceipt>,
    /// Exact terminal retained-manifest identity and physical classification
    /// counts. This remains mandatory even when no Volume is retained so a
    /// Killed successor never infers "empty" from a missing local artifact.
    pub retained_evidence: RetainedEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompletedVolumeDisposition {
    PersistentRetainedDetached {
        volume: Box<VolumeTerminalReceipt>,
        normal_release_receipt_digest: Sha256Digest,
    },
    PersistentAlreadyDetached {
        volume_id: Id,
        disk_id: Id,
        already_unowned_receipt_digest: Sha256Digest,
    },
    RootNormallyDeleted {
        volume: Box<VolumeTerminalReceipt>,
        delete_completion_receipt_digest: Sha256Digest,
    },
    RootAlreadyUnownedDeleted {
        volume_id: Id,
        disk_id: Id,
        already_unowned_receipt_digest: Sha256Digest,
        delete_completion_receipt_digest: Sha256Digest,
    },
    RootDisposableTailDeleted {
        volume_id: Id,
        disk_id: Id,
        previous_attachment_id: Id,
        previous_attachment_epoch: FenceEpoch,
        disposable_authorization_id: Id,
        authorization_consumed_receipt_digest: Sha256Digest,
        delete_completion_receipt_digest: Sha256Digest,
        local_lineage_absence_digest: Sha256Digest,
    },
}

impl CompletedVolumeDisposition {
    pub fn volume_id(&self) -> &Id {
        match self {
            Self::PersistentRetainedDetached { volume, .. }
            | Self::RootNormallyDeleted { volume, .. } => &volume.volume_id,
            Self::PersistentAlreadyDetached { volume_id, .. }
            | Self::RootAlreadyUnownedDeleted { volume_id, .. }
            | Self::RootDisposableTailDeleted { volume_id, .. } => volume_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletedResult {
    pub execution_absence: ExecutionAbsenceProof,
    pub volume_dispositions: Vec<CompletedVolumeDisposition>,
    pub destructive_cleanup_absent_digest: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionTarget {
    Warm,
    Cold,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionReason {
    RetainedLocalTail,
    PersistentDiskNotRemoteDurable,
    AuthorityAmbiguous,
    ForeignOrAmbiguousResidue,
    WarmSnapshotAmbiguous,
    NormalReleaseAmbiguous,
    DestructiveAuthorizationRejected,
    LocalLineageAbsenceUnproven,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeedsInterventionResult {
    pub attempted_target: InterventionTarget,
    pub reason: InterventionReason,
    pub not_running: ExecutionAbsenceProof,
    pub retained_evidence: RetainedEvidence,
    pub retained_volume_receipts: Vec<VolumeTerminalReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum NodeResult {
    RuntimeReady(Box<RuntimeReadyResult>),
    StartFailed(Box<CommandFailedResult>),
    Suspended(Box<SuspendedResult>),
    SuspendDeclined(Box<SuspendDeclinedResult>),
    SuspendFailed(Box<CommandFailedResult>),
    Warm(Box<WarmResult>),
    WarmFailed(Box<CommandFailedResult>),
    Cold(Box<ColdResult>),
    Killed(Box<KilledResult>),
    Deleted(Box<DeletedResult>),
    NeedsIntervention(Box<NeedsInterventionResult>),
}

impl NodeResult {
    pub const fn kind(&self) -> TerminalResultKind {
        match self {
            Self::RuntimeReady(_) => TerminalResultKind::RuntimeReady,
            Self::StartFailed(_) => TerminalResultKind::StartFailed,
            Self::Suspended(_) => TerminalResultKind::Suspended,
            Self::SuspendDeclined(_) => TerminalResultKind::SuspendDeclined,
            Self::SuspendFailed(_) => TerminalResultKind::SuspendFailed,
            Self::Warm(_) => TerminalResultKind::Warm,
            Self::WarmFailed(_) => TerminalResultKind::WarmFailed,
            Self::Cold(_) => TerminalResultKind::Cold,
            Self::Killed(_) => TerminalResultKind::Killed,
            Self::Deleted(_) => TerminalResultKind::Deleted,
            Self::NeedsIntervention(_) => TerminalResultKind::NeedsIntervention,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCommandResponse {
    pub version: ContractVersion,
    pub operation_id: Id,
    pub workspace_id: Id,
    pub cat_id: Id,
    pub node_id: Id,
    pub placement_identity: PlacementIdentity,
    pub request_fingerprint: Sha256Digest,
    pub result: NodeResult,
}

impl LifecycleCommandResponse {
    pub fn new(
        command: &LifecycleCommandEnvelope,
        result: NodeResult,
    ) -> Result<Self, RuntimeLifecycleContractError> {
        let response = Self {
            version: ContractVersion::V1,
            operation_id: command.operation_id.clone(),
            workspace_id: command.workspace_id.clone(),
            cat_id: command.cat_id.clone(),
            node_id: command.node_id.clone(),
            placement_identity: command.placement_identity.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            result,
        };
        validate_lifecycle_command_response_for_command(&response, command)?;
        Ok(response)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleTerminalResult {
    NodeResult {
        response: Box<LifecycleCommandResponse>,
    },
    HostLost {
        host_fence_event_id: Id,
        interrupted_operation_id: Id,
    },
}

impl LifecycleTerminalResult {
    pub const fn kind(&self) -> TerminalResultKind {
        match self {
            Self::NodeResult { response } => response.result.kind(),
            Self::HostLost { .. } => TerminalResultKind::HostLost,
        }
    }

    pub fn operation_id(&self) -> &Id {
        match self {
            Self::NodeResult { response } => &response.operation_id,
            Self::HostLost {
                interrupted_operation_id,
                ..
            } => interrupted_operation_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleOperationState {
    Unresolved,
    Terminal {
        terminal: Box<LifecycleTerminalResult>,
        terminal_result_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleOperation {
    pub version: ContractVersion,
    pub operation_id: Id,
    pub workspace_id: Id,
    pub cat_id: Id,
    pub node_id: Id,
    pub placement_identity: PlacementIdentity,
    pub runtime_config_id: Id,
    pub runtime_config_digest: Sha256Digest,
    pub command_kind: LifecycleCommandKind,
    pub canonical_request: Box<LifecycleCommandEnvelope>,
    pub request_fingerprint: Sha256Digest,
    pub expected_predecessor_operation_id: Option<Id>,
    pub predecessor: LifecyclePredecessor,
    pub state: LifecycleOperationState,
    pub created_at_unix_ms: UnixMillis,
    pub terminal_at_unix_ms: Option<UnixMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCommandPollRequest {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub request_sequence: Sequence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCommandBatch {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub request_sequence: Sequence,
    pub commands: Vec<LifecycleCommandEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCommandQuery {
    pub version: ContractVersion,
    pub node_id: Id,
    pub cat_id: Id,
    pub operation_id: Id,
    pub request_fingerprint: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleResultCommitRequest {
    pub version: ContractVersion,
    pub session: SessionBinding,
    pub response: Box<LifecycleCommandResponse>,
    pub terminal_result_digest: Sha256Digest,
}

impl LifecycleResultCommitRequest {
    pub fn new(
        session: &AgentSession,
        response: LifecycleCommandResponse,
    ) -> Result<Self, RuntimeLifecycleContractError> {
        validate_agent_session(session)?;
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(response.clone()),
        };
        let commit = Self {
            version: ContractVersion::V1,
            session: session_binding(session),
            response: Box::new(response),
            terminal_result_digest: lifecycle_terminal_result_digest(&terminal)?,
        };
        validate_lifecycle_result_commit_request(&commit)?;
        Ok(commit)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleResultStoredAck {
    pub version: ContractVersion,
    pub node_id: Id,
    pub cat_id: Id,
    pub operation_id: Id,
    pub request_fingerprint: Sha256Digest,
    pub terminal_result_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedCommandReceipt {
    pub version: ContractVersion,
    pub node_id: Id,
    pub cat_id: Id,
    pub placement_identity: PlacementIdentity,
    pub operation_id: Id,
    pub request_fingerprint: Sha256Digest,
    pub terminal_response: Box<LifecycleCommandResponse>,
    pub terminal_result_digest: Sha256Digest,
    pub completed_receipt_digest: Sha256Digest,
}

impl CompletedCommandReceipt {
    pub fn new(response: LifecycleCommandResponse) -> Result<Self, RuntimeLifecycleContractError> {
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(response.clone()),
        };
        let mut receipt = Self {
            version: ContractVersion::V1,
            node_id: response.node_id.clone(),
            cat_id: response.cat_id.clone(),
            placement_identity: response.placement_identity.clone(),
            operation_id: response.operation_id.clone(),
            request_fingerprint: response.request_fingerprint.clone(),
            terminal_response: Box::new(response),
            terminal_result_digest: lifecycle_terminal_result_digest(&terminal)?,
            completed_receipt_digest: Sha256Digest::from_bytes([0; 32]),
        };
        receipt.completed_receipt_digest = completed_command_receipt_digest(&receipt)?;
        validate_completed_command_receipt(&receipt)?;
        Ok(receipt)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactClassification {
    AdoptableCatState {
        artifact_id: Id,
        ownership_digest: Sha256Digest,
    },
    CatOwnedGcCandidate {
        artifact_id: Id,
        ownership_digest: Sha256Digest,
        postcondition_digest: Sha256Digest,
    },
    RetainedAuthorityOrData {
        artifact_id: Id,
        evidence_digest: Sha256Digest,
    },
    QuarantinedForeignOrAmbiguous {
        artifact_id: Id,
        evidence_digest: Sha256Digest,
    },
}

impl ArtifactClassification {
    pub fn artifact_id(&self) -> &Id {
        match self {
            Self::AdoptableCatState { artifact_id, .. }
            | Self::CatOwnedGcCandidate { artifact_id, .. }
            | Self::RetainedAuthorityOrData { artifact_id, .. }
            | Self::QuarantinedForeignOrAmbiguous { artifact_id, .. } => artifact_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtomicLifecycleError {
    MalformedPayload {
        json_pointer: AsciiText,
        message: AsciiText,
    },
    UnsupportedVersion {
        supported_version: ContractVersion,
    },
    LimitExceeded {
        limit: AsciiText,
        maximum: WireU64,
    },
    AuthenticationFailed,
    WrongNode {
        expected_node_id: Id,
    },
    LifecycleOperationInProgress {
        operation_id: Id,
        command_kind: LifecycleCommandKind,
    },
    OperationIdentityConflict {
        operation_id: Id,
    },
    StaleOperation {
        current_operation_id: Option<Id>,
    },
    IllegalSuccessor {
        predecessor_kind: TerminalResultKind,
        command_kind: LifecycleCommandKind,
    },
    SupersededOperation {
        current_operation_id: Id,
    },
    ConflictingTerminalResult {
        operation_id: Id,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeLifecycleContractError {
    #[error("atomic lifecycle wire body exceeds its byte limit")]
    WireTooLarge,
    #[error("atomic lifecycle wire body is malformed")]
    Malformed,
    #[error("atomic lifecycle wire body is not exact canonical JSON")]
    NonCanonical,
    #[error("atomic lifecycle contract is invalid")]
    InvalidContract,
}

#[derive(Serialize)]
struct RuntimeConfigDigestInput<'a> {
    version: ContractVersion,
    config_id: &'a Id,
    boot_image_digest: &'a Sha256Digest,
    vcpus: u32,
    memory_bytes: u64,
    guest_runtime_profile_digest: &'a Sha256Digest,
    network_config: &'a RuntimeNetworkConfig,
    volumes: &'a [RuntimeVolumeConfig],
}

#[derive(Serialize)]
struct CommandFingerprintInput<'a> {
    version: ContractVersion,
    operation_id: &'a Id,
    workspace_id: &'a Id,
    cat_id: &'a Id,
    node_id: &'a Id,
    placement_identity: &'a PlacementIdentity,
    runtime_config: &'a ImmutableRuntimeConfig,
    expected_predecessor_operation_id: &'a Option<Id>,
    predecessor: &'a LifecyclePredecessor,
    command: &'a LifecycleCommand,
}

#[derive(Serialize)]
struct CompletedReceiptDigestInput<'a> {
    version: ContractVersion,
    node_id: &'a Id,
    cat_id: &'a Id,
    placement_identity: &'a PlacementIdentity,
    operation_id: &'a Id,
    request_fingerprint: &'a Sha256Digest,
    terminal_response: &'a LifecycleCommandResponse,
    terminal_result_digest: &'a Sha256Digest,
}

pub fn immutable_runtime_config_digest(
    config: &ImmutableRuntimeConfig,
) -> Result<Sha256Digest, RuntimeLifecycleContractError> {
    validate_immutable_runtime_config_unsigned(config)?;
    digest_canonical(
        RUNTIME_CONFIG_DIGEST_DOMAIN,
        &RuntimeConfigDigestInput {
            version: config.version,
            config_id: &config.config_id,
            boot_image_digest: &config.boot_image_digest,
            vcpus: config.vcpus,
            memory_bytes: config.memory_bytes,
            guest_runtime_profile_digest: &config.guest_runtime_profile_digest,
            network_config: &config.network_config,
            volumes: &config.volumes,
        },
        IMMUTABLE_RUNTIME_CONFIG_MAX_WIRE_BYTES,
    )
}

pub fn lifecycle_command_request_fingerprint(
    envelope: &LifecycleCommandEnvelope,
) -> Result<Sha256Digest, RuntimeLifecycleContractError> {
    validate_lifecycle_command_envelope_unsigned(envelope)?;
    digest_canonical(
        REQUEST_FINGERPRINT_DOMAIN,
        &CommandFingerprintInput {
            version: envelope.version,
            operation_id: &envelope.operation_id,
            workspace_id: &envelope.workspace_id,
            cat_id: &envelope.cat_id,
            node_id: &envelope.node_id,
            placement_identity: &envelope.placement_identity,
            runtime_config: &envelope.runtime_config,
            expected_predecessor_operation_id: &envelope.expected_predecessor_operation_id,
            predecessor: &envelope.predecessor,
            command: &envelope.command,
        },
        LIFECYCLE_COMMAND_ENVELOPE_MAX_WIRE_BYTES,
    )
}

pub fn lifecycle_terminal_result_digest(
    terminal: &LifecycleTerminalResult,
) -> Result<Sha256Digest, RuntimeLifecycleContractError> {
    validate_lifecycle_terminal_result(terminal)?;
    digest_canonical(
        TERMINAL_RESULT_DIGEST_DOMAIN,
        terminal,
        LIFECYCLE_COMMAND_RESPONSE_MAX_WIRE_BYTES,
    )
}

pub fn completed_command_receipt_digest(
    receipt: &CompletedCommandReceipt,
) -> Result<Sha256Digest, RuntimeLifecycleContractError> {
    validate_completed_command_receipt_unsigned(receipt)?;
    digest_canonical(
        COMPLETED_RECEIPT_DIGEST_DOMAIN,
        &CompletedReceiptDigestInput {
            version: receipt.version,
            node_id: &receipt.node_id,
            cat_id: &receipt.cat_id,
            placement_identity: &receipt.placement_identity,
            operation_id: &receipt.operation_id,
            request_fingerprint: &receipt.request_fingerprint,
            terminal_response: &receipt.terminal_response,
            terminal_result_digest: &receipt.terminal_result_digest,
        },
        COMPLETED_COMMAND_RECEIPT_MAX_WIRE_BYTES,
    )
}

pub fn encode_immutable_runtime_config(
    config: &ImmutableRuntimeConfig,
) -> Result<Vec<u8>, RuntimeLifecycleContractError> {
    validate_immutable_runtime_config(config)?;
    encode_canonical(config, IMMUTABLE_RUNTIME_CONFIG_MAX_WIRE_BYTES)
}

pub fn decode_immutable_runtime_config(
    bytes: &[u8],
) -> Result<ImmutableRuntimeConfig, RuntimeLifecycleContractError> {
    decode_canonical(
        bytes,
        IMMUTABLE_RUNTIME_CONFIG_MAX_WIRE_BYTES,
        validate_immutable_runtime_config,
    )
}

pub fn encode_lifecycle_command_envelope(
    envelope: &LifecycleCommandEnvelope,
) -> Result<Vec<u8>, RuntimeLifecycleContractError> {
    validate_lifecycle_command_envelope(envelope)?;
    encode_canonical(envelope, LIFECYCLE_COMMAND_ENVELOPE_MAX_WIRE_BYTES)
}

pub fn decode_lifecycle_command_envelope(
    bytes: &[u8],
) -> Result<LifecycleCommandEnvelope, RuntimeLifecycleContractError> {
    decode_canonical(
        bytes,
        LIFECYCLE_COMMAND_ENVELOPE_MAX_WIRE_BYTES,
        validate_lifecycle_command_envelope,
    )
}

pub fn encode_lifecycle_command_response(
    response: &LifecycleCommandResponse,
) -> Result<Vec<u8>, RuntimeLifecycleContractError> {
    validate_lifecycle_command_response(response)?;
    encode_canonical(response, LIFECYCLE_COMMAND_RESPONSE_MAX_WIRE_BYTES)
}

pub fn decode_lifecycle_command_response(
    bytes: &[u8],
) -> Result<LifecycleCommandResponse, RuntimeLifecycleContractError> {
    decode_canonical(
        bytes,
        LIFECYCLE_COMMAND_RESPONSE_MAX_WIRE_BYTES,
        validate_lifecycle_command_response,
    )
}

pub fn encode_lifecycle_command_poll_request(
    poll: &LifecycleCommandPollRequest,
) -> Result<Vec<u8>, RuntimeLifecycleContractError> {
    validate_lifecycle_command_poll_request(poll)?;
    encode_canonical(poll, LIFECYCLE_COMMAND_POLL_MAX_WIRE_BYTES)
}

pub fn decode_lifecycle_command_poll_request(
    bytes: &[u8],
) -> Result<LifecycleCommandPollRequest, RuntimeLifecycleContractError> {
    decode_canonical(
        bytes,
        LIFECYCLE_COMMAND_POLL_MAX_WIRE_BYTES,
        validate_lifecycle_command_poll_request,
    )
}

pub fn encode_lifecycle_command_batch(
    batch: &LifecycleCommandBatch,
) -> Result<Vec<u8>, RuntimeLifecycleContractError> {
    validate_lifecycle_command_batch(batch)?;
    encode_canonical(batch, LIFECYCLE_COMMAND_BATCH_MAX_WIRE_BYTES)
}

pub fn decode_lifecycle_command_batch(
    bytes: &[u8],
) -> Result<LifecycleCommandBatch, RuntimeLifecycleContractError> {
    decode_canonical(
        bytes,
        LIFECYCLE_COMMAND_BATCH_MAX_WIRE_BYTES,
        validate_lifecycle_command_batch,
    )
}

pub fn encode_lifecycle_command_query(
    query: &LifecycleCommandQuery,
) -> Result<Vec<u8>, RuntimeLifecycleContractError> {
    validate_lifecycle_command_query(query)?;
    encode_canonical(query, LIFECYCLE_COMMAND_QUERY_MAX_WIRE_BYTES)
}

pub fn decode_lifecycle_command_query(
    bytes: &[u8],
) -> Result<LifecycleCommandQuery, RuntimeLifecycleContractError> {
    decode_canonical(
        bytes,
        LIFECYCLE_COMMAND_QUERY_MAX_WIRE_BYTES,
        validate_lifecycle_command_query,
    )
}

pub fn encode_lifecycle_result_commit_request(
    commit: &LifecycleResultCommitRequest,
) -> Result<Vec<u8>, RuntimeLifecycleContractError> {
    validate_lifecycle_result_commit_request(commit)?;
    encode_canonical(commit, LIFECYCLE_RESULT_COMMIT_MAX_WIRE_BYTES)
}

pub fn decode_lifecycle_result_commit_request(
    bytes: &[u8],
) -> Result<LifecycleResultCommitRequest, RuntimeLifecycleContractError> {
    decode_canonical(
        bytes,
        LIFECYCLE_RESULT_COMMIT_MAX_WIRE_BYTES,
        validate_lifecycle_result_commit_request,
    )
}

pub fn encode_lifecycle_result_stored_ack(
    ack: &LifecycleResultStoredAck,
) -> Result<Vec<u8>, RuntimeLifecycleContractError> {
    validate_lifecycle_result_stored_ack(ack)?;
    encode_canonical(ack, LIFECYCLE_RESULT_STORED_ACK_MAX_WIRE_BYTES)
}

pub fn decode_lifecycle_result_stored_ack(
    bytes: &[u8],
) -> Result<LifecycleResultStoredAck, RuntimeLifecycleContractError> {
    decode_canonical(
        bytes,
        LIFECYCLE_RESULT_STORED_ACK_MAX_WIRE_BYTES,
        validate_lifecycle_result_stored_ack,
    )
}

pub fn encode_completed_command_receipt(
    receipt: &CompletedCommandReceipt,
) -> Result<Vec<u8>, RuntimeLifecycleContractError> {
    validate_completed_command_receipt(receipt)?;
    encode_canonical(receipt, COMPLETED_COMMAND_RECEIPT_MAX_WIRE_BYTES)
}

pub fn decode_completed_command_receipt(
    bytes: &[u8],
) -> Result<CompletedCommandReceipt, RuntimeLifecycleContractError> {
    decode_canonical(
        bytes,
        COMPLETED_COMMAND_RECEIPT_MAX_WIRE_BYTES,
        validate_completed_command_receipt,
    )
}

pub fn encode_lifecycle_operation(
    operation: &LifecycleOperation,
) -> Result<Vec<u8>, RuntimeLifecycleContractError> {
    validate_lifecycle_operation(operation)?;
    encode_canonical(operation, LIFECYCLE_OPERATION_MAX_WIRE_BYTES)
}

pub fn decode_lifecycle_operation(
    bytes: &[u8],
) -> Result<LifecycleOperation, RuntimeLifecycleContractError> {
    decode_canonical(
        bytes,
        LIFECYCLE_OPERATION_MAX_WIRE_BYTES,
        validate_lifecycle_operation,
    )
}

pub fn encode_atomic_lifecycle_error(
    error: &AtomicLifecycleError,
) -> Result<Vec<u8>, RuntimeLifecycleContractError> {
    validate_atomic_lifecycle_error(error)?;
    encode_canonical(error, ATOMIC_LIFECYCLE_ERROR_MAX_WIRE_BYTES)
}

pub fn decode_atomic_lifecycle_error(
    bytes: &[u8],
) -> Result<AtomicLifecycleError, RuntimeLifecycleContractError> {
    decode_canonical(
        bytes,
        ATOMIC_LIFECYCLE_ERROR_MAX_WIRE_BYTES,
        validate_atomic_lifecycle_error,
    )
}

pub fn validate_immutable_runtime_config(
    config: &ImmutableRuntimeConfig,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_immutable_runtime_config_unsigned(config)?;
    if immutable_runtime_config_digest(config)? != config.config_digest {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

fn validate_immutable_runtime_config_unsigned(
    config: &ImmutableRuntimeConfig,
) -> Result<(), RuntimeLifecycleContractError> {
    if config.version != ContractVersion::V1
        || config.vcpus == 0
        || config.memory_bytes == 0
        || config.memory_bytes > i64::MAX as u64
        || !runtime_network_config_valid(&config.network_config)
        || config.volumes.is_empty()
        || config.volumes.len() > LIFECYCLE_MAX_VOLUMES
        || !config
            .volumes
            .windows(2)
            .all(|pair| pair[0].volume_id.as_str() < pair[1].volume_id.as_str())
        || has_duplicate_by(&config.volumes, |volume| volume.disk_id.as_str())
        || has_duplicate_by(&config.volumes, |volume| {
            volume.guest_device_serial.as_str()
        })
        || has_duplicate_u16(&config.volumes, |volume| volume.guest_device_slot)
        || config
            .volumes
            .iter()
            .filter(|volume| volume.disk_role == DiskRole::Root)
            .count()
            != 1
    {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    for volume in &config.volumes {
        if volume.size_bytes == 0
            || volume.size_bytes > i64::MAX as u64
            || volume.guest_device_serial.as_str().len() > 20
            || !runtime_volume_guest_binding_valid(volume)
        {
            return Err(RuntimeLifecycleContractError::InvalidContract);
        }
    }
    encode_canonical(config, IMMUTABLE_RUNTIME_CONFIG_MAX_WIRE_BYTES).map(|_| ())
}

fn runtime_volume_guest_binding_valid(volume: &RuntimeVolumeConfig) -> bool {
    match (&volume.disk_role, &volume.guest_binding) {
        (DiskRole::Root, RuntimeVolumeGuestBinding::RootBoot) => true,
        (DiskRole::Persistent, RuntimeVolumeGuestBinding::PersistentExt4 { mount_path, .. }) => {
            canonical_guest_mount_path(mount_path)
        }
        _ => false,
    }
}

fn canonical_guest_mount_path(path: &AsciiText) -> bool {
    let path = path.as_str();
    path.starts_with('/')
        && path != "/"
        && !path.ends_with('/')
        && path[1..]
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn runtime_network_config_valid(config: &RuntimeNetworkConfig) -> bool {
    let RuntimeNetworkConfig::IsolatedIpv4 {
        guest_mac,
        guest_ipv4,
        prefix_length,
        gateway_ipv4,
        ..
    } = config;

    if *prefix_length != 30 {
        return false;
    }
    let Ok(guest) = guest_ipv4.as_str().parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Ok(gateway) = gateway_ipv4.as_str().parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let guest = u32::from(guest);
    let gateway = u32::from(gateway);
    let host_mask = 0b11_u32;
    let guest_host = guest & host_mask;
    let gateway_host = gateway & host_mask;
    if guest & !host_mask != gateway & !host_mask
        || guest == gateway
        || matches!(guest_host, 0 | 3)
        || matches!(gateway_host, 0 | 3)
    {
        return false;
    }

    let Some(first_octet) = guest_mac
        .as_str()
        .split(':')
        .next()
        .and_then(|octet| u8::from_str_radix(octet, 16).ok())
    else {
        return false;
    };
    first_octet & 0b1 == 0 && first_octet & 0b10 != 0
}

pub fn validate_lifecycle_command_envelope(
    envelope: &LifecycleCommandEnvelope,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_lifecycle_command_envelope_unsigned(envelope)?;
    if lifecycle_command_request_fingerprint(envelope)? != envelope.request_fingerprint {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

fn validate_lifecycle_command_envelope_unsigned(
    envelope: &LifecycleCommandEnvelope,
) -> Result<(), RuntimeLifecycleContractError> {
    if envelope.version != ContractVersion::V1
        || envelope.placement_identity.node_id != envelope.node_id
        || envelope
            .expected_predecessor_operation_id
            .as_ref()
            .is_some_and(|predecessor| predecessor == &envelope.operation_id)
    {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    validate_immutable_runtime_config(&envelope.runtime_config)?;
    validate_lifecycle_command(&envelope.command, &envelope.runtime_config)?;
    validate_lifecycle_predecessor(envelope)?;
    encode_canonical(envelope, LIFECYCLE_COMMAND_ENVELOPE_MAX_WIRE_BYTES).map(|_| ())
}

fn validate_lifecycle_command(
    command: &LifecycleCommand,
    runtime_config: &ImmutableRuntimeConfig,
) -> Result<(), RuntimeLifecycleContractError> {
    let valid = match command {
        LifecycleCommand::Start(spec) => {
            start_volume_authorities_match_config(&spec.volume_authorities, runtime_config)
                && spec.effect_deadline_unix_ms.get() > 0
        }
        LifecycleCommand::Suspend(spec) => spec.grace_deadline_unix_ms.get() > 0,
        LifecycleCommand::Warm(spec) => deadline_pair_valid(
            spec.grace_deadline_unix_ms,
            spec.convergence_deadline_unix_ms,
        ),
        LifecycleCommand::Cold(spec) => deadline_pair_valid(
            spec.grace_deadline_unix_ms,
            spec.convergence_deadline_unix_ms,
        ),
        LifecycleCommand::Stop(spec) => spec.grace_deadline_unix_ms.get() > 0,
        LifecycleCommand::Delete(spec) => {
            deadline_pair_valid(
                spec.grace_deadline_unix_ms,
                spec.convergence_deadline_unix_ms,
            ) && requested_volume_dispositions_valid(&spec.volume_dispositions)
                && requested_dispositions_match_config(&spec.volume_dispositions, runtime_config)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(RuntimeLifecycleContractError::InvalidContract)
    }
}

fn validate_lifecycle_predecessor(
    envelope: &LifecycleCommandEnvelope,
) -> Result<(), RuntimeLifecycleContractError> {
    let valid = match &envelope.predecessor {
        LifecyclePredecessor::Genesis {
            target_placement, ..
        } => {
            envelope.expected_predecessor_operation_id.is_none()
                && target_placement == &envelope.placement_identity
                && matches!(
                    envelope.command,
                    LifecycleCommand::Start(ref spec)
                        if spec.source == StartSource::Genesis
                            && start_authorities_match_source(
                                &spec.volume_authorities,
                                spec.source,
                            )
                )
        }
        LifecyclePredecessor::SameNode {
            operation_id,
            terminal_result_kind,
            node_id,
            placement_identity,
            ..
        } => {
            envelope.expected_predecessor_operation_id.as_ref() == Some(operation_id)
                && operation_id != &envelope.operation_id
                && node_id == &envelope.node_id
                && placement_identity == &envelope.placement_identity
                && *terminal_result_kind != TerminalResultKind::HostLost
                && legal_successor_kind(*terminal_result_kind, envelope.command.kind())
                && same_node_start_source_valid(*terminal_result_kind, &envelope.command)
        }
        LifecyclePredecessor::CrossNodeColdHandoff {
            cold_operation_id,
            source_node_id,
            source_placement,
            volume_disposition_receipts,
            target_placement,
            ..
        } => {
            envelope.expected_predecessor_operation_id.as_ref() == Some(cold_operation_id)
                && cold_operation_id != &envelope.operation_id
                && source_node_id != &envelope.node_id
                && source_placement.node_id == *source_node_id
                && source_placement != target_placement
                && target_placement == &envelope.placement_identity
                && matches!(
                    envelope.command,
                    LifecycleCommand::Start(ref spec)
                        if spec.source == StartSource::ColdHandoff
                            && start_authorities_match_source(
                                &spec.volume_authorities,
                                spec.source,
                            )
                            && cold_disposition_digest_set_is_canonical(
                                volume_disposition_receipts,
                            )
                )
        }
        LifecyclePredecessor::HostFenceRecovery {
            interrupted_operation_id,
            old_node_identity,
            takeover_authorization_ids,
            target_placement,
            ..
        } => {
            envelope.expected_predecessor_operation_id.as_ref() == Some(interrupted_operation_id)
                && interrupted_operation_id != &envelope.operation_id
                && old_node_identity.node_id != envelope.node_id
                && target_placement == &envelope.placement_identity
                && matches!(
                    envelope.command,
                    LifecycleCommand::Start(ref spec)
                        if spec.source == StartSource::HostFenceRecovery
                            && start_authorities_match_source(
                                &spec.volume_authorities,
                                spec.source,
                            )
                            && volume_authorization_set_matches_config(
                                takeover_authorization_ids,
                                spec,
                                &envelope.runtime_config,
                            )
                )
        }
    };
    if valid {
        Ok(())
    } else {
        Err(RuntimeLifecycleContractError::InvalidContract)
    }
}

fn same_node_start_source_valid(
    predecessor_kind: TerminalResultKind,
    command: &LifecycleCommand,
) -> bool {
    let LifecycleCommand::Start(spec) = command else {
        return true;
    };
    matches!(
        (predecessor_kind, spec.source),
        (
            TerminalResultKind::Suspended,
            StartSource::SameNodeSuspended
        ) | (TerminalResultKind::Warm, StartSource::SameNodeWarm)
            | (TerminalResultKind::Killed, StartSource::SameNodeStopped)
            | (TerminalResultKind::Cold, StartSource::SameNodeCold)
            | (
                TerminalResultKind::StartFailed
                    | TerminalResultKind::SuspendFailed
                    | TerminalResultKind::WarmFailed
                    | TerminalResultKind::NeedsIntervention,
                StartSource::SameNodeRetry
            )
    ) && start_authorities_match_source(&spec.volume_authorities, spec.source)
}

fn start_authorities_match_source(
    authorities: &[StartVolumeAuthority],
    source: StartSource,
) -> bool {
    authorities.iter().all(|volume| match source {
        StartSource::Genesis | StartSource::SameNodeCold | StartSource::ColdHandoff => {
            matches!(
                volume.authority,
                RuntimeVolumeAuthorityInput::NormalUnowned { .. }
            )
        }
        StartSource::SameNodeSuspended | StartSource::SameNodeWarm => matches!(
            volume.authority,
            RuntimeVolumeAuthorityInput::SameNodeOwned { .. }
        ),
        // A prior Stop can leave some volumes Owned while others were never
        // acquired or were already normally released. The exact predecessor
        // receipt and current Volume Authority decide each slot below.
        StartSource::SameNodeStopped => matches!(
            volume.authority,
            RuntimeVolumeAuthorityInput::SameNodeOwned { .. }
                | RuntimeVolumeAuthorityInput::NormalUnowned { .. }
        ),
        StartSource::HostFenceRecovery => matches!(
            volume.authority,
            RuntimeVolumeAuthorityInput::Takeover { .. }
        ),
        // A retry adopts the exact authority recorded by its failed command,
        // which may be at any one of the three closed authority stages.
        StartSource::SameNodeRetry => true,
    })
}

fn legal_successor_kind(predecessor: TerminalResultKind, successor: LifecycleCommandKind) -> bool {
    match predecessor {
        TerminalResultKind::RuntimeReady | TerminalResultKind::SuspendDeclined => matches!(
            successor,
            LifecycleCommandKind::Suspend
                | LifecycleCommandKind::Warm
                | LifecycleCommandKind::Cold
                | LifecycleCommandKind::Stop
                | LifecycleCommandKind::Delete
        ),
        TerminalResultKind::Suspended => matches!(
            successor,
            LifecycleCommandKind::Start
                | LifecycleCommandKind::Warm
                | LifecycleCommandKind::Cold
                | LifecycleCommandKind::Stop
                | LifecycleCommandKind::Delete
        ),
        TerminalResultKind::Warm => matches!(
            successor,
            LifecycleCommandKind::Start
                | LifecycleCommandKind::Cold
                | LifecycleCommandKind::Stop
                | LifecycleCommandKind::Delete
        ),
        TerminalResultKind::Cold => {
            matches!(
                successor,
                LifecycleCommandKind::Start | LifecycleCommandKind::Delete
            )
        }
        TerminalResultKind::Killed => matches!(
            successor,
            LifecycleCommandKind::Start | LifecycleCommandKind::Cold | LifecycleCommandKind::Delete
        ),
        TerminalResultKind::StartFailed => matches!(
            successor,
            LifecycleCommandKind::Start
                | LifecycleCommandKind::Cold
                | LifecycleCommandKind::Stop
                | LifecycleCommandKind::Delete
        ),
        TerminalResultKind::SuspendFailed => matches!(
            successor,
            LifecycleCommandKind::Start
                | LifecycleCommandKind::Cold
                | LifecycleCommandKind::Stop
                | LifecycleCommandKind::Delete
        ),
        TerminalResultKind::WarmFailed => matches!(
            successor,
            LifecycleCommandKind::Start
                | LifecycleCommandKind::Cold
                | LifecycleCommandKind::Stop
                | LifecycleCommandKind::Delete
        ),
        TerminalResultKind::NeedsIntervention => matches!(
            successor,
            LifecycleCommandKind::Warm
                | LifecycleCommandKind::Cold
                | LifecycleCommandKind::Stop
                | LifecycleCommandKind::Delete
        ),
        TerminalResultKind::HostLost => successor == LifecycleCommandKind::Start,
        TerminalResultKind::Deleted => false,
    }
}

fn legal_successor_result(result: &NodeResult, successor: LifecycleCommandKind) -> bool {
    match result {
        NodeResult::NeedsIntervention(intervention) => {
            if intervention.reason == InterventionReason::ForeignOrAmbiguousResidue {
                return successor == LifecycleCommandKind::Stop;
            }
            successor == LifecycleCommandKind::Stop
                || matches!(
                    (intervention.attempted_target, successor),
                    (InterventionTarget::Warm, LifecycleCommandKind::Warm)
                        | (InterventionTarget::Cold, LifecycleCommandKind::Cold)
                        | (InterventionTarget::Delete, LifecycleCommandKind::Delete)
                )
                || (successor == LifecycleCommandKind::Delete
                    && matches!(
                        intervention.reason,
                        InterventionReason::RetainedLocalTail
                            | InterventionReason::PersistentDiskNotRemoteDurable
                            | InterventionReason::WarmSnapshotAmbiguous
                            | InterventionReason::NormalReleaseAmbiguous
                            | InterventionReason::DestructiveAuthorizationRejected
                            | InterventionReason::LocalLineageAbsenceUnproven
                    ))
        }
        _ => legal_successor_kind(result.kind(), successor),
    }
}

/// Validate a command which legitimately has no predecessor journal on this
/// target Node. Genesis, planned Cold handoff and Host-fenced recovery all
/// require a complete local absence proof before the caller persists them;
/// SameNode commands must instead join the exact local terminal checkpoint.
pub fn validate_lifecycle_initial_target_admission(
    command: &LifecycleCommandEnvelope,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_lifecycle_command_envelope(command)?;
    if matches!(
        &command.predecessor,
        LifecyclePredecessor::Genesis { .. }
            | LifecyclePredecessor::CrossNodeColdHandoff { .. }
            | LifecyclePredecessor::HostFenceRecovery { .. }
    ) {
        Ok(())
    } else {
        Err(RuntimeLifecycleContractError::InvalidContract)
    }
}

/// Validate the exact durable predecessor and the frozen §4.4 successor table.
/// This must run before the Node durably accepts the successor command.
pub fn validate_lifecycle_successor(
    current: Option<&LifecycleTerminalResult>,
    successor: &LifecycleCommandEnvelope,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_lifecycle_successor_inner(current, None, successor)
}

/// Validate a successor while also binding it to the exact canonical
/// predecessor command. Failed Start retries need this extra input because a
/// terminal response intentionally carries only retained Owned receipts: the
/// prior request is the sole immutable source for an absent slot's exact
/// `NormalUnowned` transition.
pub fn validate_lifecycle_successor_with_predecessor_command(
    current: Option<&LifecycleTerminalResult>,
    predecessor_command: Option<&LifecycleCommandEnvelope>,
    successor: &LifecycleCommandEnvelope,
) -> Result<(), RuntimeLifecycleContractError> {
    match (current, predecessor_command) {
        (None, None) => {}
        (Some(LifecycleTerminalResult::NodeResult { response }), Some(predecessor_command)) => {
            validate_lifecycle_command_response_for_command(response, predecessor_command)?
        }
        (
            Some(LifecycleTerminalResult::HostLost {
                interrupted_operation_id,
                ..
            }),
            Some(predecessor_command),
        ) => {
            if interrupted_operation_id != &predecessor_command.operation_id
                || predecessor_command.workspace_id != successor.workspace_id
                || predecessor_command.cat_id != successor.cat_id
            {
                return Err(RuntimeLifecycleContractError::InvalidContract);
            }
        }
        _ => return Err(RuntimeLifecycleContractError::InvalidContract),
    }
    validate_lifecycle_successor_inner(current, predecessor_command, successor)
}

fn validate_lifecycle_successor_inner(
    current: Option<&LifecycleTerminalResult>,
    predecessor_command: Option<&LifecycleCommandEnvelope>,
    successor: &LifecycleCommandEnvelope,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_lifecycle_command_envelope(successor)?;
    match (current, &successor.predecessor) {
        (None, LifecyclePredecessor::Genesis { .. }) => Ok(()),
        (
            Some(terminal),
            LifecyclePredecessor::SameNode {
                operation_id,
                terminal_result_kind,
                terminal_result_digest,
                node_id,
                placement_identity,
            },
        ) => {
            let LifecycleTerminalResult::NodeResult { response } = terminal else {
                return Err(RuntimeLifecycleContractError::InvalidContract);
            };
            if operation_id != &response.operation_id
                || response.workspace_id != successor.workspace_id
                || response.cat_id != successor.cat_id
                || *terminal_result_kind != response.result.kind()
                || terminal_result_digest != &lifecycle_terminal_result_digest(terminal)?
                || node_id != &response.node_id
                || placement_identity != &response.placement_identity
                || !legal_successor_result(&response.result, successor.command.kind())
                || !same_node_start_authority_matches_result(
                    &response.result,
                    predecessor_command,
                    successor,
                )
            {
                return Err(RuntimeLifecycleContractError::InvalidContract);
            }
            Ok(())
        }
        (
            Some(terminal),
            LifecyclePredecessor::CrossNodeColdHandoff {
                cold_operation_id,
                cold_result_digest,
                source_node_id,
                source_placement,
                volume_disposition_receipts,
                ..
            },
        ) => {
            let LifecycleTerminalResult::NodeResult { response } = terminal else {
                return Err(RuntimeLifecycleContractError::InvalidContract);
            };
            let NodeResult::Cold(cold) = &response.result else {
                return Err(RuntimeLifecycleContractError::InvalidContract);
            };
            if cold_operation_id != &response.operation_id
                || response.workspace_id != successor.workspace_id
                || response.cat_id != successor.cat_id
                || cold_result_digest != &lifecycle_terminal_result_digest(terminal)?
                || source_node_id != &response.node_id
                || source_placement != &response.placement_identity
                || !disposition_digests_match_cold_result(volume_disposition_receipts, cold)
            {
                return Err(RuntimeLifecycleContractError::InvalidContract);
            }
            Ok(())
        }
        (
            Some(terminal),
            LifecyclePredecessor::HostFenceRecovery {
                interrupted_operation_id,
                host_lost_result_digest,
                host_fence_event_id,
                ..
            },
        ) => {
            let LifecycleTerminalResult::HostLost {
                host_fence_event_id: stored_event,
                interrupted_operation_id: stored_operation,
            } = terminal
            else {
                return Err(RuntimeLifecycleContractError::InvalidContract);
            };
            if interrupted_operation_id != stored_operation
                || host_fence_event_id != stored_event
                || host_lost_result_digest != &lifecycle_terminal_result_digest(terminal)?
            {
                return Err(RuntimeLifecycleContractError::InvalidContract);
            }
            Ok(())
        }
        _ => Err(RuntimeLifecycleContractError::InvalidContract),
    }
}

fn same_node_start_authority_matches_result(
    result: &NodeResult,
    predecessor_command: Option<&LifecycleCommandEnvelope>,
    successor: &LifecycleCommandEnvelope,
) -> bool {
    let LifecycleCommand::Start(spec) = &successor.command else {
        return true;
    };
    let receipts = match (spec.source, result) {
        (StartSource::SameNodeSuspended, NodeResult::Suspended(value)) => {
            Some(value.local_durability_receipts.as_slice())
        }
        (StartSource::SameNodeWarm, NodeResult::Warm(value)) => {
            Some(value.volume_receipts.as_slice())
        }
        (StartSource::SameNodeStopped, NodeResult::Killed(value)) => {
            return stopped_start_authorities_match_retained_receipts(
                spec,
                &successor.runtime_config,
                &value.retained_volume_receipts,
            );
        }
        (StartSource::SameNodeCold, NodeResult::Cold(_)) => None,
        (StartSource::SameNodeRetry, NodeResult::StartFailed(value)) => {
            let Some(predecessor_command) = predecessor_command else {
                return false;
            };
            return failed_start_authorities_match_retained_receipts(
                spec,
                &successor.runtime_config,
                &value.retained_volume_receipts,
                predecessor_command,
            );
        }
        (
            StartSource::SameNodeRetry,
            NodeResult::SuspendFailed(value) | NodeResult::WarmFailed(value),
        ) => {
            let Some(predecessor_command) = predecessor_command else {
                return false;
            };
            return stopped_failure_start_authorities_match_complete_receipts(
                spec,
                &successor.runtime_config,
                &value.retained_volume_receipts,
                predecessor_command,
            );
        }
        _ => return false,
    };
    receipts.is_none_or(|receipts| {
        spec.volume_authorities.len() == receipts.len()
            && spec
                .volume_authorities
                .iter()
                .zip(receipts)
                .all(|(authority, receipt)| {
                    authority.volume_id == receipt.volume_id
                        && authority.disk_id == receipt.disk_id
                        && matches!(
                            &authority.authority,
                            RuntimeVolumeAuthorityInput::SameNodeOwned {
                                attachment_id,
                                attachment_epoch,
                            } if attachment_id == &receipt.attachment_id
                                && attachment_epoch == &receipt.attachment_epoch
                        )
                })
    })
}

fn failed_start_authorities_match_retained_receipts(
    retry: &StartSpec,
    config: &ImmutableRuntimeConfig,
    retained: &[VolumeTerminalReceipt],
    predecessor_command: &LifecycleCommandEnvelope,
) -> bool {
    let LifecycleCommand::Start(failed) = &predecessor_command.command else {
        return false;
    };
    if predecessor_command.runtime_config.as_ref() != config
        || !volume_receipts_are_config_subset(retained, config)
    {
        return false;
    }

    retry
        .volume_authorities
        .iter()
        .zip(&config.volumes)
        .zip(&failed.volume_authorities)
        .all(|((retry_authority, volume), failed_authority)| {
            let retained = retained
                .binary_search_by(|receipt| {
                    receipt.volume_id.as_str().cmp(volume.volume_id.as_str())
                })
                .ok()
                .map(|index| &retained[index]);
            match (retained, &retry_authority.authority) {
                (
                    Some(receipt),
                    RuntimeVolumeAuthorityInput::SameNodeOwned {
                        attachment_id,
                        attachment_epoch,
                    },
                ) => {
                    retry_authority.volume_id == receipt.volume_id
                        && retry_authority.disk_id == receipt.disk_id
                        && attachment_id == &receipt.attachment_id
                        && attachment_epoch == &receipt.attachment_epoch
                }
                (None, RuntimeVolumeAuthorityInput::NormalUnowned { .. }) => {
                    retry_authority.volume_id == volume.volume_id
                        && retry_authority.disk_id == volume.disk_id
                        && failed_authority.volume_id == volume.volume_id
                        && failed_authority.disk_id == volume.disk_id
                        && matches!(
                            &failed_authority.authority,
                            RuntimeVolumeAuthorityInput::NormalUnowned { .. }
                        )
                        && retry_authority == failed_authority
                }
                _ => false,
            }
        })
}

fn stopped_failure_start_authorities_match_complete_receipts(
    retry: &StartSpec,
    config: &ImmutableRuntimeConfig,
    retained: &[VolumeTerminalReceipt],
    predecessor_command: &LifecycleCommandEnvelope,
) -> bool {
    if predecessor_command.runtime_config.as_ref() != config
        || !matches!(
            &predecessor_command.command,
            LifecycleCommand::Suspend(_) | LifecycleCommand::Warm(_)
        )
        || !volume_receipts_match_config(retained, config)
    {
        return false;
    }
    retry
        .volume_authorities
        .iter()
        .zip(retained)
        .all(|(authority, receipt)| {
            authority.volume_id == receipt.volume_id
                && authority.disk_id == receipt.disk_id
                && matches!(
                    &authority.authority,
                    RuntimeVolumeAuthorityInput::SameNodeOwned {
                        attachment_id,
                        attachment_epoch,
                    } if attachment_id == &receipt.attachment_id
                        && attachment_epoch == &receipt.attachment_epoch
                )
        })
}

fn stopped_start_authorities_match_retained_receipts(
    spec: &StartSpec,
    config: &ImmutableRuntimeConfig,
    retained: &[VolumeTerminalReceipt],
) -> bool {
    if !volume_receipts_are_config_subset(retained, config) {
        return false;
    }
    spec.volume_authorities
        .iter()
        .zip(&config.volumes)
        .all(|(authority, volume)| {
            let retained = retained
                .binary_search_by(|receipt| {
                    receipt.volume_id.as_str().cmp(volume.volume_id.as_str())
                })
                .ok()
                .map(|index| &retained[index]);
            match (retained, &authority.authority) {
                (
                    Some(receipt),
                    RuntimeVolumeAuthorityInput::SameNodeOwned {
                        attachment_id,
                        attachment_epoch,
                    },
                ) => {
                    authority.volume_id == receipt.volume_id
                        && authority.disk_id == receipt.disk_id
                        && attachment_id == &receipt.attachment_id
                        && attachment_epoch == &receipt.attachment_epoch
                }
                (None, RuntimeVolumeAuthorityInput::NormalUnowned { .. }) => {
                    authority.volume_id == volume.volume_id && authority.disk_id == volume.disk_id
                }
                _ => false,
            }
        })
}

pub fn validate_lifecycle_command_response(
    response: &LifecycleCommandResponse,
) -> Result<(), RuntimeLifecycleContractError> {
    if response.version != ContractVersion::V1
        || response.placement_identity.node_id != response.node_id
        || !node_result_structure_valid(&response.result)
    {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_lifecycle_command_response_for_command(
    response: &LifecycleCommandResponse,
    command: &LifecycleCommandEnvelope,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_lifecycle_command_response(response)?;
    validate_lifecycle_command_envelope(command)?;
    if response.operation_id != command.operation_id
        || response.workspace_id != command.workspace_id
        || response.cat_id != command.cat_id
        || response.node_id != command.node_id
        || response.placement_identity != command.placement_identity
        || response.request_fingerprint != command.request_fingerprint
        || !node_result_matches_command(&response.result, &command.command)
        || !node_result_matches_runtime_config(&response.result, &command.runtime_config)
        || !node_result_matches_delete_request(&response.result, &command.command)
    {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

/// Validate result evidence against an immutable config obtained independently
/// from its command (for example, while checking a persisted projection).
pub fn validate_lifecycle_command_response_for_runtime_config(
    response: &LifecycleCommandResponse,
    config: &ImmutableRuntimeConfig,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_lifecycle_command_response(response)?;
    validate_immutable_runtime_config(config)?;
    if !node_result_matches_runtime_config(&response.result, config) {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_lifecycle_terminal_result(
    terminal: &LifecycleTerminalResult,
) -> Result<(), RuntimeLifecycleContractError> {
    match terminal {
        LifecycleTerminalResult::NodeResult { response } => {
            validate_lifecycle_command_response(response)
        }
        LifecycleTerminalResult::HostLost {
            host_fence_event_id: _,
            interrupted_operation_id: _,
        } => Ok(()),
    }
}

fn node_result_matches_command(result: &NodeResult, command: &LifecycleCommand) -> bool {
    matches!(
        (command.kind(), result),
        (
            LifecycleCommandKind::Start,
            NodeResult::RuntimeReady(_) | NodeResult::StartFailed(_)
        ) | (
            LifecycleCommandKind::Suspend,
            NodeResult::Suspended(_)
                | NodeResult::SuspendDeclined(_)
                | NodeResult::SuspendFailed(_)
        ) | (
            LifecycleCommandKind::Warm,
            NodeResult::Warm(_) | NodeResult::WarmFailed(_) | NodeResult::NeedsIntervention(_)
        ) | (
            LifecycleCommandKind::Cold,
            NodeResult::Cold(_) | NodeResult::NeedsIntervention(_)
        ) | (LifecycleCommandKind::Stop, NodeResult::Killed(_))
            | (
                LifecycleCommandKind::Delete,
                NodeResult::Deleted(_) | NodeResult::NeedsIntervention(_)
            )
    ) && match result {
        NodeResult::NeedsIntervention(value) => matches!(
            (command.kind(), value.attempted_target),
            (LifecycleCommandKind::Warm, InterventionTarget::Warm)
                | (LifecycleCommandKind::Cold, InterventionTarget::Cold)
                | (LifecycleCommandKind::Delete, InterventionTarget::Delete)
        ),
        _ => true,
    }
}

fn node_result_matches_delete_request(result: &NodeResult, command: &LifecycleCommand) -> bool {
    match command {
        LifecycleCommand::Delete(spec) => match result {
            NodeResult::Deleted(deleted) => completed_dispositions_match_requested(
                &deleted.volume_dispositions,
                &spec.volume_dispositions,
            ),
            _ => true,
        },
        _ => true,
    }
}

fn node_result_matches_runtime_config(
    result: &NodeResult,
    config: &ImmutableRuntimeConfig,
) -> bool {
    if let NodeResult::Cold(cold) = result {
        return cold.runtime_config_digest == config.config_digest
            && cold_dispositions_match_config(&cold.volume_dispositions, config);
    }
    let (digest, receipts, receipts_must_be_complete): (
        Option<&Sha256Digest>,
        Option<&[VolumeTerminalReceipt]>,
        bool,
    ) = match result {
        NodeResult::RuntimeReady(value) => (
            Some(&value.runtime_config_digest),
            Some(&value.volume_receipts),
            true,
        ),
        NodeResult::Suspended(value) => (
            Some(&value.runtime_config_digest),
            Some(&value.local_durability_receipts),
            true,
        ),
        NodeResult::SuspendDeclined(value) => (
            Some(&value.effective_runtime_ready.runtime_config_digest),
            None,
            false,
        ),
        NodeResult::Warm(value) => (
            Some(&value.runtime_config_digest),
            Some(&value.volume_receipts),
            true,
        ),
        // Handled above because Cold has a closed mixed disposition set, not
        // a homogeneous list of attachment-bearing terminal receipts.
        NodeResult::Cold(_) => (None, None, false),
        NodeResult::Killed(value) => (None, Some(&value.retained_volume_receipts), false),
        NodeResult::NeedsIntervention(value) => {
            (None, Some(&value.retained_volume_receipts), false)
        }
        NodeResult::StartFailed(value)
        | NodeResult::SuspendFailed(value)
        | NodeResult::WarmFailed(value) => (None, Some(&value.retained_volume_receipts), false),
        NodeResult::Deleted(_) => (None, None, false),
    };
    digest.is_none_or(|digest| digest == &config.config_digest)
        && receipts.is_none_or(|receipts| {
            if receipts_must_be_complete {
                volume_receipts_match_config(receipts, config)
            } else {
                volume_receipts_are_config_subset(receipts, config)
            }
        })
}

fn node_result_structure_valid(result: &NodeResult) -> bool {
    match result {
        NodeResult::RuntimeReady(value) => {
            volume_receipts_valid(&value.volume_receipts, false, true)
        }
        NodeResult::StartFailed(value)
        | NodeResult::SuspendFailed(value)
        | NodeResult::WarmFailed(value) => {
            retained_evidence_valid(&value.retained_evidence)
                && volume_receipts_valid(&value.retained_volume_receipts, false, true)
        }
        NodeResult::Suspended(value) => {
            volume_receipts_valid(&value.local_durability_receipts, false, true)
        }
        NodeResult::SuspendDeclined(_) => true,
        NodeResult::Warm(value) => volume_receipts_valid(&value.volume_receipts, true, true),
        NodeResult::Cold(value) => cold_volume_dispositions_valid(&value.volume_dispositions),
        NodeResult::Killed(value) => {
            retained_evidence_valid(&value.retained_evidence)
                && volume_receipts_valid(&value.retained_volume_receipts, false, true)
        }
        NodeResult::Deleted(value) => {
            completed_volume_dispositions_valid(&value.volume_dispositions)
        }
        NodeResult::NeedsIntervention(value) => {
            retained_evidence_valid(&value.retained_evidence)
                && volume_receipts_valid(&value.retained_volume_receipts, false, true)
        }
    }
}

pub fn validate_lifecycle_command_poll_request(
    poll: &LifecycleCommandPollRequest,
) -> Result<(), RuntimeLifecycleContractError> {
    if poll.version == ContractVersion::V1 {
        Ok(())
    } else {
        Err(RuntimeLifecycleContractError::InvalidContract)
    }
}

pub fn validate_lifecycle_command_poll_for_session(
    poll: &LifecycleCommandPollRequest,
    current_session: &AgentSession,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_lifecycle_command_poll_request(poll)?;
    validate_agent_session(current_session)?;
    if poll.session != session_binding(current_session) {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_lifecycle_command_batch(
    batch: &LifecycleCommandBatch,
) -> Result<(), RuntimeLifecycleContractError> {
    if batch.version != ContractVersion::V1
        || batch.commands.len() > LIFECYCLE_COMMAND_BATCH_MAX_COMMANDS
        || !batch
            .commands
            .windows(2)
            .all(|pair| pair[0].cat_id.as_str() < pair[1].cat_id.as_str())
        || has_duplicate_by(&batch.commands, |command| command.operation_id.as_str())
    {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    for command in &batch.commands {
        validate_lifecycle_command_envelope(command)?;
        if command.node_id != batch.session.node_id {
            return Err(RuntimeLifecycleContractError::InvalidContract);
        }
    }
    Ok(())
}

pub fn validate_lifecycle_command_batch_for_poll(
    batch: &LifecycleCommandBatch,
    poll: &LifecycleCommandPollRequest,
    current_session: &AgentSession,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_lifecycle_command_batch(batch)?;
    validate_lifecycle_command_poll_for_session(poll, current_session)?;
    if batch.session != poll.session || batch.request_sequence != poll.request_sequence {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_lifecycle_command_query(
    query: &LifecycleCommandQuery,
) -> Result<(), RuntimeLifecycleContractError> {
    if query.version == ContractVersion::V1 {
        Ok(())
    } else {
        Err(RuntimeLifecycleContractError::InvalidContract)
    }
}

pub fn validate_lifecycle_command_query_for_session(
    query: &LifecycleCommandQuery,
    current_session: &AgentSession,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_lifecycle_command_query(query)?;
    validate_agent_session(current_session)?;
    if query.node_id != current_session.node_id {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_lifecycle_result_commit_request(
    commit: &LifecycleResultCommitRequest,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_lifecycle_command_response(&commit.response)?;
    let terminal = LifecycleTerminalResult::NodeResult {
        response: commit.response.clone(),
    };
    if commit.version != ContractVersion::V1
        || commit.session.node_id != commit.response.node_id
        || commit.terminal_result_digest != lifecycle_terminal_result_digest(&terminal)?
    {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_lifecycle_result_commit_for_command(
    commit: &LifecycleResultCommitRequest,
    command: &LifecycleCommandEnvelope,
    current_session: &AgentSession,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_lifecycle_result_commit_request(commit)?;
    validate_agent_session(current_session)?;
    validate_lifecycle_command_response_for_command(&commit.response, command)?;
    if commit.session != session_binding(current_session) {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_lifecycle_result_stored_ack(
    ack: &LifecycleResultStoredAck,
) -> Result<(), RuntimeLifecycleContractError> {
    if ack.version == ContractVersion::V1 {
        Ok(())
    } else {
        Err(RuntimeLifecycleContractError::InvalidContract)
    }
}

pub fn validate_lifecycle_result_stored_ack_for_response(
    ack: &LifecycleResultStoredAck,
    response: &LifecycleCommandResponse,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_lifecycle_result_stored_ack(ack)?;
    validate_lifecycle_command_response(response)?;
    let terminal = LifecycleTerminalResult::NodeResult {
        response: Box::new(response.clone()),
    };
    if ack.node_id != response.node_id
        || ack.cat_id != response.cat_id
        || ack.operation_id != response.operation_id
        || ack.request_fingerprint != response.request_fingerprint
        || ack.terminal_result_digest != lifecycle_terminal_result_digest(&terminal)?
    {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_completed_command_receipt(
    receipt: &CompletedCommandReceipt,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_completed_command_receipt_unsigned(receipt)?;
    if completed_command_receipt_digest(receipt)? != receipt.completed_receipt_digest {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

fn validate_completed_command_receipt_unsigned(
    receipt: &CompletedCommandReceipt,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_lifecycle_command_response(&receipt.terminal_response)?;
    let terminal = LifecycleTerminalResult::NodeResult {
        response: receipt.terminal_response.clone(),
    };
    if receipt.version != ContractVersion::V1
        || receipt.node_id != receipt.terminal_response.node_id
        || receipt.cat_id != receipt.terminal_response.cat_id
        || receipt.placement_identity != receipt.terminal_response.placement_identity
        || receipt.operation_id != receipt.terminal_response.operation_id
        || receipt.request_fingerprint != receipt.terminal_response.request_fingerprint
        || receipt.terminal_result_digest != lifecycle_terminal_result_digest(&terminal)?
        || !matches!(receipt.terminal_response.result, NodeResult::Deleted(_))
    {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_lifecycle_operation(
    operation: &LifecycleOperation,
) -> Result<(), RuntimeLifecycleContractError> {
    validate_lifecycle_command_envelope(&operation.canonical_request)?;
    if operation.version != ContractVersion::V1
        || operation.operation_id != operation.canonical_request.operation_id
        || operation.workspace_id != operation.canonical_request.workspace_id
        || operation.cat_id != operation.canonical_request.cat_id
        || operation.node_id != operation.canonical_request.node_id
        || operation.placement_identity != operation.canonical_request.placement_identity
        || operation.runtime_config_id != operation.canonical_request.runtime_config.config_id
        || operation.runtime_config_digest
            != operation.canonical_request.runtime_config.config_digest
        || operation.command_kind != operation.canonical_request.command.kind()
        || operation.request_fingerprint != operation.canonical_request.request_fingerprint
        || operation.expected_predecessor_operation_id
            != operation
                .canonical_request
                .expected_predecessor_operation_id
        || operation.predecessor != operation.canonical_request.predecessor
        || operation.created_at_unix_ms.get() == 0
    {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    match (&operation.state, operation.terminal_at_unix_ms) {
        (LifecycleOperationState::Unresolved, None) => Ok(()),
        (
            LifecycleOperationState::Terminal {
                terminal,
                terminal_result_digest,
            },
            Some(terminal_at),
        ) if terminal_at >= operation.created_at_unix_ms => {
            validate_lifecycle_terminal_result(terminal)?;
            if terminal_result_digest != &lifecycle_terminal_result_digest(terminal)?
                || terminal.operation_id() != &operation.operation_id
            {
                return Err(RuntimeLifecycleContractError::InvalidContract);
            }
            match terminal.as_ref() {
                LifecycleTerminalResult::NodeResult { response } => {
                    validate_lifecycle_command_response_for_command(
                        response,
                        &operation.canonical_request,
                    )
                }
                LifecycleTerminalResult::HostLost { .. } => Ok(()),
            }
        }
        _ => Err(RuntimeLifecycleContractError::InvalidContract),
    }
}

pub fn validate_artifact_classifications(
    artifacts: &[ArtifactClassification],
) -> Result<(), RuntimeLifecycleContractError> {
    if artifacts.len() > LIFECYCLE_MAX_ARTIFACT_CLASSIFICATIONS
        || !artifacts
            .windows(2)
            .all(|pair| pair[0].artifact_id().as_str() < pair[1].artifact_id().as_str())
    {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

pub fn validate_atomic_lifecycle_error(
    error: &AtomicLifecycleError,
) -> Result<(), RuntimeLifecycleContractError> {
    if matches!(
        error,
        AtomicLifecycleError::UnsupportedVersion { supported_version }
            if *supported_version != ContractVersion::V1
    ) {
        return Err(RuntimeLifecycleContractError::InvalidContract);
    }
    Ok(())
}

fn deadline_pair_valid(grace: UnixMillis, convergence: UnixMillis) -> bool {
    grace.get() > 0 && convergence >= grace
}

fn requested_volume_dispositions_valid(dispositions: &[RequestedVolumeDisposition]) -> bool {
    !dispositions.is_empty()
        && dispositions.len() <= LIFECYCLE_MAX_VOLUMES
        && dispositions
            .windows(2)
            .all(|pair| pair[0].volume_id().as_str() < pair[1].volume_id().as_str())
        && !has_duplicate_by(dispositions, |disposition| disposition.disk_id().as_str())
        && dispositions
            .iter()
            .filter(|disposition| {
                matches!(
                    disposition,
                    RequestedVolumeDisposition::DiscardWithCat {
                        disk_role: DiskRole::Root,
                        ..
                    }
                )
            })
            .count()
            == 1
        && dispositions.iter().all(|disposition| {
            matches!(
                disposition,
                RequestedVolumeDisposition::DiscardWithCat {
                    disk_role: DiskRole::Root,
                    ..
                } | RequestedVolumeDisposition::RetainDetached {
                    disk_role: DiskRole::Persistent,
                    ..
                }
            )
        })
}

fn requested_dispositions_match_config(
    dispositions: &[RequestedVolumeDisposition],
    config: &ImmutableRuntimeConfig,
) -> bool {
    dispositions.len() == config.volumes.len()
        && dispositions
            .iter()
            .zip(&config.volumes)
            .all(|(disposition, volume)| match disposition {
                RequestedVolumeDisposition::DiscardWithCat {
                    volume_id,
                    disk_id,
                    disk_role,
                }
                | RequestedVolumeDisposition::RetainDetached {
                    volume_id,
                    disk_id,
                    disk_role,
                } => {
                    volume_id == &volume.volume_id
                        && disk_id == &volume.disk_id
                        && disk_role == &volume.disk_role
                }
            })
}

fn start_volume_authorities_match_config(
    authorities: &[StartVolumeAuthority],
    config: &ImmutableRuntimeConfig,
) -> bool {
    authorities.len() == config.volumes.len()
        && !authorities.is_empty()
        && authorities.len() <= LIFECYCLE_MAX_VOLUMES
        && authorities
            .windows(2)
            .all(|pair| pair[0].volume_id.as_str() < pair[1].volume_id.as_str())
        && authorities
            .iter()
            .zip(&config.volumes)
            .all(|(authority, volume)| {
                authority.volume_id == volume.volume_id
                    && authority.disk_id == volume.disk_id
                    && !matches!(
                        authority.authority,
                        RuntimeVolumeAuthorityInput::SameNodeOwned {
                            attachment_epoch,
                            ..
                        } if attachment_epoch.get() == 0
                    )
            })
}

fn cold_disposition_digest_set_is_canonical(dispositions: &[ColdVolumeDispositionDigest]) -> bool {
    // These receipts describe the immutable predecessor Cold config, not the
    // successor Start config. A settled Cold window may append/detach product
    // volumes before Start. Standalone envelope validation can prove only the
    // canonical closed set; `validate_lifecycle_successor` below binds the
    // whole set byte-for-byte to the exact Cold terminal result.
    !dispositions.is_empty()
        && dispositions.len() <= LIFECYCLE_MAX_VOLUMES
        && dispositions
            .windows(2)
            .all(|pair| pair[0].volume_id().as_str() < pair[1].volume_id().as_str())
}

fn volume_authorization_set_matches_config(
    authorizations: &[VolumeAuthorizationId],
    spec: &StartSpec,
    config: &ImmutableRuntimeConfig,
) -> bool {
    authorizations.len() == config.volumes.len()
        && authorizations.len() <= LIFECYCLE_MAX_TAKEOVER_AUTHORIZATIONS
        && authorizations
            .windows(2)
            .all(|pair| pair[0].volume_id.as_str() < pair[1].volume_id.as_str())
        && authorizations
            .iter()
            .zip(&spec.volume_authorities)
            .all(|(authorization, volume)| {
                authorization.volume_id == volume.volume_id
                    && matches!(
                        &volume.authority,
                        RuntimeVolumeAuthorityInput::Takeover { authorization_id }
                            if authorization_id == &authorization.authorization_id
                    )
            })
}

fn disposition_digests_match_cold_result(
    digests: &[ColdVolumeDispositionDigest],
    cold: &ColdResult,
) -> bool {
    digests.len() == cold.volume_dispositions.len()
        && digests
            .iter()
            .zip(&cold.volume_dispositions)
            .all(|(digest, disposition)| {
                matches!(
                    (digest, disposition),
                    (
                        ColdVolumeDispositionDigest::NormallyReleased {
                            volume_id,
                            normal_release_receipt_digest,
                        },
                        ColdVolumeDisposition::NormallyReleased {
                            volume,
                            normal_release_receipt_digest: terminal_digest,
                        },
                    ) if volume_id == &volume.volume_id
                        && normal_release_receipt_digest == terminal_digest
                        && volume.authority_receipt_digest.as_ref() == Some(terminal_digest)
                ) || matches!(
                    (digest, disposition),
                    (
                        ColdVolumeDispositionDigest::AlreadyUnowned {
                            volume_id,
                            already_unowned_receipt_digest,
                        },
                        ColdVolumeDisposition::AlreadyUnowned {
                            volume_id: terminal_volume_id,
                            already_unowned_receipt_digest: terminal_digest,
                            ..
                        },
                    ) if volume_id == terminal_volume_id
                        && already_unowned_receipt_digest == terminal_digest
                )
            })
}

fn retained_evidence_valid(evidence: &RetainedEvidence) -> bool {
    let counts = [
        evidence.adoptable_count,
        evidence.gc_candidate_count,
        evidence.retained_authority_or_data_count,
        evidence.quarantined_count,
    ];
    counts.iter().all(|count| *count <= 1_024)
        && counts
            .iter()
            .try_fold(0_u16, |sum, count| sum.checked_add(*count))
            .is_some_and(|sum| sum <= 1_024)
}

fn volume_receipts_valid(
    receipts: &[VolumeTerminalReceipt],
    require_remote_equals_local: bool,
    require_authority_receipt: bool,
) -> bool {
    receipts.len() <= LIFECYCLE_MAX_VOLUMES
        && receipts
            .windows(2)
            .all(|pair| pair[0].volume_id.as_str() < pair[1].volume_id.as_str())
        && !has_duplicate_by(receipts, |receipt| receipt.disk_id.as_str())
        && receipts
            .iter()
            .filter(|receipt| receipt.disk_role == DiskRole::Root)
            .count()
            <= 1
        && receipts.iter().all(|receipt| {
            receipt.attachment_epoch.get() > 0
                && receipt.remote_durable_generation <= receipt.local_durable_generation
                && (!require_remote_equals_local
                    || receipt.remote_durable_generation == receipt.local_durable_generation)
                && (!require_authority_receipt || receipt.authority_receipt_digest.is_some())
        })
}

fn cold_volume_dispositions_valid(dispositions: &[ColdVolumeDisposition]) -> bool {
    !dispositions.is_empty()
        && dispositions.len() <= LIFECYCLE_MAX_VOLUMES
        && dispositions
            .windows(2)
            .all(|pair| pair[0].volume_id().as_str() < pair[1].volume_id().as_str())
        && !has_duplicate_by(dispositions, |disposition| match disposition {
            ColdVolumeDisposition::NormallyReleased { volume, .. } => volume.disk_id.as_str(),
            ColdVolumeDisposition::AlreadyUnowned { disk_id, .. } => disk_id.as_str(),
        })
        && dispositions
            .iter()
            .filter(|disposition| {
                matches!(
                    disposition,
                    ColdVolumeDisposition::NormallyReleased { volume, .. }
                        if volume.disk_role == DiskRole::Root
                ) || matches!(
                    disposition,
                    ColdVolumeDisposition::AlreadyUnowned {
                        disk_role: DiskRole::Root,
                        ..
                    }
                )
            })
            .count()
            <= 1
        && dispositions.iter().all(|disposition| match disposition {
            ColdVolumeDisposition::NormallyReleased {
                volume,
                normal_release_receipt_digest,
            } => {
                volume.remote_durable_generation == volume.local_durable_generation
                    && volume.attachment_epoch.get() > 0
                    && volume.authority_receipt_digest.as_ref()
                        == Some(normal_release_receipt_digest)
            }
            ColdVolumeDisposition::AlreadyUnowned {
                unowned_epoch,
                remote_head,
                ..
            } => unowned_epoch.get() > 0 && lifecycle_remote_head_valid(remote_head),
        })
}

fn lifecycle_remote_head_valid(head: &RemoteHead) -> bool {
    if head.generation.get() == 0 {
        head.root_hash.is_none() && head.root_object_id.is_none()
    } else {
        head.root_hash.is_some() && head.root_object_id.is_some()
    }
}

fn cold_dispositions_match_config(
    dispositions: &[ColdVolumeDisposition],
    config: &ImmutableRuntimeConfig,
) -> bool {
    dispositions.len() == config.volumes.len()
        && dispositions
            .iter()
            .zip(&config.volumes)
            .all(|(disposition, expected)| match disposition {
                ColdVolumeDisposition::NormallyReleased { volume, .. } => {
                    volume.volume_id == expected.volume_id
                        && volume.disk_id == expected.disk_id
                        && volume.disk_role == expected.disk_role
                }
                ColdVolumeDisposition::AlreadyUnowned {
                    volume_id,
                    disk_id,
                    disk_role,
                    ..
                } => {
                    volume_id == &expected.volume_id
                        && disk_id == &expected.disk_id
                        && disk_role == &expected.disk_role
                }
            })
}

fn volume_receipts_match_config(
    receipts: &[VolumeTerminalReceipt],
    config: &ImmutableRuntimeConfig,
) -> bool {
    receipts.len() == config.volumes.len()
        && receipts
            .iter()
            .zip(&config.volumes)
            .all(|(receipt, volume)| {
                receipt.volume_id == volume.volume_id
                    && receipt.disk_id == volume.disk_id
                    && receipt.disk_role == volume.disk_role
            })
}

fn volume_receipts_are_config_subset(
    receipts: &[VolumeTerminalReceipt],
    config: &ImmutableRuntimeConfig,
) -> bool {
    receipts.iter().all(|receipt| {
        config
            .volumes
            .binary_search_by(|volume| volume.volume_id.as_str().cmp(receipt.volume_id.as_str()))
            .ok()
            .is_some_and(|index| {
                let volume = &config.volumes[index];
                receipt.disk_id == volume.disk_id && receipt.disk_role == volume.disk_role
            })
    })
}

fn completed_volume_dispositions_valid(dispositions: &[CompletedVolumeDisposition]) -> bool {
    !dispositions.is_empty()
        && dispositions.len() <= LIFECYCLE_MAX_VOLUMES
        && dispositions
            .windows(2)
            .all(|pair| pair[0].volume_id().as_str() < pair[1].volume_id().as_str())
        && dispositions
            .iter()
            .filter(|disposition| {
                matches!(
                    disposition,
                    CompletedVolumeDisposition::RootNormallyDeleted { .. }
                        | CompletedVolumeDisposition::RootAlreadyUnownedDeleted { .. }
                        | CompletedVolumeDisposition::RootDisposableTailDeleted { .. }
                )
            })
            .count()
            == 1
        && dispositions.iter().all(|disposition| match disposition {
            CompletedVolumeDisposition::PersistentRetainedDetached {
                volume,
                normal_release_receipt_digest,
            } => {
                volume.disk_role == DiskRole::Persistent
                    && volume.remote_durable_generation == volume.local_durable_generation
                    && volume.authority_receipt_digest.as_ref()
                        == Some(normal_release_receipt_digest)
            }
            CompletedVolumeDisposition::PersistentAlreadyDetached { .. } => true,
            CompletedVolumeDisposition::RootNormallyDeleted { volume, .. } => {
                volume.disk_role == DiskRole::Root
                    && volume.remote_durable_generation == volume.local_durable_generation
                    && volume.authority_receipt_digest.is_some()
            }
            CompletedVolumeDisposition::RootAlreadyUnownedDeleted { .. } => true,
            CompletedVolumeDisposition::RootDisposableTailDeleted {
                previous_attachment_epoch,
                ..
            } => previous_attachment_epoch.get() > 0,
        })
}

fn completed_dispositions_match_requested(
    completed: &[CompletedVolumeDisposition],
    requested: &[RequestedVolumeDisposition],
) -> bool {
    completed.len() == requested.len()
        && completed
            .iter()
            .zip(requested)
            .all(|(completed, requested)| match (completed, requested) {
                (
                    CompletedVolumeDisposition::PersistentRetainedDetached { volume, .. },
                    RequestedVolumeDisposition::RetainDetached {
                        volume_id,
                        disk_id,
                        disk_role: DiskRole::Persistent,
                    },
                ) => volume.volume_id == *volume_id && volume.disk_id == *disk_id,
                (
                    CompletedVolumeDisposition::PersistentAlreadyDetached {
                        volume_id: completed_volume_id,
                        disk_id: completed_disk_id,
                        ..
                    },
                    RequestedVolumeDisposition::RetainDetached {
                        volume_id,
                        disk_id,
                        disk_role: DiskRole::Persistent,
                    },
                ) => completed_volume_id == volume_id && completed_disk_id == disk_id,
                (
                    CompletedVolumeDisposition::RootNormallyDeleted { volume, .. },
                    RequestedVolumeDisposition::DiscardWithCat {
                        volume_id,
                        disk_id,
                        disk_role: DiskRole::Root,
                    },
                ) => volume.volume_id == *volume_id && volume.disk_id == *disk_id,
                (
                    CompletedVolumeDisposition::RootAlreadyUnownedDeleted {
                        volume_id: completed_volume_id,
                        disk_id: completed_disk_id,
                        ..
                    },
                    RequestedVolumeDisposition::DiscardWithCat {
                        volume_id,
                        disk_id,
                        disk_role: DiskRole::Root,
                    },
                ) => completed_volume_id == volume_id && completed_disk_id == disk_id,
                (
                    CompletedVolumeDisposition::RootDisposableTailDeleted {
                        volume_id: completed_volume_id,
                        disk_id: completed_disk_id,
                        ..
                    },
                    RequestedVolumeDisposition::DiscardWithCat {
                        volume_id,
                        disk_id,
                        disk_role: DiskRole::Root,
                    },
                ) => completed_volume_id == volume_id && completed_disk_id == disk_id,
                _ => false,
            })
}

fn validate_agent_session(session: &AgentSession) -> Result<(), RuntimeLifecycleContractError> {
    encode_agent_session(session)
        .map(|_| ())
        .map_err(|_| RuntimeLifecycleContractError::InvalidContract)
}

fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn has_duplicate_by<T>(items: &[T], key: fn(&T) -> &str) -> bool {
    items.iter().enumerate().any(|(index, item)| {
        items[index + 1..]
            .iter()
            .any(|other| key(item) == key(other))
    })
}

fn has_duplicate_u16<T>(items: &[T], key: fn(&T) -> u16) -> bool {
    items.iter().enumerate().any(|(index, item)| {
        items[index + 1..]
            .iter()
            .any(|other| key(item) == key(other))
    })
}

fn digest_canonical<T: Serialize>(
    domain: &[u8],
    value: &T,
    maximum: usize,
) -> Result<Sha256Digest, RuntimeLifecycleContractError> {
    let canonical = encode_canonical(value, maximum)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(canonical);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn encode_canonical<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, RuntimeLifecycleContractError> {
    let value =
        serde_json::to_value(value).map_err(|_| RuntimeLifecycleContractError::InvalidContract)?;
    let bytes = crate::runtime_reconciliation::canonical_json_value_bytes(&value);
    if bytes.len() > maximum {
        return Err(RuntimeLifecycleContractError::WireTooLarge);
    }
    Ok(bytes)
}

fn decode_canonical<T>(
    bytes: &[u8],
    maximum: usize,
    validate: fn(&T) -> Result<(), RuntimeLifecycleContractError>,
) -> Result<T, RuntimeLifecycleContractError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.len() > maximum {
        return Err(RuntimeLifecycleContractError::WireTooLarge);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value =
        T::deserialize(&mut decoder).map_err(|_| RuntimeLifecycleContractError::Malformed)?;
    decoder
        .end()
        .map_err(|_| RuntimeLifecycleContractError::Malformed)?;
    validate(&value)?;
    if encode_canonical(&value, maximum)?.as_slice() != bytes {
        return Err(RuntimeLifecycleContractError::NonCanonical);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_reconciliation::NodeBootId;

    fn id(value: &str) -> Id {
        Id::new(value).expect("valid test ID")
    }

    fn random(value: u128) -> RandomId128 {
        RandomId128::new(format!("{value:032x}")).expect("valid test random ID")
    }

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    fn epoch(value: u64) -> Epoch {
        Epoch::new(value).expect("positive epoch")
    }

    fn fence_epoch(value: u64) -> FenceEpoch {
        FenceEpoch::new(value).expect("wire fence epoch")
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("wire generation")
    }

    fn millis(value: u64) -> UnixMillis {
        UnixMillis::new(value).expect("wire timestamp")
    }

    fn placement(node: &str, value: u64) -> PlacementIdentity {
        PlacementIdentity {
            node_id: id(node),
            placement_epoch: epoch(value),
        }
    }

    fn runtime_config(vcpus: u32) -> ImmutableRuntimeConfig {
        ImmutableRuntimeConfig::new(
            id("config.001"),
            digest(1),
            vcpus,
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
        .expect("valid runtime config")
    }

    fn normal_authorities(config: &ImmutableRuntimeConfig) -> Vec<StartVolumeAuthority> {
        config
            .volumes
            .iter()
            .enumerate()
            .map(|(index, volume)| StartVolumeAuthority {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                authority: RuntimeVolumeAuthorityInput::NormalUnowned {
                    expected_unowned_epoch: fence_epoch(index as u64),
                    transition_id: random(10 + index as u128),
                },
            })
            .collect()
    }

    fn same_node_authorities(config: &ImmutableRuntimeConfig) -> Vec<StartVolumeAuthority> {
        config
            .volumes
            .iter()
            .enumerate()
            .map(|(index, volume)| StartVolumeAuthority {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                authority: RuntimeVolumeAuthorityInput::SameNodeOwned {
                    attachment_id: id(&format!("attachment.{index}")),
                    attachment_epoch: fence_epoch(10 + index as u64),
                },
            })
            .collect()
    }

    fn takeover_authorities(
        config: &ImmutableRuntimeConfig,
    ) -> (Vec<StartVolumeAuthority>, Vec<VolumeAuthorizationId>) {
        let authorizations = config
            .volumes
            .iter()
            .enumerate()
            .map(|(index, volume)| VolumeAuthorizationId {
                volume_id: volume.volume_id.clone(),
                authorization_id: id(&format!("authorization.{index}")),
            })
            .collect::<Vec<_>>();
        let inputs = config
            .volumes
            .iter()
            .zip(&authorizations)
            .map(|(volume, authorization)| StartVolumeAuthority {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                authority: RuntimeVolumeAuthorityInput::Takeover {
                    authorization_id: authorization.authorization_id.clone(),
                },
            })
            .collect();
        (inputs, authorizations)
    }

    fn genesis_start_with_config(config: ImmutableRuntimeConfig) -> LifecycleCommandEnvelope {
        let target = placement("node.a", 1);
        let volume_authorities = normal_authorities(&config);
        LifecycleCommandEnvelope::new(
            id("operation.genesis"),
            id("workspace.001"),
            id("cat.001"),
            target.node_id.clone(),
            target.clone(),
            config,
            None,
            LifecyclePredecessor::Genesis {
                cat_creation_id: id("creation.001"),
                target_placement: target.clone(),
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities,
                source: StartSource::Genesis,
                effect_deadline_unix_ms: millis(1_000),
            })),
        )
        .expect("valid Genesis Start")
    }

    fn genesis_start() -> LifecycleCommandEnvelope {
        genesis_start_with_config(runtime_config(2))
    }

    fn absence() -> ExecutionAbsenceProof {
        ExecutionAbsenceProof {
            stop_fence_receipt_digest: digest(31),
            admission_closed_receipt_digest: digest(32),
            dedicated_scope_absence_receipt_digest: digest(33),
            frontend_absence_receipt_digest: digest(34),
            restart_source_absence_receipt_digest: digest(35),
        }
    }

    fn retained_evidence() -> RetainedEvidence {
        RetainedEvidence {
            artifact_manifest_digest: digest(36),
            adoptable_count: 0,
            gc_candidate_count: 1,
            retained_authority_or_data_count: 1,
            quarantined_count: 0,
        }
    }

    fn command_failed(retained_volume_receipts: Vec<VolumeTerminalReceipt>) -> CommandFailedResult {
        CommandFailedResult {
            reason: CommandFailureReason::VmmFailed,
            not_running: absence(),
            retained_evidence: retained_evidence(),
            retained_volume_receipts,
        }
    }

    fn volume_receipts(
        config: &ImmutableRuntimeConfig,
        remote_equals_local: bool,
        authority_receipt: bool,
    ) -> Vec<VolumeTerminalReceipt> {
        config
            .volumes
            .iter()
            .enumerate()
            .map(|(index, volume)| VolumeTerminalReceipt {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                disk_role: volume.disk_role,
                attachment_id: id(&format!("attachment.result.{index}")),
                attachment_epoch: fence_epoch(20 + index as u64),
                local_durable_generation: generation(9),
                remote_durable_generation: generation(if remote_equals_local { 9 } else { 8 }),
                authority_receipt_digest: authority_receipt.then(|| digest(40 + index as u8)),
            })
            .collect()
    }

    fn cold_dispositions(
        config: &ImmutableRuntimeConfig,
        remote_equals_local: bool,
        authority_receipt: bool,
    ) -> Vec<ColdVolumeDisposition> {
        volume_receipts(config, remote_equals_local, authority_receipt)
            .into_iter()
            .enumerate()
            .map(|(index, volume)| ColdVolumeDisposition::NormallyReleased {
                normal_release_receipt_digest: volume
                    .authority_receipt_digest
                    .clone()
                    .unwrap_or_else(|| digest(140 + index as u8)),
                volume: Box::new(volume),
            })
            .collect()
    }

    fn runtime_ready_response(
        command: &LifecycleCommandEnvelope,
        config: &ImmutableRuntimeConfig,
    ) -> LifecycleCommandResponse {
        LifecycleCommandResponse::new(
            command,
            NodeResult::RuntimeReady(Box::new(RuntimeReadyResult {
                runtime_incarnation: random(50),
                runtime_config_digest: config.config_digest.clone(),
                execution_receipt_digest: digest(51),
                guest_ready_receipt_digest: digest(52),
                volume_receipts: volume_receipts(config, false, true),
            })),
        )
        .expect("valid RuntimeReady response")
    }

    #[test]
    fn every_owned_terminal_receipt_requires_current_start_grant_digest() {
        let config = runtime_config(2);
        let mut results = vec![
            NodeResult::RuntimeReady(Box::new(RuntimeReadyResult {
                runtime_incarnation: random(141),
                runtime_config_digest: config.config_digest.clone(),
                execution_receipt_digest: digest(142),
                guest_ready_receipt_digest: digest(143),
                volume_receipts: volume_receipts(&config, false, true),
            })),
            NodeResult::Suspended(Box::new(SuspendedResult {
                runtime_incarnation: random(144),
                runtime_config_digest: config.config_digest.clone(),
                pause_receipt_digest: digest(145),
                local_durability_receipts: volume_receipts(&config, false, true),
            })),
            NodeResult::Warm(Box::new(WarmResult {
                runtime_config_digest: config.config_digest.clone(),
                source_runtime_incarnation: random(146),
                warm_snapshot_receipt_digest: digest(147),
                warm_snapshot_manifest_digest: digest(148),
                volume_receipts: volume_receipts(&config, true, true),
            })),
            NodeResult::StartFailed(Box::new(command_failed(vec![volume_receipts(
                &config, false, true,
            )
            .remove(0)]))),
            NodeResult::Killed(Box::new(KilledResult {
                stopped_runtime_incarnation: Some(random(149)),
                execution_absence: absence(),
                stop_fence_receipt_digest: digest(150),
                retained_volume_receipts: vec![volume_receipts(&config, false, true).remove(0)],
                retained_evidence: retained_evidence(),
            })),
            NodeResult::NeedsIntervention(Box::new(NeedsInterventionResult {
                attempted_target: InterventionTarget::Cold,
                reason: InterventionReason::RetainedLocalTail,
                not_running: absence(),
                retained_evidence: retained_evidence(),
                retained_volume_receipts: vec![volume_receipts(&config, false, true).remove(0)],
            })),
        ];

        for result in &mut results {
            assert!(node_result_structure_valid(result));
            let receipts = match result {
                NodeResult::RuntimeReady(value) => &mut value.volume_receipts,
                NodeResult::Suspended(value) => &mut value.local_durability_receipts,
                NodeResult::Warm(value) => &mut value.volume_receipts,
                NodeResult::StartFailed(value) => &mut value.retained_volume_receipts,
                NodeResult::Killed(value) => &mut value.retained_volume_receipts,
                NodeResult::NeedsIntervention(value) => &mut value.retained_volume_receipts,
                _ => unreachable!(),
            };
            receipts[0].authority_receipt_digest = None;
            assert!(!node_result_structure_valid(result));
        }
    }

    fn same_node_predecessor(response: &LifecycleCommandResponse) -> LifecyclePredecessor {
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(response.clone()),
        };
        LifecyclePredecessor::SameNode {
            operation_id: response.operation_id.clone(),
            terminal_result_kind: response.result.kind(),
            terminal_result_digest: lifecycle_terminal_result_digest(&terminal).unwrap(),
            node_id: response.node_id.clone(),
            placement_identity: response.placement_identity.clone(),
        }
    }

    fn session(node: &str, instance: u128, session_epoch: u64) -> AgentSession {
        AgentSession {
            version: ContractVersion::V1,
            node_id: id(node),
            immutable_host_id: id("host.immutable.001"),
            node_boot_id: NodeBootId::new(format!("{:032x}", 70_u128)).unwrap(),
            agent_instance_id: random(instance),
            agent_session_epoch: epoch(session_epoch),
            registration_attempt_id: random(72),
            guest_config_digest: digest(73),
            lease_deadline_unix_ms: millis(10_000),
        }
    }

    #[test]
    fn canonical_request_round_trip_and_fixed_fingerprint() {
        let request = genesis_start();
        let encoded = encode_lifecycle_command_envelope(&request).unwrap();
        assert_eq!(
            decode_lifecycle_command_envelope(&encoded).unwrap(),
            request
        );
        let json = std::str::from_utf8(&encoded).unwrap();
        assert!(json.contains("\"source\":{\"kind\":\"genesis\"}"));
        assert!(json.contains("\"kind\":\"isolated_ipv4\""));
        assert_eq!(
            request.request_fingerprint.as_str(),
            "sha256:0097a4ef920fc7b9f72b2f4dbeb014dec8151a3898a619ebc8ab00624c13f687"
        );
    }

    #[test]
    fn fingerprint_binds_every_payload_field_and_rejects_tampering() {
        let original = genesis_start_with_config(runtime_config(2));
        let changed = genesis_start_with_config(runtime_config(4));
        assert_eq!(original.operation_id, changed.operation_id);
        assert_ne!(original.request_fingerprint, changed.request_fingerprint);

        let mut tampered = original.clone();
        let LifecycleCommand::Start(spec) = &mut tampered.command else {
            unreachable!();
        };
        spec.effect_deadline_unix_ms = millis(1_001);
        assert_eq!(
            validate_lifecycle_command_envelope(&tampered),
            Err(RuntimeLifecycleContractError::InvalidContract)
        );

        let mut invalid_network = runtime_config(2);
        let RuntimeNetworkConfig::IsolatedIpv4 { prefix_length, .. } =
            &mut invalid_network.network_config;
        *prefix_length = 29;
        assert!(matches!(
            validate_immutable_runtime_config(&invalid_network),
            Err(RuntimeLifecycleContractError::InvalidContract)
        ));

        let mut role_mismatch = runtime_config(2);
        role_mismatch.volumes[0].guest_binding = RuntimeVolumeGuestBinding::PersistentExt4 {
            filesystem_uuid: random(99),
            mount_path: AsciiText::new("/bad").unwrap(),
        };
        assert!(validate_immutable_runtime_config(&role_mismatch).is_err());
    }

    #[test]
    fn strict_decoder_rejects_unknown_duplicate_noncanonical_and_oversize() {
        let request = genesis_start();
        let encoded = encode_lifecycle_command_envelope(&request).unwrap();
        let body = std::str::from_utf8(&encoded).unwrap();
        let unknown = format!("{{\"unknown\":1,{}", &body[1..]);
        assert_eq!(
            decode_lifecycle_command_envelope(unknown.as_bytes()),
            Err(RuntimeLifecycleContractError::Malformed)
        );
        let duplicate = format!("{{\"version\":1,{}", &body[1..]);
        assert_eq!(
            decode_lifecycle_command_envelope(duplicate.as_bytes()),
            Err(RuntimeLifecycleContractError::Malformed)
        );
        let mut whitespace = vec![b' '];
        whitespace.extend_from_slice(&encoded);
        assert_eq!(
            decode_lifecycle_command_envelope(&whitespace),
            Err(RuntimeLifecycleContractError::NonCanonical)
        );
        assert_eq!(
            decode_lifecycle_command_envelope(&vec![
                b' ';
                LIFECYCLE_COMMAND_ENVELOPE_MAX_WIRE_BYTES + 1
            ]),
            Err(RuntimeLifecycleContractError::WireTooLarge)
        );

        let mut unsorted = runtime_config(2);
        unsorted.volumes.swap(0, 1);
        assert!(validate_immutable_runtime_config(&unsorted).is_err());
        let mut duplicate_volume = runtime_config(2);
        duplicate_volume
            .volumes
            .push(duplicate_volume.volumes[1].clone());
        assert!(validate_immutable_runtime_config(&duplicate_volume).is_err());
    }

    #[test]
    fn all_typed_predecessors_bind_source_authority_and_exact_sets() {
        let genesis = genesis_start();
        validate_lifecycle_successor(None, &genesis).unwrap();
        validate_lifecycle_initial_target_admission(&genesis).unwrap();
        let config = genesis.runtime_config().clone();
        let ready = runtime_ready_response(&genesis, &config);

        let stop = LifecycleCommandEnvelope::new(
            id("operation.stop"),
            ready.workspace_id.clone(),
            ready.cat_id.clone(),
            ready.node_id.clone(),
            ready.placement_identity.clone(),
            config.clone(),
            Some(ready.operation_id.clone()),
            same_node_predecessor(&ready),
            LifecycleCommand::Stop(StopSpec {
                grace_deadline_unix_ms: millis(3_000),
            }),
        )
        .unwrap();
        let ready_terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(ready),
        };
        validate_lifecycle_successor(Some(&ready_terminal), &stop).unwrap();
        assert!(validate_lifecycle_initial_target_admission(&stop).is_err());

        let source = placement("node.a", 1);
        let target = placement("node.b", 2);
        let release_digests: Vec<ColdVolumeDispositionDigest> = config
            .volumes
            .iter()
            .enumerate()
            .map(
                |(index, volume)| ColdVolumeDispositionDigest::NormallyReleased {
                    volume_id: volume.volume_id.clone(),
                    normal_release_receipt_digest: digest(80 + index as u8),
                },
            )
            .collect();
        let handoff = LifecycleCommandEnvelope::new(
            id("operation.handoff"),
            id("workspace.001"),
            id("cat.001"),
            target.node_id.clone(),
            target.clone(),
            config.clone(),
            Some(id("operation.cold")),
            LifecyclePredecessor::CrossNodeColdHandoff {
                cold_operation_id: id("operation.cold"),
                cold_result_digest: digest(82),
                source_node_id: source.node_id.clone(),
                source_placement: source,
                volume_disposition_receipts: release_digests.clone(),
                target_placement: target,
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: normal_authorities(&config),
                source: StartSource::ColdHandoff,
                effect_deadline_unix_ms: millis(4_000),
            })),
        )
        .unwrap();
        validate_lifecycle_initial_target_admission(&handoff).unwrap();

        let (takeover_inputs, takeover_ids) = takeover_authorities(&config);
        let recovery_target = placement("node.c", 3);
        let recovery = LifecycleCommandEnvelope::new(
            id("operation.recovery"),
            id("workspace.001"),
            id("cat.001"),
            recovery_target.node_id.clone(),
            recovery_target.clone(),
            config.clone(),
            Some(id("operation.interrupted")),
            LifecyclePredecessor::HostFenceRecovery {
                interrupted_operation_id: id("operation.interrupted"),
                host_lost_result_digest: digest(83),
                host_fence_event_id: id("host.fence.001"),
                old_node_identity: OldNodeIdentity {
                    node_id: id("node.a"),
                    immutable_host_id: id("host.a"),
                    state_path_id: id("state.a"),
                },
                takeover_authorization_ids: takeover_ids,
                target_placement: recovery_target,
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: takeover_inputs,
                source: StartSource::HostFenceRecovery,
                effect_deadline_unix_ms: millis(5_000),
            })),
        )
        .unwrap();
        validate_lifecycle_command_envelope(&recovery).unwrap();
        validate_lifecycle_initial_target_admission(&recovery).unwrap();

        let mut mismatched = recovery;
        let LifecycleCommand::Start(spec) = &mut mismatched.command else {
            unreachable!();
        };
        let RuntimeVolumeAuthorityInput::Takeover { authorization_id } =
            &mut spec.volume_authorities[0].authority
        else {
            unreachable!();
        };
        *authorization_id = id("authorization.wrong");
        assert!(lifecycle_command_request_fingerprint(&mismatched).is_err());
        assert!(validate_lifecycle_command_envelope(&mismatched).is_err());

        let cold_same_node = LifecycleCommandEnvelope::new(
            id("operation.same.cold.start"),
            id("workspace.001"),
            id("cat.001"),
            id("node.a"),
            placement("node.a", 1),
            config.clone(),
            Some(id("operation.previous.cold")),
            LifecyclePredecessor::SameNode {
                operation_id: id("operation.previous.cold"),
                terminal_result_kind: TerminalResultKind::Cold,
                terminal_result_digest: digest(84),
                node_id: id("node.a"),
                placement_identity: placement("node.a", 1),
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: normal_authorities(&config),
                source: StartSource::SameNodeCold,
                effect_deadline_unix_ms: millis(6_000),
            })),
        );
        assert!(cold_same_node.is_ok());

        let mut wrong_same_node = same_node_authorities(&config);
        wrong_same_node[0].authority = RuntimeVolumeAuthorityInput::NormalUnowned {
            expected_unowned_epoch: fence_epoch(0),
            transition_id: random(90),
        };
        assert!(LifecycleCommandEnvelope::new(
            id("operation.bad.resume"),
            id("workspace.001"),
            id("cat.001"),
            id("node.a"),
            placement("node.a", 1),
            config,
            Some(id("operation.suspended")),
            LifecyclePredecessor::SameNode {
                operation_id: id("operation.suspended"),
                terminal_result_kind: TerminalResultKind::Suspended,
                terminal_result_digest: digest(85),
                node_id: id("node.a"),
                placement_identity: placement("node.a", 1),
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: wrong_same_node,
                source: StartSource::SameNodeSuspended,
                effect_deadline_unix_ms: millis(7_000),
            })),
        )
        .is_err());
    }

    #[test]
    fn cold_requires_remote_durability_release_and_is_not_killed() {
        let config = runtime_config(2);
        let place = placement("node.a", 1);
        let cold = LifecycleCommandEnvelope::new(
            id("operation.cold"),
            id("workspace.001"),
            id("cat.001"),
            place.node_id.clone(),
            place.clone(),
            config.clone(),
            Some(id("operation.ready")),
            LifecyclePredecessor::SameNode {
                operation_id: id("operation.ready"),
                terminal_result_kind: TerminalResultKind::RuntimeReady,
                terminal_result_digest: digest(100),
                node_id: place.node_id.clone(),
                placement_identity: place,
            },
            LifecycleCommand::Cold(ColdSpec {
                grace_deadline_unix_ms: millis(1_000),
                convergence_deadline_unix_ms: millis(2_000),
            }),
        )
        .unwrap();
        let valid = LifecycleCommandResponse::new(
            &cold,
            NodeResult::Cold(Box::new(ColdResult {
                runtime_config_digest: config.config_digest.clone(),
                execution_absence: absence(),
                volume_dispositions: cold_dispositions(&config, true, true),
                local_recovery_dependency_absent_digest: digest(101),
            })),
        )
        .unwrap();
        validate_lifecycle_command_response_for_runtime_config(&valid, &config).unwrap();

        let NodeResult::Cold(cold_result) = &valid.result else {
            unreachable!();
        };
        let release_digests: Vec<ColdVolumeDispositionDigest> = cold_result
            .volume_dispositions
            .iter()
            .map(|disposition| match disposition {
                ColdVolumeDisposition::NormallyReleased {
                    volume,
                    normal_release_receipt_digest,
                } => ColdVolumeDispositionDigest::NormallyReleased {
                    volume_id: volume.volume_id.clone(),
                    normal_release_receipt_digest: normal_release_receipt_digest.clone(),
                },
                ColdVolumeDisposition::AlreadyUnowned {
                    volume_id,
                    already_unowned_receipt_digest,
                    ..
                } => ColdVolumeDispositionDigest::AlreadyUnowned {
                    volume_id: volume_id.clone(),
                    already_unowned_receipt_digest: already_unowned_receipt_digest.clone(),
                },
            })
            .collect();
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(valid.clone()),
        };
        let target = placement("node.b", 2);
        let handoff = LifecycleCommandEnvelope::new(
            id("operation.cold.handoff.start"),
            valid.workspace_id.clone(),
            valid.cat_id.clone(),
            target.node_id.clone(),
            target.clone(),
            config.clone(),
            Some(valid.operation_id.clone()),
            LifecyclePredecessor::CrossNodeColdHandoff {
                cold_operation_id: valid.operation_id.clone(),
                cold_result_digest: lifecycle_terminal_result_digest(&terminal).unwrap(),
                source_node_id: valid.node_id.clone(),
                source_placement: valid.placement_identity.clone(),
                volume_disposition_receipts: release_digests.clone(),
                target_placement: target.clone(),
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: normal_authorities(&config),
                source: StartSource::ColdHandoff,
                effect_deadline_unix_ms: millis(4_000),
            })),
        )
        .unwrap();
        validate_lifecycle_successor(Some(&terminal), &handoff).unwrap();

        // A product mutation in the settled Cold window may detach an old
        // Persistent slot and attach a new one. The handoff still carries the
        // complete old Cold receipt set, while Start authorities cover the
        // independently frozen successor config.
        let replacement_persistent = RuntimeVolumeConfig {
            volume_id: id("volume.02.replacement"),
            disk_id: id("disk.02.replacement"),
            disk_role: DiskRole::Persistent,
            size_bytes: 32 * 1024 * 1024 * 1024,
            durability: Durability::Strict,
            guest_device_serial: id("replacement.serial"),
            guest_device_slot: 2,
            guest_binding: RuntimeVolumeGuestBinding::PersistentExt4 {
                filesystem_uuid: random(108),
                mount_path: AsciiText::new("/srv/replacement").unwrap(),
            },
        };
        let successor_config = ImmutableRuntimeConfig::new(
            id("config.002"),
            config.boot_image_digest.clone(),
            config.vcpus,
            config.memory_bytes,
            config.guest_runtime_profile_digest.clone(),
            config.network_config.clone(),
            vec![config.volumes[0].clone(), replacement_persistent],
        )
        .unwrap();
        let changed_handoff = LifecycleCommandEnvelope::new(
            id("operation.cold.handoff.changed-config"),
            valid.workspace_id.clone(),
            valid.cat_id.clone(),
            target.node_id.clone(),
            target.clone(),
            successor_config.clone(),
            Some(valid.operation_id.clone()),
            LifecyclePredecessor::CrossNodeColdHandoff {
                cold_operation_id: valid.operation_id.clone(),
                cold_result_digest: lifecycle_terminal_result_digest(&terminal).unwrap(),
                source_node_id: valid.node_id.clone(),
                source_placement: valid.placement_identity.clone(),
                volume_disposition_receipts: release_digests.clone(),
                target_placement: target.clone(),
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: normal_authorities(&successor_config),
                source: StartSource::ColdHandoff,
                effect_deadline_unix_ms: millis(4_000),
            })),
        )
        .unwrap();
        validate_lifecycle_successor(Some(&terminal), &changed_handoff).unwrap();

        for mutation in ["omit", "add", "tamper"] {
            let mut invalid = changed_handoff.clone();
            let LifecyclePredecessor::CrossNodeColdHandoff {
                volume_disposition_receipts,
                ..
            } = &mut invalid.predecessor
            else {
                unreachable!();
            };
            match mutation {
                "omit" => {
                    volume_disposition_receipts.pop();
                }
                "add" => {
                    volume_disposition_receipts.push(ColdVolumeDispositionDigest::AlreadyUnowned {
                        volume_id: id("volume.zz.extra"),
                        already_unowned_receipt_digest: digest(108),
                    })
                }
                "tamper" => match &mut volume_disposition_receipts[0] {
                    ColdVolumeDispositionDigest::NormallyReleased {
                        normal_release_receipt_digest,
                        ..
                    } => *normal_release_receipt_digest = digest(108),
                    ColdVolumeDispositionDigest::AlreadyUnowned {
                        already_unowned_receipt_digest,
                        ..
                    } => *already_unowned_receipt_digest = digest(108),
                },
                _ => unreachable!(),
            }
            invalid.request_fingerprint = lifecycle_command_request_fingerprint(&invalid).unwrap();
            assert!(validate_lifecycle_command_envelope(&invalid).is_ok());
            assert!(validate_lifecycle_successor(Some(&terminal), &invalid).is_err());
        }

        let mut wrong_handoff = handoff;
        let LifecyclePredecessor::CrossNodeColdHandoff {
            cold_result_digest, ..
        } = &mut wrong_handoff.predecessor
        else {
            unreachable!();
        };
        *cold_result_digest = digest(109);
        wrong_handoff.request_fingerprint =
            lifecycle_command_request_fingerprint(&wrong_handoff).unwrap();
        assert!(validate_lifecycle_successor(Some(&terminal), &wrong_handoff).is_err());

        let killed = NodeResult::Killed(Box::new(KilledResult {
            stopped_runtime_incarnation: Some(random(102)),
            execution_absence: absence(),
            stop_fence_receipt_digest: digest(103),
            retained_volume_receipts: volume_receipts(&config, false, true),
            retained_evidence: retained_evidence(),
        }));
        assert!(LifecycleCommandResponse::new(&cold, killed).is_err());

        for (remote_equals_local, authority) in [(false, true), (true, false)] {
            let result = NodeResult::Cold(Box::new(ColdResult {
                runtime_config_digest: config.config_digest.clone(),
                execution_absence: absence(),
                volume_dispositions: cold_dispositions(&config, remote_equals_local, authority),
                local_recovery_dependency_absent_digest: digest(104),
            }));
            assert!(LifecycleCommandResponse::new(&cold, result).is_err());
        }
    }

    #[test]
    fn killed_retains_only_owned_subset_and_stopped_start_binds_each_volume_authority() {
        let config = runtime_config(2);
        let place = placement("node.a", 1);
        let stop = LifecycleCommandEnvelope::new(
            id("operation.stop"),
            id("workspace.001"),
            id("cat.001"),
            place.node_id.clone(),
            place.clone(),
            config.clone(),
            Some(id("operation.ready")),
            LifecyclePredecessor::SameNode {
                operation_id: id("operation.ready"),
                terminal_result_kind: TerminalResultKind::RuntimeReady,
                terminal_result_digest: digest(105),
                node_id: place.node_id.clone(),
                placement_identity: place,
            },
            LifecycleCommand::Stop(StopSpec {
                grace_deadline_unix_ms: millis(1_000),
            }),
        )
        .unwrap();

        // A strong Stop can precede acquisition or follow a partial Start, so
        // Killed may retain no volume authority at all.
        let empty_killed = LifecycleCommandResponse::new(
            &stop,
            NodeResult::Killed(Box::new(KilledResult {
                stopped_runtime_incarnation: None,
                execution_absence: absence(),
                stop_fence_receipt_digest: digest(106),
                retained_volume_receipts: Vec::new(),
                retained_evidence: retained_evidence(),
            })),
        )
        .unwrap();
        validate_lifecycle_command_response_for_runtime_config(&empty_killed, &config).unwrap();

        // With one retained Owned volume, the other slot must be an exact
        // NormalUnowned input.  The predecessor response, not the opaque
        // predecessor ID, decides the per-volume authority shape.
        let retained = vec![volume_receipts(&config, false, true).remove(0)];
        let killed = LifecycleCommandResponse::new(
            &stop,
            NodeResult::Killed(Box::new(KilledResult {
                stopped_runtime_incarnation: Some(random(107)),
                execution_absence: absence(),
                stop_fence_receipt_digest: digest(108),
                retained_volume_receipts: retained.clone(),
                retained_evidence: retained_evidence(),
            })),
        )
        .unwrap();
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(killed.clone()),
        };
        let mut authorities = normal_authorities(&config);
        authorities[0].authority = RuntimeVolumeAuthorityInput::SameNodeOwned {
            attachment_id: retained[0].attachment_id.clone(),
            attachment_epoch: retained[0].attachment_epoch,
        };
        let start = LifecycleCommandEnvelope::new(
            id("operation.start.after.stop"),
            killed.workspace_id.clone(),
            killed.cat_id.clone(),
            killed.node_id.clone(),
            killed.placement_identity.clone(),
            config.clone(),
            Some(killed.operation_id.clone()),
            same_node_predecessor(&killed),
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: authorities,
                source: StartSource::SameNodeStopped,
                effect_deadline_unix_ms: millis(2_000),
            })),
        )
        .unwrap();
        validate_lifecycle_successor(Some(&terminal), &start).unwrap();

        let mut wrong = start;
        let LifecycleCommand::Start(spec) = &mut wrong.command else {
            unreachable!();
        };
        spec.volume_authorities[1].authority = RuntimeVolumeAuthorityInput::SameNodeOwned {
            attachment_id: id("attachment.not-retained"),
            attachment_epoch: fence_epoch(99),
        };
        wrong.request_fingerprint = lifecycle_command_request_fingerprint(&wrong).unwrap();
        assert!(validate_lifecycle_successor(Some(&terminal), &wrong).is_err());

        let mut foreign = retained;
        foreign[0].volume_id = id("volume.foreign");
        assert!(LifecycleCommandResponse::new(
            &stop,
            NodeResult::Killed(Box::new(KilledResult {
                stopped_runtime_incarnation: None,
                execution_absence: absence(),
                stop_fence_receipt_digest: digest(109),
                retained_volume_receipts: foreign,
                retained_evidence: retained_evidence(),
            })),
        )
        .is_err());
    }

    #[test]
    fn failed_start_retry_binds_retained_owned_and_original_unowned_slots() {
        let failed_command = genesis_start();
        let config = failed_command.runtime_config().clone();
        let LifecycleCommand::Start(failed_spec) = &failed_command.command else {
            unreachable!();
        };
        let all_receipts = volume_receipts(&config, false, true);

        for (case, retained) in [
            ("empty", Vec::new()),
            ("partial", vec![all_receipts[0].clone()]),
            ("full", all_receipts.clone()),
        ] {
            let response = LifecycleCommandResponse::new(
                &failed_command,
                NodeResult::StartFailed(Box::new(command_failed(retained.clone()))),
            )
            .unwrap();
            let terminal = LifecycleTerminalResult::NodeResult {
                response: Box::new(response.clone()),
            };
            let mut retry_authorities = failed_spec.volume_authorities.clone();
            for receipt in &retained {
                let index = config
                    .volumes
                    .binary_search_by(|volume| {
                        volume.volume_id.as_str().cmp(receipt.volume_id.as_str())
                    })
                    .unwrap();
                retry_authorities[index].authority = RuntimeVolumeAuthorityInput::SameNodeOwned {
                    attachment_id: receipt.attachment_id.clone(),
                    attachment_epoch: receipt.attachment_epoch,
                };
            }
            let retry = LifecycleCommandEnvelope::new(
                id(&format!("operation.retry.{case}")),
                response.workspace_id.clone(),
                response.cat_id.clone(),
                response.node_id.clone(),
                response.placement_identity.clone(),
                config.clone(),
                Some(response.operation_id.clone()),
                same_node_predecessor(&response),
                LifecycleCommand::Start(Box::new(StartSpec {
                    volume_authorities: retry_authorities,
                    source: StartSource::SameNodeRetry,
                    effect_deadline_unix_ms: millis(2_000),
                })),
            )
            .unwrap();

            // A terminal response alone cannot recover an absent slot's exact
            // acquire transition; the canonical failed command is mandatory.
            assert!(validate_lifecycle_successor(Some(&terminal), &retry).is_err());
            validate_lifecycle_successor_with_predecessor_command(
                Some(&terminal),
                Some(&failed_command),
                &retry,
            )
            .unwrap();

            if let Some(retained_receipt) = retained.first() {
                let mut wrong_owned = retry.clone();
                let LifecycleCommand::Start(spec) = &mut wrong_owned.command else {
                    unreachable!();
                };
                let index = config
                    .volumes
                    .binary_search_by(|volume| {
                        volume
                            .volume_id
                            .as_str()
                            .cmp(retained_receipt.volume_id.as_str())
                    })
                    .unwrap();
                spec.volume_authorities[index].authority =
                    RuntimeVolumeAuthorityInput::SameNodeOwned {
                        attachment_id: retained_receipt.attachment_id.clone(),
                        attachment_epoch: fence_epoch(999),
                    };
                wrong_owned.request_fingerprint =
                    lifecycle_command_request_fingerprint(&wrong_owned).unwrap();
                assert!(validate_lifecycle_successor_with_predecessor_command(
                    Some(&terminal),
                    Some(&failed_command),
                    &wrong_owned,
                )
                .is_err());
            }

            if retained.len() < config.volumes.len() {
                let mut wrong_unowned = retry.clone();
                let LifecycleCommand::Start(spec) = &mut wrong_unowned.command else {
                    unreachable!();
                };
                let missing = config
                    .volumes
                    .iter()
                    .position(|volume| {
                        retained
                            .binary_search_by(|receipt| {
                                receipt.volume_id.as_str().cmp(volume.volume_id.as_str())
                            })
                            .is_err()
                    })
                    .unwrap();
                let RuntimeVolumeAuthorityInput::NormalUnowned { transition_id, .. } =
                    &mut spec.volume_authorities[missing].authority
                else {
                    unreachable!();
                };
                *transition_id = random(999);
                wrong_unowned.request_fingerprint =
                    lifecycle_command_request_fingerprint(&wrong_unowned).unwrap();
                assert!(validate_lifecycle_successor_with_predecessor_command(
                    Some(&terminal),
                    Some(&failed_command),
                    &wrong_unowned,
                )
                .is_err());
            }
        }

        for invalid_receipts in [
            vec![all_receipts[1].clone(), all_receipts[0].clone()],
            vec![all_receipts[0].clone(), all_receipts[0].clone()],
        ] {
            assert!(LifecycleCommandResponse::new(
                &failed_command,
                NodeResult::StartFailed(Box::new(command_failed(invalid_receipts))),
            )
            .is_err());
        }

        let mut foreign = all_receipts[0].clone();
        foreign.disk_id = id("disk.foreign");
        assert!(LifecycleCommandResponse::new(
            &failed_command,
            NodeResult::StartFailed(Box::new(command_failed(vec![foreign]))),
        )
        .is_err());

        let mut zero_epoch = all_receipts[0].clone();
        zero_epoch.attachment_epoch = fence_epoch(0);
        assert!(LifecycleCommandResponse::new(
            &failed_command,
            NodeResult::StartFailed(Box::new(command_failed(vec![zero_epoch]))),
        )
        .is_err());
    }

    #[test]
    fn suspend_and_warm_failure_retry_requires_complete_retained_receipts() {
        let config = runtime_config(2);
        let place = placement("node.a", 1);
        let commands = [
            LifecycleCommandEnvelope::new(
                id("operation.suspend.failed"),
                id("workspace.001"),
                id("cat.001"),
                place.node_id.clone(),
                place.clone(),
                config.clone(),
                Some(id("operation.ready")),
                LifecyclePredecessor::SameNode {
                    operation_id: id("operation.ready"),
                    terminal_result_kind: TerminalResultKind::RuntimeReady,
                    terminal_result_digest: digest(160),
                    node_id: place.node_id.clone(),
                    placement_identity: place.clone(),
                },
                LifecycleCommand::Suspend(SuspendSpec {
                    admission_policy: SuspendAdmissionPolicy::CloseAndDrain,
                    grace_deadline_unix_ms: millis(1_000),
                }),
            )
            .unwrap(),
            LifecycleCommandEnvelope::new(
                id("operation.warm.failed"),
                id("workspace.001"),
                id("cat.001"),
                place.node_id.clone(),
                place.clone(),
                config.clone(),
                Some(id("operation.ready")),
                LifecyclePredecessor::SameNode {
                    operation_id: id("operation.ready"),
                    terminal_result_kind: TerminalResultKind::RuntimeReady,
                    terminal_result_digest: digest(161),
                    node_id: place.node_id.clone(),
                    placement_identity: place,
                },
                LifecycleCommand::Warm(WarmSpec {
                    grace_deadline_unix_ms: millis(1_000),
                    convergence_deadline_unix_ms: millis(2_000),
                }),
            )
            .unwrap(),
        ];

        for command in commands {
            let all_receipts = volume_receipts(&config, false, true);
            for retained in [
                Vec::new(),
                vec![all_receipts[0].clone()],
                all_receipts.clone(),
            ] {
                let result = match command.command {
                    LifecycleCommand::Suspend(_) => {
                        NodeResult::SuspendFailed(Box::new(command_failed(retained.clone())))
                    }
                    LifecycleCommand::Warm(_) => {
                        NodeResult::WarmFailed(Box::new(command_failed(retained.clone())))
                    }
                    _ => unreachable!(),
                };
                let response = LifecycleCommandResponse::new(&command, result).unwrap();
                let terminal = LifecycleTerminalResult::NodeResult {
                    response: Box::new(response.clone()),
                };
                let mut authorities = normal_authorities(&config);
                for (authority, receipt) in authorities.iter_mut().zip(&retained) {
                    authority.authority = RuntimeVolumeAuthorityInput::SameNodeOwned {
                        attachment_id: receipt.attachment_id.clone(),
                        attachment_epoch: receipt.attachment_epoch,
                    };
                }
                let retry = LifecycleCommandEnvelope::new(
                    id(&format!(
                        "operation.retry.{}",
                        command.operation_id.as_str()
                    )),
                    response.workspace_id.clone(),
                    response.cat_id.clone(),
                    response.node_id.clone(),
                    response.placement_identity.clone(),
                    config.clone(),
                    Some(response.operation_id.clone()),
                    same_node_predecessor(&response),
                    LifecycleCommand::Start(Box::new(StartSpec {
                        volume_authorities: authorities,
                        source: StartSource::SameNodeRetry,
                        effect_deadline_unix_ms: millis(3_000),
                    })),
                )
                .unwrap();
                let validation = validate_lifecycle_successor_with_predecessor_command(
                    Some(&terminal),
                    Some(&command),
                    &retry,
                );
                assert_eq!(validation.is_ok(), retained.len() == config.volumes.len());
            }
        }
    }

    #[test]
    fn delete_allows_only_disposable_root_and_remote_durable_persistent() {
        let config = runtime_config(2);
        let place = placement("node.a", 1);
        let requested = vec![
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
        ];
        let delete = LifecycleCommandEnvelope::new(
            id("operation.delete"),
            id("workspace.001"),
            id("cat.001"),
            place.node_id.clone(),
            place.clone(),
            config.clone(),
            Some(id("operation.ready")),
            LifecyclePredecessor::SameNode {
                operation_id: id("operation.ready"),
                terminal_result_kind: TerminalResultKind::RuntimeReady,
                terminal_result_digest: digest(110),
                node_id: place.node_id.clone(),
                placement_identity: place,
            },
            LifecycleCommand::Delete(DeleteSpec {
                delete_id: id("delete.001"),
                grace_deadline_unix_ms: millis(1_000),
                convergence_deadline_unix_ms: millis(2_000),
                volume_dispositions: requested,
            }),
        )
        .unwrap();
        let persistent_release_digest = digest(111);
        let mut persistent = volume_receipts(&config, true, true).remove(1);
        persistent.authority_receipt_digest = Some(persistent_release_digest.clone());
        let result = NodeResult::Deleted(Box::new(DeletedResult {
            execution_absence: absence(),
            volume_dispositions: vec![
                CompletedVolumeDisposition::RootDisposableTailDeleted {
                    volume_id: config.volumes[0].volume_id.clone(),
                    disk_id: config.volumes[0].disk_id.clone(),
                    previous_attachment_id: id("attachment.root.previous"),
                    previous_attachment_epoch: fence_epoch(12),
                    disposable_authorization_id: id("authorization.root.discard"),
                    authorization_consumed_receipt_digest: digest(112),
                    delete_completion_receipt_digest: digest(115),
                    local_lineage_absence_digest: digest(113),
                },
                CompletedVolumeDisposition::PersistentRetainedDetached {
                    volume: Box::new(persistent.clone()),
                    normal_release_receipt_digest: persistent_release_digest,
                },
            ],
            destructive_cleanup_absent_digest: digest(114),
        }));
        let response = LifecycleCommandResponse::new(&delete, result).unwrap();
        let receipt = CompletedCommandReceipt::new(response.clone()).unwrap();
        assert_eq!(
            decode_completed_command_receipt(&encode_completed_command_receipt(&receipt).unwrap())
                .unwrap(),
            receipt
        );

        persistent.remote_durable_generation = generation(8);
        let bad = NodeResult::Deleted(Box::new(DeletedResult {
            execution_absence: absence(),
            volume_dispositions: vec![
                CompletedVolumeDisposition::RootDisposableTailDeleted {
                    volume_id: config.volumes[0].volume_id.clone(),
                    disk_id: config.volumes[0].disk_id.clone(),
                    previous_attachment_id: id("attachment.root.previous"),
                    previous_attachment_epoch: fence_epoch(12),
                    disposable_authorization_id: id("authorization.root.discard"),
                    authorization_consumed_receipt_digest: digest(112),
                    delete_completion_receipt_digest: digest(115),
                    local_lineage_absence_digest: digest(113),
                },
                CompletedVolumeDisposition::PersistentRetainedDetached {
                    volume: Box::new(persistent),
                    normal_release_receipt_digest: digest(111),
                },
            ],
            destructive_cleanup_absent_digest: digest(114),
        }));
        assert!(LifecycleCommandResponse::new(&delete, bad).is_err());
    }

    #[test]
    fn transport_session_is_replaceable_but_durable_result_identity_is_not() {
        let command = genesis_start();
        let config = command.runtime_config().clone();
        let response = runtime_ready_response(&command, &config);
        let session_one = session("node.a", 71, 1);
        let session_two = session("node.a", 81, 2);
        let poll = LifecycleCommandPollRequest {
            version: ContractVersion::V1,
            session: session_binding(&session_one),
            request_sequence: Sequence::new(1).unwrap(),
        };
        let batch = LifecycleCommandBatch {
            version: ContractVersion::V1,
            session: poll.session.clone(),
            request_sequence: poll.request_sequence,
            commands: vec![command.clone()],
        };
        validate_lifecycle_command_batch_for_poll(&batch, &poll, &session_one).unwrap();
        assert_eq!(
            decode_lifecycle_command_batch(&encode_lifecycle_command_batch(&batch).unwrap())
                .unwrap(),
            batch
        );

        let commit_one = LifecycleResultCommitRequest::new(&session_one, response.clone()).unwrap();
        let commit_two = LifecycleResultCommitRequest::new(&session_two, response.clone()).unwrap();
        assert_eq!(commit_one.response, commit_two.response);
        assert_eq!(
            commit_one.terminal_result_digest,
            commit_two.terminal_result_digest
        );
        validate_lifecycle_result_commit_for_command(&commit_one, &command, &session_one).unwrap();
        assert!(
            validate_lifecycle_result_commit_for_command(&commit_one, &command, &session_two)
                .is_err()
        );

        let ack = LifecycleResultStoredAck {
            version: ContractVersion::V1,
            node_id: response.node_id.clone(),
            cat_id: response.cat_id.clone(),
            operation_id: response.operation_id.clone(),
            request_fingerprint: response.request_fingerprint.clone(),
            terminal_result_digest: commit_one.terminal_result_digest.clone(),
        };
        validate_lifecycle_result_stored_ack_for_response(&ack, &response).unwrap();

        let mut wrong_workspace = response;
        wrong_workspace.workspace_id = id("workspace.wrong");
        assert!(
            validate_lifecycle_command_response_for_command(&wrong_workspace, &command).is_err()
        );
        assert!(
            LifecycleResultCommitRequest::new(&session("node.wrong", 91, 1), wrong_workspace)
                .is_err()
        );
    }

    #[test]
    fn exact_successor_operation_and_public_error_validation_are_closed() {
        let config = runtime_config(2);
        let place = placement("node.a", 1);
        let warm_command = LifecycleCommandEnvelope::new(
            id("operation.warm"),
            id("workspace.001"),
            id("cat.001"),
            place.node_id.clone(),
            place.clone(),
            config.clone(),
            Some(id("operation.ready")),
            LifecyclePredecessor::SameNode {
                operation_id: id("operation.ready"),
                terminal_result_kind: TerminalResultKind::RuntimeReady,
                terminal_result_digest: digest(120),
                node_id: place.node_id.clone(),
                placement_identity: place.clone(),
            },
            LifecycleCommand::Warm(WarmSpec {
                grace_deadline_unix_ms: millis(1_000),
                convergence_deadline_unix_ms: millis(2_000),
            }),
        )
        .unwrap();
        let intervention = LifecycleCommandResponse::new(
            &warm_command,
            NodeResult::NeedsIntervention(Box::new(NeedsInterventionResult {
                attempted_target: InterventionTarget::Warm,
                reason: InterventionReason::RetainedLocalTail,
                not_running: absence(),
                retained_evidence: retained_evidence(),
                retained_volume_receipts: volume_receipts(&config, false, true),
            })),
        )
        .unwrap();
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(intervention.clone()),
        };
        let make_successor = |operation: &str, command: LifecycleCommand| {
            LifecycleCommandEnvelope::new(
                id(operation),
                intervention.workspace_id.clone(),
                intervention.cat_id.clone(),
                intervention.node_id.clone(),
                intervention.placement_identity.clone(),
                config.clone(),
                Some(intervention.operation_id.clone()),
                same_node_predecessor(&intervention),
                command,
            )
            .unwrap()
        };
        let warm_retry = make_successor(
            "operation.warm.retry",
            LifecycleCommand::Warm(WarmSpec {
                grace_deadline_unix_ms: millis(4_000),
                convergence_deadline_unix_ms: millis(5_000),
            }),
        );
        validate_lifecycle_successor(Some(&terminal), &warm_retry).unwrap();
        let cold_retry = make_successor(
            "operation.cold.wrong",
            LifecycleCommand::Cold(ColdSpec {
                grace_deadline_unix_ms: millis(4_000),
                convergence_deadline_unix_ms: millis(5_000),
            }),
        );
        assert!(validate_lifecycle_successor(Some(&terminal), &cold_retry).is_err());

        let unresolved = LifecycleOperation {
            version: ContractVersion::V1,
            operation_id: warm_retry.operation_id.clone(),
            workspace_id: warm_retry.workspace_id.clone(),
            cat_id: warm_retry.cat_id.clone(),
            node_id: warm_retry.node_id.clone(),
            placement_identity: warm_retry.placement_identity.clone(),
            runtime_config_id: warm_retry.runtime_config.config_id.clone(),
            runtime_config_digest: warm_retry.runtime_config.config_digest.clone(),
            command_kind: warm_retry.command.kind(),
            canonical_request: Box::new(warm_retry.clone()),
            request_fingerprint: warm_retry.request_fingerprint.clone(),
            expected_predecessor_operation_id: warm_retry.expected_predecessor_operation_id.clone(),
            predecessor: warm_retry.predecessor.clone(),
            state: LifecycleOperationState::Unresolved,
            created_at_unix_ms: millis(6_000),
            terminal_at_unix_ms: None,
        };
        validate_lifecycle_operation(&unresolved).unwrap();
        let mut invalid_time = unresolved.clone();
        invalid_time.terminal_at_unix_ms = Some(millis(6_001));
        assert!(validate_lifecycle_operation(&invalid_time).is_err());

        let public_error = AtomicLifecycleError::IllegalSuccessor {
            predecessor_kind: TerminalResultKind::NeedsIntervention,
            command_kind: LifecycleCommandKind::Cold,
        };
        let encoded = encode_atomic_lifecycle_error(&public_error).unwrap();
        assert_eq!(
            decode_atomic_lifecycle_error(&encoded).unwrap(),
            public_error
        );
        assert_eq!(
            std::str::from_utf8(&encoded).unwrap(),
            "{\"code\":\"illegal_successor\",\"command_kind\":\"cold\",\"predecessor_kind\":\"needs_intervention\"}"
        );
    }
}
